//! Fuzz hedeflerinin mantığı (PLAN I8, R5-14). Hem `fuzz_targets/*.rs` (libFuzzer) hem de
//! `crates/lephy-core/tests/regress.rs` (her `cargo test`te `tests/regress/<hedef>/*` girdilerini
//! yeniden oynatır) bu dosyayı `#[path]` ile içerir.

use std::io::Write;

use lephy_core::archive::{ExtractOptions, Extractor, SymlinkPolicy};
use lephy_core::cipher::{AlgId, SharedCipher};
use lephy_core::error::Error;
use lephy_core::header::{HEADER_LEN, Header, chunk_aad};
use lephy_core::names::{self, SymlinkClass};
use lephy_core::pad::RawPadWriter;
use lephy_core::pipeline::{StreamParams, decrypt_stream, encrypt_stream, verify_stream};

use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};

pub struct Scratch {
    pub base: PathBuf,
    pub root: PathBuf,
}

impl Scratch {
    pub fn new(tag: &str) -> Self {
        static N: AtomicU64 = AtomicU64::new(0);
        let base = std::env::temp_dir().join(format!(
            "lphy-fuzz-{tag}-{}-{}",
            std::process::id(),
            N.fetch_add(1, Ordering::Relaxed)
        ));
        let _ = std::fs::remove_dir_all(&base);
        std::fs::create_dir_all(&base).expect("scratch");
        let root = base.join("root");
        std::fs::create_dir(&root).expect("root");
        Self { base, root }
    }

    /// Kök dışına hiçbir şey yazılmadığını doğrular (zip-slip/symlink kaçışı).
    pub fn assert_contained(&self) {
        let outside: Vec<_> = std::fs::read_dir(&self.base)
            .expect("read base")
            .filter_map(Result::ok)
            .map(|e| e.file_name())
            .filter(|n| n != "root")
            .collect();
        assert!(outside.is_empty(), "çıkarma kök dışına yazdı: {outside:?}");
    }
}

impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.base);
    }
}

/// `decrypt_known_key` için küçük chunk: çok chunk'lı yolları ucuzca dener.
const CHUNK: usize = 256;

pub fn header(data: &[u8]) {
    let mut b = [0u8; HEADER_LEN];
    let n = data.len().min(HEADER_LEN);
    b[..n].copy_from_slice(&data[..n]);
    if let Ok(h) = Header::parse(&b) {
        assert_eq!(h.to_bytes(), b, "kabul edilen başlık kanonik olmalı");
        let _ = chunk_aad(&b);
        assert!(h.chunk_size() >= 64 * 1024);
    }
}

pub fn archive_entry(data: &[u8]) {
    let Some((&flags, body)) = data.split_first() else {
        return;
    };
    let opts = ExtractOptions {
        strict: flags & 1 != 0,
        symlinks: match (flags >> 1) & 3 {
            0 => SymlinkPolicy::None,
            1 => SymlinkPolicy::Safe,
            _ => SymlinkPolicy::Unsafe,
        },
        rename_conflicts: flags & 8 != 0,
        padded: flags & 16 != 0,
    };
    let s = Scratch::new("arc");
    let Ok(mut ex) = Extractor::new(&s.root, opts) else {
        return;
    };
    // Parçalı yazım: çerçeve sınırlarının bölünmesini de dener.
    let step = usize::from(flags >> 5) * 7 + 1;
    let mut ok = true;
    for part in body.chunks(step) {
        if ex.write_all(part).is_err() {
            ok = false;
            break;
        }
    }
    if ok {
        let _ = ex.finish();
    }
    s.assert_contained();
}

pub fn names(data: &[u8]) {
    if let Ok(p) = names::validate_archive_path(data) {
        assert!(!p.split('/').any(|c| c.is_empty() || c == "." || c == ".."));
        assert!(!p.starts_with('/') && !p.contains('\\') && !p.contains('\0'));
    }
    if data.split(|&b| b == b'/').any(|c| c == b"..") {
        assert_eq!(names::classify_symlink_target(data), SymlinkClass::Unsafe);
    }
    let _ = names::validate_symlink_target(data);
    if let Ok(s) = std::str::from_utf8(data) {
        let _ = names::fold_key(s);
        let esc = names::escape_display(s);
        assert!(!esc.contains('\u{1b}') && !esc.contains('\u{202e}'));
        let (fixed, _) = names::windows_sanitize(s);
        assert!(
            !fixed
                .chars()
                .any(|c| matches!(c, ':' | '*' | '?' | '"' | '<' | '>' | '|') || c.is_control())
        );
        assert!(!fixed.ends_with(' ') && !fixed.ends_with('.'));
    }
}

pub fn decrypt_known_key(data: &[u8]) {
    let Some((&mode, body)) = data.split_first() else {
        return;
    };
    let alg = if mode & 0x80 != 0 {
        AlgId::Aes256Gcm
    } else {
        AlgId::XChaCha20Poly1305
    };
    let cipher = SharedCipher::new(alg, &[0x42; 32]).expect("cipher");
    let p = StreamParams {
        cipher: &cipher,
        prefix: &[9u8; 24],
        aad: &[1u8; 32],
        chunk_size: CHUNK,
    };
    match mode & 3 {
        0 => {
            let mut ct = Vec::new();
            let mut inp: &[u8] = body;
            encrypt_stream(&p, &mut inp, &mut ct).expect("encrypt");
            let s = Scratch::new("dkk");
            let opts = ExtractOptions {
                padded: mode & 4 != 0,
                symlinks: if mode & 8 != 0 {
                    SymlinkPolicy::Unsafe
                } else {
                    SymlinkPolicy::Safe
                },
                ..ExtractOptions::default()
            };
            let mut ex = Extractor::new(&s.root, opts).expect("extractor");
            let mut inp: &[u8] = &ct;
            match decrypt_stream(&p, &mut inp, &mut ex) {
                Ok(n) => {
                    assert_eq!(n as usize, body.len());
                    let _ = ex.finish();
                }
                Err(Error::Corrupt { .. } | Error::Io(_) | Error::Environment(_)) => {}
                Err(e) => panic!("beklenmeyen hata: {e:?}"),
            }
            s.assert_contained();
        }
        1 => {
            let mut inp: &[u8] = body;
            match verify_stream(&p, &mut inp) {
                Ok(_) | Err(Error::Corrupt { .. }) => {}
                Err(e) => panic!("beklenmeyen hata: {e:?}"),
            }
        }
        _ => {
            let mut ct = Vec::new();
            let mut inp: &[u8] = body;
            encrypt_stream(&p, &mut inp, &mut ct).expect("encrypt");
            let mut out = Vec::new();
            let mut w = RawPadWriter::new(&mut out);
            let mut inp: &[u8] = &ct;
            if decrypt_stream(&p, &mut inp, &mut w).is_ok() {
                if let Ok((_, len)) = w.finish() {
                    assert!(len as usize <= body.len());
                }
            }
        }
    }
}
