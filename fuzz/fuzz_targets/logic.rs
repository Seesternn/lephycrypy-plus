//! Logic of the fuzz targets. Both `fuzz_targets/*.rs` (libFuzzer) and
//! `crates/lephy-core/tests/regress.rs` (which replays the `tests/regress/<target>/*` inputs on every
//! `cargo test`) include this file with `#[path]`.

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

    /// Checks that nothing was written outside the root (zip-slip/symlink escape).
    pub fn assert_contained(&self) {
        let outside: Vec<_> = std::fs::read_dir(&self.base)
            .expect("read base")
            .filter_map(Result::ok)
            .map(|e| e.file_name())
            .filter(|n| n != "root")
            .collect();
        assert!(
            outside.is_empty(),
            "extraction wrote outside the root: {outside:?}"
        );
    }
}

impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.base);
    }
}

/// Small chunks for `decrypt_known_key`: exercises multi-chunk paths cheaply.
const CHUNK: usize = 256;

pub fn header(data: &[u8]) {
    let mut b = [0u8; HEADER_LEN];
    let n = data.len().min(HEADER_LEN);
    b[..n].copy_from_slice(&data[..n]);
    if let Ok(h) = Header::parse(&b) {
        assert_eq!(h.to_bytes(), b, "an accepted header must be canonical");
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
    // Fragmented writes: also exercises split frame boundaries.
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
                Err(e) => panic!("unexpected error: {e:?}"),
            }
            s.assert_contained();
        }
        1 => {
            let mut inp: &[u8] = body;
            match verify_stream(&p, &mut inp) {
                Ok(_) | Err(Error::Corrupt { .. }) => {}
                Err(e) => panic!("unexpected error: {e:?}"),
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

/// Error-correction envelope and Reed–Solomon decoder invariants.
///
/// * mode 0: an RS codeword with at most `nsym / 2` corrupted symbols always decodes back to the
///   original message.
/// * mode 1: arbitrary bytes parsed as an envelope never panic (strict and lenient).
/// * mode 2: a real envelope with corrupted bytes either decodes to the original payload or
///   fails with an error — never returns wrong data in strict mode.
pub fn envelope(data: &[u8]) {
    use lephy_core::envelope::{DecodeReader, EncodeWriter, HEADER_AREA, NSYM, Stats};
    use lephy_core::rs;
    use std::io::{Cursor, Read};
    use std::sync::Arc;

    let Some((&mode, body)) = data.split_first() else {
        return;
    };
    match mode % 3 {
        0 => {
            let (errs, msg) = body.split_at(body.len().min(NSYM / 2 * 2));
            let msg = &msg[..msg.len().min(255 - NSYM)];
            let mut cw = msg.to_vec();
            cw.extend_from_slice(&rs::encode(msg, NSYM));
            let original = cw.clone();
            for pair in errs.as_chunks::<2>().0 {
                let pos = usize::from(pair[0]) % cw.len();
                cw[pos] ^= pair[1];
            }
            let fixed = rs::decode(&mut cw, NSYM);
            assert!(fixed.is_some(), "correctable codeword rejected");
            assert_eq!(cw, original, "decoder returned wrong codeword");
        }
        1 => {
            let mut area = [0u8; HEADER_AREA];
            let n = body.len().min(HEADER_AREA);
            area[..n].copy_from_slice(&body[..n]);
            for lenient in [false, true] {
                let stats = Arc::new(Stats::default());
                if let Ok(r) = DecodeReader::with_header(&area, &body[n..], lenient, stats) {
                    let mut sink = Vec::new();
                    let _ = r.take(1 << 20).read_to_end(&mut sink);
                }
            }
        }
        _ => {
            let (flips, payload) = body.split_at(body.len().min(64));
            let mut w = EncodeWriter::new(Cursor::new(Vec::new())).expect("encoder");
            std::io::Write::write_all(&mut w, payload).expect("write");
            let mut disk = w.finish().expect("finish").into_inner();
            for pair in flips.as_chunks::<2>().0 {
                let pos = (usize::from(pair[0]) * 257) % disk.len();
                disk[pos] ^= pair[1];
            }
            let mut area = [0u8; HEADER_AREA];
            area.copy_from_slice(&disk[..HEADER_AREA]);
            let stats = Arc::new(Stats::default());
            if let Ok(mut r) = DecodeReader::with_header(&area, &disk[HEADER_AREA..], false, stats)
            {
                let mut out = Vec::new();
                if r.read_to_end(&mut out).is_ok() {
                    assert_eq!(out, payload, "strict envelope decode returned wrong data");
                }
            }
        }
    }
}
