//! Kanarya taraması — yalnızca Linux (`/proc/self/maps` + `/proc/self/mem`),
//! `test-vectors` feature'ı ile. Yöntemin sağlamlığı DOĞRULANMADI (plan); sonuçlar raporlanır.
//!
//! Bilinen parola ve FK, hiçbir bitişik literal ya da heap kopyası bırakmadan çalışma anında
//! üretilir; ardından `ops::encrypt` + `ops::decrypt` çalıştırılır ve süreç kendi okunabilir
//! belleğini tarar.
//!
//! Beklenti: `[heap]` (glibc malloc) bölgesinde eşleşme **yok** → iddia. Yığınlar ve anonim
//! eşlemeler (iş parçacığı yığınları, büyük ayırmalar) yalnızca raporlanır; sır envanterindeki
//! "hayır" satırları (HKDF/SHA-2 taşıma kopyaları, yazmaç taşmaları) buralarda görünebilir.

#![cfg(target_os = "linux")]
#![allow(
    clippy::unwrap_used,
    clippy::missing_panics_doc,
    clippy::cast_possible_truncation
)]

use std::io::{Read, Seek, SeekFrom};

use lephy_core::cipher::AlgId;
use lephy_core::entropy::Entropy;
use lephy_core::kdf::KdfParams;
use lephy_core::ops::{self, DecryptOptions, EncryptOptions, Input, Output};
use lephy_sys::mem::SecretBytes;

/// Kanarya baytı i: bitişik literal olmadan hesaplanır.
fn pw_byte(i: usize) -> u8 {
    // "lphy-canary-" + 20 küçük harf; ASCII, 32 bayt.
    const HEAD: [u8; 12] = [
        b'l' ^ 0x55,
        b'p' ^ 0x55,
        b'h' ^ 0x55,
        b'y' ^ 0x55,
        b'-' ^ 0x55,
        b'c' ^ 0x55,
        b'a' ^ 0x55,
        b'n' ^ 0x55,
        b'a' ^ 0x55,
        b'r' ^ 0x55,
        b'y' ^ 0x55,
        b'-' ^ 0x55,
    ];
    if i < HEAD.len() {
        HEAD[i] ^ 0x55
    } else {
        b'a' + ((i * 7 + 3) % 26) as u8
    }
}

fn fk_byte(i: usize) -> u8 {
    (0xC3u8).wrapping_add((i as u8).wrapping_mul(29)) ^ 0x5A
}

const PW_LEN: usize = 32;
const FK_LEN: usize = 32;

/// `salt`/`prefix`/`wrap_nonce` sabit, FK hesaplanmış; hiçbir şey heap'te tutulmaz.
struct CanaryEntropy {
    calls: usize,
}

impl Entropy for CanaryEntropy {
    fn fill(&mut self, dest: &mut [u8]) -> lephy_core::error::Result<()> {
        self.calls += 1;
        if self.calls == 4 {
            for (i, b) in dest.iter_mut().enumerate() {
                *b = fk_byte(i);
            }
        } else {
            dest.fill(self.calls as u8);
        }
        Ok(())
    }
}

#[derive(Default, Debug)]
struct Hits {
    heap: usize,
    stack: usize,
    anon: usize,
    other: Vec<String>,
}

fn scan(needle_at: impl Fn(usize) -> u8, len: usize) -> Hits {
    // Arama deseninin ilk 8 baytı yığında tek kopya halinde (aranan desen olarak) durur; tam
    // eşleşme `len` bayt ister ve karşılaştırma bayt bayt yapılır, desen bellekte tutulmaz.
    let maps = std::fs::read_to_string("/proc/self/maps").unwrap();
    let mut mem = std::fs::File::open("/proc/self/mem").unwrap();
    let mut hits = Hits::default();
    let mut buf = vec![0u8; 1 << 20];
    for line in maps.lines() {
        let mut parts = line.split_whitespace();
        let range = parts.next().unwrap();
        let perms = parts.next().unwrap();
        let name = parts.nth(3).unwrap_or("");
        if !perms.starts_with('r') || name == "[vvar]" || name == "[vsyscall]" || name == "[vdso]" {
            continue;
        }
        let (a, b) = range.split_once('-').unwrap();
        let (a, b) = (
            u64::from_str_radix(a, 16).unwrap(),
            u64::from_str_radix(b, 16).unwrap(),
        );
        let mut off = a;
        while off < b {
            let n = ((b - off) as usize).min(buf.len());
            if mem.seek(SeekFrom::Start(off)).is_err() {
                break;
            }
            let got = match mem.read(&mut buf[..n]) {
                Ok(k) if k > 0 => k,
                _ => break,
            };
            let mut i = 0;
            while i + len <= got {
                if buf[i] == needle_at(0) && (1..len).all(|j| buf[i + j] == needle_at(j)) {
                    // Tarayıcının kendi tamponu (`buf`) heap'tedir; okunan kopya sayılmaz.
                    let addr = off + i as u64;
                    let self_buf = buf.as_ptr() as u64;
                    if !(self_buf..self_buf + buf.len() as u64).contains(&addr) {
                        match name {
                            "[heap]" => hits.heap += 1,
                            n if n.starts_with("[stack") => hits.stack += 1,
                            "" => hits.anon += 1,
                            other => hits.other.push(other.to_string()),
                        }
                    }
                }
                i += 1;
            }
            // Okuma penceresi `len − 1` bayt örtüşür: sınırda bölünen eşleşme kaçmaz.
            off += got.saturating_sub(len.saturating_sub(1)).max(1) as u64;
        }
    }
    buf.fill(0);
    hits
}

#[test]
fn canary_not_left_in_heap_after_encrypt_and_decrypt() {
    let dir = std::env::temp_dir().join(format!("lphy-canary-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let src = dir.join("in.bin");
    std::fs::write(&src, vec![0x11u8; 200_000]).unwrap();
    let out = dir.join("out.lphy");
    let dec = dir.join("dec.bin");
    {
        let mut pw = SecretBytes::with_capacity(PW_LEN).unwrap();
        for i in 0..PW_LEN {
            pw.push_slice(&[pw_byte(i)]).unwrap();
        }
        let opts = EncryptOptions {
            alg: AlgId::XChaCha20Poly1305,
            chunk_code: 0,
            kdf: KdfParams {
                m_kib: 64 * 1024,
                t: 1,
                p: 1,
            },
            force: false,
            strict_memory: false,
            raw: true,
            pad: None,
            strict: false,
            compress: false,
            ecc: false,
        };
        ops::encrypt(
            &Input::Path(&src),
            &out,
            &pw,
            None,
            &opts,
            &mut CanaryEntropy { calls: 0 },
            &mut |_| {},
        )
        .unwrap();
        ops::decrypt(
            &out,
            &Output::Path(&dec, false),
            &pw,
            None,
            DecryptOptions::default(),
            &mut |_| {},
        )
        .unwrap();
    }
    let pw_hits = scan(pw_byte, PW_LEN);
    let fk_hits = scan(fk_byte, FK_LEN);
    eprintln!("kanarya parola: {pw_hits:?}");
    eprintln!("kanarya FK:     {fk_hits:?}");
    let _ = std::fs::remove_dir_all(&dir);
    assert_eq!(pw_hits.heap, 0, "parola heap'te kaldı");
    assert_eq!(fk_hits.heap, 0, "FK heap'te kaldı");
}
