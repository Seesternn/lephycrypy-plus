//! 256 baytlık başlık (FORMAT.md › Başlık).
//!
//! `parse` sırası: sabit alanlar → reserved (ofs 12, 15, 28..32, 192..224) sıfır → bilinmeyen
//! bayrak bitleri → nonce kuyrukları (AES) → KDF biçim sınırları; ihlal →
//! `Error::Corrupt { at: "başlık" }`, KDF'den önce. Bütçe (`m×t`, RAM) burada **değil**,
//! `kdf::check_budget`'tadır (kod 6).

use crate::cipher::AlgId;
use crate::error::{Error, Result};
use crate::kdf::KdfParams;

/// Başlık uzunluğu.
pub const HEADER_LEN: usize = 256;
/// Magic.
pub const MAGIC: [u8; 6] = *b"LPHY+\0";
/// Biçim sürümü.
pub const VERSION: u16 = 1;
/// `wrapped_fk` AAD aralığı.
pub const WRAP_AAD_END: usize = 144;
/// `header_mac` girdisi aralığı.
pub const MAC_END: usize = 224;

/// İçerik türü (ofset 9).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
#[repr(u8)]
pub enum ContentType {
    /// Ham akış (tek dosya/stdin).
    #[default]
    Raw = 0,
    /// Arşiv.
    Archive = 1,
}

/// Ayrıştırılmış başlık.
#[derive(Debug, Clone)]
pub struct Header {
    /// Algoritma.
    pub alg: AlgId,
    /// İçerik türü.
    pub content_type: ContentType,
    /// PADMÉ dolgulu mu (`stream_flags.bit0`).
    pub padded: bool,
    /// `chunk_code` 0..=4.
    pub chunk_code: u8,
    /// Argon2 parametreleri.
    pub kdf: KdfParams,
    /// Keyfile kullanılıyor mu (`kdf_flags.bit0`).
    pub keyfile: bool,
    /// Argon2 salt.
    pub salt: [u8; 32],
    /// STREAM nonce prefix'i (24 B'ın tamamı; AES'te kuyruk sıfır).
    pub stream_nonce_prefix: [u8; 24],
    /// Wrap nonce (24 B; AES'te kuyruk sıfır).
    pub wrap_nonce: [u8; 24],
    /// Taahhüt etiketi.
    pub commit_tag: [u8; 32],
    /// Sarılmış FK (32 + 16).
    pub wrapped_fk: [u8; 48],
    /// Başlık MAC'i.
    pub header_mac: [u8; 32],
}

fn corrupt(detail: &str) -> Error {
    Error::Corrupt {
        at: "başlık".into(),
        detail: Some(detail.into()),
    }
}

/// `chunk_code` → chunk boyutu (bayt).
#[must_use]
pub const fn chunk_size_for(code: u8) -> Option<usize> {
    match code {
        0 => Some(64 * 1024),
        1 => Some(256 * 1024),
        2 => Some(1024 * 1024),
        3 => Some(4 * 1024 * 1024),
        4 => Some(16 * 1024 * 1024),
        _ => None,
    }
}

impl Header {
    /// Chunk boyutu.
    #[must_use]
    pub fn chunk_size(&self) -> usize {
        chunk_size_for(self.chunk_code).unwrap_or(1024 * 1024)
    }

    /// Serileştirir. Reserved alanlar sıfır; AES nonce kuyrukları sıfırlanır.
    #[must_use]
    pub fn to_bytes(&self) -> [u8; HEADER_LEN] {
        let mut b = [0u8; HEADER_LEN];
        b[0..6].copy_from_slice(&MAGIC);
        b[6..8].copy_from_slice(&VERSION.to_le_bytes());
        b[8] = self.alg as u8;
        b[9] = self.content_type as u8;
        b[10] = u8::from(self.padded);
        b[11] = self.chunk_code;
        b[13] = 1; // kdf_id Argon2id
        b[14] = u8::from(self.keyfile);
        b[16..20].copy_from_slice(&self.kdf.m_kib.to_le_bytes());
        b[20..24].copy_from_slice(&self.kdf.t.to_le_bytes());
        b[24..28].copy_from_slice(&self.kdf.p.to_le_bytes());
        b[32..64].copy_from_slice(&self.salt);
        let pl = self.alg.prefix_len();
        b[64..64 + pl].copy_from_slice(&self.stream_nonce_prefix[..pl]);
        let nl = self.alg.nonce_len();
        b[88..88 + nl].copy_from_slice(&self.wrap_nonce[..nl]);
        b[112..144].copy_from_slice(&self.commit_tag);
        b[144..192].copy_from_slice(&self.wrapped_fk);
        b[224..256].copy_from_slice(&self.header_mac);
        b
    }

    /// Ayrıştırır ve biçim denetimlerini yapar (FORMAT.md › Çözme sırası, adım 1).
    ///
    /// # Errors
    /// Her ihlal `Error::Corrupt { at: "başlık" }` (kod 4); ayrıntı yalnızca `--verbose`.
    pub fn parse(b: &[u8; HEADER_LEN]) -> Result<Self> {
        if b[0..6] != MAGIC {
            return Err(corrupt("magic"));
        }
        let version = u16::from_le_bytes([b[6], b[7]]);
        if version != VERSION {
            return Err(corrupt("bilinmeyen sürüm"));
        }
        let alg = AlgId::from_u8(b[8]).ok_or_else(|| corrupt("alg_id"))?;
        let content_type = match b[9] {
            0 => ContentType::Raw,
            1 => ContentType::Archive,
            _ => return Err(corrupt("content_type")),
        };
        if b[10] & 0xFE != 0 {
            return Err(corrupt("stream_flags rezerve bit"));
        }
        let padded = b[10] & 1 == 1;
        let chunk_code = b[11];
        if chunk_size_for(chunk_code).is_none() {
            return Err(corrupt("chunk_code"));
        }
        if b[12] != 0 || b[15] != 0 {
            return Err(corrupt("reserved bayt ≠ 0"));
        }
        if b[13] != 1 {
            return Err(corrupt("kdf_id"));
        }
        if b[14] & 0xFE != 0 {
            return Err(corrupt("kdf_flags rezerve bit"));
        }
        let keyfile = b[14] & 1 == 1;
        if b[28..32].iter().any(|&x| x != 0) || b[192..224].iter().any(|&x| x != 0) {
            return Err(corrupt("reserved alan ≠ 0"));
        }
        let kdf = KdfParams {
            m_kib: u32::from_le_bytes([b[16], b[17], b[18], b[19]]),
            t: u32::from_le_bytes([b[20], b[21], b[22], b[23]]),
            p: u32::from_le_bytes([b[24], b[25], b[26], b[27]]),
        };
        kdf.check_format_limits()?;
        let mut salt = [0u8; 32];
        salt.copy_from_slice(&b[32..64]);
        let mut stream_nonce_prefix = [0u8; 24];
        stream_nonce_prefix.copy_from_slice(&b[64..88]);
        let mut wrap_nonce = [0u8; 24];
        wrap_nonce.copy_from_slice(&b[88..112]);
        // Nonce kuyruk kuralı.
        if stream_nonce_prefix[alg.prefix_len()..]
            .iter()
            .any(|&x| x != 0)
            || wrap_nonce[alg.nonce_len()..].iter().any(|&x| x != 0)
        {
            return Err(corrupt("nonce kuyruğu ≠ 0"));
        }
        let mut commit_tag = [0u8; 32];
        commit_tag.copy_from_slice(&b[112..144]);
        let mut wrapped_fk = [0u8; 48];
        wrapped_fk.copy_from_slice(&b[144..192]);
        let mut header_mac = [0u8; 32];
        header_mac.copy_from_slice(&b[224..256]);
        Ok(Self {
            alg,
            content_type,
            padded,
            chunk_code,
            kdf,
            keyfile,
            salt,
            stream_nonce_prefix,
            wrap_nonce,
            commit_tag,
            wrapped_fk,
            header_mac,
        })
    }
}

/// `chunk_aad = BLAKE3(header[0..13] || header[64..88])` — yalnızca değişmez alanlar.
#[must_use]
pub fn chunk_aad(b: &[u8; HEADER_LEN]) -> [u8; 32] {
    let mut h = blake3::Hasher::new();
    h.update(&b[0..13]);
    h.update(&b[64..88]);
    *h.finalize().as_bytes()
}

/// Yeni başlık için şifreleyicinin ürettiği değişken alanlar.
#[derive(Debug, Clone, Copy)]
pub struct NewHeaderParams {
    /// Algoritma.
    pub alg: AlgId,
    /// İçerik türü.
    pub content_type: ContentType,
    /// Dolgu.
    pub padded: bool,
    /// `chunk_code`.
    pub chunk_code: u8,
    /// KDF.
    pub kdf: KdfParams,
    /// Keyfile var mı.
    pub keyfile: bool,
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::panic)]
mod tests {
    use super::*;

    fn sample() -> Header {
        Header {
            alg: AlgId::Aes256Gcm,
            content_type: ContentType::Raw,
            padded: false,
            chunk_code: 2,
            kdf: KdfParams {
                m_kib: 65536,
                t: 1,
                p: 1,
            },
            keyfile: false,
            salt: [1; 32],
            stream_nonce_prefix: {
                let mut p = [0u8; 24];
                p[..7].copy_from_slice(&[2; 7]);
                p
            },
            wrap_nonce: {
                let mut p = [0u8; 24];
                p[..12].copy_from_slice(&[3; 12]);
                p
            },
            commit_tag: [4; 32],
            wrapped_fk: [5; 48],
            header_mac: [6; 32],
        }
    }

    #[test]
    fn roundtrip_and_offsets() {
        let h = sample();
        let b = h.to_bytes();
        assert_eq!(&b[0..6], b"LPHY+\0");
        assert_eq!(b[8], 2);
        assert_eq!(b[13], 1);
        assert_eq!(&b[16..20], &65536u32.to_le_bytes());
        assert_eq!(&b[224..256], &[6; 32]);
        let p = Header::parse(&b).unwrap();
        assert_eq!(p.alg, AlgId::Aes256Gcm);
        assert_eq!(p.kdf.m_kib, 65536);
        assert_eq!(p.wrapped_fk, [5; 48]);
        assert_eq!(p.chunk_size(), 1024 * 1024);
    }

    fn expect_corrupt(mut b: [u8; 256], detail: &str) {
        let _ = &mut b;
        match Header::parse(&b) {
            Err(Error::Corrupt { at, detail: d }) => {
                assert_eq!(at, "başlık");
                assert!(d.unwrap().contains(detail), "{detail}");
            }
            other => panic!("beklenen Corrupt({detail}), gelen {other:?}"),
        }
    }

    #[test]
    fn reserved_and_flags_rejected() {
        let h = sample();
        let mut b = h.to_bytes();
        b[12] = 1;
        expect_corrupt(b, "reserved");
        let mut b = h.to_bytes();
        b[200] = 1;
        expect_corrupt(b, "reserved");
        let mut b = h.to_bytes();
        b[10] |= 0x80;
        expect_corrupt(b, "stream_flags");
        let mut b = h.to_bytes();
        b[14] |= 0x02;
        expect_corrupt(b, "kdf_flags");
        let mut b = h.to_bytes();
        b[7] = 9;
        expect_corrupt(b, "sürüm");
    }

    #[test]
    fn aes_nonce_tail_must_be_zero() {
        let h = sample();
        let mut b = h.to_bytes();
        b[64 + 7] = 1;
        expect_corrupt(b, "nonce kuyruğu");
        let mut b = h.to_bytes();
        b[88 + 12] = 1;
        expect_corrupt(b, "nonce kuyruğu");
    }

    #[test]
    fn kdf_format_limits_are_code_4() {
        let h = sample();
        let mut b = h.to_bytes();
        b[16..20].copy_from_slice(&1000u32.to_le_bytes()); // m < 64 MiB
        expect_corrupt(b, "KDF");
        let mut b = h.to_bytes();
        b[24..28].copy_from_slice(&64u32.to_le_bytes()); // p=64 → 8p=512 ≤ m ok
        assert!(Header::parse(&b).is_ok());
        b[24..28].copy_from_slice(&65u32.to_le_bytes());
        expect_corrupt(b, "KDF");
    }

    #[test]
    fn chunk_aad_depends_only_on_immutable_fields() {
        let h = sample();
        let b1 = h.to_bytes();
        let mut h2 = h.clone();
        h2.salt = [9; 32];
        h2.commit_tag = [8; 32];
        h2.wrap_nonce = [0; 24];
        let b2 = h2.to_bytes();
        assert_eq!(chunk_aad(&b1), chunk_aad(&b2));
        let mut h3 = h;
        h3.stream_nonce_prefix[0] = 0xFF;
        assert_ne!(chunk_aad(&b1), chunk_aad(&h3.to_bytes()));
    }
}
