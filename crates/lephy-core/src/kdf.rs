//! Anahtar türetme (FORMAT.md › Anahtar türetme).
//!
//! ```text
//! argon2_out     = Argon2id(P=pwd_nfc, S=salt, p, T=32, m=m_kib, t, v=0x13, K=ε, X=ε, y=2)
//! KEK            = argon2_out                                                 (keyfile yok)
//! KEK            = HKDF-SHA512(argon2_out || BLAKE3(keyfile), salt, "lphy+/v1/kek")  (keyfile)
//! wrap_key       = HKDF-SHA512(KEK, salt, "lphy+/v1/wrap")
//! commit_tag     = HKDF-SHA512(KEK, salt, "lphy+/v1/commit")
//! data_key       = HKDF-SHA512(FK, stream_nonce_prefix, "lphy+/v1/data")
//! header_mac_key = HKDF-SHA512(FK, stream_nonce_prefix, "lphy+/v1/hmac")
//! ```
//! Argon2 çalışma belleği `LargeSecretBuf<Block>` (mmap, best-effort kilit, Drop'ta sıfır).

use argon2::{Algorithm, Argon2, Block, Params, Version};
use hkdf::Hkdf;
use lephy_sys::mem::{LargeSecretBuf, SecretBytes};
use sha2::Sha512;
use zeroize::Zeroize;

use crate::error::{Error, Result};

/// HKDF info dizgileri (ASCII, NUL yok, uzunluk öneki yok).
pub const INFO_KEK: &[u8] = b"lphy+/v1/kek";
/// Bkz. [`INFO_KEK`].
pub const INFO_WRAP: &[u8] = b"lphy+/v1/wrap";
/// Bkz. [`INFO_KEK`].
pub const INFO_COMMIT: &[u8] = b"lphy+/v1/commit";
/// Bkz. [`INFO_KEK`].
pub const INFO_DATA: &[u8] = b"lphy+/v1/data";
/// Bkz. [`INFO_KEK`].
pub const INFO_HMAC: &[u8] = b"lphy+/v1/hmac";

/// Argon2 çıktısı / tüm türetilmiş anahtarlar 32 B.
pub const KEY_LEN: usize = 32;

/// Argon2id parametreleri (başlık ofset 16..28).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct KdfParams {
    /// Bellek (KiB).
    pub m_kib: u32,
    /// Yineleme.
    pub t: u32,
    /// Paralellik (lane).
    pub p: u32,
}

impl KdfParams {
    /// Varsayılan: 512 MiB / 3 / 4.
    pub const DEFAULT: Self = Self {
        m_kib: 512 * 1024,
        t: 3,
        p: 4,
    };
    /// Biçim alt sınırı: 64 MiB.
    pub const MIN_M_KIB: u32 = 64 * 1024;
    /// Biçim üst sınırı: 4 GiB.
    pub const MAX_M_KIB: u32 = 4 * 1024 * 1024;
    /// `t` üst sınırı.
    pub const MAX_T: u32 = 64;
    /// `p` üst sınırı.
    pub const MAX_P: u32 = 64;
    /// Bütçe: `m_kib × t ≤ 16 GiB·iter` (KiB cinsinden).
    pub const BUDGET_KIB_ITER: u64 = 16 * 1024 * 1024;

    /// Biçim sınırları (FORMAT.md): ihlal → kod 4. KDF çağrılmadan önce.
    ///
    /// # Errors
    /// `Error::Corrupt { at: "başlık" }`.
    pub fn check_format_limits(&self) -> Result<()> {
        let bad = |d: &str| Error::Corrupt {
            at: "başlık".into(),
            detail: Some(format!("KDF parametresi: {d}")),
        };
        if self.m_kib < Self::MIN_M_KIB || self.m_kib > Self::MAX_M_KIB {
            return Err(bad("m_kib aralık dışı"));
        }
        if self.t < 1 || self.t > Self::MAX_T {
            return Err(bad("t aralık dışı"));
        }
        if self.p < 1 || self.p > Self::MAX_P {
            return Err(bad("p aralık dışı"));
        }
        if self.p.saturating_mul(8) > self.m_kib {
            return Err(bad("8·p > m"));
        }
        Ok(())
    }

    /// Bütçe ve RAM denetimi (kod 6). `ram_bytes` = fiziksel RAM; `None` ise RAM denetimi atlanır.
    ///
    /// # Errors
    /// `Error::KdfBudget` — `allow_large` ile bütçe aşılabilir, RAM eşiği aşılamaz.
    pub fn check_budget(&self, allow_large: bool, ram_bytes: Option<u64>) -> Result<()> {
        let cost = u64::from(self.m_kib) * u64::from(self.t);
        if cost > Self::BUDGET_KIB_ITER && !allow_large {
            return Err(Error::KdfBudget(format!(
                "~{} MiB × {} yineleme, bütçe 16 GiB·iter",
                self.m_kib / 1024,
                self.t
            )));
        }
        if let Some(ram) = ram_bytes {
            let need = u64::from(self.m_kib) * 1024;
            if need > ram / 4 * 3 {
                return Err(Error::KdfBudget(format!(
                    "~{} MiB bellek, fiziksel RAM'in %75'i ({} MiB) aşılıyor",
                    self.m_kib / 1024,
                    ram / 1024 / 1024 / 4 * 3
                )));
            }
        }
        Ok(())
    }

    /// Şifreleme politikası: minimum 64 MiB.
    ///
    /// # Errors
    /// `Error::Environment`.
    pub fn check_encrypt_policy(&self) -> Result<()> {
        self.check_format_limits().map_err(|_| {
            Error::Environment(
                "KDF parametreleri geçersiz (m ≥ 64 MiB, t 1..64, p 1..64, 8·p ≤ m)".into(),
            )
        })
    }

    /// Kullanıcıya gösterilen tahmin: bellek (MiB).
    #[must_use]
    pub const fn memory_mib(&self) -> u32 {
        self.m_kib / 1024
    }
}

fn arena_err(e: impl std::fmt::Display) -> Error {
    Error::Environment(format!("kilitli bellek: {e}"))
}

/// `argon2_out = Argon2id(pwd_nfc, salt, …)`; 32 B, kilitli.
///
/// # Errors
/// Bellek ayrılamadı (kod 1/6) ya da argon2 hatası.
pub fn argon2_out(pwd_nfc: &[u8], salt: &[u8; 32], params: &KdfParams) -> Result<SecretBytes> {
    params.check_format_limits()?;
    let p = Params::new(params.m_kib, params.t, params.p, Some(KEY_LEN))
        .map_err(|e| Error::Environment(format!("argon2 parametre: {e}")))?;
    let a = Argon2::new(Algorithm::Argon2id, Version::V0x13, p);
    let blocks = usize::try_from(params.m_kib).map_err(|_| Error::Environment("m_kib".into()))?;
    let mut mem = LargeSecretBuf::<Block>::new_filled(blocks, Block::new()).map_err(|e| {
        Error::KdfBudget(format!(
            "Argon2 belleği ({} MiB) ayrılamadı: {e}",
            params.memory_mib()
        ))
    })?;
    let mut out = SecretBytes::with_capacity(KEY_LEN).map_err(arena_err)?;
    out.set_len(KEY_LEN).map_err(arena_err)?;
    a.hash_password_into_with_memory(pwd_nfc, salt, out.expose_mut(), mem.as_mut_slice())
        .map_err(|e| Error::Environment(format!("argon2: {e}")))?;
    Ok(out)
}

/// HKDF-SHA512, L = 32, doğrudan `out`'a.
pub fn hkdf32(ikm: &[u8], salt: &[u8], info: &[u8], out: &mut [u8; KEY_LEN]) {
    let hk = Hkdf::<Sha512>::new(Some(salt), ikm);
    // L=32 ≤ 255·64; hata imkânsız.
    let _ = hk.expand(info, out);
}

/// Keyfile içeriğinin BLAKE3'ü (anahtarsız, 32 B).
#[must_use]
pub fn keyfile_digest(keyfile_bytes: &[u8]) -> [u8; 32] {
    let mut h = blake3::Hasher::new();
    h.update(keyfile_bytes);
    let out = *h.finalize().as_bytes();
    h.zeroize();
    out
}

/// KEK: keyfile yoksa `argon2_out`'un kendisi; varsa `HKDF(argon2_out || BLAKE3(keyfile))`.
/// `argon2_out` tüketilir (düşürülünce sıfırlanır).
///
/// # Errors
/// Arena hatası.
pub fn derive_kek(
    mut argon2_out: SecretBytes,
    keyfile_digest: Option<&[u8; 32]>,
    salt: &[u8; 32],
) -> Result<SecretBytes> {
    let Some(kd) = keyfile_digest else {
        return Ok(argon2_out);
    };
    // ikm = argon2_out || BLAKE3(keyfile): bitiştirme kilitli tamponda.
    let mut ikm = SecretBytes::with_capacity(64).map_err(arena_err)?;
    ikm.push_slice(argon2_out.expose()).map_err(arena_err)?;
    ikm.push_slice(kd).map_err(arena_err)?;
    argon2_out.clear();
    let mut kek = SecretBytes::with_capacity(KEY_LEN).map_err(arena_err)?;
    kek.set_len(KEY_LEN).map_err(arena_err)?;
    let out: &mut [u8; KEY_LEN] = kek
        .expose_mut()
        .try_into()
        .map_err(|_| Error::Environment("kek len".into()))?;
    hkdf32(ikm.expose(), salt, INFO_KEK, out);
    Ok(kek)
}

/// KEK'ten `wrap_key` (kilitli) ve `commit_tag` (sır değil) türetir.
///
/// # Errors
/// Arena hatası.
pub fn derive_wrap_and_commit(
    kek: &SecretBytes,
    salt: &[u8; 32],
) -> Result<(SecretBytes, [u8; 32])> {
    let mut wrap = SecretBytes::with_capacity(KEY_LEN).map_err(arena_err)?;
    wrap.set_len(KEY_LEN).map_err(arena_err)?;
    let out: &mut [u8; KEY_LEN] = wrap
        .expose_mut()
        .try_into()
        .map_err(|_| Error::Environment("wrap len".into()))?;
    hkdf32(kek.expose(), salt, INFO_WRAP, out);
    let mut commit = [0u8; KEY_LEN];
    hkdf32(kek.expose(), salt, INFO_COMMIT, &mut commit);
    Ok((wrap, commit))
}

/// FK'dan `data_key` ve `header_mac_key` türetir (salt = `stream_nonce_prefix`, 24 B'ın tamamı).
///
/// # Errors
/// Arena hatası.
pub fn derive_fk_subkeys(
    fk: &SecretBytes,
    stream_nonce_prefix: &[u8; 24],
) -> Result<(SecretBytes, SecretBytes)> {
    let mut data = SecretBytes::with_capacity(KEY_LEN).map_err(arena_err)?;
    data.set_len(KEY_LEN).map_err(arena_err)?;
    let out: &mut [u8; KEY_LEN] = data
        .expose_mut()
        .try_into()
        .map_err(|_| Error::Environment("data len".into()))?;
    hkdf32(fk.expose(), stream_nonce_prefix, INFO_DATA, out);
    let mut mac = SecretBytes::with_capacity(KEY_LEN).map_err(arena_err)?;
    mac.set_len(KEY_LEN).map_err(arena_err)?;
    let out: &mut [u8; KEY_LEN] = mac
        .expose_mut()
        .try_into()
        .map_err(|_| Error::Environment("mac len".into()))?;
    hkdf32(fk.expose(), stream_nonce_prefix, INFO_HMAC, out);
    Ok((data, mac))
}

/// `header_mac = BLAKE3-keyed(header_mac_key, header[0..224])`. `Hasher` kullanım sonunda
/// açıkça sıfırlanır (`ZeroizeOnDrop` yok).
///
/// # Errors
/// Anahtar uzunluğu ≠ 32.
pub fn header_mac(header_mac_key: &SecretBytes, header_prefix: &[u8]) -> Result<[u8; 32]> {
    let key: &[u8; 32] = header_mac_key
        .expose()
        .try_into()
        .map_err(|_| Error::Environment("header_mac_key len".into()))?;
    let mut h = blake3::Hasher::new_keyed(key);
    h.update(header_prefix);
    let out = *h.finalize().as_bytes();
    h.zeroize();
    Ok(out)
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::panic)]
mod tests {
    use super::*;

    #[test]
    fn info_strings_match_format_hex_table() {
        assert_eq!(
            INFO_KEK,
            &hex::decode("6c7068792b2f76312f6b656b").unwrap()[..]
        );
        assert_eq!(
            INFO_WRAP,
            &hex::decode("6c7068792b2f76312f77726170").unwrap()[..]
        );
        assert_eq!(
            INFO_COMMIT,
            &hex::decode("6c7068792b2f76312f636f6d6d6974").unwrap()[..]
        );
        assert_eq!(
            INFO_DATA,
            &hex::decode("6c7068792b2f76312f64617461").unwrap()[..]
        );
        assert_eq!(
            INFO_HMAC,
            &hex::decode("6c7068792b2f76312f686d6163").unwrap()[..]
        );
    }

    #[test]
    fn budget_rules() {
        let p = KdfParams {
            m_kib: 4 * 1024 * 1024,
            t: 5,
            p: 1,
        };
        assert!(matches!(
            p.check_budget(false, None),
            Err(Error::KdfBudget(_))
        ));
        assert!(p.check_budget(true, None).is_ok());
        let q = KdfParams {
            m_kib: 1024 * 1024,
            t: 1,
            p: 1,
        };
        assert!(matches!(
            q.check_budget(true, Some(1024 * 1024 * 1024)),
            Err(Error::KdfBudget(_))
        ));
        assert!(q.check_budget(false, Some(8 * 1024 * 1024 * 1024)).is_ok());
    }

    #[test]
    fn rfc9106_argon2id_kat_via_small_params_is_out_of_format_range() {
        // RFC 9106 §5.3 vektörü m=32 KiB kullanır; biçim sınırı 64 MiB olduğundan KAT ayrı
        // testte (tests/kat) doğrudan argon2 crate'i üzerinden çalıştırılır.
        let p = KdfParams {
            m_kib: 32,
            t: 3,
            p: 4,
        };
        assert!(p.check_format_limits().is_err());
    }

    #[test]
    fn hkdf_rfc5869_a1_sha256_shape_holds_for_sha512_pipeline() {
        // RFC 5869 Ek A yalnızca SHA-256/SHA-1 verir; SHA-512 için Python çapraz kontrol.
        // Burada determinizm ve salt/info duyarlılığı denetlenir.
        let mut a = [0u8; 32];
        let mut b = [0u8; 32];
        hkdf32(b"ikm", b"salt", INFO_DATA, &mut a);
        hkdf32(b"ikm", b"salt", INFO_DATA, &mut b);
        assert_eq!(a, b);
        hkdf32(b"ikm", b"salt", INFO_HMAC, &mut b);
        assert_ne!(a, b);
    }

    #[test]
    fn kek_with_keyfile_differs_and_consumes_argon2_out() {
        let salt = [1u8; 32];
        let a = SecretBytes::from_slice(&[2u8; 32]).unwrap();
        let k1 = derive_kek(a, None, &salt).unwrap();
        let a2 = SecretBytes::from_slice(&[2u8; 32]).unwrap();
        let kd = keyfile_digest(&[9u8; 64]);
        let k2 = derive_kek(a2, Some(&kd), &salt).unwrap();
        assert_ne!(k1.expose(), k2.expose());
        let (w, c) = derive_wrap_and_commit(&k1, &salt).unwrap();
        assert_ne!(w.expose(), &c[..]);
    }

    #[test]
    #[ignore = "64 MiB Argon2; `cargo test -- --ignored` ile"]
    fn argon2_min_params_runs() {
        let p = KdfParams {
            m_kib: 65536,
            t: 1,
            p: 1,
        };
        let out = argon2_out(b"test", &[0u8; 32], &p).unwrap();
        assert_eq!(out.len(), 32);
    }
}
