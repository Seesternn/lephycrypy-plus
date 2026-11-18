//! Key derivation (FORMAT.md › Key derivation).
//!
//! ```text
//! argon2_out     = Argon2id(P=pwd_nfc, S=salt, p, T=32, m=m_kib, t, v=0x13, K=ε, X=ε, y=2)
//! KEK            = argon2_out                                                 (no key file)
//! KEK            = HKDF-SHA512(argon2_out || BLAKE3(keyfile), salt, "lphy+/v1/kek")  (key file)
//! wrap_key       = HKDF-SHA512(KEK, salt, "lphy+/v1/wrap")
//! commit_tag     = HKDF-SHA512(KEK, salt, "lphy+/v1/commit")
//! data_key       = HKDF-SHA512(FK, stream_nonce_prefix, "lphy+/v1/data")
//! header_mac_key = HKDF-SHA512(FK, stream_nonce_prefix, "lphy+/v1/hmac")
//! ```
//! Argon2 working memory is a `LargeSecretBuf<Block>` (mmap, best-effort lock, zeroed on Drop).

use argon2::{Algorithm, Argon2, Block, Params, Version};
use hkdf::Hkdf;
use lephy_sys::mem::{LargeSecretBuf, SecretBytes};
use sha2::Sha512;
use zeroize::Zeroize;

use crate::error::{Error, Result};

/// HKDF info strings (ASCII, no NUL, no length prefix).
pub const INFO_KEK: &[u8] = b"lphy+/v1/kek";
/// See [`INFO_KEK`].
pub const INFO_WRAP: &[u8] = b"lphy+/v1/wrap";
/// See [`INFO_KEK`].
pub const INFO_COMMIT: &[u8] = b"lphy+/v1/commit";
/// See [`INFO_KEK`].
pub const INFO_DATA: &[u8] = b"lphy+/v1/data";
/// See [`INFO_KEK`].
pub const INFO_HMAC: &[u8] = b"lphy+/v1/hmac";

/// Argon2 output / all derived keys are 32 B.
pub const KEY_LEN: usize = 32;

/// Argon2id parameters (header offsets 16..28).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct KdfParams {
    /// Memory (KiB).
    pub m_kib: u32,
    /// Iterations.
    pub t: u32,
    /// Parallelism (lanes).
    pub p: u32,
}

impl KdfParams {
    /// Default: 512 MiB / 3 / 4.
    pub const DEFAULT: Self = Self {
        m_kib: 512 * 1024,
        t: 3,
        p: 4,
    };
    /// Format lower limit: 64 MiB.
    pub const MIN_M_KIB: u32 = 64 * 1024;
    /// Format upper limit: 4 GiB.
    pub const MAX_M_KIB: u32 = 4 * 1024 * 1024;
    /// Upper limit for `t`.
    pub const MAX_T: u32 = 64;
    /// Upper limit for `p`.
    pub const MAX_P: u32 = 64;
    /// Budget: `m_kib × t ≤ 16 GiB·iterations` (in KiB).
    pub const BUDGET_KIB_ITER: u64 = 16 * 1024 * 1024;

    /// Format limits (FORMAT.md): a violation → code 4. Checked before key derivation.
    ///
    /// # Errors
    /// `Error::Corrupt { at: "header" }`.
    pub fn check_format_limits(&self) -> Result<()> {
        let bad = |d: &str| Error::Corrupt {
            at: "header".into(),
            detail: Some(format!("KDF parameter: {d}")),
        };
        if self.m_kib < Self::MIN_M_KIB || self.m_kib > Self::MAX_M_KIB {
            return Err(bad("m_kib out of range"));
        }
        if self.t < 1 || self.t > Self::MAX_T {
            return Err(bad("t out of range"));
        }
        if self.p < 1 || self.p > Self::MAX_P {
            return Err(bad("p out of range"));
        }
        if self.p.saturating_mul(8) > self.m_kib {
            return Err(bad("8·p > m"));
        }
        Ok(())
    }

    /// Largest KDF memory accepted without confirmation when RAM cannot be measured (1 GiB).
    pub const UNKNOWN_RAM_MAX_KIB: u32 = 1024 * 1024;

    /// Budget and RAM check (code 6). `ram_bytes` = physical RAM; with `None`, only up to
    /// `UNKNOWN_RAM_MAX_KIB` is accepted (unless `allow_large`).
    ///
    /// # Errors
    /// `Error::KdfBudget` — `allow_large` may exceed the budget, never the RAM threshold.
    pub fn check_budget(&self, allow_large: bool, ram_bytes: Option<u64>) -> Result<()> {
        let cost = u64::from(self.m_kib) * u64::from(self.t);
        if cost > Self::BUDGET_KIB_ITER && !allow_large {
            return Err(Error::KdfBudget(format!(
                "~{} MiB × {} iterations, budget 16 GiB·iterations",
                self.m_kib / 1024,
                self.t
            )));
        }
        match ram_bytes {
            Some(ram) => {
                let need = u64::from(self.m_kib) * 1024;
                if need > ram / 4 * 3 {
                    return Err(Error::KdfBudget(format!(
                        "~{} MiB of memory exceeds 75 % of physical RAM ({} MiB)",
                        self.m_kib / 1024,
                        ram / 1024 / 1024 / 4 * 3
                    )));
                }
            }
            // RAM could not be measured: stay on the safe side (a header asking for a lot of
            // memory must not exhaust it).
            None if !allow_large && self.m_kib > Self::UNKNOWN_RAM_MAX_KIB => {
                return Err(Error::KdfBudget(format!(
                    "physical RAM could not be measured; ~{} MiB of KDF memory needs confirmation",
                    self.m_kib / 1024
                )));
            }
            None => {}
        }
        Ok(())
    }

    /// Encryption policy: at least 64 MiB.
    ///
    /// # Errors
    /// `Error::Environment`.
    pub fn check_encrypt_policy(&self) -> Result<()> {
        self.check_format_limits().map_err(|_| {
            Error::Environment(
                "invalid KDF parameters (m ≥ 64 MiB, t 1..64, p 1..64, 8·p ≤ m)".into(),
            )
        })
    }

    /// Estimate shown to the user: memory (MiB).
    #[must_use]
    pub const fn memory_mib(&self) -> u32 {
        self.m_kib / 1024
    }
}

fn arena_err(e: impl std::fmt::Display) -> Error {
    Error::Environment(format!("locked memory: {e}"))
}

/// `argon2_out = Argon2id(pwd_nfc, salt, …)`; 32 B, locked.
///
/// # Errors
/// Memory could not be allocated (code 1/6) or an argon2 error.
pub fn argon2_out(pwd_nfc: &[u8], salt: &[u8; 32], params: &KdfParams) -> Result<SecretBytes> {
    params.check_format_limits()?;
    let p = Params::new(params.m_kib, params.t, params.p, Some(KEY_LEN))
        .map_err(|e| Error::Environment(format!("argon2 parameters: {e}")))?;
    let a = Argon2::new(Algorithm::Argon2id, Version::V0x13, p);
    let blocks = usize::try_from(params.m_kib).map_err(|_| Error::Environment("m_kib".into()))?;
    let mut mem = LargeSecretBuf::<Block>::new_filled(blocks, Block::new()).map_err(|e| {
        Error::KdfBudget(format!(
            "Argon2 memory ({} MiB) could not be allocated: {e}",
            params.memory_mib()
        ))
    })?;
    let mut out = SecretBytes::with_capacity(KEY_LEN).map_err(arena_err)?;
    out.set_len(KEY_LEN).map_err(arena_err)?;
    a.hash_password_into_with_memory(pwd_nfc, salt, out.expose_mut(), mem.as_mut_slice())
        .map_err(|e| Error::Environment(format!("argon2: {e}")))?;
    Ok(out)
}

/// HKDF-SHA512, L = 32, directly into `out`.
pub fn hkdf32(ikm: &[u8], salt: &[u8], info: &[u8], out: &mut [u8; KEY_LEN]) {
    let hk = Hkdf::<Sha512>::new(Some(salt), ikm);
    // L=32 ≤ 255·64; cannot fail.
    let _ = hk.expand(info, out);
}

/// BLAKE3 of the key-file content (unkeyed, 32 B).
#[must_use]
pub fn keyfile_digest(keyfile_bytes: &[u8]) -> [u8; 32] {
    let mut h = blake3::Hasher::new();
    h.update(keyfile_bytes);
    let out = *h.finalize().as_bytes();
    h.zeroize();
    out
}

/// KEK: `argon2_out` itself without a key file; with one, `HKDF(argon2_out || BLAKE3(keyfile))`.
/// `argon2_out` is consumed (zeroized when dropped).
///
/// # Errors
/// Arena error.
pub fn derive_kek(
    mut argon2_out: SecretBytes,
    keyfile_digest: Option<&[u8; 32]>,
    salt: &[u8; 32],
) -> Result<SecretBytes> {
    let Some(kd) = keyfile_digest else {
        return Ok(argon2_out);
    };
    // ikm = argon2_out || BLAKE3(keyfile): concatenated in a locked buffer.
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

/// Derives `wrap_key` (locked) and `commit_tag` (not secret) from the KEK.
///
/// # Errors
/// Arena error.
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

/// Derives `data_key` and `header_mac_key` from FK (salt = `stream_nonce_prefix`, all 24 bytes).
///
/// # Errors
/// Arena error.
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

/// `header_mac = BLAKE3-keyed(header_mac_key, header[0..224])`. The `Hasher` is zeroized
/// explicitly after use (no `ZeroizeOnDrop`).
///
/// # Errors
/// Key length ≠ 32.
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
        // Unknown RAM: large memory is refused without confirmation, the default is accepted.
        let big = KdfParams {
            m_kib: 2 * 1024 * 1024,
            t: 1,
            p: 1,
        };
        assert!(matches!(
            big.check_budget(false, None),
            Err(Error::KdfBudget(_))
        ));
        assert!(big.check_budget(true, None).is_ok());
        assert!(KdfParams::DEFAULT.check_budget(false, None).is_ok());
    }

    #[test]
    fn rfc9106_argon2id_kat_via_small_params_is_out_of_format_range() {
        // The RFC 9106 §5.3 vector uses m=32 KiB; the format minimum is 64 MiB, so the KAT runs
        // separately (tests/kat) directly through the argon2 crate.
        let p = KdfParams {
            m_kib: 32,
            t: 3,
            p: 4,
        };
        assert!(p.check_format_limits().is_err());
    }

    #[test]
    fn hkdf_rfc5869_a1_sha256_shape_holds_for_sha512_pipeline() {
        // RFC 5869 Appendix A only covers SHA-256/SHA-1; SHA-512 is cross-checked with Python.
        // Here determinism and salt/info sensitivity are checked.
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
    #[ignore = "64 MiB Argon2; run with `cargo test -- --ignored`"]
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
