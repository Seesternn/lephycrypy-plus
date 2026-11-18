//! Post-quantum hybrid recipients: ML-KEM-768 (FIPS 203) together with X25519
//! (FORMAT.md › Format version 2 (hybrid recipients)).
//!
//! A hybrid file has `feature_flags.bit1` and `bit3` set; every stanza is hybrid (mixing with
//! classic X25519-only stanzas would leave a quantum-weak way in). An attacker has to break both
//! X25519 and ML-KEM-768 to unwrap the file key.
//!
//! ```text
//! stanza     = E (32) ‖ ct (1088) ‖ wrap_nonce (24) ‖ commit (32) ‖ wrapped_fk (48)    1224 bytes
//! E          = X25519(e, 9);  ss_x = X25519(e, pk_x)            (all-zero → reject)
//! ct, ss_k   = ML-KEM-768.Encaps(ek, m)                         (m: 32 random bytes)
//! kek        = HKDF-SHA512(ikm = ss_x ‖ ss_k, salt = E ‖ pk_x ‖ BLAKE3(ek) ‖ BLAKE3(ct),
//!                          info = "lphy+/v2/hybrid")
//! wrap_key, commit and wrapped_fk as for X25519 stanzas (salt E, AAD = header[0..144] ‖ E)
//! ```
//!
//! The ML-KEM key of an identity is derived from its secret `sk`:
//! `d = HKDF-SHA512(sk, "", "lphy+/v2/ml-kem-768/d")`, `z = HKDF-SHA512(sk, "", "lphy+/v2/ml-kem-768/z")`,
//! `(ek, dk) = ML-KEM-768.KeyGen_internal(d, z)` — so existing identities and paper backups
//! cover it.

use std::fmt;
use std::str::FromStr;

use lephy_sys::mem::SecretBytes;
use ml_kem::kem::{Decapsulate, KeyExport};
use ml_kem::{B32, DecapsulationKey, EncapsulationKey, MlKem768, Seed};
use subtle::ConstantTimeEq;
use zeroize::Zeroizing;

use crate::cipher::{AlgId, SharedCipher, TAG_LEN};
use crate::entropy::Entropy;
use crate::error::{Error, Result};
use crate::header::{HEADER_LEN, WRAP_AAD_END};
use crate::kdf::{self, KEY_LEN};

/// Encapsulation key length.
pub const EK_LEN: usize = 1184;
/// Ciphertext length.
pub const CT_LEN: usize = 1088;
/// Hybrid stanza length.
pub const PQ_STANZA_LEN: usize = 32 + CT_LEN + 24 + 32 + 48;
/// Text prefix of a hybrid public key.
pub const HYBRID_PREFIX: &str = "lphypq1";
const INFO_D: &[u8] = b"lphy+/v2/ml-kem-768/d";
const INFO_Z: &[u8] = b"lphy+/v2/ml-kem-768/z";
const INFO_HYBRID: &[u8] = b"lphy+/v2/hybrid";

fn arena_err(e: impl fmt::Display) -> Error {
    Error::Environment(format!("locked memory: {e}"))
}

fn bad_key(detail: &str) -> Error {
    Error::Environment(format!("invalid post-quantum public key: {detail}"))
}

/// A hybrid public key: X25519 and ML-KEM-768 encapsulation key.
#[derive(Clone, PartialEq, Eq)]
pub struct HybridKey {
    /// X25519 public key.
    pub x: [u8; 32],
    /// ML-KEM-768 encapsulation key.
    pub ek: Box<[u8; EK_LEN]>,
}

impl fmt::Debug for HybridKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = self.to_string();
        write!(f, "HybridKey({}…)", &s[..24.min(s.len())])
    }
}

fn checksum(body: &[u8]) -> [u8; 4] {
    let h = blake3::hash(body);
    let mut c = [0u8; 4];
    c.copy_from_slice(&h.as_bytes()[..4]);
    c
}

impl fmt::Display for HybridKey {
    /// `lphypq1` followed by base32 of `x ‖ ek ‖ BLAKE3(x ‖ ek)[..4]`.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut raw = Vec::with_capacity(32 + EK_LEN + 4);
        raw.extend_from_slice(&self.x);
        raw.extend_from_slice(&self.ek[..]);
        let c = checksum(&raw);
        raw.extend_from_slice(&c);
        write!(
            f,
            "{HYBRID_PREFIX}{}",
            crate::recipient::base32_encode(&raw)
        )
    }
}

impl FromStr for HybridKey {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self> {
        let body = s
            .trim()
            .strip_prefix(HYBRID_PREFIX)
            .ok_or_else(|| bad_key("must start with \"lphypq1\""))?;
        let raw = crate::recipient::base32_decode(body).ok_or_else(|| bad_key("not base32"))?;
        if raw.len() != 32 + EK_LEN + 4 {
            return Err(bad_key("wrong length"));
        }
        if checksum(&raw[..32 + EK_LEN]) != raw[32 + EK_LEN..] {
            return Err(bad_key("checksum mismatch (typo?)"));
        }
        let mut x = [0u8; 32];
        x.copy_from_slice(&raw[..32]);
        if x.iter().all(|&b| b == 0) {
            return Err(bad_key("all-zero key"));
        }
        let mut ek = Box::new([0u8; EK_LEN]);
        ek.copy_from_slice(&raw[32..32 + EK_LEN]);
        // FIPS 203 encapsulation-key check (coefficients in range).
        encapsulation_key(&ek)?;
        Ok(Self { x, ek })
    }
}

/// Hybrid public keys from text: `lphypq1…` lines (other key lines and `#` comments skipped).
///
/// # Errors
/// An invalid `lphypq1` line.
pub fn parse_hybrid_keys(text: &str) -> Result<Vec<HybridKey>> {
    text.lines()
        .map(str::trim)
        .filter(|l| l.starts_with(HYBRID_PREFIX))
        .map(HybridKey::from_str)
        .collect()
}

fn encapsulation_key(ek: &[u8; EK_LEN]) -> Result<EncapsulationKey<MlKem768>> {
    let arr = ml_kem::Key::<EncapsulationKey<MlKem768>>::try_from(&ek[..])
        .map_err(|_| bad_key("encapsulation key length"))?;
    EncapsulationKey::<MlKem768>::new(&arr).map_err(|_| bad_key("encapsulation key out of range"))
}

/// The ML-KEM-768 decapsulation key of an identity secret.
fn decapsulation_key(identity_secret: &[u8]) -> Result<DecapsulationKey<MlKem768>> {
    let mut seed = Zeroizing::new([0u8; 64]);
    let (d, z) = seed.split_at_mut(32);
    let d: &mut [u8; 32] = d.try_into().map_err(|_| bad_key("seed"))?;
    let z: &mut [u8; 32] = z.try_into().map_err(|_| bad_key("seed"))?;
    kdf::hkdf32(identity_secret, b"", INFO_D, d);
    kdf::hkdf32(identity_secret, b"", INFO_Z, z);
    let s = Zeroizing::new(Seed::try_from(&seed[..]).map_err(|_| bad_key("seed"))?);
    Ok(DecapsulationKey::<MlKem768>::from_seed(*s))
}

/// The hybrid public key of an identity secret (its X25519 public key and its ML-KEM key).
pub(crate) fn public_of(identity_secret: &[u8], x: [u8; 32]) -> Result<HybridKey> {
    let dk = decapsulation_key(identity_secret)?;
    let bytes = dk.encapsulation_key().to_bytes();
    let mut ek = Box::new([0u8; EK_LEN]);
    ek.copy_from_slice(&bytes[..]);
    Ok(HybridKey { x, ek })
}

fn x25519(scalar: &[u8; 32], point: &[u8; 32]) -> Result<Zeroizing<[u8; 32]>> {
    let out = Zeroizing::new(
        curve25519_dalek::montgomery::MontgomeryPoint(*point)
            .mul_clamped(*scalar)
            .0,
    );
    if out.ct_eq(&[0u8; 32]).unwrap_u8() == 1 {
        return Err(Error::Corrupt {
            at: "header".into(),
            detail: Some("X25519 low-order point".into()),
        });
    }
    Ok(out)
}

fn hybrid_kek(
    ss_x: &[u8; 32],
    ss_k: &[u8],
    eph: &[u8; 32],
    pk_x: &[u8; 32],
    ek: &[u8],
    ct: &[u8],
) -> Result<SecretBytes> {
    let mut ikm = Zeroizing::new([0u8; 64]);
    ikm[..32].copy_from_slice(ss_x);
    ikm[32..].copy_from_slice(ss_k);
    let mut salt = [0u8; 128];
    salt[..32].copy_from_slice(eph);
    salt[32..64].copy_from_slice(pk_x);
    salt[64..96].copy_from_slice(blake3::hash(ek).as_bytes());
    salt[96..].copy_from_slice(blake3::hash(ct).as_bytes());
    let mut kek = SecretBytes::with_capacity(KEY_LEN).map_err(arena_err)?;
    kek.set_len(KEY_LEN).map_err(arena_err)?;
    let out: &mut [u8; KEY_LEN] = kek
        .expose_mut()
        .try_into()
        .map_err(|_| Error::Environment("kek len".into()))?;
    kdf::hkdf32(&ikm[..], &salt, INFO_HYBRID, out);
    Ok(kek)
}

fn wrap_aad(header: &[u8; HEADER_LEN], eph: &[u8; 32]) -> [u8; WRAP_AAD_END + 32] {
    let mut aad = [0u8; WRAP_AAD_END + 32];
    aad[..WRAP_AAD_END].copy_from_slice(&header[..WRAP_AAD_END]);
    aad[WRAP_AAD_END..].copy_from_slice(eph);
    aad
}

fn key_ref(k: &SecretBytes) -> Result<&[u8; KEY_LEN]> {
    k.expose()
        .try_into()
        .map_err(|_| Error::Environment("key len".into()))
}

/// Wraps `fk` for each hybrid recipient. Entropy order per recipient: X25519 ephemeral secret
/// (32 B), ML-KEM randomness `m` (32 B), then `wrap_nonce` (nonce length of `alg`).
///
/// # Errors
/// RNG, locked-memory or AEAD error; an invalid key.
pub fn wrap_for(
    header: &[u8; HEADER_LEN],
    alg: AlgId,
    fk: &SecretBytes,
    recipients: &[HybridKey],
    entropy: &mut dyn Entropy,
) -> Result<Vec<u8>> {
    let mut ext = Vec::with_capacity(recipients.len() * PQ_STANZA_LEN);
    for r in recipients {
        let mut e = Zeroizing::new([0u8; 32]);
        entropy.fill(&mut e[..])?;
        let eph = curve25519_dalek::montgomery::MontgomeryPoint::mul_base_clamped(*e).0;
        let ss_x = x25519(&e, &r.x).map_err(|_| bad_key("low-order X25519 point"))?;
        drop(e);
        let mut m = Zeroizing::new([0u8; 32]);
        entropy.fill(&mut m[..])?;
        let ekey = encapsulation_key(&r.ek)?;
        let mb = Zeroizing::new(B32::try_from(&m[..]).map_err(|_| bad_key("m"))?);
        let (ct, ss_k) = ekey.encapsulate_deterministic(&mb);
        let ss_k = Zeroizing::new(ss_k);
        let kek = hybrid_kek(&ss_x, &ss_k[..], &eph, &r.x, &r.ek[..], &ct[..])?;
        let (wrap_key, commit) = kdf::derive_wrap_and_commit(&kek, &eph)?;
        drop(kek);
        let mut nonce = [0u8; 24];
        entropy.fill(&mut nonce[..alg.nonce_len()])?;
        let wrapper = SharedCipher::new(alg, key_ref(&wrap_key)?)?;
        drop(wrap_key);
        let mut wrapped = [0u8; 48];
        wrapped[..KEY_LEN].copy_from_slice(fk.expose());
        let tag = wrapper.seal_in_place(
            &nonce[..alg.nonce_len()],
            &wrap_aad(header, &eph),
            &mut wrapped[..KEY_LEN],
        )?;
        wrapped[KEY_LEN..].copy_from_slice(&tag);
        ext.extend_from_slice(&eph);
        ext.extend_from_slice(&ct[..]);
        ext.extend_from_slice(&nonce);
        ext.extend_from_slice(&commit);
        ext.extend_from_slice(&wrapped);
    }
    Ok(ext)
}

/// Finds the identity's hybrid stanza and unwraps FK.
///
/// # Errors
/// 4 (malformed stanzas or a failing unwrap after a matching commit), 3 (no stanza matches).
pub fn unwrap_with(
    header: &[u8; HEADER_LEN],
    alg: AlgId,
    ext: &[u8],
    identity_secret: &[u8],
    pk_x: &[u8; 32],
) -> Result<SecretBytes> {
    if ext.is_empty() || !ext.len().is_multiple_of(PQ_STANZA_LEN) {
        return Err(Error::Corrupt {
            at: "header".into(),
            detail: Some("hybrid recipient stanzas".into()),
        });
    }
    let dk = decapsulation_key(identity_secret)?;
    let ek = dk.encapsulation_key().to_bytes();
    let mut sk = Zeroizing::new([0u8; 32]);
    sk.copy_from_slice(identity_secret);
    let nl = alg.nonce_len();
    for st in ext.chunks(PQ_STANZA_LEN) {
        let mut eph = [0u8; 32];
        eph.copy_from_slice(&st[..32]);
        let ct = &st[32..32 + CT_LEN];
        let rest = &st[32 + CT_LEN..];
        let nonce = &rest[..24];
        if nonce[nl..].iter().any(|&x| x != 0) {
            return Err(Error::Corrupt {
                at: "header".into(),
                detail: Some("nonce tail ≠ 0".into()),
            });
        }
        let Ok(ss_x) = x25519(&sk, &eph) else {
            continue;
        };
        let cta = ml_kem::Ciphertext::<MlKem768>::try_from(ct).map_err(|_| Error::Corrupt {
            at: "header".into(),
            detail: Some("ML-KEM ciphertext".into()),
        })?;
        // Implicit rejection: a foreign or changed ciphertext gives an unrelated key.
        let ss_k = Zeroizing::new(dk.decapsulate(&cta));
        let kek = hybrid_kek(&ss_x, &ss_k[..], &eph, pk_x, &ek[..], ct)?;
        let (wrap_key, commit) = kdf::derive_wrap_and_commit(&kek, &eph)?;
        drop(kek);
        if commit.ct_eq(&rest[24..56]).unwrap_u8() != 1 {
            continue;
        }
        let wrapper = SharedCipher::new(alg, key_ref(&wrap_key)?)?;
        drop(wrap_key);
        let mut fk = SecretBytes::with_capacity(KEY_LEN).map_err(arena_err)?;
        fk.push_slice(&rest[56..56 + KEY_LEN]).map_err(arena_err)?;
        let mut tag = [0u8; TAG_LEN];
        tag.copy_from_slice(&rest[56 + KEY_LEN..]);
        let ok =
            wrapper.open_in_place(&nonce[..nl], &wrap_aad(header, &eph), fk.expose_mut(), &tag)?;
        if ok.is_err() {
            return Err(Error::Corrupt {
                at: "header".into(),
                detail: Some("recipient wrapped_fk (commit matched)".into()),
            });
        }
        return Ok(fk);
    }
    Err(Error::NoMatchingIdentity)
}
