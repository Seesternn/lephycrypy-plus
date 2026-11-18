//! Recipient (public-key) encryption with X25519 (format v2, `feature_flags.bit1`).
//!
//! A recipient file has no password slot. For each recipient public key `pk` the encryptor
//! draws an ephemeral secret `e` and writes one 136-byte stanza after the header:
//!
//! ```text
//! E          = X25519(e, 9)
//! ss         = X25519(e, pk)                       (all-zero → rejected)
//! kek        = HKDF-SHA512(ikm=ss, salt=E ‖ pk, info="lphy+/v2/x25519", L=32)
//! wrap_key   = HKDF-SHA512(ikm=kek, salt=E, info="lphy+/v1/wrap",   L=32)
//! commit     = HKDF-SHA512(ikm=kek, salt=E, info="lphy+/v1/commit", L=32)
//! wrapped_fk = AEAD_{wrap_key}(wrap_nonce, FK, AAD = header[0..144] ‖ E)
//! stanza     = E ‖ wrap_nonce (24 B, AES: tail zero) ‖ commit ‖ wrapped_fk
//! ```
//!
//! The recipient computes `ss = X25519(sk, E)` for each stanza and compares `commit` in
//! constant time; the first match is unwrapped. Public keys are not stored in the file.
//!
//! Identities (secret keys) live in a password-protected `.lphykey` file: an ordinary `.lphy`
//! raw stream whose 40-byte content is `"LPHYID1\0" ‖ secret`.

use std::fmt;
use std::io::{Read, Write};
use std::path::Path;
use std::str::FromStr;

use curve25519_dalek::montgomery::MontgomeryPoint;
use lephy_sys::mem::SecretBytes;
use subtle::ConstantTimeEq;
use zeroize::Zeroizing;

use crate::cipher::{AlgId, SharedCipher, TAG_LEN};
use crate::entropy::Entropy;
use crate::error::{Error, Result};
use crate::header::{ContentType, HEADER_LEN, NewHeaderParams, STANZA_LEN, WRAP_AAD_END};
use crate::kdf::{self, KEY_LEN, KdfParams};

/// HKDF info for the X25519 key-encryption key.
pub const INFO_X25519: &[u8] = b"lphy+/v2/x25519";
/// Public-key text prefix.
pub const PUBLIC_PREFIX: &str = "lphy1";
/// Identity file content magic.
const IDENTITY_MAGIC: &[u8; 8] = b"LPHYID1\0";
/// Identity files are tiny; anything larger is not one.
const IDENTITY_FILE_MAX: u64 = 4096;

fn arena_err(e: impl fmt::Display) -> Error {
    Error::Environment(format!("locked memory: {e}"))
}

fn bad_key(detail: &str) -> Error {
    Error::Environment(format!("invalid public key: {detail}"))
}

// ---------------------------------------------------------------------------------------------
// Public keys

/// An X25519 public key.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct PublicKey(pub [u8; 32]);

impl fmt::Debug for PublicKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "PublicKey({self})")
    }
}

const B32: &[u8; 32] = b"abcdefghijklmnopqrstuvwxyz234567";

fn base32_encode(data: &[u8]) -> String {
    let mut out = String::with_capacity(data.len().div_ceil(5) * 8);
    let mut acc: u32 = 0;
    let mut bits = 0;
    for &b in data {
        acc = (acc << 8) | u32::from(b);
        bits += 8;
        while bits >= 5 {
            bits -= 5;
            out.push(char::from(B32[((acc >> bits) & 31) as usize]));
        }
    }
    if bits > 0 {
        out.push(char::from(B32[((acc << (5 - bits)) & 31) as usize]));
    }
    out
}

fn base32_decode(s: &str) -> Option<Vec<u8>> {
    let mut out = Vec::with_capacity(s.len() * 5 / 8);
    let mut acc: u32 = 0;
    let mut bits = 0;
    for c in s.bytes() {
        let v = B32.iter().position(|&x| x == c.to_ascii_lowercase())?;
        acc = (acc << 5) | u32::try_from(v).ok()?;
        bits += 5;
        if bits >= 8 {
            bits -= 8;
            out.push(u8::try_from((acc >> bits) & 0xFF).ok()?);
        }
    }
    // Leftover bits must be zero padding.
    if acc & ((1 << bits) - 1) != 0 {
        return None;
    }
    Some(out)
}

fn checksum(pk: &[u8; 32]) -> [u8; 4] {
    let h = blake3::hash(pk);
    let mut c = [0u8; 4];
    c.copy_from_slice(&h.as_bytes()[..4]);
    c
}

impl fmt::Display for PublicKey {
    /// `lphy1` followed by base32 (lowercase, no padding) of `pk ‖ BLAKE3(pk)[..4]`.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut raw = [0u8; 36];
        raw[..32].copy_from_slice(&self.0);
        raw[32..].copy_from_slice(&checksum(&self.0));
        write!(f, "{PUBLIC_PREFIX}{}", base32_encode(&raw))
    }
}

impl FromStr for PublicKey {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self> {
        let s = s.trim();
        let body = s
            .strip_prefix(PUBLIC_PREFIX)
            .ok_or_else(|| bad_key("must start with \"lphy1\""))?;
        let raw = base32_decode(body).ok_or_else(|| bad_key("not base32"))?;
        if raw.len() != 36 {
            return Err(bad_key("wrong length"));
        }
        let mut pk = [0u8; 32];
        pk.copy_from_slice(&raw[..32]);
        if checksum(&pk) != raw[32..] {
            return Err(bad_key("checksum mismatch (typo?)"));
        }
        if pk.iter().all(|&b| b == 0) {
            return Err(bad_key("all-zero key"));
        }
        Ok(Self(pk))
    }
}

/// Reads public keys from text: one per line; empty lines and `#` comments are skipped.
///
/// # Errors
/// An invalid key line.
pub fn parse_public_keys(text: &str) -> Result<Vec<PublicKey>> {
    text.lines()
        .map(str::trim)
        .filter(|l| !l.is_empty() && !l.starts_with('#'))
        .map(PublicKey::from_str)
        .collect()
}

// ---------------------------------------------------------------------------------------------
// Identities

/// An X25519 secret key (in locked memory) and its public key.
pub struct Identity {
    secret: SecretBytes,
    public: PublicKey,
}

fn x25519(scalar: &[u8], point: &[u8; 32]) -> Result<Zeroizing<[u8; 32]>> {
    let mut s = Zeroizing::new([0u8; 32]);
    s.copy_from_slice(scalar);
    let out = Zeroizing::new(MontgomeryPoint(*point).mul_clamped(*s).0);
    // A low-order point gives an all-zero shared secret (RFC 7748 §6.1).
    if out.ct_eq(&[0u8; 32]).unwrap_u8() == 1 {
        return Err(Error::Corrupt {
            at: "header".into(),
            detail: Some("X25519 low-order point".into()),
        });
    }
    Ok(out)
}

impl Identity {
    /// A new random identity.
    ///
    /// # Errors
    /// RNG or locked-memory error.
    pub fn generate(entropy: &mut dyn Entropy) -> Result<Self> {
        let mut secret = SecretBytes::with_capacity(KEY_LEN).map_err(arena_err)?;
        secret.set_len(KEY_LEN).map_err(arena_err)?;
        entropy.fill(secret.expose_mut())?;
        Self::from_secret(secret)
    }

    /// From 32 secret bytes.
    ///
    /// # Errors
    /// Wrong length or locked-memory error.
    pub fn from_secret(secret: SecretBytes) -> Result<Self> {
        if secret.expose().len() != KEY_LEN {
            return Err(Error::Environment("identity secret is not 32 bytes".into()));
        }
        let mut s = Zeroizing::new([0u8; 32]);
        s.copy_from_slice(secret.expose());
        let public = PublicKey(MontgomeryPoint::mul_base_clamped(*s).0);
        Ok(Self { secret, public })
    }

    /// The public key to give to people who encrypt for this identity.
    #[must_use]
    pub const fn public(&self) -> PublicKey {
        self.public
    }
}

impl fmt::Debug for Identity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Identity({})", self.public)
    }
}

// ---------------------------------------------------------------------------------------------
// Stanzas

fn stanza_keys(ss: &[u8; 32], eph: &[u8; 32], pk: &[u8; 32]) -> Result<(SecretBytes, [u8; 32])> {
    let mut kek = SecretBytes::with_capacity(KEY_LEN).map_err(arena_err)?;
    kek.set_len(KEY_LEN).map_err(arena_err)?;
    let mut salt = [0u8; 64];
    salt[..32].copy_from_slice(eph);
    salt[32..].copy_from_slice(pk);
    let out: &mut [u8; KEY_LEN] = kek
        .expose_mut()
        .try_into()
        .map_err(|_| Error::Environment("kek len".into()))?;
    kdf::hkdf32(ss, &salt, INFO_X25519, out);
    kdf::derive_wrap_and_commit(&kek, eph)
}

fn wrap_aad(header: &[u8; HEADER_LEN], eph: &[u8; 32]) -> [u8; WRAP_AAD_END + 32] {
    let mut aad = [0u8; WRAP_AAD_END + 32];
    aad[..WRAP_AAD_END].copy_from_slice(&header[..WRAP_AAD_END]);
    aad[WRAP_AAD_END..].copy_from_slice(eph);
    aad
}

/// Wraps `fk` for each recipient. Entropy order per recipient: ephemeral secret (32 B), then
/// `wrap_nonce` (nonce length of `alg`).
///
/// # Errors
/// RNG, locked-memory or AEAD error; a low-order recipient key.
pub fn wrap_for(
    header: &[u8; HEADER_LEN],
    alg: AlgId,
    fk: &SecretBytes,
    recipients: &[PublicKey],
    entropy: &mut dyn Entropy,
) -> Result<Vec<u8>> {
    let mut ext = Vec::with_capacity(recipients.len() * STANZA_LEN);
    for pk in recipients {
        let mut e = SecretBytes::with_capacity(KEY_LEN).map_err(arena_err)?;
        e.set_len(KEY_LEN).map_err(arena_err)?;
        entropy.fill(e.expose_mut())?;
        let mut es = Zeroizing::new([0u8; 32]);
        es.copy_from_slice(e.expose());
        let eph = MontgomeryPoint::mul_base_clamped(*es).0;
        let ss = x25519(e.expose(), &pk.0).map_err(|_| bad_key("low-order point"))?;
        drop(e);
        let mut nonce = [0u8; 24];
        entropy.fill(&mut nonce[..alg.nonce_len()])?;
        let (wrap_key, commit) = stanza_keys(&ss, &eph, &pk.0)?;
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
        ext.extend_from_slice(&nonce);
        ext.extend_from_slice(&commit);
        ext.extend_from_slice(&wrapped);
    }
    Ok(ext)
}

fn key_ref(s: &SecretBytes) -> Result<&[u8; KEY_LEN]> {
    s.expose()
        .try_into()
        .map_err(|_| Error::Environment("key is not 32 bytes".into()))
}

/// Finds the stanza for `identity` and returns the file key.
///
/// # Errors
/// [`Error::NoMatchingIdentity`] (code 3) if no stanza is for this identity; code 4 if the
/// matching stanza does not authenticate or `ext` is malformed.
pub fn unwrap_with(
    header: &[u8; HEADER_LEN],
    alg: AlgId,
    ext: &[u8],
    identity: &Identity,
) -> Result<SecretBytes> {
    if ext.is_empty() || !ext.len().is_multiple_of(STANZA_LEN) {
        return Err(Error::Corrupt {
            at: "header".into(),
            detail: Some("recipient stanzas".into()),
        });
    }
    let nl = alg.nonce_len();
    for st in ext.chunks(STANZA_LEN) {
        let mut eph = [0u8; 32];
        eph.copy_from_slice(&st[..32]);
        let nonce = &st[32..56];
        if nonce[nl..].iter().any(|&x| x != 0) {
            return Err(Error::Corrupt {
                at: "header".into(),
                detail: Some("nonce tail ≠ 0".into()),
            });
        }
        let Ok(ss) = x25519(identity.secret.expose(), &eph) else {
            continue;
        };
        let (wrap_key, commit) = stanza_keys(&ss, &eph, &identity.public.0)?;
        if commit.ct_eq(&st[56..88]).unwrap_u8() != 1 {
            continue;
        }
        let wrapper = SharedCipher::new(alg, key_ref(&wrap_key)?)?;
        drop(wrap_key);
        let mut fk = SecretBytes::with_capacity(KEY_LEN).map_err(arena_err)?;
        fk.push_slice(&st[88..88 + KEY_LEN]).map_err(arena_err)?;
        let mut tag = [0u8; TAG_LEN];
        tag.copy_from_slice(&st[88 + KEY_LEN..STANZA_LEN]);
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

// ---------------------------------------------------------------------------------------------
// Identity files

struct SecretSink(SecretBytes);

impl Write for SecretSink {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.0
            .push_slice(buf)
            .map_err(|e| std::io::Error::other(e.to_string()))?;
        Ok(buf.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

/// Writes `identity` to a new password-protected identity file (mode `0600`, never
/// overwrites).
///
/// # Errors
/// Code 7 if `path` exists; 1, 6.
pub fn write_identity_file(
    path: &Path,
    identity: &Identity,
    pwd_nfc: &SecretBytes,
    kdf: KdfParams,
    entropy: &mut dyn Entropy,
    log: &mut dyn FnMut(&str),
) -> Result<()> {
    let params = NewHeaderParams {
        alg: AlgId::XChaCha20Poly1305,
        content_type: ContentType::Raw,
        padded: false,
        chunk_code: 0,
        kdf,
        keyfile: false,
        compressed: false,
    };
    let u = crate::ops::build_header(
        &params,
        pwd_nfc,
        None,
        crate::ops::Reuse::default(),
        entropy,
        false,
        log,
    )?;
    let cipher = SharedCipher::new(params.alg, key_ref(&u.data_key)?)?;
    let aad = crate::header::chunk_aad(&u.bytes);
    let mut content = SecretBytes::with_capacity(40).map_err(arena_err)?;
    content.push_slice(IDENTITY_MAGIC).map_err(arena_err)?;
    content
        .push_slice(identity.secret.expose())
        .map_err(arena_err)?;
    let mut w = crate::io::AtomicWriter::create(path, false)?;
    w.set_mode(0o600)?;
    w.file().write_all(&u.bytes)?;
    let sp = crate::pipeline::StreamParams {
        cipher: &cipher,
        prefix: &u.header.stream_nonce_prefix,
        aad: &aad,
        chunk_size: u.header.chunk_size(),
    };
    let mut src: &[u8] = content.expose();
    crate::pipeline::encrypt_stream(&sp, &mut src, w.file())?;
    w.commit(false)?;
    Ok(())
}

/// Opens a password-protected identity file.
///
/// # Errors
/// Code 3 (wrong password), 4 (not an identity file), 1, 6.
pub fn read_identity_file(
    path: &Path,
    pwd_nfc: &SecretBytes,
    opts: crate::ops::UnlockOptions<'_>,
    log: &mut dyn FnMut(&str),
) -> Result<Identity> {
    let not_identity = || Error::Corrupt {
        at: "identity file".into(),
        detail: Some("not an identity file".into()),
    };
    let f = std::fs::File::open(path)?;
    if f.metadata()?.len() > IDENTITY_FILE_MAX {
        return Err(not_identity());
    }
    let mut data = Vec::new();
    f.take(IDENTITY_FILE_MAX).read_to_end(&mut data)?;
    let b: [u8; HEADER_LEN] = data
        .get(..HEADER_LEN)
        .and_then(|s| s.try_into().ok())
        .ok_or_else(not_identity)?;
    let opts = crate::ops::UnlockOptions {
        identity: None,
        ..opts
    };
    let u = crate::ops::unlock_header(&b, &[], pwd_nfc, None, opts, log)?;
    if u.header.content_type != ContentType::Raw || u.header.padded || u.header.compressed {
        return Err(not_identity());
    }
    let cipher = SharedCipher::new(u.header.alg, key_ref(&u.data_key)?)?;
    let aad = crate::header::chunk_aad(&u.bytes);
    let sp = crate::pipeline::StreamParams {
        cipher: &cipher,
        prefix: &u.header.stream_nonce_prefix,
        aad: &aad,
        chunk_size: u.header.chunk_size(),
    };
    let mut sink = SecretSink(SecretBytes::with_capacity(64).map_err(arena_err)?);
    let mut body: &[u8] = &data[HEADER_LEN..];
    crate::pipeline::decrypt_stream(&sp, &mut body, &mut sink).map_err(|e| match e {
        Error::Io(_) => not_identity(),
        other => other,
    })?;
    data.fill(0);
    let content = sink.0.expose();
    if content.len() != 40 || &content[..8] != IDENTITY_MAGIC {
        return Err(not_identity());
    }
    let secret = SecretBytes::from_slice(&content[8..]).map_err(arena_err)?;
    Identity::from_secret(secret)
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::panic)]
mod tests {
    use super::*;
    use crate::entropy::OsEntropy;

    #[test]
    fn rfc7748_vector() {
        // RFC 7748 §6.1 Alice/Bob.
        let a = hex("77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a");
        let b_pub = hex("de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f");
        let a_pub = hex("8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a");
        let shared = hex("4a5d9d5b a4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742");
        let id = Identity::from_secret(SecretBytes::from_slice(&a).unwrap()).unwrap();
        assert_eq!(id.public().0, a_pub);
        assert_eq!(*x25519(&a, &b_pub).unwrap(), shared);
    }

    fn hex(s: &str) -> [u8; 32] {
        let s: String = s.split_whitespace().collect();
        let v = ::hex::decode(s).unwrap();
        v.try_into().unwrap()
    }

    #[test]
    fn public_key_text_roundtrip_and_typos() {
        let id = Identity::generate(&mut OsEntropy).unwrap();
        let t = id.public().to_string();
        assert!(t.starts_with("lphy1"));
        assert_eq!(t.len(), 5 + 58);
        assert_eq!(t.parse::<PublicKey>().unwrap(), id.public());
        assert_eq!(
            t.to_uppercase()
                .replacen("LPHY1", "lphy1", 1)
                .parse::<PublicKey>()
                .unwrap(),
            id.public()
        );
        let mut typo = t.clone().into_bytes();
        typo[20] = if typo[20] == b'a' { b'b' } else { b'a' };
        assert!(
            String::from_utf8(typo)
                .unwrap()
                .parse::<PublicKey>()
                .is_err()
        );
        assert!("lphy1abc".parse::<PublicKey>().is_err());
        assert!("age1xyz".parse::<PublicKey>().is_err());
        let list = format!("# team\n\n{t}\n  {t}  \n");
        assert_eq!(parse_public_keys(&list).unwrap().len(), 2);
    }

    #[test]
    fn wrap_and_unwrap_for_several_recipients() {
        let ids: Vec<Identity> = (0..3)
            .map(|_| Identity::generate(&mut OsEntropy).unwrap())
            .collect();
        let pks: Vec<PublicKey> = ids.iter().map(Identity::public).collect();
        let header = [7u8; HEADER_LEN];
        let mut fk = SecretBytes::with_capacity(32).unwrap();
        fk.push_slice(&[0x5a; 32]).unwrap();
        for alg in [AlgId::XChaCha20Poly1305, AlgId::Aes256Gcm] {
            let ext = wrap_for(&header, alg, &fk, &pks, &mut OsEntropy).unwrap();
            assert_eq!(ext.len(), 3 * STANZA_LEN);
            for id in &ids {
                let got = unwrap_with(&header, alg, &ext, id).unwrap();
                assert_eq!(got.expose(), &[0x5a; 32]);
            }
            let stranger = Identity::generate(&mut OsEntropy).unwrap();
            assert!(matches!(
                unwrap_with(&header, alg, &ext, &stranger),
                Err(Error::NoMatchingIdentity)
            ));
            // The header is bound to every stanza.
            let mut other = header;
            other[9] ^= 1;
            assert!(matches!(
                unwrap_with(&other, alg, &ext, &ids[1]),
                Err(Error::Corrupt { .. })
            ));
        }
    }

    #[test]
    fn low_order_recipient_is_rejected() {
        let mut fk = SecretBytes::with_capacity(32).unwrap();
        fk.push_slice(&[1; 32]).unwrap();
        let zero = PublicKey([0; 32]);
        assert!(
            wrap_for(
                &[0; HEADER_LEN],
                AlgId::XChaCha20Poly1305,
                &fk,
                &[zero],
                &mut OsEntropy
            )
            .is_err()
        );
    }

    #[test]
    fn identity_file_roundtrip() {
        let d = std::env::temp_dir().join(format!("lphy-id-{}", std::process::id()));
        std::fs::create_dir_all(&d).unwrap();
        let p = d.join("me.lphykey");
        let _ = std::fs::remove_file(&p);
        let kdf = KdfParams {
            m_kib: 65536,
            t: 1,
            p: 1,
        };
        let pwd = SecretBytes::from_slice(b"correct horse").unwrap();
        let id = Identity::generate(&mut OsEntropy).unwrap();
        write_identity_file(&p, &id, &pwd, kdf, &mut OsEntropy, &mut |_| {}).unwrap();
        // Never overwrites.
        assert!(write_identity_file(&p, &id, &pwd, kdf, &mut OsEntropy, &mut |_| {}).is_err());
        let back = read_identity_file(&p, &pwd, crate::ops::UnlockOptions::default(), &mut |_| {})
            .unwrap();
        assert_eq!(back.public(), id.public());
        let wrong = SecretBytes::from_slice(b"wrong").unwrap();
        assert!(matches!(
            read_identity_file(
                &p,
                &wrong,
                crate::ops::UnlockOptions::default(),
                &mut |_| {}
            ),
            Err(Error::WrongPassword)
        ));
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(&p).unwrap().permissions().mode();
            assert_eq!(mode & 0o777, 0o600);
        }
        std::fs::remove_dir_all(&d).unwrap();
    }
}
