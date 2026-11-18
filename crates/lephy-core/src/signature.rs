//! Sender signatures (FORMAT.md › Format version 2 (signatures)).
//!
//! A signed file has `feature_flags.bit2` set and ends with a 136-byte trailer after the last
//! STREAM chunk:
//!
//! ```text
//! sig_key   = HKDF-SHA512(ikm = FK, salt = stream_nonce_prefix, info = "lphy+/v2/sig-key")
//! message   = "lphy+/v2/sig\0" ‖ chunk_aad ‖ BLAKE3(every chunk ciphertext, in order)
//! signature = Ed25519(signing key, message)                      (RFC 8032, deterministic)
//! trailer   = nonce (24; AES: bytes 12..24 zero) ‖ AEAD_alg(sig_key, nonce, vk ‖ signature,
//!             AAD = chunk_aad)                                   (24 + 96 + 16 = 136 bytes)
//! ```
//!
//! The signer's key is encrypted, so only those who can open the file see who signed it. The
//! signature binds the content and the immutable header fields (`chunk_aad`), not the password
//! slot or recipient stanzas, so `rekey` and replacing recipients keep it valid. The signing key
//! is derived from an identity: `seed = HKDF-SHA512(ikm = sk, salt = "", info = "lphy+/v2/ed25519")`.

use std::io::{self, Read, Write};
use std::str::FromStr;
use std::sync::{Arc, Mutex};

use ed25519_dalek::{Signature, Signer as _, SigningKey, VerifyingKey};
use lephy_sys::mem::SecretBytes;
use zeroize::Zeroizing;

use crate::cipher::{AlgId, SharedCipher};
use crate::entropy::Entropy;
use crate::error::{Error, FormatViolation, Result};
use crate::kdf::{self, KEY_LEN};

/// Trailer length.
pub const TRAILER_LEN: usize = 136;
/// Text prefix of a signer key.
pub const SIGNER_PREFIX: &str = "lphysig1";
const INFO_SEED: &[u8] = b"lphy+/v2/ed25519";
const INFO_SIG_KEY: &[u8] = b"lphy+/v2/sig-key";
const CONTEXT: &[u8] = b"lphy+/v2/sig\0";
const TAG_LEN: usize = 16;

/// An Ed25519 verifying key (who signed a file).
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct SignerKey(pub [u8; 32]);

impl std::fmt::Debug for SignerKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "SignerKey({self})")
    }
}

impl std::fmt::Display for SignerKey {
    /// `lphysig1` followed by base32 of `vk ‖ BLAKE3(vk)[..4]`, like a public key.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{SIGNER_PREFIX}{}",
            crate::recipient::key_text_body(&self.0)
        )
    }
}

impl FromStr for SignerKey {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self> {
        let body = s.trim().strip_prefix(SIGNER_PREFIX).ok_or_else(|| {
            Error::Environment(format!(
                "invalid signer key: must start with \"{SIGNER_PREFIX}\""
            ))
        })?;
        let raw = crate::recipient::key_from_text_body(body)
            .map_err(|d| Error::Environment(format!("invalid signer key: {d}")))?;
        VerifyingKey::from_bytes(&raw)
            .map_err(|_| Error::Environment("invalid signer key: not a curve point".into()))?;
        Ok(Self(raw))
    }
}

/// Signer keys in text: lines starting with `lphysig1` (other lines, such as `lphy1…` public keys
/// in a `.pub` file, and `#` comments are skipped).
///
/// # Errors
/// An invalid `lphysig1` line.
pub fn parse_signer_keys(text: &str) -> Result<Vec<SignerKey>> {
    text.lines()
        .map(str::trim)
        .filter(|l| l.starts_with(SIGNER_PREFIX))
        .map(SignerKey::from_str)
        .collect()
}

fn arena_err(e: impl std::fmt::Display) -> Error {
    Error::Environment(format!("locked memory: {e}"))
}

/// The Ed25519 signing key of an identity secret.
pub(crate) fn signing_key(identity_secret: &[u8]) -> SigningKey {
    let mut seed = Zeroizing::new([0u8; KEY_LEN]);
    kdf::hkdf32(identity_secret, b"", INFO_SEED, &mut seed);
    SigningKey::from_bytes(&seed)
}

/// The signer key of an identity secret.
pub(crate) fn signer_key(identity_secret: &[u8]) -> SignerKey {
    SignerKey(signing_key(identity_secret).verifying_key().to_bytes())
}

fn sig_cipher(alg: AlgId, fk: &SecretBytes, prefix: &[u8; 24]) -> Result<SharedCipher> {
    let mut k = SecretBytes::with_capacity(KEY_LEN).map_err(arena_err)?;
    k.set_len(KEY_LEN).map_err(arena_err)?;
    let out: &mut [u8; KEY_LEN] = k
        .expose_mut()
        .try_into()
        .map_err(|_| Error::Environment("sig key len".into()))?;
    kdf::hkdf32(fk.expose(), prefix, INFO_SIG_KEY, out);
    let key: &[u8; KEY_LEN] = k
        .expose()
        .try_into()
        .map_err(|_| Error::Environment("sig key len".into()))?;
    SharedCipher::new(alg, key)
}

fn message(chunk_aad: &[u8; 32], digest: &[u8; 32]) -> Vec<u8> {
    [CONTEXT, chunk_aad, digest].concat()
}

/// Parameters shared by the writer and the reader.
pub struct SigParams {
    cipher: SharedCipher,
    alg: AlgId,
    chunk_aad: [u8; 32],
}

impl SigParams {
    /// From the file key and header.
    ///
    /// # Errors
    /// Locked-memory or cipher error.
    pub fn new(
        alg: AlgId,
        fk: &SecretBytes,
        prefix: &[u8; 24],
        chunk_aad: [u8; 32],
    ) -> Result<Self> {
        Ok(Self {
            cipher: sig_cipher(alg, fk, prefix)?,
            alg,
            chunk_aad,
        })
    }
}

/// Hashes the chunk ciphertext written through it; [`HashWriter::trailer`] signs it.
pub struct HashWriter<'a> {
    inner: &'a mut (dyn Write + Send),
    hasher: blake3::Hasher,
}

impl<'a> HashWriter<'a> {
    /// Wraps the sink that receives the chunks.
    pub fn new(inner: &'a mut (dyn Write + Send)) -> Self {
        Self {
            inner,
            hasher: blake3::Hasher::new(),
        }
    }

    /// Builds the trailer for everything written so far and writes it to the sink.
    ///
    /// # Errors
    /// RNG, cipher or I/O error.
    pub fn finish(
        self,
        p: &SigParams,
        identity_secret: &[u8],
        entropy: &mut dyn Entropy,
    ) -> Result<()> {
        let digest = *self.hasher.finalize().as_bytes();
        let sk = signing_key(identity_secret);
        let sig = sk.sign(&message(&p.chunk_aad, &digest));
        let mut nonce = [0u8; 24];
        let nl = p.alg.nonce_len();
        entropy.fill(&mut nonce[..nl])?;
        let mut body = [0u8; 96];
        body[..32].copy_from_slice(&sk.verifying_key().to_bytes());
        body[32..].copy_from_slice(&sig.to_bytes());
        drop(sk);
        let tag = p
            .cipher
            .seal_in_place(&nonce[..nl], &p.chunk_aad, &mut body)?;
        self.inner.write_all(&nonce)?;
        self.inner.write_all(&body)?;
        self.inner.write_all(&tag)?;
        Ok(())
    }
}

impl Write for HashWriter<'_> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        let n = self.inner.write(buf)?;
        self.hasher.update(&buf[..n]);
        Ok(n)
    }
    fn flush(&mut self) -> io::Result<()> {
        self.inner.flush()
    }
}

/// Who signed the file, filled in when the end of a signed stream has been verified.
pub type SignerSlot = Arc<Mutex<Option<SignerKey>>>;

/// Passes the chunk ciphertext through and holds back the last 136 bytes (the trailer). At the
/// end of the input it opens the trailer and verifies the signature; a bad or missing signature, or
/// a signer other than the expected one, is an error before the caller sees end of input, so
/// nothing is committed.
pub struct SignedReader<R> {
    inner: R,
    params: SigParams,
    expect: Option<SignerKey>,
    slot: SignerSlot,
    hasher: blake3::Hasher,
    held: Vec<u8>,
    done: bool,
}

impl<R: Read> SignedReader<R> {
    /// Wraps the reader positioned at the first chunk.
    pub fn new(inner: R, params: SigParams, expect: Option<SignerKey>, slot: SignerSlot) -> Self {
        Self {
            inner,
            params,
            expect,
            slot,
            hasher: blake3::Hasher::new(),
            held: Vec::with_capacity(TRAILER_LEN * 2),
            done: false,
        }
    }

    fn verify_trailer(&mut self) -> io::Result<()> {
        let bad = |d: &str| FormatViolation::io_at("signature", d);
        if self.held.len() != TRAILER_LEN {
            return Err(bad("signature trailer missing"));
        }
        let nl = self.params.alg.nonce_len();
        let nonce = self.held[..24].to_vec();
        if nonce[nl..].iter().any(|&b| b != 0) {
            return Err(bad("signature nonce tail ≠ 0"));
        }
        let mut body = [0u8; 96];
        body.copy_from_slice(&self.held[24..120]);
        let mut tag = [0u8; TAG_LEN];
        tag.copy_from_slice(&self.held[120..]);
        let ok = self
            .params
            .cipher
            .open_in_place(&nonce[..nl], &self.params.chunk_aad, &mut body, &tag)
            .map_err(|e| io::Error::other(e.to_string()))?;
        if ok.is_err() {
            return Err(bad("signature trailer does not authenticate"));
        }
        let mut vk_bytes = [0u8; 32];
        vk_bytes.copy_from_slice(&body[..32]);
        let mut sig_bytes = [0u8; 64];
        sig_bytes.copy_from_slice(&body[32..]);
        let digest = *self.hasher.finalize().as_bytes();
        let vk = VerifyingKey::from_bytes(&vk_bytes).map_err(|_| bad("signer key invalid"))?;
        vk.verify_strict(
            &message(&self.params.chunk_aad, &digest),
            &Signature::from_bytes(&sig_bytes),
        )
        .map_err(|_| bad("signature does not verify"))?;
        let signer = SignerKey(vk_bytes);
        if let Some(want) = self.expect
            && want != signer
        {
            return Err(io::Error::other(crate::error::SignerMismatchIo(format!(
                "signed by {signer}, not by the expected {want}"
            ))));
        }
        if let Ok(mut s) = self.slot.lock() {
            *s = Some(signer);
        }
        Ok(())
    }
}

impl<R: Read> Read for SignedReader<R> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        if self.done || buf.is_empty() {
            return Ok(0);
        }
        // Keep at least TRAILER_LEN bytes held back; release the rest.
        loop {
            if self.held.len() > TRAILER_LEN {
                let n = (self.held.len() - TRAILER_LEN).min(buf.len());
                buf[..n].copy_from_slice(&self.held[..n]);
                self.hasher.update(&buf[..n]);
                self.held.drain(..n);
                return Ok(n);
            }
            let start = self.held.len();
            self.held.resize(start + 16 * 1024, 0);
            let n = match self.inner.read(&mut self.held[start..]) {
                Ok(n) => n,
                Err(e) => {
                    self.held.truncate(start);
                    return Err(e);
                }
            };
            self.held.truncate(start + n);
            if n == 0 {
                self.done = true;
                self.verify_trailer()?;
                return Ok(0);
            }
        }
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use crate::entropy::OsEntropy;

    fn params() -> SigParams {
        let fk = SecretBytes::from_slice(&[7u8; 32]).unwrap();
        SigParams::new(AlgId::XChaCha20Poly1305, &fk, &[1u8; 24], [2u8; 32]).unwrap()
    }

    fn signed(data: &[u8], secret: &[u8]) -> Vec<u8> {
        let mut out = Vec::new();
        {
            let mut sink: &mut (dyn Write + Send) = &mut out;
            let mut hw = HashWriter::new(&mut sink);
            hw.write_all(data).unwrap();
            hw.finish(&params(), secret, &mut OsEntropy).unwrap();
        }
        out
    }

    fn read_all(bytes: &[u8], expect: Option<SignerKey>) -> (io::Result<Vec<u8>>, SignerSlot) {
        let slot = SignerSlot::default();
        let mut r = SignedReader::new(bytes, params(), expect, slot.clone());
        let mut out = Vec::new();
        let res = r.read_to_end(&mut out).map(|_| out);
        (res, slot)
    }

    #[test]
    #[cfg_attr(miri, ignore = "slow under Miri")]
    fn sign_verify_tamper_and_expect() {
        let data = vec![9u8; 200_000];
        let me = [3u8; 32];
        let file = signed(&data, &me);
        assert_eq!(file.len(), data.len() + TRAILER_LEN);
        let (r, slot) = read_all(&file, None);
        assert_eq!(r.unwrap(), data);
        assert_eq!(*slot.lock().unwrap(), Some(signer_key(&me)));
        // Expected signer.
        assert!(read_all(&file, Some(signer_key(&me))).0.is_ok());
        assert!(read_all(&file, Some(signer_key(&[4u8; 32]))).0.is_err());
        // Changed content, changed trailer, missing trailer.
        let mut t = file.clone();
        t[10] ^= 1;
        assert!(read_all(&t, None).0.is_err());
        let mut t = file.clone();
        let last = t.len() - 1;
        t[last] ^= 1;
        assert!(read_all(&t, None).0.is_err());
        assert!(read_all(&file[..file.len() - 10], None).0.is_err());
        assert!(read_all(&data, None).0.is_err());
    }

    #[test]
    fn signer_key_text() {
        let k = signer_key(&[3u8; 32]);
        let s = k.to_string();
        assert!(s.starts_with(SIGNER_PREFIX));
        assert_eq!(s.parse::<SignerKey>().unwrap(), k);
        let keys = parse_signer_keys(&format!("lphy1abc\n# c\n{s}\n")).unwrap();
        assert_eq!(keys, vec![k]);
        let mut bad = s.clone();
        bad.pop();
        assert!(bad.parse::<SignerKey>().is_err());
    }
}
