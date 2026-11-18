//! AEAD abstraction.
//!
//! Only the in-place, detached-tag API is used (`AeadInOut::*_inout_detached`); the `Vec`-returning
//! `Aead::encrypt/decrypt` are forbidden by clippy `disallowed-methods`. The AEAD struct lives in
//! locked arena memory ([`SecretBox`]) inside [`SharedCipher`]; it is `!Clone` and `Sync` — workers
//! share `&SharedCipher`, the key is never copied.

use aead::inout::InOutBuf;
use aead::{AeadInOut, KeyInit};
use aes_gcm::Aes256Gcm;
use chacha20poly1305::XChaCha20Poly1305;
use lephy_sys::mem::SecretBox;

use crate::error::{Error, Result};

/// Algorithm identifier (FORMAT.md › Header, offset 8).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum AlgId {
    /// XChaCha20-Poly1305 (default): 24 B nonce, 19 B prefix.
    XChaCha20Poly1305 = 1,
    /// AES-256-GCM: 12 B nonce, 7 B prefix; tails are zero.
    Aes256Gcm = 2,
}

impl AlgId {
    /// From a byte.
    #[must_use]
    pub const fn from_u8(b: u8) -> Option<Self> {
        match b {
            1 => Some(AlgId::XChaCha20Poly1305),
            2 => Some(AlgId::Aes256Gcm),
            _ => None,
        }
    }

    /// Nonce length (bytes).
    #[must_use]
    pub const fn nonce_len(self) -> usize {
        match self {
            AlgId::XChaCha20Poly1305 => 24,
            AlgId::Aes256Gcm => 12,
        }
    }

    /// STREAM prefix length (`nonce_len − 5`).
    #[must_use]
    pub const fn prefix_len(self) -> usize {
        self.nonce_len() - 5
    }

    /// Name shown to the user.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            AlgId::XChaCha20Poly1305 => "XChaCha20-Poly1305",
            AlgId::Aes256Gcm => "AES-256-GCM",
        }
    }
}

/// Tag length.
pub const TAG_LEN: usize = 16;
/// Key length.
pub const KEY_LEN: usize = 32;

#[allow(clippy::large_enum_variant)] // both variants live in the arena (SecretBox)
enum Inner {
    X(XChaCha20Poly1305),
    A(Aes256Gcm),
}

/// AEAD living in locked arena memory; does not implement `Clone`.
pub struct SharedCipher {
    inner: SecretBox<Inner>,
    alg: AlgId,
}

impl SharedCipher {
    /// Builds it from a key. `key` is in the caller's `SecretBytes`; the struct's temporary copy
    /// on the stack is moved into the arena by `SecretBox::new` (stack residue: see THREAT-MODEL).
    ///
    /// # Errors
    /// Arena full or could not be set up.
    pub fn new(alg: AlgId, key: &[u8; KEY_LEN]) -> Result<Self> {
        // The key is not copied to the stack: built directly from the slice.
        let bad = |_| Error::Environment("key length".into());
        let inner = match alg {
            AlgId::XChaCha20Poly1305 => {
                Inner::X(XChaCha20Poly1305::new_from_slice(key).map_err(bad)?)
            }
            AlgId::Aes256Gcm => Inner::A(Aes256Gcm::new_from_slice(key).map_err(bad)?),
        };
        let boxed = SecretBox::new(inner).map_err(|e| Error::Environment(e.to_string()))?;
        Ok(Self { inner: boxed, alg })
    }

    /// Algorithm.
    #[must_use]
    pub const fn alg(&self) -> AlgId {
        self.alg
    }

    /// Encrypts in place and returns the tag. `nonce.len()` must be the algorithm's nonce length.
    ///
    /// # Errors
    /// Wrong nonce length or AEAD limit (`Environment`, not `Corrupt`).
    pub fn seal_in_place(&self, nonce: &[u8], aad: &[u8], buf: &mut [u8]) -> Result<[u8; TAG_LEN]> {
        let tag = match &*self.inner {
            Inner::X(c) => {
                let n = nonce_x(nonce)?;
                c.encrypt_inout_detached(&n, aad, InOutBuf::from(buf))
            }
            Inner::A(c) => {
                let n = nonce_a(nonce)?;
                c.encrypt_inout_detached(&n, aad, InOutBuf::from(buf))
            }
        }
        .map_err(|_| Error::Environment("AEAD encryption error (length limit)".into()))?;
        Ok(tag.into())
    }

    /// Decrypts in place and checks the tag. An authentication failure is reported as `Err(())`
    /// so that the caller can produce the right `Corrupt { at }`.
    ///
    /// # Errors
    /// `Ok(Err(()))`: tag/length failure; `Err(_)`: wrong nonce length.
    pub fn open_in_place(
        &self,
        nonce: &[u8],
        aad: &[u8],
        buf: &mut [u8],
        tag: &[u8; TAG_LEN],
    ) -> Result<std::result::Result<(), ()>> {
        let t = aead::Tag::<XChaCha20Poly1305>::from(*tag);
        let r = match &*self.inner {
            Inner::X(c) => {
                let n = nonce_x(nonce)?;
                c.decrypt_inout_detached(&n, aad, InOutBuf::from(buf), &t)
            }
            Inner::A(c) => {
                let n = nonce_a(nonce)?;
                c.decrypt_inout_detached(&n, aad, InOutBuf::from(buf), &t)
            }
        };
        Ok(r.map_err(|_| ()))
    }
}

fn nonce_x(nonce: &[u8]) -> Result<aead::Nonce<XChaCha20Poly1305>> {
    let arr: [u8; 24] = nonce
        .try_into()
        .map_err(|_| Error::Environment("XChaCha nonce must be 24 bytes".into()))?;
    Ok(arr.into())
}

fn nonce_a(nonce: &[u8]) -> Result<aead::Nonce<Aes256Gcm>> {
    let arr: [u8; 12] = nonce
        .try_into()
        .map_err(|_| Error::Environment("AES-GCM nonce must be 12 bytes".into()))?;
    Ok(arr.into())
}

/// `SharedCipher: !Clone`. Compile-time assertion (autoref specialisation pattern: if `Clone`
/// were implemented, `some_item` would become ambiguous and fail to compile).
const _: () = {
    trait AmbiguousIfClone<A> {
        fn some_item() {}
    }
    impl<T: ?Sized> AmbiguousIfClone<()> for T {}
    impl<T: Clone> AmbiguousIfClone<u8> for T {}
    let _ = <SharedCipher as AmbiguousIfClone<_>>::some_item;
};

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::panic)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip_both_algorithms() {
        for alg in [AlgId::XChaCha20Poly1305, AlgId::Aes256Gcm] {
            let c = SharedCipher::new(alg, &[7u8; 32]).unwrap();
            let nonce = vec![1u8; alg.nonce_len()];
            let mut buf = *b"merhaba dunya";
            let tag = c.seal_in_place(&nonce, b"aad", &mut buf).unwrap();
            assert_ne!(&buf, b"merhaba dunya");
            c.open_in_place(&nonce, b"aad", &mut buf, &tag)
                .unwrap()
                .unwrap();
            assert_eq!(&buf, b"merhaba dunya");
            // tampered aad
            let mut buf2 = *b"merhaba dunya";
            let tag2 = c.seal_in_place(&nonce, b"aad", &mut buf2).unwrap();
            assert!(
                c.open_in_place(&nonce, b"xxx", &mut buf2, &tag2)
                    .unwrap()
                    .is_err()
            );
        }
    }

    #[test]
    fn wrong_nonce_len_is_error() {
        let c = SharedCipher::new(AlgId::Aes256Gcm, &[0u8; 32]).unwrap();
        assert!(c.seal_in_place(&[0u8; 24], b"", &mut []).is_err());
    }

    fn assert_sync<T: Sync + Send>() {}
    #[test]
    fn shared_cipher_is_sync() {
        assert_sync::<SharedCipher>();
    }
}
