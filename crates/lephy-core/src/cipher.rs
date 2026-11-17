//! AEAD soyutlaması.
//!
//! Yalnızca yerinde/ayrık-tag API'si kullanılır (`AeadInOut::*_inout_detached`); `Vec` döndüren
//! `Aead::encrypt/decrypt` clippy `disallowed-methods` ile yasaktır. AEAD struct'ı
//! [`SharedCipher`] içinde kilitli arenada ([`SecretBox`]) yaşar; `!Clone`, `Sync` — işçiler
//! `&SharedCipher` paylaşır, anahtar kopyalanmaz.

use aead::inout::InOutBuf;
use aead::{AeadInOut, KeyInit};
use aes_gcm::Aes256Gcm;
use chacha20poly1305::XChaCha20Poly1305;
use lephy_sys::mem::SecretBox;

use crate::error::{Error, Result};

/// Algoritma kimliği (FORMAT.md › Başlık, ofset 8).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum AlgId {
    /// XChaCha20-Poly1305 (varsayılan): 24 B nonce, 19 B prefix.
    XChaCha20Poly1305 = 1,
    /// AES-256-GCM: 12 B nonce, 7 B prefix; kuyruklar sıfır.
    Aes256Gcm = 2,
}

impl AlgId {
    /// Bayttan.
    #[must_use]
    pub const fn from_u8(b: u8) -> Option<Self> {
        match b {
            1 => Some(AlgId::XChaCha20Poly1305),
            2 => Some(AlgId::Aes256Gcm),
            _ => None,
        }
    }

    /// Nonce uzunluğu (bayt).
    #[must_use]
    pub const fn nonce_len(self) -> usize {
        match self {
            AlgId::XChaCha20Poly1305 => 24,
            AlgId::Aes256Gcm => 12,
        }
    }

    /// STREAM prefix uzunluğu (`nonce_len − 5`).
    #[must_use]
    pub const fn prefix_len(self) -> usize {
        self.nonce_len() - 5
    }

    /// Kullanıcıya gösterilen ad.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            AlgId::XChaCha20Poly1305 => "XChaCha20-Poly1305",
            AlgId::Aes256Gcm => "AES-256-GCM",
        }
    }
}

/// Tag uzunluğu.
pub const TAG_LEN: usize = 16;
/// Anahtar uzunluğu.
pub const KEY_LEN: usize = 32;

#[allow(clippy::large_enum_variant)] // her iki değişken de arenada (SecretBox) yaşar
enum Inner {
    X(XChaCha20Poly1305),
    A(Aes256Gcm),
}

/// Kilitli arenada yaşayan AEAD; `Clone` uygulamaz.
pub struct SharedCipher {
    inner: SecretBox<Inner>,
    alg: AlgId,
}

impl SharedCipher {
    /// Anahtardan kurar. `key` çağıranın `SecretBytes`'ındadır; struct'ın yığındaki geçici
    /// kopyası `SecretBox::new` ile arenaya taşınır (yığın kalıntısı THREAT-MODEL'de).
    ///
    /// # Errors
    /// Arena dolu/kurulamadı.
    pub fn new(alg: AlgId, key: &[u8; KEY_LEN]) -> Result<Self> {
        // Anahtar yığına kopyalanmaz: dilimden doğrudan kurulur.
        let bad = |_| Error::Environment("anahtar uzunluğu".into());
        let inner = match alg {
            AlgId::XChaCha20Poly1305 => {
                Inner::X(XChaCha20Poly1305::new_from_slice(key).map_err(bad)?)
            }
            AlgId::Aes256Gcm => Inner::A(Aes256Gcm::new_from_slice(key).map_err(bad)?),
        };
        let boxed = SecretBox::new(inner).map_err(|e| Error::Environment(e.to_string()))?;
        Ok(Self { inner: boxed, alg })
    }

    /// Algoritma.
    #[must_use]
    pub const fn alg(&self) -> AlgId {
        self.alg
    }

    /// Yerinde şifreler; tag'i döner. `nonce.len()` algoritmanın nonce uzunluğu olmalıdır.
    ///
    /// # Errors
    /// Nonce uzunluğu yanlış ya da AEAD sınırı (`Corrupt` değil, `Environment`).
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
        .map_err(|_| Error::Environment("AEAD şifreleme hatası (uzunluk sınırı)".into()))?;
        Ok(tag.into())
    }

    /// Yerinde çözer ve tag'i doğrular. Doğrulama hatası `Err(())` ile ayırt edilir ki çağıran
    /// doğru `Corrupt { at }` üretsin.
    ///
    /// # Errors
    /// `Ok(Err(()))`: tag/uzunluk hatası; `Err(_)`: nonce uzunluğu yanlış.
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
        .map_err(|_| Error::Environment("XChaCha nonce 24 bayt olmalı".into()))?;
    Ok(arr.into())
}

fn nonce_a(nonce: &[u8]) -> Result<aead::Nonce<Aes256Gcm>> {
    let arr: [u8; 12] = nonce
        .try_into()
        .map_err(|_| Error::Environment("AES-GCM nonce 12 bayt olmalı".into()))?;
    Ok(arr.into())
}

/// `SharedCipher: !Clone`. Derleme zamanı iddiası (autoref özelleştirme kalıbı:
/// `Clone` uygulanırsa `some_item` belirsizleşir ve derleme hatası verir).
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
            // bozuk aad
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
