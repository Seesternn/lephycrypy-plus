//! STREAM framing (FORMAT.md › STREAM).
//!
//! Nonce = `prefix || BE32(i) || last`; `XChaCha` 19+4+1 = 24, AES 7+4+1 = 12. The canonical
//! last-chunk rules and the `chunk_size + 17`-byte read-ahead are in [`crate::pipeline`]; this module
//! only builds nonces and seals/opens a single chunk.

use crate::cipher::{AlgId, SharedCipher, TAG_LEN};
use crate::error::Result;

/// Chunk nonce; `len` is the number of valid bytes.
#[derive(Debug, Clone, Copy)]
pub struct ChunkNonce {
    bytes: [u8; 24],
    len: usize,
}

impl ChunkNonce {
    /// Builds it.
    #[must_use]
    pub fn new(alg: AlgId, prefix: &[u8; 24], index: u32, last: bool) -> Self {
        let pl = alg.prefix_len();
        let mut bytes = [0u8; 24];
        bytes[..pl].copy_from_slice(&prefix[..pl]);
        bytes[pl..pl + 4].copy_from_slice(&index.to_be_bytes());
        bytes[pl + 4] = u8::from(last);
        Self {
            bytes,
            len: alg.nonce_len(),
        }
    }

    /// Byte slice.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes[..self.len]
    }
}

/// Encrypts the plaintext `buf[..len]` in place and writes the tag to `buf[len..len+16]`.
/// Returns the ciphertext length (`len + 16`).
///
/// # Errors
/// AEAD error.
pub fn seal_chunk(
    cipher: &SharedCipher,
    prefix: &[u8; 24],
    aad: &[u8; 32],
    index: u32,
    last: bool,
    buf: &mut [u8],
    len: usize,
) -> Result<usize> {
    let nonce = ChunkNonce::new(cipher.alg(), prefix, index, last);
    let tag = cipher.seal_in_place(nonce.as_bytes(), aad, &mut buf[..len])?;
    buf[len..len + TAG_LEN].copy_from_slice(&tag);
    Ok(len + TAG_LEN)
}

/// Opens `buf[..ct_len]` (ciphertext || tag) in place; the plaintext is `buf[..ct_len-16]`.
/// Returns `Ok(Some(plain_len))`; a tag failure is `Ok(None)`.
///
/// # Errors
/// Nonce length (internal inconsistency).
pub fn open_chunk(
    cipher: &SharedCipher,
    prefix: &[u8; 24],
    aad: &[u8; 32],
    index: u32,
    last: bool,
    buf: &mut [u8],
    ct_len: usize,
) -> Result<Option<usize>> {
    if ct_len < TAG_LEN {
        return Ok(None);
    }
    let plain_len = ct_len - TAG_LEN;
    let mut tag = [0u8; TAG_LEN];
    tag.copy_from_slice(&buf[plain_len..ct_len]);
    let nonce = ChunkNonce::new(cipher.alg(), prefix, index, last);
    let r = cipher.open_in_place(nonce.as_bytes(), aad, &mut buf[..plain_len], &tag)?;
    Ok(r.ok().map(|()| plain_len))
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::panic)]
mod tests {
    use super::*;

    #[test]
    fn nonce_layout() {
        let prefix = {
            let mut p = [0u8; 24];
            for (i, b) in p.iter_mut().enumerate() {
                *b = u8::try_from(0x20 + i).unwrap();
            }
            p
        };
        let n = ChunkNonce::new(AlgId::XChaCha20Poly1305, &prefix, 0x0102_0304, true);
        assert_eq!(n.as_bytes().len(), 24);
        assert_eq!(&n.as_bytes()[..19], &prefix[..19]);
        assert_eq!(&n.as_bytes()[19..23], &[1, 2, 3, 4]);
        assert_eq!(n.as_bytes()[23], 1);
        let a = ChunkNonce::new(AlgId::Aes256Gcm, &prefix, 7, false);
        assert_eq!(a.as_bytes().len(), 12);
        assert_eq!(&a.as_bytes()[..7], &prefix[..7]);
        assert_eq!(&a.as_bytes()[7..11], &7u32.to_be_bytes());
        assert_eq!(a.as_bytes()[11], 0);
    }

    #[test]
    fn seal_open_and_last_flag_binding() {
        let c = SharedCipher::new(AlgId::XChaCha20Poly1305, &[1; 32]).unwrap();
        let prefix = [5u8; 24];
        let aad = [6u8; 32];
        let mut buf = vec![0u8; 100 + TAG_LEN];
        buf[..100].copy_from_slice(&[0xAB; 100]);
        let ct = seal_chunk(&c, &prefix, &aad, 3, false, &mut buf, 100).unwrap();
        assert_eq!(ct, 116);
        // does not open once the last flag changes (last=1 in the middle → 4)
        let mut copy = buf.clone();
        assert!(
            open_chunk(&c, &prefix, &aad, 3, true, &mut copy, ct)
                .unwrap()
                .is_none()
        );
        let mut copy = buf.clone();
        assert!(
            open_chunk(&c, &prefix, &aad, 4, false, &mut copy, ct)
                .unwrap()
                .is_none()
        );
        let n = open_chunk(&c, &prefix, &aad, 3, false, &mut buf, ct)
            .unwrap()
            .unwrap();
        assert_eq!(n, 100);
        assert!(buf[..100].iter().all(|&b| b == 0xAB));
    }
}
