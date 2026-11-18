//! Paper backup of an identity (FORMAT.md › Paper backup).
//!
//! The 32-byte identity secret and a 2-byte checksum, `BLAKE3("lphy+/paper/v1" ‖ secret)[0..2]`,
//! form a 272-bit big-endian number that is written as [`WORDS`] base-7776 digits (most
//! significant first), each digit a word of the EFF large wordlist. 22 words hold 284 bits, so the
//! two top bytes of the decoded number must be zero. The checksum catches a wrong or swapped word
//! with probability 1 − 2⁻¹⁶. All intermediate values live in zeroized buffers.

use lephy_sys::mem::SecretBytes;
use subtle::ConstantTimeEq;
use zeroize::{Zeroize, Zeroizing};

use crate::error::{Error, Result};
use crate::passphrase::{WORD_COUNT, words};

/// Number of words in a paper backup.
pub const WORDS: usize = 22;
const INFO: &[u8] = b"lphy+/paper/v1";
/// Secret + checksum.
const PAYLOAD: usize = 34;
/// Big enough for 7776^22 (< 2^285).
const ACC: usize = 36;
#[allow(clippy::cast_possible_truncation)]
const BASE: u32 = WORD_COUNT as u32;

fn arena_err(e: impl std::fmt::Display) -> Error {
    Error::Environment(format!("locked memory: {e}"))
}

fn checksum(secret: &[u8; 32]) -> [u8; 2] {
    let mut h = blake3::Hasher::new();
    h.update(INFO);
    h.update(secret);
    let d = h.finalize();
    h.zeroize();
    [d.as_bytes()[0], d.as_bytes()[1]]
}

/// The 22 words for `secret`, separated by single spaces, in locked memory.
///
/// # Errors
/// Locked-memory error.
pub fn encode(secret: &[u8; 32]) -> Result<SecretBytes> {
    let mut num = Zeroizing::new([0u8; PAYLOAD]);
    num[..32].copy_from_slice(secret);
    num[32..].copy_from_slice(&checksum(secret));
    let mut digits = Zeroizing::new([0u16; WORDS]);
    for d in digits.iter_mut().rev() {
        // Long division of the big-endian number by 7776; the remainder is the next digit.
        let mut rem: u32 = 0;
        for b in num.iter_mut() {
            let cur = (rem << 8) | u32::from(*b);
            #[allow(clippy::cast_possible_truncation)]
            {
                *b = (cur / BASE) as u8;
                *d = (cur % BASE) as u16;
            }
            rem = cur % BASE;
        }
    }
    debug_assert!(num.iter().all(|&b| b == 0));
    let list = words();
    let mut out = SecretBytes::with_capacity(WORDS * 10).map_err(arena_err)?;
    for (i, &d) in digits.iter().enumerate() {
        if i > 0 {
            out.push_slice(b" ").map_err(arena_err)?;
        }
        out.push_slice(list[usize::from(d)].as_bytes())
            .map_err(arena_err)?;
    }
    Ok(out)
}

/// The 32-byte secret from the words. Words may be separated by spaces, line breaks or hyphens;
/// case does not matter.
///
/// # Errors
/// Code 1: wrong number of words or a word that is not in the list (only its position is
/// reported, never the word). Code 4: checksum mismatch (a word is wrong or two are swapped).
pub fn decode(text: &[u8]) -> Result<SecretBytes> {
    let list = words();
    let mut acc = Zeroizing::new([0u8; ACC]);
    let mut n = 0usize;
    let mut word = Zeroizing::new([0u8; 16]);
    let mut wlen = 0usize;
    let mut too_long = false;
    let feed = |word: &[u8], n: &mut usize, acc: &mut [u8; ACC]| -> Result<()> {
        *n += 1;
        if *n > WORDS {
            return Err(Error::Environment(format!(
                "a paper backup has {WORDS} words; more were given"
            )));
        }
        let w = std::str::from_utf8(word).unwrap_or("");
        let idx = list
            .binary_search(&w)
            .map_err(|_| Error::Environment(format!("word {n} is not in the word list")))?;
        // acc = acc · 7776 + idx
        #[allow(clippy::cast_possible_truncation)]
        let mut carry = idx as u32;
        for b in acc.iter_mut().rev() {
            let cur = u32::from(*b) * BASE + carry;
            #[allow(clippy::cast_possible_truncation)]
            {
                *b = cur as u8;
            }
            carry = cur >> 8;
        }
        Ok(())
    };
    for &c in text.iter().chain(std::iter::once(&b' ')) {
        if c.is_ascii_alphabetic() {
            if wlen < word.len() {
                word[wlen] = c.to_ascii_lowercase();
                wlen += 1;
            } else {
                too_long = true;
            }
        } else if c.is_ascii_whitespace() || c == b'-' || c == b',' {
            if wlen > 0 || too_long {
                if too_long {
                    return Err(Error::Environment(format!(
                        "word {} is not in the word list",
                        n + 1
                    )));
                }
                feed(&word[..wlen], &mut n, &mut acc)?;
                word.zeroize();
                wlen = 0;
            }
        } else {
            return Err(Error::Environment(
                "a paper backup contains only words separated by spaces".into(),
            ));
        }
    }
    if n != WORDS {
        return Err(Error::Environment(format!(
            "a paper backup has {WORDS} words; {n} were given"
        )));
    }
    let bad = || Error::Corrupt {
        at: "paper backup".into(),
        detail: Some("checksum mismatch: a word is wrong or two are swapped".into()),
    };
    if acc[..ACC - PAYLOAD].iter().any(|&b| b != 0) {
        return Err(bad());
    }
    let mut secret = Zeroizing::new([0u8; 32]);
    secret.copy_from_slice(&acc[ACC - PAYLOAD..ACC - 2]);
    if checksum(&secret).ct_eq(&acc[ACC - 2..]).unwrap_u8() != 1 {
        return Err(bad());
    }
    let mut out = SecretBytes::with_capacity(32).map_err(arena_err)?;
    out.push_slice(&*secret).map_err(arena_err)?;
    Ok(out)
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    fn secret(start: u8) -> [u8; 32] {
        let mut s = [0u8; 32];
        for (i, b) in s.iter_mut().enumerate() {
            #[allow(clippy::cast_possible_truncation)]
            {
                *b = start.wrapping_add(i as u8);
            }
        }
        s
    }

    #[test]
    #[cfg_attr(miri, ignore = "slow under Miri")]
    fn roundtrip_and_format() {
        for s in [[0u8; 32], [0xff; 32], secret(0x80)] {
            let w = encode(&s).unwrap();
            let text = std::str::from_utf8(w.expose()).unwrap().to_owned();
            assert_eq!(text.split(' ').count(), WORDS);
            assert_eq!(decode(text.as_bytes()).unwrap().expose(), &s);
            // Case, hyphens and line breaks are accepted.
            let messy = text
                .to_uppercase()
                .replacen(' ', "-", 3)
                .replacen(' ', "\n", 2);
            assert_eq!(decode(messy.as_bytes()).unwrap().expose(), &s);
        }
    }

    #[test]
    #[cfg_attr(miri, ignore = "slow under Miri")]
    fn mistakes_are_caught() {
        let w = encode(&secret(0x80)).unwrap();
        let text = std::str::from_utf8(w.expose()).unwrap().to_owned();
        let mut v: Vec<&str> = text.split(' ').collect();
        // Two swapped words.
        v.swap(3, 4);
        assert!(matches!(
            decode(v.join(" ").as_bytes()),
            Err(Error::Corrupt { .. })
        ));
        v.swap(3, 4);
        // A different valid word.
        let other = if v[5] == "abacus" { "zoom" } else { "abacus" };
        let orig = v[5];
        v[5] = other;
        assert!(decode(v.join(" ").as_bytes()).is_err());
        v[5] = orig;
        // Unknown word, too few, too many.
        v[0] = "notaword";
        let e = decode(v.join(" ").as_bytes()).unwrap_err().to_string();
        assert!(e.contains("word 1") && !e.contains("notaword"), "{e}");
        assert!(decode(text.rsplit_once(' ').unwrap().0.as_bytes()).is_err());
        assert!(decode(format!("{text} abacus").as_bytes()).is_err());
        assert!(decode(b"abacus 1234").is_err());
    }
}
