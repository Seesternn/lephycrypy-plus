//! A rough password-strength estimate (a small, dependency-free estimator instead of zxcvbn).
//!
//! - For passphrases made only of EFF-list words and a single separator, the entropy is exactly
//!   `words × 12.925` bits.
//! - For other passwords an upper bound is computed from the character pool, then reduced for
//!   common weaknesses (repetition, sequences, keyboard rows, common passwords, years).
//!
//! This is a guide for the user, not an attack model; the app presents it as an "estimate".

use crate::passphrase;

/// Strength level.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Level {
    /// < 28 bit.
    VeryWeak,
    /// < 40 bit.
    Weak,
    /// < 60 bit.
    Fair,
    /// < 80 bit.
    Strong,
    /// ≥ 80 bit.
    VeryStrong,
}

/// Estimate result.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct Estimate {
    /// Estimated entropy (bits).
    pub bits: f64,
    /// Level.
    pub level: Level,
    /// Whether it was recognised as an EFF passphrase.
    pub passphrase: bool,
}

const COMMON: &[&str] = &[
    "password",
    "parola",
    "sifre",
    "şifre",
    "123456",
    "qwerty",
    "azerty",
    "letmein",
    "welcome",
    "admin",
    "iloveyou",
    "monkey",
    "dragon",
    "football",
    "baseball",
    "sunshine",
    "princess",
    "master",
    "login",
    "abc123",
    "passw0rd",
    "trustno1",
    "galatasaray",
    "fenerbahce",
    "besiktas",
    "istanbul",
    "ankara",
    "turkiye",
    "türkiye",
    "asdasd",
    "qweqwe",
];

const ROWS: &[&str] = &[
    "qwertyuiopğü",
    "asdfghjklşi",
    "zxcvbnmöç",
    "1234567890",
    "qwertzuiop",
    "azertyuiop",
];

fn level_of(bits: f64) -> Level {
    match bits {
        b if b < 28.0 => Level::VeryWeak,
        b if b < 40.0 => Level::Weak,
        b if b < 60.0 => Level::Fair,
        b if b < 80.0 => Level::Strong,
        _ => Level::VeryStrong,
    }
}

/// Whether it is an EFF passphrase: returns the number of words.
fn as_passphrase(s: &str) -> Option<usize> {
    let sep = s.chars().find(|c| !c.is_ascii_lowercase())?;
    if sep.is_alphanumeric() {
        return None;
    }
    let parts: Vec<&str> = s.split(sep).collect();
    let list = passphrase::words();
    (parts.len() >= 2 && parts.iter().all(|p| list.binary_search(p).is_ok())).then_some(parts.len())
}

/// Estimates. Invalid UTF-8 input is accepted too (byte based).
#[must_use]
#[allow(clippy::cast_precision_loss)]
pub fn estimate(pwd: &[u8]) -> Estimate {
    let Ok(s) = std::str::from_utf8(pwd) else {
        let bits = pwd.len() as f64 * 6.0;
        return Estimate {
            bits,
            level: level_of(bits),
            passphrase: false,
        };
    };
    if let Some(n) = as_passphrase(s) {
        let bits = passphrase::bits(n);
        return Estimate {
            bits,
            level: level_of(bits),
            passphrase: true,
        };
    }
    let chars: Vec<char> = s.chars().collect();
    if chars.is_empty() {
        return Estimate {
            bits: 0.0,
            level: Level::VeryWeak,
            passphrase: false,
        };
    }
    let (mut lower, mut upper, mut digit, mut symbol, mut other) =
        (false, false, false, false, false);
    for c in &chars {
        match c {
            'a'..='z' => lower = true,
            'A'..='Z' => upper = true,
            '0'..='9' => digit = true,
            c if c.is_ascii() => symbol = true,
            _ => other = true,
        }
    }
    let pool = u32::from(lower) * 26
        + u32::from(upper) * 26
        + u32::from(digit) * 10
        + u32::from(symbol) * 33
        + u32::from(other) * 40;
    let per_char = f64::from(pool.max(1)).log2();

    // Effective length: repetitions, sequences and keyboard rows count as cheap.
    let lower_s: Vec<char> = s.to_lowercase().chars().collect();
    let mut effective = 0.0;
    for i in 0..lower_s.len() {
        let cheap = i > 0 && {
            let (a, b) = (lower_s[i - 1], lower_s[i]);
            let step = (b as i64) - (a as i64);
            a == b
                || step.abs() == 1
                || ROWS.iter().any(|r| {
                    let rc: Vec<char> = r.chars().collect();
                    rc.windows(2)
                        .any(|w| (w[0] == a && w[1] == b) || (w[0] == b && w[1] == a))
                })
        };
        effective += if cheap { 0.25 } else { 1.0 };
    }
    let mut bits = effective * per_char;

    let folded: String = lower_s.iter().collect();
    if COMMON.iter().any(|w| folded.contains(w)) {
        bits = bits.min(20.0);
    }
    // A year (1900–2099) costs ~7 bits.
    let has_year = folded.as_bytes().windows(4).any(|w| {
        w.iter().all(u8::is_ascii_digit) && (w.starts_with(b"19") || w.starts_with(b"20"))
    });
    if has_year {
        bits -= 7.0;
    }
    let bits = bits.max(0.0);
    Estimate {
        bits,
        level: level_of(bits),
        passphrase: false,
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn levels_are_ordered_sensibly() {
        assert_eq!(estimate(b"").level, Level::VeryWeak);
        assert_eq!(estimate(b"password123").level, Level::VeryWeak);
        assert!(estimate(b"qwertyuiop").level <= Level::Weak);
        assert!(estimate(b"aaaaaaaaaaaa").level <= Level::Weak);
        assert!(estimate(b"Tr7#kq!Lm2@vX9").level >= Level::Strong);
        let p = estimate(b"abacus-zoom-tidy-cradle-ample-gloss");
        assert!(p.passphrase);
        assert_eq!(p.level, Level::Strong);
        assert!((p.bits - 6.0 * passphrase::BITS_PER_WORD).abs() < 1e-6);
    }

    #[test]
    fn never_panics_on_odd_input() {
        for s in [
            &b"\xff\xfe"[..],
            "ğüşıöç".as_bytes(),
            b"-",
            b"--",
            "😀😀😀".as_bytes(),
        ] {
            let e = estimate(s);
            assert!(e.bits >= 0.0);
        }
    }
}
