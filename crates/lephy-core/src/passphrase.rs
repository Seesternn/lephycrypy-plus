//! Kelime öbeği (passphrase) üretimi: EFF büyük kelime listesi (7776 kelime, CC BY 3.0; NOTICE).
//!
//! Her kelime 12,925 bit entropi taşır (log2 7776). Kelime seçimi işletim sistemi RNG'sinden
//! reddetme örneklemesiyle yapılır (`u16 < 62 208 = 8 × 7776`), böylece her kelime eşit
//! olasılıklıdır. Sonuç doğrudan kilitli `SecretBytes`'a yazılır.

use std::sync::OnceLock;

use lephy_sys::mem::SecretBytes;

use crate::entropy::Entropy;
use crate::error::{Error, Result};

const RAW: &str = include_str!("../data/eff_large_wordlist.txt");

/// Listedeki kelime sayısı.
pub const WORD_COUNT: usize = 7776;
/// Kelime başına entropi (bit).
pub const BITS_PER_WORD: f64 = 12.925_074_6;
/// Önerilen kelime sayısı (≈ 77,5 bit).
pub const DEFAULT_WORDS: usize = 6;
/// İzin verilen kelime sayısı aralığı.
pub const WORD_RANGE: std::ops::RangeInclusive<usize> = 4..=16;

/// Kelime listesi (ilk çağrıda bir kez ayrıştırılır).
#[must_use]
pub fn words() -> &'static [&'static str] {
    static LIST: OnceLock<Vec<&'static str>> = OnceLock::new();
    LIST.get_or_init(|| {
        RAW.lines()
            .filter_map(|l| l.split('\t').nth(1))
            .map(str::trim)
            .filter(|w| !w.is_empty())
            .collect()
    })
}

/// Tek bir eşit olasılıklı kelime dizini.
fn index(entropy: &mut dyn Entropy) -> Result<usize> {
    const LIMIT: u16 = 62_208; // 8 × 7776: 65 536'nın altındaki en büyük kat
    loop {
        let mut b = [0u8; 2];
        entropy.fill(&mut b)?;
        let v = u16::from_le_bytes(b);
        if v < LIMIT {
            return Ok(usize::from(v) % WORD_COUNT);
        }
    }
}

/// `n` kelimelik öbek üretir; kelimeler `sep` ile ayrılır.
///
/// # Errors
/// Kelime sayısı aralık dışı, RNG ya da kilitli bellek hatası.
pub fn generate(entropy: &mut dyn Entropy, n: usize, sep: char) -> Result<SecretBytes> {
    if !WORD_RANGE.contains(&n) {
        return Err(Error::Environment(format!(
            "kelime sayısı {}–{} olmalı",
            WORD_RANGE.start(),
            WORD_RANGE.end()
        )));
    }
    let list = words();
    let mut sep_buf = [0u8; 4];
    let sep = sep.encode_utf8(&mut sep_buf).as_bytes();
    let mut out = SecretBytes::with_capacity(n * (9 + sep.len()))
        .map_err(|e| Error::Environment(e.to_string()))?;
    for i in 0..n {
        if i > 0 {
            out.push_slice(sep)
                .map_err(|e| Error::Environment(e.to_string()))?;
        }
        out.push_slice(list[index(entropy)?].as_bytes())
            .map_err(|e| Error::Environment(e.to_string()))?;
    }
    Ok(out)
}

/// `n` kelimelik öbeğin entropisi (bit).
#[must_use]
#[allow(clippy::cast_precision_loss)]
pub fn bits(n: usize) -> f64 {
    n as f64 * BITS_PER_WORD
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use crate::entropy::OsEntropy;

    #[test]
    fn list_is_complete_and_unique() {
        let w = words();
        assert_eq!(w.len(), WORD_COUNT);
        let set: std::collections::HashSet<_> = w.iter().collect();
        assert_eq!(set.len(), WORD_COUNT);
        assert_eq!(w[0], "abacus");
        assert_eq!(w[WORD_COUNT - 1], "zoom");
    }

    #[test]
    fn generates_requested_words_from_the_list() {
        let p = generate(&mut OsEntropy, 6, '-').unwrap();
        let s = std::str::from_utf8(p.expose()).unwrap();
        let parts: Vec<&str> = s.split('-').collect();
        assert_eq!(parts.len(), 6);
        assert!(parts.iter().all(|x| words().contains(x)));
        assert!(generate(&mut OsEntropy, 3, ' ').is_err());
        assert!(generate(&mut OsEntropy, 17, ' ').is_err());
    }

    #[test]
    fn index_distribution_is_roughly_uniform() {
        // 7776 kutuya 7776×20 çekiliş; ki-kare ≈ 7775 ± ~125. Gevşek sınır yalnızca kaba
        // önyargıyı (ör. modulo hatası) yakalar.
        let mut counts = vec![0u32; WORD_COUNT];
        let draws = WORD_COUNT * 20;
        let mut e = OsEntropy;
        for _ in 0..draws {
            counts[index(&mut e).unwrap()] += 1;
        }
        let expected = 20.0_f64;
        let chi: f64 = counts
            .iter()
            .map(|&c| (f64::from(c) - expected).powi(2) / expected)
            .sum();
        assert!(chi > 7000.0 && chi < 8600.0, "ki-kare {chi}");
    }
}
