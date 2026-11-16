//! Rastgelelik kaynağı (PLAN R4-O11, R5-02).
//!
//! [`Entropy`] trait'i; varsayılan uygulama `getrandom`, doğrudan hedef tampona (arena) yazar.
//! `test-vectors` feature'ı ile [`crate::testvec::FixedEntropy`] sabit değerleri sırayla verir.

use crate::error::{Error, Result};

/// Rastgele bayt üreticisi.
pub trait Entropy {
    /// `dest`'i tamamen doldurur.
    ///
    /// # Errors
    /// OS RNG hatası ya da (sabit kaynakta) tükenme.
    fn fill(&mut self, dest: &mut [u8]) -> Result<()>;
}

/// İşletim sistemi RNG'si.
#[derive(Debug, Default, Clone, Copy)]
pub struct OsEntropy;

impl Entropy for OsEntropy {
    fn fill(&mut self, dest: &mut [u8]) -> Result<()> {
        getrandom::fill(dest).map_err(|e| Error::Environment(format!("OS RNG hatası: {e}")))
    }
}
