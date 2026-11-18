//! Source of randomness.
//!
//! The [`Entropy`] trait; the default implementation uses `getrandom` and writes straight into the
//! target buffer (arena). With `test-vectors`, [`crate::testvec::FixedEntropy`] returns fixed values in order.

use crate::error::{Error, Result};

/// Random byte generator.
pub trait Entropy {
    /// Fills `dest` completely.
    ///
    /// # Errors
    /// OS RNG error, or (for a fixed source) exhaustion.
    fn fill(&mut self, dest: &mut [u8]) -> Result<()>;
}

/// Operating-system RNG.
#[derive(Debug, Default, Clone, Copy)]
pub struct OsEntropy;

impl Entropy for OsEntropy {
    fn fill(&mut self, dest: &mut [u8]) -> Result<()> {
        getrandom::fill(dest).map_err(|e| Error::Environment(format!("OS RNG error: {e}")))
    }
}
