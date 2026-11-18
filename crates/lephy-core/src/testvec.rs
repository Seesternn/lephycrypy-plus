//! Deterministic test-vector injection.
//!
//! Compiled only with the `test-vectors` cargo feature. `cfg(test)` is **not** used (integration
//! tests in tests/ do not see `cfg(test)`). Binaries reject this feature with a `const` assertion;
//! `test-vectors` must not appear in the release `cargo tree -e features`, and the stripped binary
//! must not contain the [`MARKER`] string.
//!
//! FORMAT.md › Test vectors: salt=`00..1f`, `stream_nonce_prefix`=`20..37` (AES: first 7 bytes),
//! `wrap_nonce`=`40..57` (AES: first 12), FK=`60..7f`. The encryptor asks for them in this order
//! ([`crate::header::NewHeaderParams`]).

#![cfg(feature = "test-vectors")]

use crate::cipher::AlgId;
use crate::entropy::Entropy;
use crate::error::{Error, Result};

/// Marker string: must not be present in a release binary.
pub const MARKER: &str = "LPHY-TEST-VECTORS-BUILD";

/// Source that returns fixed buffers in order; each `fill` consumes the next buffer and fails if
/// the length does not match.
#[derive(Debug, Clone)]
pub struct FixedEntropy {
    queue: std::collections::VecDeque<Vec<u8>>,
}

impl FixedEntropy {
    /// The given buffers, in order.
    #[must_use]
    pub fn new(items: Vec<Vec<u8>>) -> Self {
        Self {
            queue: items.into_iter().collect(),
        }
    }

    /// Common FORMAT.md vector values: salt, prefix, `wrap_nonce`, FK.
    #[must_use]
    pub fn format_defaults(alg: AlgId) -> Self {
        let salt: Vec<u8> = (0x00..0x20).collect();
        let prefix: Vec<u8> = (0x20..0x38).take(alg.prefix_len()).collect();
        let wrap: Vec<u8> = (0x40..0x58).take(alg.nonce_len()).collect();
        let fk: Vec<u8> = (0x60..0x80).collect();
        Self::new(vec![salt, prefix, wrap, fk])
    }
}

impl Entropy for FixedEntropy {
    fn fill(&mut self, dest: &mut [u8]) -> Result<()> {
        let Some(next) = self.queue.pop_front() else {
            return Err(Error::Environment(format!(
                "{MARKER}: fixed entropy exhausted"
            )));
        };
        if next.len() != dest.len() {
            return Err(Error::Environment(format!(
                "{MARKER}: fixed entropy length {} ≠ requested {}",
                next.len(),
                dest.len()
            )));
        }
        dest.copy_from_slice(&next);
        Ok(())
    }
}
