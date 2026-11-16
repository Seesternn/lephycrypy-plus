//! Deterministik test vektörü enjeksiyonu (PLAN R5-02, I7).
//!
//! Yalnızca `test-vectors` cargo feature'ı ile derlenir. `cfg(test)` **kullanılmaz** (tests/
//! entegrasyon testleri `cfg(test)` görmez). İkililer bu feature'ı `const` iddiasıyla reddeder;
//! release `cargo tree -e features` içinde `test-vectors` görünmemeli ve strip sonrası ikilide
//! [`MARKER`] dizgesi bulunmamalıdır.
//!
//! FORMAT.md › Test vektörleri: salt=`00..1f`, `stream_nonce_prefix`=`20..37` (AES: ilk 7 bayt),
//! `wrap_nonce`=`40..57` (AES: ilk 12), FK=`60..7f`. Şifreleyici bu sırayla ister
//! ([`crate::header::NewHeaderParams`]).

#![cfg(feature = "test-vectors")]

use crate::cipher::AlgId;
use crate::entropy::Entropy;
use crate::error::{Error, Result};

/// İşaret dizgesi: release ikilisinde bulunmamalı (R5-02 doğrulaması).
pub const MARKER: &str = "LPHY-TEST-VECTORS-BUILD";

/// Sırayla sabit tamponlar veren kaynak; her `fill` bir sonraki tamponu tüketir ve uzunluk
/// eşleşmezse hata verir.
#[derive(Debug, Clone)]
pub struct FixedEntropy {
    queue: std::collections::VecDeque<Vec<u8>>,
}

impl FixedEntropy {
    /// Verilen tamponlar sırayla.
    #[must_use]
    pub fn new(items: Vec<Vec<u8>>) -> Self {
        Self {
            queue: items.into_iter().collect(),
        }
    }

    /// FORMAT.md ortak vektör değerleri: salt, prefix, `wrap_nonce`, FK.
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
                "{MARKER}: sabit entropi tükendi"
            )));
        };
        if next.len() != dest.len() {
            return Err(Error::Environment(format!(
                "{MARKER}: sabit entropi uzunluğu {} ≠ istenen {}",
                next.len(),
                dest.len()
            )));
        }
        dest.copy_from_slice(&next);
        Ok(())
    }
}
