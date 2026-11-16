//! Deterministik test vektörü enjeksiyonu (PLAN R5-02, I7).
//!
//! Yalnızca `test-vectors` cargo feature'ı ile derlenir. `cfg(test)` **kullanılmaz** (tests/
//! entegrasyon testleri `cfg(test)` görmez). İkililer bu feature'ı `const` iddiasıyla reddeder;
//! release `cargo tree -e features` içinde `test-vectors` görünmemeli ve strip sonrası ikilide
//! [`MARKER`] dizgesi bulunmamalıdır.
//!
//! Aşama 1'de: sabit salt (`00..1f`), `stream_nonce_prefix` (`20..37`), `wrap_nonce` (`40..57`),
//! FK (`60..7f`) veren `Entropy` uygulaması (FORMAT.md › Test vektörleri).

/// İşaret dizgesi: release ikilisinde bulunmamalı (R5-02 doğrulaması).
#[cfg(feature = "test-vectors")]
pub const MARKER: &str = "LPHY-TEST-VECTORS-BUILD";
