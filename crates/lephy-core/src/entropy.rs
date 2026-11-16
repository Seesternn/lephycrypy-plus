//! Crate-içi `Entropy` trait'i (PLAN R4-O11, R5-02). Aşama 1.
//!
//! Varsayılan uygulama `getrandom`; doğrudan `SecretBytes` arenasına yazar. `test-vectors`
//! feature'ı ile [`crate::testvec`] sabit değerleri enjekte eder.
