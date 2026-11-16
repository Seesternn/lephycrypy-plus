//! Anahtar türetme (FORMAT.md › Anahtar türetme; R4-Y1, R4-O1, R4-D6, R5-09). Aşama 1.
//!
//! Argon2id (v=0x13, T=32, K=ε, X=ε, y=2; `LargeSecretBuf` ile `hash_password_into_with_memory`),
//! HKDF-SHA512 (`lphy+/v1/{kek,wrap,commit,data,hmac}`, L=32), bütçe (`m×t ≤ 16 GiB·iter`,
//! `8·p ≤ m`, `m ≤ %75 RAM`) ve şifreleme minimumu (`m ≥ 64 MiB`).
