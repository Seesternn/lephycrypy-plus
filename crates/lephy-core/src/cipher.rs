//! AEAD soyutlaması (PLAN › STREAM, R5-03). Aşama 1.
//!
//! `AlgId` (1 = XChaCha20-Poly1305, 2 = AES-256-GCM), `AeadCore` trait'i (yalnızca
//! `*_in_place_detached`), `SharedCipher` (`SecretBox<Cipher>`, `!Clone`, `Sync`), AES nonce
//! kuyruk kuralı. `Aead::encrypt/decrypt` (Vec dönen) clippy `disallowed-methods` ile yasak.
