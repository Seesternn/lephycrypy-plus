# tests/

- `kat/` — resmî bilinen-cevap testleri (Argon2id RFC 9106, HKDF RFC 5869, XChaCha20-Poly1305,
  AES-256-GCM CAVP, BLAKE3) ve deterministik vektör testleri (`required-features = ["test-vectors"]`). Aşama 1.
- `ref/` — Python referans uygulaması (cryptography + argon2-cffi + blake3); **yalnızca
  docs/FORMAT.md okunarak yazılır** (PR'da beyan). Aşama 1.
- `regress/` — fuzz ile bulunan girdilerin regresyon testleri. Aşama 3.
