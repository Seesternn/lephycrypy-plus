# tests/

- `kat/` — resmî bilinen-cevap verileri: `argon2id_rfc9106.txt`, `hkdf_rfc5869.txt`,
  `xchacha20poly1305_draft03.txt`, `aes256gcm_cavp_subset.txt` (NIST CAVP, pyca aynası),
  `blake3_test_vectors.json` (resmî). Test: `crates/lephy-core/tests/kat.rs`.
  `kat/vectors/` — Python referansının ürettiği FORMAT.md vektörleri (`v1..v9.lphy`, `vectors.json`);
  test: `crates/lephy-core/tests/vectors.rs` (`required-features = ["test-vectors"]`).
- `ref/lephy_ref.py` — Python referans uygulaması (cryptography + argon2-cffi + blake3; HChaCha20 elle);
  **yalnızca docs/FORMAT.md okunarak yazılmıştır**. `selftest` draft-xchacha vektörlerini doğrular,
  `vectors <dizin>` vektörleri üretir.
- `regress/` — fuzz ile bulunan girdilerin regresyon testleri. Aşama 3.
