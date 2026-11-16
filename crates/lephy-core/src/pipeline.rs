//! Paralel STREAM hattı (PLAN E2, E3, R5-12, R5-17). Aşama 1.
//!
//! okuyucu → bounded kanal → rayon işçileri (`seal/open_chunk(index, last)`) → sıralı yazıcı
//! (`BTreeMap`). Havuz `clamp(64 MiB / chunk_size, 2, 8)` tampon × `chunk_size + 17` B, tek
//! `LargeSecretBuf`; yerinde şifreleme; her chunk sınırında `lephy_sys::signal::interrupted()`.
//! `BufReader`/`BufWriter`/`Stdout` yasak (clippy.toml).
