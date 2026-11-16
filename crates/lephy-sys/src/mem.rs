//! Kilitli bellek (PLAN E1, R4-Y6, R5-03, R5-17).
//!
//! Aşama 1'de gelecek API (hepsi safe):
//! - `SecretBytes`: sabit boyutlu, sayfa hizalı, `mlock`/`VirtualLock` ile kilitli arenada
//!   yaşayan bayt tamponu; `expose()`/`expose_mut()`, `Debug` → `[REDACTED]`, `Clone`/`Display`/
//!   `serde` yok; Drop'ta zeroize. Kapasite aşımı hata, realloc yok.
//! - `SecretBox<T>`: arenada hizalı yer, `ptr::write` ile kurulum, Drop'ta `drop_in_place` + ham
//!   zeroize (AEAD struct'ları için).
//! - Arena: süreç başında tek bölge (16 sayfa), büyümez; taban/uzunluk `static` atomiklerde
//!   (panik hook'u için); sayfa başına refcount; `munlock` yalnızca sayfadaki son sır düşünce.
//!   Windows'ta önce `SetProcessWorkingSetSize`.
//! - `LargeSecretBuf`: `mmap(MAP_PRIVATE|MAP_ANONYMOUS)` / `VirtualAlloc`; `MADV_DONTDUMP` yalnızca
//!   `cfg(target_os = "linux")`; kilit best-effort; Drop'ta sıfırla + unmap; hook listesi için
//!   `[AtomicPtr; 16]` kaydı. Ayırma hatası `Err` döner (OOM abort'u yerine kod 6/1).
//! - `zeroize_all_registered()`: panik hook'unun (1) adımı; kilitsiz volatile yazım.
//!
//! `cfg(miri)`: `std::alloc::alloc_zeroed` + no-op kilit; refcount/hizalama/sınır aritmetiği ve
//! zeroize-sonra-dealloc Miri altında test edilir (PLAN I3).
