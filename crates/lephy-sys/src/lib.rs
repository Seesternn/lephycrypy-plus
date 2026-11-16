//! lephycrypy+ için **tek** unsafe/FFI crate'i (PLAN R5-01).
//!
//! Kurallar:
//! - Dışa açılan her fonksiyon safe'tir ve sözleşmesini (hizalama, uzunluk, yaşam süresi,
//!   handle sahipliği) kendi içinde doğrular.
//! - Her `unsafe` bloğu tek işlem içerir ve `// SAFETY:` yorumu taşır
//!   (clippy `undocumented_unsafe_blocks`, `multiple_unsafe_ops_per_block` = deny).
//! - `#![deny(unsafe_op_in_unsafe_fn)]` (Cargo.toml `[lints]`).
//! - Bağımlılık bütçesi: `libc` (unix), `windows-sys` (windows), `zeroize`.
//! - `cfg(miri)` altında OS çağrıları yerine `std::alloc` + no-op kilit kullanılır (PLAN I3);
//!   gerçek FFI yolları yalnızca macOS/Windows CI'da çalışır.
//!
//! Aşama 0: modül iskeleti. Her modülün başlığı aşama 1–3'te doldurulacak API'yi listeler.

#![cfg_attr(not(test), warn(clippy::missing_errors_doc))]

pub mod fs;
pub mod mem;
pub mod platform;
pub mod signal;
pub mod term;
pub mod vol;

/// Aşama 0 işaret sabiti: crate'in derlendiğini ve bütçe denetiminin çalıştığını doğrular.
pub const CRATE_NAME: &str = "lephy-sys";
