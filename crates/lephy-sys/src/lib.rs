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

pub mod fdio;
pub mod fs;
pub mod mem;
pub mod platform;
pub mod signal;
pub mod term;
pub mod vol;

/// Ham G/Ç tanıtıcısı: Unix `RawFd`, Windows `RawHandle`.
#[cfg(unix)]
pub type RawIo = std::os::fd::RawFd;
/// Ham G/Ç tanıtıcısı: Unix `RawFd`, Windows `RawHandle`.
#[cfg(windows)]
pub type RawIo = std::os::windows::io::RawHandle;

/// `File`, `Stdin`, `Stdout`, `Stderr` gibi std nesnelerinin ham tanıtıcısına ortak erişim.
pub trait AsRawIo {
    /// Ham fd/handle.
    fn raw_io(&self) -> RawIo;
}

#[cfg(unix)]
impl<T: std::os::fd::AsRawFd> AsRawIo for T {
    fn raw_io(&self) -> RawIo {
        self.as_raw_fd()
    }
}

#[cfg(windows)]
impl<T: std::os::windows::io::AsRawHandle> AsRawIo for T {
    fn raw_io(&self) -> RawIo {
        self.as_raw_handle()
    }
}

/// Crate adı (bütçe denetimi için işaret).
pub const CRATE_NAME: &str = "lephy-sys";
