//! The **only** unsafe/FFI crate of lephycrypy+.
//!
//! Rules:
//! - Every exported function is safe and checks its own contract (alignment, length, lifetime,
//!   handle ownership).
//! - Every `unsafe` block holds one operation and carries a `// SAFETY:` comment
//!   (clippy `undocumented_unsafe_blocks`, `multiple_unsafe_ops_per_block` = deny).
//! - `#![deny(unsafe_op_in_unsafe_fn)]` (Cargo.toml `[lints]`).
//! - Dependency budget: `libc` (unix), `windows-sys` (windows), `zeroize`.
//! - Under `cfg(miri)`, `std::alloc` and a no-op lock replace OS calls; the real FFI paths
//!   run only in macOS/Windows CI.
//!

#![cfg_attr(not(test), warn(clippy::missing_errors_doc))]

pub mod alloc;
pub mod fdio;
pub mod fs;
pub mod lifecycle;
pub mod locale;
pub mod mem;
pub mod open_docs;
pub mod platform;
pub mod quarantine;
pub mod quick_action;
pub mod secure_input;
pub mod shell;
pub mod signal;
pub mod term;
pub mod vol;

/// Raw I/O handle: Unix `RawFd`, Windows `RawHandle`.
#[cfg(unix)]
pub type RawIo = std::os::fd::RawFd;
/// Raw I/O handle: Unix `RawFd`, Windows `RawHandle`.
#[cfg(windows)]
pub type RawIo = std::os::windows::io::RawHandle;

/// Common access to the raw handle of std objects such as `File`, `Stdin`, `Stdout`, `Stderr`.
pub trait AsRawIo {
    /// Raw fd/handle.
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

/// Crate name (a marker for the budget check).
pub const CRATE_NAME: &str = "lephy-sys";
