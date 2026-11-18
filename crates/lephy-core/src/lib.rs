//! lephycrypy+ core. Contains no `unsafe`; all FFI lives in `lephy-sys`.

#![forbid(unsafe_code)]

pub mod archive;
pub mod cipher;
pub mod compress;
pub mod entropy;
pub mod envelope;
pub mod error;
pub mod header;
pub mod io;
pub mod kdf;
pub mod names;
pub mod ops;
pub mod pad;
pub mod passphrase;
pub mod password;
pub mod pipeline;
pub mod recipient;
pub mod rs;
pub mod split;
pub mod stream;
pub mod strength;
pub mod testvec;

/// Whether the `test-vectors` feature is enabled. Binaries reject this feature at compile time
/// with `const _: () = assert!(!lephy_core::TEST_VECTORS_ENABLED);`.
pub const TEST_VECTORS_ENABLED: bool = cfg!(feature = "test-vectors");

/// Whether the `fault-injection` feature is enabled (panic-hook test). Never enabled in releases.
pub const FAULT_INJECTION_ENABLED: bool = cfg!(feature = "fault-injection");

pub use header::{HEADER_LEN, VERSION as FORMAT_VERSION};
