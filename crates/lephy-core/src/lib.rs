//! lephycrypy+ çekirdeği. Hiçbir `unsafe` içermez; tüm FFI `lephy-sys`'tedir.

#![forbid(unsafe_code)]

pub mod archive;
pub mod cipher;
pub mod compress;
pub mod entropy;
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
pub mod split;
pub mod stream;
pub mod strength;
pub mod testvec;

/// `test-vectors` feature'ının açık olup olmadığı. İkililer
/// `const _: () = assert!(!lephy_core::TEST_VECTORS_ENABLED);` ile bu feature'ı derleme zamanında
/// reddeder.
pub const TEST_VECTORS_ENABLED: bool = cfg!(feature = "test-vectors");

/// `fault-injection` feature'ı açık mı (panik hook testi). Release'te asla açık değildir.
pub const FAULT_INJECTION_ENABLED: bool = cfg!(feature = "fault-injection");

pub use header::{HEADER_LEN, VERSION as FORMAT_VERSION};
