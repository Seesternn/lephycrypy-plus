//! lephycrypy+ çekirdeği. Hiçbir `unsafe` içermez; tüm FFI `lephy-sys`'tedir (PLAN R5-01).
//!
//! Aşama 0: modül iskeleti ve hata/çıkış kodu tablosu. Kriptografi aşama 1'de.

#![forbid(unsafe_code)]

pub mod archive;
pub mod cipher;
pub mod entropy;
pub mod error;
pub mod header;
pub mod io;
pub mod kdf;
pub mod names;
pub mod pad;
pub mod password;
pub mod pipeline;
pub mod stream;
pub mod testvec;

/// `test-vectors` feature'ının açık olup olmadığı (R5-02). İkililer
/// `const _: () = assert!(!lephy_core::TEST_VECTORS_ENABLED);` ile bu feature'ı derleme zamanında
/// reddeder.
pub const TEST_VECTORS_ENABLED: bool = cfg!(feature = "test-vectors");

/// Biçim sürümü (FORMAT.md › Başlık, ofset 6).
pub const FORMAT_VERSION: u16 = 1;

/// Başlık boyutu (FORMAT.md): 256 bayt.
pub const HEADER_LEN: usize = 256;
