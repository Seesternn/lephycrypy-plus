//! The full decryption pipeline with a known key (logic: logic.rs).
#![no_main]

#[path = "logic.rs"]
#[allow(dead_code)] // each target uses only part of the shared logic
mod logic;

libfuzzer_sys::fuzz_target!(|data: &[u8]| logic::decrypt_known_key(data));
