//! I8 / bilinen anahtarla tam çözme hattı (mantık: logic.rs).
#![no_main]

#[path = "logic.rs"]
mod logic;

libfuzzer_sys::fuzz_target!(|data: &[u8]| logic::decrypt_known_key(data));
