//! I8: arşiv çıkarıcı, keyfi düz metin akışı (mantık: logic.rs).
#![no_main]

#[path = "logic.rs"]
mod logic;

libfuzzer_sys::fuzz_target!(|data: &[u8]| logic::archive_entry(data));
