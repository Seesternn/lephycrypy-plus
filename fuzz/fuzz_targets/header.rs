//! I8: 256 baytlık başlık ayrıştırıcısı (mantık: logic.rs).
#![no_main]

#[path = "logic.rs"]
mod logic;

libfuzzer_sys::fuzz_target!(|data: &[u8]| logic::header(data));
