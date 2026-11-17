//! I8: ad işleme değişmezleri (mantık: logic.rs).
#![no_main]

#[path = "logic.rs"]
mod logic;

libfuzzer_sys::fuzz_target!(|data: &[u8]| logic::names(data));
