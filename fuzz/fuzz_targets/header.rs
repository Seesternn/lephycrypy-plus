//! The 256-byte header parser (logic: logic.rs).
#![no_main]

#[path = "logic.rs"]
#[allow(dead_code)] // each target uses only part of the shared logic
mod logic;

libfuzzer_sys::fuzz_target!(|data: &[u8]| logic::header(data));
