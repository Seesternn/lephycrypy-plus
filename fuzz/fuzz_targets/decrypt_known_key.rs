//! I8 / bilinen anahtarla tam çözme hattı (mantık: logic.rs).
#![no_main]

#[path = "logic.rs"]
#[allow(dead_code)] // her hedef ortak mantığın yalnızca bir kısmını kullanır
mod logic;

libfuzzer_sys::fuzz_target!(|data: &[u8]| logic::decrypt_known_key(data));
