//! I8: 256 baytlık başlık ayrıştırıcısı (mantık: logic.rs).
#![no_main]

#[path = "logic.rs"]
#[allow(dead_code)] // her hedef ortak mantığın yalnızca bir kısmını kullanır
mod logic;

libfuzzer_sys::fuzz_target!(|data: &[u8]| logic::header(data));
