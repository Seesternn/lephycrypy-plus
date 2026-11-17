//! I8: arşiv çıkarıcı, keyfi düz metin akışı (mantık: logic.rs).
#![no_main]

#[path = "logic.rs"]
#[allow(dead_code)] // her hedef ortak mantığın yalnızca bir kısmını kullanır
mod logic;

libfuzzer_sys::fuzz_target!(|data: &[u8]| logic::archive_entry(data));
