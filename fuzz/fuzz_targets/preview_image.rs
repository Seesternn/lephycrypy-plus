//! The desktop preview's bounded PNG / JPEG decoding on arbitrary bytes: must not panic, hang or
//! exceed its limits.
#![no_main]

#[path = "../../crates/lephy-gui/src/preview_decode.rs"]
mod preview_decode;

libfuzzer_sys::fuzz_target!(|data: &[u8]| {
    if let Some((w, h, px)) = preview_decode::decode_rgba(data) {
        assert!(w <= preview_decode::MAX_SIDE && h <= preview_decode::MAX_SIDE);
        assert_eq!(px.len() as u64, u64::from(w) * u64::from(h) * 4);
    }
});
