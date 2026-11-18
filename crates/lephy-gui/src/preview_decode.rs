//! Bounded PNG / JPEG decoding for the preview. Kept free of the window library so the fuzz
//! target (`fuzz/fuzz_targets/preview_image.rs`) runs exactly this code.

use std::io::Cursor;

/// Largest image side (pixels).
pub const MAX_SIDE: u32 = 8192;
/// Decoder allocation limit.
pub const MAX_ALLOC: u64 = 256 * 1024 * 1024;

/// RGBA pixels of a PNG or JPEG (the format comes from the content), within the limits.
#[must_use]
pub fn decode_rgba(data: &[u8]) -> Option<(u32, u32, Vec<u8>)> {
    let mut reader = image::ImageReader::new(Cursor::new(data))
        .with_guessed_format()
        .ok()?;
    if !matches!(
        reader.format(),
        Some(image::ImageFormat::Png | image::ImageFormat::Jpeg)
    ) {
        return None;
    }
    let mut limits = image::Limits::default();
    limits.max_image_width = Some(MAX_SIDE);
    limits.max_image_height = Some(MAX_SIDE);
    limits.max_alloc = Some(MAX_ALLOC);
    reader.limits(limits);
    let rgba = reader.decode().ok()?.to_rgba8();
    Some((rgba.width(), rgba.height(), rgba.into_raw()))
}
