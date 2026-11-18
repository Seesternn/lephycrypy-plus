//! Preview of a decrypted file in memory: plain text, PNG or JPEG. Nothing is written to disk.
//!
//! Images come from files anyone could have encrypted, so decoding is bounded: only PNG and
//! JPEG (detected from the content, not the name), at most 8192 × 8192 pixels and 256 MiB of
//! decoder allocations. Pixel buffers are wiped once copied into the texture image.

use eframe::egui::ColorImage;
use zeroize::Zeroize;

/// Largest decrypted file previewed (bytes).
pub const MAX_BYTES: usize = 32 * 1024 * 1024;
/// Text shown at most (bytes).
const MAX_TEXT: usize = 1024 * 1024;

/// What a preview shows.
pub enum Content {
    /// UTF-8 text, made safe to show (bidirectional and control characters replaced); `true`
    /// when it was cut at [`MAX_TEXT`].
    Text(String, bool),
    /// Decoded pixels.
    Image(ColorImage),
}

/// Why a file cannot be previewed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Refusal {
    /// Neither text nor PNG / JPEG.
    Unsupported,
    /// The image is damaged or over the limits.
    BadImage,
}

/// Picks the kind from the content and decodes it.
///
/// # Errors
/// [`Refusal`] when the file is not text, PNG or JPEG, or the image cannot be decoded within
/// the limits.
pub fn decode(data: &[u8]) -> Result<Content, Refusal> {
    if data.starts_with(b"\x89PNG\r\n\x1a\n") || data.starts_with(&[0xFF, 0xD8, 0xFF]) {
        return decode_image(data).ok_or(Refusal::BadImage);
    }
    let cut = data.len() > MAX_TEXT;
    let mut end = data.len().min(MAX_TEXT);
    // Do not cut a UTF-8 sequence in half.
    while end > 0 && end < data.len() && (data[end] & 0b1100_0000) == 0b1000_0000 {
        end -= 1;
    }
    let text = std::str::from_utf8(&data[..end]).map_err(|_| Refusal::Unsupported)?;
    if text.contains('\0') {
        return Err(Refusal::Unsupported);
    }
    let shown = text
        .lines()
        .map(|l| lephy_core::names::sanitize_display_name(&l.replace('\t', "    ")))
        .collect::<Vec<_>>()
        .join("\n");
    Ok(Content::Text(shown, cut))
}

fn decode_image(data: &[u8]) -> Option<Content> {
    let (w, h, mut raw) = crate::preview_decode::decode_rgba(data)?;
    let out = ColorImage::from_rgba_unmultiplied([w as usize, h as usize], &raw);
    raw.zeroize();
    Some(Content::Image(out))
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::panic)]
mod tests {
    use super::*;
    use std::io::Cursor;

    fn png_2x1() -> Vec<u8> {
        let mut out = Vec::new();
        let img = image::RgbaImage::from_raw(2, 1, vec![255, 0, 0, 255, 0, 0, 255, 255]).unwrap();
        img.write_to(&mut Cursor::new(&mut out), image::ImageFormat::Png)
            .unwrap();
        out
    }

    #[test]
    fn text_png_and_refusals() {
        match decode("satır 1\n\u{202E}gizli\tson".as_bytes())
            .ok()
            .unwrap()
        {
            Content::Text(t, cut) => {
                assert_eq!(t, "satır 1\n_gizli    son");
                assert!(!cut);
            }
            Content::Image(_) => panic!("text expected"),
        }
        match decode(&png_2x1()).ok().unwrap() {
            Content::Image(i) => assert_eq!(i.size, [2, 1]),
            Content::Text(..) => panic!("image expected"),
        }
        let mut broken = png_2x1();
        broken.truncate(30);
        assert_eq!(decode(&broken).err(), Some(Refusal::BadImage));
        assert_eq!(
            decode(&[0xFF, 0xD8, 0xFF, 0, 1, 2]).err(),
            Some(Refusal::BadImage)
        );
        assert_eq!(
            decode(&[0, 159, 146, 150]).err(),
            Some(Refusal::Unsupported)
        );
        let long = "a".repeat(MAX_TEXT + 10);
        assert!(matches!(
            decode(long.as_bytes()),
            Ok(Content::Text(_, true))
        ));
    }
}
