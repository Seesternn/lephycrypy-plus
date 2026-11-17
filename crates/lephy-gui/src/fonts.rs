//! Sistem yazı tipi: gömülü yazı tipi yok; çalışma anında işletim sisteminin
//! Türkçe karakterleri kapsayan bir TrueType yazı tipi okunur.

use std::sync::Arc;

use eframe::egui::{self, FontData, FontDefinitions, FontFamily};

#[cfg(target_os = "macos")]
const CANDIDATES: &[&str] = &[
    "/System/Library/Fonts/Supplemental/Arial.ttf",
    "/System/Library/Fonts/Supplemental/Verdana.ttf",
    "/Library/Fonts/Arial Unicode.ttf",
];
#[cfg(windows)]
const CANDIDATES: &[&str] = &[
    "C:\\Windows\\Fonts\\segoeui.ttf",
    "C:\\Windows\\Fonts\\arial.ttf",
    "C:\\Windows\\Fonts\\tahoma.ttf",
];
#[cfg(not(any(target_os = "macos", windows)))]
const CANDIDATES: &[&str] = &[
    "/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf",
    "/usr/share/fonts/dejavu/DejaVuSans.ttf",
    "/usr/share/fonts/TTF/DejaVuSans.ttf",
    "/usr/share/fonts/truetype/liberation/LiberationSans-Regular.ttf",
];

/// İlk bulunan sistem yazı tipi: (yol, baytlar).
#[must_use]
pub fn find_system_font() -> Option<(&'static str, Vec<u8>)> {
    CANDIDATES.iter().find_map(|p| {
        std::fs::read(p)
            .ok()
            .filter(|b| b.len() > 1024)
            .map(|b| (*p, b))
    })
}

/// Yazı tipini egui'ye kurar.
pub fn install(ctx: &egui::Context, bytes: Vec<u8>) {
    let mut fonts = FontDefinitions::empty();
    fonts
        .font_data
        .insert("sistem".to_owned(), Arc::new(FontData::from_owned(bytes)));
    for fam in [FontFamily::Proportional, FontFamily::Monospace] {
        fonts
            .families
            .entry(fam)
            .or_default()
            .push("sistem".to_owned());
    }
    ctx.set_fonts(fonts);
}

#[cfg(test)]
mod tests {
    #[test]
    fn a_system_font_exists_on_supported_platforms() {
        if cfg!(any(target_os = "macos", windows)) {
            assert!(
                super::find_system_font().is_some(),
                "sistem yazı tipi bulunamadı"
            );
        }
    }
}
