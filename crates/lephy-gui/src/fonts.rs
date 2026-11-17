//! Sistem yazı tipleri: gömülü yazı tipi yok; çalışma anında işletim sisteminin Türkçe
//! karakterleri kapsayan bir normal ve bir yarı kalın yüzü okunur.

use std::sync::Arc;

use eframe::egui::{self, FontData, FontDefinitions, FontFamily, FontId};

/// Yarı kalın aile adı.
pub const SEMIBOLD: &str = "semibold";

/// Dosya yolu + koleksiyon (`.ttc`) içindeki yüz indeksi.
type Face = (&'static str, u32);

/// (normal, yarı kalın) aday çiftleri; ilk okunabilen çift kullanılır.
#[cfg(target_os = "macos")]
const CANDIDATES: &[(Face, Face)] = &[
    (
        ("/System/Library/Fonts/Avenir Next.ttc", 7),
        ("/System/Library/Fonts/Avenir Next.ttc", 2),
    ),
    (
        ("/System/Library/Fonts/Supplemental/Arial.ttf", 0),
        ("/System/Library/Fonts/Supplemental/Arial Bold.ttf", 0),
    ),
];
#[cfg(windows)]
const CANDIDATES: &[(Face, Face)] = &[
    (
        ("C:\\Windows\\Fonts\\segoeui.ttf", 0),
        ("C:\\Windows\\Fonts\\seguisb.ttf", 0),
    ),
    (
        ("C:\\Windows\\Fonts\\arial.ttf", 0),
        ("C:\\Windows\\Fonts\\arialbd.ttf", 0),
    ),
];
#[cfg(not(any(target_os = "macos", windows)))]
const CANDIDATES: &[(Face, Face)] = &[];

/// Okunmuş yazı tipi çifti.
pub struct SystemFonts {
    regular: FontData,
    semibold: FontData,
}

fn load(face: Face) -> Option<FontData> {
    let bytes = std::fs::read(face.0).ok().filter(|b| b.len() > 1024)?;
    let mut d = FontData::from_owned(bytes);
    d.index = face.1;
    Some(d)
}

/// İlk bulunan sistem yazı tipi çifti.
#[must_use]
pub fn find_system_fonts() -> Option<SystemFonts> {
    CANDIDATES.iter().find_map(|&(r, b)| {
        Some(SystemFonts {
            regular: load(r)?,
            semibold: load(b)?,
        })
    })
}

/// Yazı tiplerini egui'ye kurar.
pub fn install(ctx: &egui::Context, fonts: SystemFonts) {
    let mut defs = FontDefinitions::empty();
    defs.font_data
        .insert("regular".to_owned(), Arc::new(fonts.regular));
    defs.font_data
        .insert("semibold".to_owned(), Arc::new(fonts.semibold));
    defs.families
        .insert(FontFamily::Proportional, vec!["regular".to_owned()]);
    defs.families
        .insert(FontFamily::Monospace, vec!["regular".to_owned()]);
    defs.families.insert(
        FontFamily::Name(SEMIBOLD.into()),
        vec!["semibold".to_owned(), "regular".to_owned()],
    );
    ctx.set_fonts(defs);
}

/// Yarı kalın yazı tipi.
#[must_use]
pub fn semibold(size: f32) -> FontId {
    FontId::new(size, FontFamily::Name(SEMIBOLD.into()))
}

/// Normal yazı tipi.
#[must_use]
pub fn regular(size: f32) -> FontId {
    FontId::proportional(size)
}

#[cfg(test)]
mod tests {
    #[test]
    fn system_fonts_exist_on_supported_platforms() {
        if cfg!(any(target_os = "macos", windows)) {
            assert!(
                super::find_system_fonts().is_some(),
                "sistem yazı tipi bulunamadı"
            );
        }
    }
}
