//! System fonts: no embedded font; at run time a regular and a semibold face of an operating-system
//! font covering Turkish characters are read.

use std::sync::Arc;

use eframe::egui::{self, FontData, FontDefinitions, FontFamily, FontId};

/// Semibold family name.
pub const SEMIBOLD: &str = "semibold";

/// File path + face index inside a collection (`.ttc`).
type Face = (&'static str, u32);

/// Candidate (regular, semibold) pairs; the first readable pair is used.
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

/// A loaded font pair.
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

/// The first system font pair found.
#[must_use]
pub fn find_system_fonts() -> Option<SystemFonts> {
    CANDIDATES.iter().find_map(|&(r, b)| {
        Some(SystemFonts {
            regular: load(r)?,
            semibold: load(b)?,
        })
    })
}

/// Installs the fonts into egui.
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

/// Semibold font.
#[must_use]
pub fn semibold(size: f32) -> FontId {
    FontId::new(size, FontFamily::Name(SEMIBOLD.into()))
}

/// Regular font.
#[must_use]
pub fn regular(size: f32) -> FontId {
    FontId::proportional(size)
}

#[cfg(test)]
mod tests {
    #[test]
    fn system_fonts_exist_on_supported_platforms() {
        if cfg!(any(target_os = "macos", windows)) {
            assert!(super::find_system_fonts().is_some(), "no system font found");
        }
    }
}
