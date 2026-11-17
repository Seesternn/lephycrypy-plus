//! Görsel dil: soğuk nötr zemin, beyaz yüzeyler, tek vurgu (koyu deniz yeşili), animasyon yok.
//! Açık/koyu tema sistem tercihini izler.

use eframe::egui::{self, Color32, CornerRadius, Stroke, TextStyle, Theme};

use crate::fonts;

/// Bir temanın renkleri.
#[derive(Clone, Copy)]
pub struct Palette {
    /// Pencere zemini.
    pub bg: Color32,
    /// Kart ve giriş alanı yüzeyi.
    pub surface: Color32,
    /// Ana metin.
    pub ink: Color32,
    /// İkincil metin.
    pub muted: Color32,
    /// Çizgi.
    pub line: Color32,
    /// Vurgu.
    pub accent: Color32,
    /// Vurgu üstünde metin.
    pub on_accent: Color32,
    /// Vurgunun hafif tonu (sürükleme, seçim).
    pub accent_soft: Color32,
    /// Hata.
    pub danger: Color32,
    /// Onay.
    pub ok: Color32,
}

/// Açık tema.
pub const LIGHT: Palette = Palette {
    bg: Color32::from_rgb(0xF5, 0xF6, 0xF7),
    surface: Color32::from_rgb(0xFF, 0xFF, 0xFF),
    ink: Color32::from_rgb(0x1D, 0x21, 0x25),
    muted: Color32::from_rgb(0x67, 0x6F, 0x76),
    line: Color32::from_rgb(0xDD, 0xE1, 0xE4),
    accent: Color32::from_rgb(0x1F, 0x6F, 0x6A),
    on_accent: Color32::from_rgb(0xFF, 0xFF, 0xFF),
    accent_soft: Color32::from_rgb(0xE4, 0xF0, 0xEE),
    danger: Color32::from_rgb(0xB4, 0x23, 0x18),
    ok: Color32::from_rgb(0x1F, 0x6F, 0x6A),
};

/// Koyu tema.
pub const DARK: Palette = Palette {
    bg: Color32::from_rgb(0x1B, 0x1E, 0x21),
    surface: Color32::from_rgb(0x25, 0x29, 0x2D),
    ink: Color32::from_rgb(0xE9, 0xEB, 0xED),
    muted: Color32::from_rgb(0x9A, 0xA1, 0xA7),
    line: Color32::from_rgb(0x38, 0x3D, 0x42),
    accent: Color32::from_rgb(0x5F, 0xB3, 0xAA),
    on_accent: Color32::from_rgb(0x10, 0x22, 0x20),
    accent_soft: Color32::from_rgb(0x23, 0x3A, 0x38),
    danger: Color32::from_rgb(0xF0, 0x8A, 0x80),
    ok: Color32::from_rgb(0x5F, 0xB3, 0xAA),
};

/// Etkin temanın paleti.
#[must_use]
pub fn palette(ctx: &egui::Context) -> Palette {
    match ctx.theme() {
        Theme::Dark => DARK,
        Theme::Light => LIGHT,
    }
}

/// Köşe yarıçapları: giriş/düğme 8, kart 12, bırakma alanı 14.
pub const R_INPUT: u8 = 8;
/// Kart köşesi.
pub const R_CARD: u8 = 12;
/// Bırakma alanı köşesi.
pub const R_ZONE: u8 = 14;
/// Giriş ve düğme yüksekliği.
pub const CONTROL_H: f32 = 40.0;

fn visuals(p: Palette, dark: bool) -> egui::Visuals {
    let mut v = if dark {
        egui::Visuals::dark()
    } else {
        egui::Visuals::light()
    };
    v.panel_fill = p.bg;
    v.window_fill = p.surface;
    v.extreme_bg_color = p.surface;
    v.faint_bg_color = p.bg;
    v.override_text_color = Some(p.ink);
    v.weak_text_color = Some(p.muted);
    v.hyperlink_color = p.accent;
    v.selection.bg_fill = p.accent_soft;
    v.selection.stroke = Stroke::new(1.5, p.accent);
    v.window_stroke = Stroke::new(1.0, p.line);
    v.text_cursor.stroke = Stroke::new(1.5, p.accent);
    let r = CornerRadius::same(R_INPUT);
    for w in [
        &mut v.widgets.noninteractive,
        &mut v.widgets.inactive,
        &mut v.widgets.hovered,
        &mut v.widgets.active,
        &mut v.widgets.open,
    ] {
        w.corner_radius = r;
        w.expansion = 0.0;
        w.fg_stroke = Stroke::new(1.0, p.ink);
    }
    v.widgets.noninteractive.bg_stroke = Stroke::new(1.0, p.line);
    v.widgets.noninteractive.bg_fill = p.surface;
    v.widgets.noninteractive.fg_stroke = Stroke::new(1.0, p.muted);
    v.widgets.inactive.bg_fill = p.surface;
    v.widgets.inactive.weak_bg_fill = p.surface;
    v.widgets.inactive.bg_stroke = Stroke::new(1.0, p.line);
    v.widgets.hovered.bg_fill = p.surface;
    v.widgets.hovered.weak_bg_fill = p.surface;
    v.widgets.hovered.bg_stroke = Stroke::new(1.0, p.muted);
    v.widgets.active.bg_fill = p.accent_soft;
    v.widgets.active.weak_bg_fill = p.accent_soft;
    v.widgets.active.bg_stroke = Stroke::new(1.0, p.accent);
    v.widgets.open = v.widgets.active;
    v
}

/// Temayı kurar (iki tema da; hangisinin etkin olduğunu sistem belirler).
pub fn apply(ctx: &egui::Context) {
    ctx.set_visuals_of(Theme::Light, visuals(LIGHT, false));
    ctx.set_visuals_of(Theme::Dark, visuals(DARK, true));
    ctx.all_styles_mut(|s| {
        s.animation_time = 0.0;
        s.spacing.item_spacing = egui::vec2(8.0, 8.0);
        s.spacing.button_padding = egui::vec2(14.0, 8.0);
        s.spacing.interact_size.y = 30.0;
        let mut scroll = egui::style::ScrollStyle::floating();
        scroll.bar_width = 7.0;
        scroll.floating_width = 3.0;
        scroll.active_background_opacity = 0.0;
        scroll.interact_background_opacity = 0.0;
        scroll.active_handle_opacity = 0.35;
        scroll.interact_handle_opacity = 0.55;
        s.spacing.scroll = scroll;
        s.text_styles = [
            (TextStyle::Heading, fonts::semibold(22.0)),
            (TextStyle::Body, fonts::regular(14.5)),
            (TextStyle::Button, fonts::regular(14.5)),
            (TextStyle::Small, fonts::regular(12.5)),
            (TextStyle::Monospace, fonts::regular(13.5)),
        ]
        .into();
    });
}
