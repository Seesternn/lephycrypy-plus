//! Visual language: cool neutral background, white surfaces, one accent (dark sea green), no animation.
//! Light/dark theme follows the system preference.

use eframe::egui::{self, Color32, CornerRadius, Stroke, TextStyle, Theme};

use crate::fonts;

/// Colours of one theme.
#[derive(Clone, Copy)]
pub struct Palette {
    /// Window background.
    pub bg: Color32,
    /// Card and input surface.
    pub surface: Color32,
    /// Main text.
    pub ink: Color32,
    /// Secondary text.
    pub muted: Color32,
    /// Line.
    pub line: Color32,
    /// Accent.
    pub accent: Color32,
    /// Text on the accent.
    pub on_accent: Color32,
    /// Light tint of the accent (dragging, selection).
    pub accent_soft: Color32,
    /// Error.
    pub danger: Color32,
    /// Success.
    pub ok: Color32,
}

/// Light theme.
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

/// Dark theme.
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

/// Palette of the active theme.
#[must_use]
pub fn palette(ctx: &egui::Context) -> Palette {
    match ctx.theme() {
        Theme::Dark => DARK,
        Theme::Light => LIGHT,
    }
}

/// Corner radii: input/button 8, card 12, drop zone 14.
pub const R_INPUT: u8 = 8;
/// Card corner.
pub const R_CARD: u8 = 12;
/// Drop-zone corner.
pub const R_ZONE: u8 = 14;
/// Input and button height.
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

/// Installs the theme (both themes; the system decides which is active).
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
