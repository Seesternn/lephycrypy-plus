//! Action buttons: everything that *does* something is a framed button with an optional icon,
//! so it never reads as plain text. Plain links stay for navigation and for showing or hiding
//! details only.

use super::{Palette, focus_ring};
use crate::{fonts, motion, theme};
use eframe::egui::{
    self, Color32, CursorIcon, Pos2, Rect, Response, Sense, Stroke, StrokeKind, Ui, WidgetInfo,
    pos2, vec2,
};

/// What a button does, which sets its look.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum Kind {
    /// The main step here: filled with the accent.
    Primary,
    /// Any other step: framed.
    Secondary,
    /// Removes or discards something: red frame and text.
    Danger,
}

/// Small line icons drawn in front of the label.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum Icon {
    /// No icon.
    None,
    /// Floppy-style save mark.
    Save,
    /// Padlock.
    Lock,
    /// Folder.
    Folder,
    /// Cross.
    Close,
    /// Bin.
    Trash,
    /// Circular arrow.
    Retry,
    /// Two pages.
    Copy,
    /// Tick.
    Check,
    /// Plus.
    Add,
    /// Three dots.
    More,
    /// Page with lines.
    File,
}

const H: f32 = 30.0;
const PAD: f32 = 12.0;
const ICON: f32 = 14.0;
const GAP: f32 = 6.0;

/// Width a button with `text` and `icon` needs.
fn width(ui: &Ui, icon: Icon, text: &str) -> f32 {
    let galley = ui
        .painter()
        .layout_no_wrap(text.to_owned(), fonts::regular(13.5), Color32::WHITE);
    let icon_w = if icon == Icon::None {
        0.0
    } else if text.is_empty() {
        ICON
    } else {
        ICON + GAP
    };
    (galley.size().x + icon_w + 2.0 * PAD).max(H)
}

/// An action button sized to its label.
pub(super) fn action(ui: &mut Ui, pal: Palette, kind: Kind, icon: Icon, text: &str) -> Response {
    action_enabled(ui, pal, kind, icon, text, true)
}

/// An action button that may be disabled.
pub(super) fn action_enabled(
    ui: &mut Ui,
    pal: Palette,
    kind: Kind,
    icon: Icon,
    text: &str,
    enabled: bool,
) -> Response {
    let w = width(ui, icon, text);
    action_sized(ui, pal, kind, icon, text, enabled, w)
}

/// An action button `w` wide.
#[allow(
    clippy::too_many_arguments,
    reason = "one widget, every argument is its look"
)]
pub(super) fn action_sized(
    ui: &mut Ui,
    pal: Palette,
    kind: Kind,
    icon: Icon,
    text: &str,
    enabled: bool,
    w: f32,
) -> Response {
    let sense = if enabled {
        Sense::click()
    } else {
        Sense::hover()
    };
    let (rect, resp) = ui.allocate_exact_size(vec2(w, H), sense);
    resp.widget_info(|| WidgetInfo::labeled(egui::Role::Button, enabled, text));
    let hover = motion::toggle(
        ui.ctx(),
        resp.id.with("hover"),
        resp.hovered() && enabled,
        0.12,
    );
    let down = resp.is_pointer_button_down_on();
    let (fill, stroke, ink) = match kind {
        Kind::Primary => {
            let mut f = pal.accent.lerp_to_gamma(Color32::BLACK, 0.08 * hover);
            if down {
                f = pal.accent.lerp_to_gamma(Color32::BLACK, 0.16);
            }
            (f, Stroke::NONE, pal.on_accent)
        }
        Kind::Secondary => {
            let f = if down {
                pal.accent_soft
            } else {
                pal.surface.lerp_to_gamma(pal.accent_soft, 0.6 * hover)
            };
            (
                f,
                Stroke::new(1.0, pal.line.lerp_to_gamma(pal.muted, hover)),
                pal.ink,
            )
        }
        Kind::Danger => {
            let soft = pal.danger.gamma_multiply(0.12);
            let f = if down {
                pal.danger.gamma_multiply(0.2)
            } else {
                pal.surface.lerp_to_gamma(soft, hover)
            };
            (
                f,
                Stroke::new(1.0, pal.danger.gamma_multiply(0.7)),
                pal.danger,
            )
        }
    };
    let (fill, stroke, ink) = if enabled {
        (fill, stroke, ink)
    } else {
        (
            fill.gamma_multiply(0.5),
            Stroke::new(stroke.width, stroke.color.gamma_multiply(0.5)),
            ink.gamma_multiply(0.45),
        )
    };
    let p = ui.painter();
    p.rect(
        rect,
        f32::from(theme::R_INPUT),
        fill,
        stroke,
        StrokeKind::Inside,
    );
    let galley = p.layout_no_wrap(text.to_owned(), fonts::regular(13.5), ink);
    let icon_w = match (icon, text.is_empty()) {
        (Icon::None, _) => 0.0,
        (_, true) => ICON,
        (_, false) => ICON + GAP,
    };
    let total = galley.size().x + icon_w;
    let left = rect.center().x - total / 2.0;
    if icon != Icon::None {
        draw_icon(p, pos2(left + ICON / 2.0, rect.center().y), icon, ink);
    }
    p.galley(
        pos2(left + icon_w, rect.center().y - galley.size().y / 2.0),
        galley,
        ink,
    );
    focus_ring(ui, &resp, rect, pal);
    if enabled {
        resp.on_hover_cursor(CursorIcon::PointingHand)
    } else {
        resp
    }
}

/// Buttons side by side; they wrap to the next line when the row is too narrow.
pub(super) fn row<R>(ui: &mut Ui, body: impl FnOnce(&mut Ui) -> R) -> R {
    ui.horizontal_wrapped(|ui| {
        ui.spacing_mut().item_spacing = vec2(8.0, 8.0);
        body(ui)
    })
    .inner
}

/// Draws `icon` centred on `c` (about 14 px).
#[allow(clippy::too_many_lines, reason = "one small drawing per icon")]
pub(super) fn draw_icon(p: &egui::Painter, c: Pos2, icon: Icon, color: Color32) {
    let st = Stroke::new(1.5, color);
    let v = |x: f32, y: f32| c + vec2(x, y);
    match icon {
        Icon::None => {}
        Icon::Save => {
            let r = Rect::from_center_size(c, vec2(12.0, 12.0));
            p.rect_stroke(r, 2.0, st, StrokeKind::Middle);
            p.rect_stroke(
                Rect::from_min_max(v(-3.0, -6.0), v(3.0, -2.0)),
                0.5,
                st,
                StrokeKind::Middle,
            );
            p.circle_stroke(v(0.0, 2.5), 1.8, st);
        }
        Icon::Lock => {
            let body = Rect::from_min_max(v(-5.5, -1.0), v(5.5, 6.5));
            p.rect_stroke(body, 1.5, st, StrokeKind::Middle);
            let pts: Vec<Pos2> = (0..=12)
                .map(|i| {
                    #[allow(clippy::cast_precision_loss, reason = "small count")]
                    let t = std::f32::consts::PI * (1.0 + i as f32 / 12.0);
                    v(3.5 * t.cos(), -3.5 + 3.5 * t.sin())
                })
                .collect();
            let mut line = vec![v(-3.5, -1.0)];
            line.extend(pts);
            line.push(v(3.5, -1.0));
            p.add(egui::Shape::line(line, st));
        }
        Icon::Folder => {
            p.add(egui::Shape::line(
                vec![
                    v(-6.5, -4.5),
                    v(-2.0, -4.5),
                    v(-0.5, -2.5),
                    v(6.5, -2.5),
                    v(6.5, 5.0),
                    v(-6.5, 5.0),
                    v(-6.5, -4.5),
                ],
                st,
            ));
        }
        Icon::Close => {
            p.line_segment([v(-4.0, -4.0), v(4.0, 4.0)], st);
            p.line_segment([v(4.0, -4.0), v(-4.0, 4.0)], st);
        }
        Icon::Trash => {
            p.line_segment([v(-6.0, -4.0), v(6.0, -4.0)], st);
            p.add(egui::Shape::line(
                vec![v(-2.0, -4.0), v(-2.0, -6.0), v(2.0, -6.0), v(2.0, -4.0)],
                st,
            ));
            p.add(egui::Shape::line(
                vec![v(-4.5, -4.0), v(-3.5, 6.0), v(3.5, 6.0), v(4.5, -4.0)],
                st,
            ));
        }
        Icon::Retry => {
            let pts: Vec<Pos2> = (0..=16)
                .map(|i| {
                    #[allow(clippy::cast_precision_loss, reason = "small count")]
                    let t = -0.4 + 5.0 * (i as f32 / 16.0);
                    v(5.0 * t.cos(), 5.0 * t.sin())
                })
                .collect();
            let end = pts[0];
            p.add(egui::Shape::line(pts, st));
            p.line_segment([end, end + vec2(-3.0, -1.0)], st);
            p.line_segment([end, end + vec2(0.5, -3.2)], st);
        }
        Icon::Copy => {
            p.rect_stroke(
                Rect::from_min_max(v(-2.5, -2.5), v(6.0, 6.0)),
                1.5,
                st,
                StrokeKind::Middle,
            );
            p.add(egui::Shape::line(
                vec![
                    v(-2.5, 3.0),
                    v(-6.0, 3.0),
                    v(-6.0, -6.0),
                    v(3.0, -6.0),
                    v(3.0, -2.5),
                ],
                st,
            ));
        }
        Icon::Check => {
            p.line_segment([v(-5.0, 0.5), v(-1.5, 4.0)], st);
            p.line_segment([v(-1.5, 4.0), v(5.5, -4.0)], st);
        }
        Icon::Add => {
            p.line_segment([v(-5.0, 0.0), v(5.0, 0.0)], st);
            p.line_segment([v(0.0, -5.0), v(0.0, 5.0)], st);
        }
        Icon::More => {
            for x in [-4.5, 0.0, 4.5] {
                p.circle_filled(v(x, 0.0), 1.5, color);
            }
        }
        Icon::File => {
            p.add(egui::Shape::line(
                vec![
                    v(-4.5, -6.0),
                    v(2.0, -6.0),
                    v(4.5, -3.5),
                    v(4.5, 6.0),
                    v(-4.5, 6.0),
                    v(-4.5, -6.0),
                ],
                st,
            ));
            p.line_segment([v(-2.0, 0.0), v(2.0, 0.0)], st);
            p.line_segment([v(-2.0, 3.0), v(2.0, 3.0)], st);
        }
    }
}
