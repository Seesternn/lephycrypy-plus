//! Settings laid out like the system settings on Apple devices: a list of grouped rows with
//! coloured icon tiles; each row opens its own page with switches, choices and short notes
//! under the groups.

use super::{App, Palette, draw_lock, fonts, logic};
use crate::i18n::{Lang, lang, tr};
use eframe::egui::{
    self, Color32, CornerRadius, CursorIcon, Pos2, Rect, Response, RichText, Sense, Stroke,
    StrokeKind, Ui, WidgetInfo, pos2, vec2,
};
use lephy_core::names::escape_display;

/// Which settings page is open.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub(super) enum Pane {
    /// The list.
    #[default]
    Root,
    Language,
    Appearance,
    Lock,
    Vault,
    #[cfg_attr(not(any(target_os = "macos", windows)), allow(dead_code))]
    Integration,
    Maintenance,
    About,
}

/// Row height (one line / with a second line).
const ROW_H: f32 = 44.0;
const ROW_H2: f32 = 58.0;
/// Left edge of the row text (after the icon tile).
const TEXT_X: f32 = 50.0;

/// Tile colours (the same in light and dark mode, as on Apple devices).
mod tile {
    use eframe::egui::Color32;
    pub const BLUE: Color32 = Color32::from_rgb(0x0A, 0x84, 0xFF);
    pub const PURPLE: Color32 = Color32::from_rgb(0xAF, 0x52, 0xDE);
    pub const RED: Color32 = Color32::from_rgb(0xFF, 0x45, 0x3A);
    pub const GREEN: Color32 = Color32::from_rgb(0x30, 0xB0, 0x50);
    pub const ORANGE: Color32 = Color32::from_rgb(0xFF, 0x95, 0x00);
    pub const GRAY: Color32 = Color32::from_rgb(0x8E, 0x8E, 0x93);
    pub const INK: Color32 = Color32::from_rgb(0x24, 0x29, 0x2F);
}

type Glyph = fn(&egui::Painter, Pos2);

fn glyph_globe(p: &egui::Painter, c: Pos2) {
    let st = Stroke::new(1.4, Color32::WHITE);
    p.circle_stroke(c, 7.5, st);
    p.line_segment([c - vec2(7.5, 0.0), c + vec2(7.5, 0.0)], st);
    let pts: Vec<Pos2> = (0..=16)
        .map(|i| {
            #[allow(clippy::cast_precision_loss, reason = "small counts")]
            let a = std::f32::consts::PI * (i as f32 / 16.0);
            c + vec2(3.2 * a.sin(), -7.5 * a.cos())
        })
        .collect();
    p.add(egui::Shape::line(pts.clone(), st));
    p.add(egui::Shape::line(
        pts.iter().map(|q| pos2(2.0 * c.x - q.x, q.y)).collect(),
        st,
    ));
}

fn glyph_appearance(p: &egui::Painter, c: Pos2) {
    p.circle_stroke(c, 7.0, Stroke::new(1.5, Color32::WHITE));
    let half: Vec<Pos2> = (0..=16)
        .map(|i| {
            #[allow(clippy::cast_precision_loss, reason = "small counts")]
            let a = std::f32::consts::FRAC_PI_2 + std::f32::consts::PI * (i as f32 / 16.0);
            c + vec2(a.cos(), a.sin()) * 7.0
        })
        .collect();
    p.add(egui::Shape::convex_polygon(
        half,
        Color32::WHITE,
        Stroke::NONE,
    ));
}

fn glyph_lock(p: &egui::Painter, c: Pos2) {
    draw_lock(p, c, 0.5, Color32::WHITE);
}

fn glyph_menu(p: &egui::Painter, c: Pos2) {
    let st = Stroke::new(1.6, Color32::WHITE);
    for dy in [-4.5, 0.0, 4.5] {
        p.circle_filled(c + vec2(-5.5, dy), 1.3, Color32::WHITE);
        p.line_segment([c + vec2(-2.5, dy), c + vec2(6.5, dy)], st);
    }
}

fn glyph_broom(p: &egui::Painter, c: Pos2) {
    let st = Stroke::new(1.6, Color32::WHITE);
    p.line_segment([c + vec2(4.5, -7.0), c + vec2(-0.5, 1.0)], st);
    let fan = vec![
        c + vec2(-3.5, -0.5),
        c + vec2(2.5, 3.0),
        c + vec2(-0.5, 7.5),
        c + vec2(-7.0, 4.5),
    ];
    p.add(egui::Shape::convex_polygon(
        fan,
        Color32::WHITE,
        Stroke::NONE,
    ));
}

fn glyph_info(p: &egui::Painter, c: Pos2) {
    p.circle_filled(c + vec2(0.0, -5.0), 1.4, Color32::WHITE);
    p.line_segment(
        [c + vec2(0.0, -1.5), c + vec2(0.0, 6.0)],
        Stroke::new(2.2, Color32::WHITE),
    );
}

fn glyph_link(p: &egui::Painter, c: Pos2) {
    let st = Stroke::new(1.5, Color32::WHITE);
    let r = Rect::from_center_size(c + vec2(-1.0, 1.0), vec2(11.0, 11.0));
    p.add(egui::Shape::line(
        vec![
            pos2(r.right(), c.y + 1.0),
            r.right_bottom(),
            r.left_bottom(),
            r.left_top(),
            pos2(c.x - 1.0, r.top()),
        ],
        st,
    ));
    let tip = c + vec2(6.5, -6.5);
    p.line_segment([c + vec2(0.5, -0.5), tip], st);
    p.line_segment([tip, tip + vec2(-4.5, 0.0)], st);
    p.line_segment([tip, tip + vec2(0.0, 4.5)], st);
}

/// A rounded group of rows.
fn group(ui: &mut Ui, pal: Palette, body: impl FnOnce(&mut Ui)) {
    egui::Frame::new()
        .fill(pal.surface)
        .stroke(Stroke::new(1.0, pal.line))
        .corner_radius(CornerRadius::same(12))
        .inner_margin(egui::Margin::same(4))
        .show(ui, |ui| {
            ui.set_width(ui.available_width());
            ui.spacing_mut().item_spacing.y = 0.0;
            body(ui);
        });
}

/// A short note under a group.
fn footer(ui: &mut Ui, pal: Palette, text: &str) {
    ui.add_space(5.0);
    ui.horizontal(|ui| {
        ui.add_space(12.0);
        ui.add(egui::Label::new(RichText::new(text).color(pal.muted).size(12.0)).wrap());
    });
    ui.add_space(16.0);
}

/// Hairline between rows, inset to the text.
fn divider(ui: &mut Ui, pal: Palette, inset: f32) {
    let (r, _) = ui.allocate_exact_size(vec2(ui.available_width(), 1.0), Sense::hover());
    ui.painter().line_segment(
        [
            pos2(r.left() + inset, r.center().y),
            pos2(r.right(), r.center().y),
        ],
        Stroke::new(1.0, pal.line),
    );
}

/// The clickable body of a row: animated hover tint; returns the response and the rect.
fn row_base(ui: &mut Ui, pal: Palette, h: f32, label: &str) -> (Response, Rect) {
    let (rect, resp) = ui.allocate_exact_size(vec2(ui.available_width(), h), Sense::click());
    resp.widget_info(|| WidgetInfo::labeled(egui::Role::Button, true, label));
    let t = crate::motion::toggle(
        ui.ctx(),
        resp.id.with("hover"),
        resp.hovered() || resp.has_focus(),
        crate::motion::HOVER_SECS,
    );
    let pressed = resp.is_pointer_button_down_on();
    if t > 0.0 || pressed {
        let a = if pressed { 1.0 } else { 0.55 * t };
        ui.painter()
            .rect_filled(rect, 8.0, pal.accent_soft.gamma_multiply(a));
    }
    (resp.on_hover_cursor(CursorIcon::PointingHand), rect)
}

fn icon_tile(p: &egui::Painter, rect: Rect, color: Color32, glyph: Glyph) {
    let c = pos2(rect.left() + 24.0, rect.center().y);
    let r = Rect::from_center_size(c, vec2(28.0, 28.0));
    p.rect_filled(r, 7.0, color);
    glyph(p, c);
}

fn chevron(p: &egui::Painter, rect: Rect, pal: Palette) {
    let c = pos2(rect.right() - 14.0, rect.center().y);
    let st = Stroke::new(1.7, pal.muted.gamma_multiply(0.8));
    p.line_segment([c + vec2(-2.5, -5.0), c + vec2(2.5, 0.0)], st);
    p.line_segment([c + vec2(2.5, 0.0), c + vec2(-2.5, 5.0)], st);
}

/// Title (and an optional second line) after the tile; returns the right edge reserved.
fn row_text(p: &egui::Painter, pal: Palette, rect: Rect, x: f32, title: &str, sub: Option<&str>) {
    let (ty, sy) = if sub.is_some() {
        (rect.center().y - 9.0, rect.center().y + 10.0)
    } else {
        (rect.center().y, 0.0)
    };
    p.text(
        pos2(rect.left() + x, ty),
        egui::Align2::LEFT_CENTER,
        title,
        fonts::regular(14.5),
        pal.ink,
    );
    if let Some(s) = sub {
        p.text(
            pos2(rect.left() + x, sy),
            egui::Align2::LEFT_CENTER,
            s,
            fonts::regular(12.0),
            pal.muted,
        );
    }
}

/// Icon, title, value on the right and a chevron: opens a page.
fn nav_row(
    ui: &mut Ui,
    pal: Palette,
    (color, glyph): (Color32, Glyph),
    title: &str,
    value: &str,
) -> bool {
    let (resp, rect) = row_base(ui, pal, ROW_H, title);
    let p = ui.painter();
    icon_tile(p, rect, color, glyph);
    row_text(p, pal, rect, TEXT_X, title, None);
    p.text(
        pos2(rect.right() - 26.0, rect.center().y),
        egui::Align2::RIGHT_CENTER,
        value,
        fonts::regular(14.0),
        pal.muted,
    );
    chevron(p, rect, pal);
    resp.clicked()
}

/// An iOS-style switch, animated; returns its rect for painting inside a row.
fn paint_switch(ui: &Ui, pal: Palette, rect: Rect, id: egui::Id, on: bool) {
    let t = crate::motion::toggle(ui.ctx(), id, on, 0.18);
    let r = Rect::from_center_size(pos2(rect.right() - 32.0, rect.center().y), vec2(42.0, 25.0));
    let p = ui.painter();
    p.rect_filled(r, 12.5, pal.line.lerp_to_gamma(tile::GREEN, t));
    let x = egui::lerp(r.left() + 12.5..=r.right() - 12.5, t);
    let k = pos2(x, r.center().y);
    p.circle_filled(
        k + vec2(0.0, 1.0),
        10.5,
        Color32::BLACK.gamma_multiply(0.12),
    );
    p.circle_filled(k, 10.5, Color32::WHITE);
}

/// Title (and a second line) with a switch on the right; the whole row toggles.
fn switch_row(
    ui: &mut Ui,
    pal: Palette,
    tile_: Option<(Color32, Glyph)>,
    title: &str,
    sub: Option<&str>,
    on: bool,
) -> bool {
    let h = if sub.is_some() { ROW_H2 } else { ROW_H };
    let (resp, rect) = row_base(ui, pal, h, title);
    resp.widget_info(|| WidgetInfo::selected(egui::Role::Switch, true, on, title));
    let x = if let Some((c, g)) = tile_ {
        icon_tile(ui.painter(), rect, c, g);
        TEXT_X
    } else {
        12.0
    };
    row_text(ui.painter(), pal, rect, x, title, sub);
    paint_switch(ui, pal, rect, resp.id.with("switch"), on);
    resp.clicked()
}

/// A choice in a list: title and a check mark when selected.
fn choice_row(ui: &mut Ui, pal: Palette, title: &str, selected: bool) -> bool {
    let (resp, rect) = row_base(ui, pal, ROW_H, title);
    row_text(ui.painter(), pal, rect, 12.0, title, None);
    if selected {
        let c = pos2(rect.right() - 18.0, rect.center().y);
        let st = Stroke::new(2.0, pal.accent);
        ui.painter()
            .line_segment([c + vec2(-6.0, 0.0), c + vec2(-2.0, 4.0)], st);
        ui.painter()
            .line_segment([c + vec2(-2.0, 4.0), c + vec2(6.0, -5.0)], st);
    }
    resp.clicked()
}

/// An action: accent-coloured title (like "Search a folder…").
fn action_row(ui: &mut Ui, pal: Palette, title: &str, enabled: bool) -> bool {
    let (resp, rect) = row_base(ui, pal, ROW_H, title);
    ui.painter().text(
        pos2(rect.left() + 12.0, rect.center().y),
        egui::Align2::LEFT_CENTER,
        title,
        fonts::regular(14.5),
        if enabled { pal.accent } else { pal.muted },
    );
    enabled && resp.clicked()
}

/// A plain label: value row (no action).
fn info_row(ui: &mut Ui, pal: Palette, title: &str, value: &str) {
    let (rect, _) = ui.allocate_exact_size(vec2(ui.available_width(), ROW_H), Sense::hover());
    row_text(ui.painter(), pal, rect, 12.0, title, None);
    ui.painter().text(
        pos2(rect.right() - 12.0, rect.center().y),
        egui::Align2::RIGHT_CENTER,
        value,
        fonts::regular(14.0),
        pal.muted,
    );
}

/// Content inside a group with the row padding.
fn padded(ui: &mut Ui, body: impl FnOnce(&mut Ui)) {
    egui::Frame::new()
        .inner_margin(egui::Margin::symmetric(12, 10))
        .show(ui, |ui| {
            ui.set_width(ui.available_width());
            ui.spacing_mut().item_spacing.y = 6.0;
            body(ui);
        });
}

fn page_head(ui: &mut Ui, pal: Palette, title: &str) {
    ui.label(
        RichText::new(title)
            .font(fonts::semibold(22.0))
            .color(pal.ink),
    );
    ui.add_space(12.0);
}

/// "GitHub repository" row (an external link).
fn repo_row(app: &mut App, ui: &mut Ui, pal: Palette) {
    group(ui, pal, |ui| {
        let (resp, rect) = row_base(ui, pal, ROW_H2, "GitHub");
        let p = ui.painter();
        icon_tile(p, rect, tile::INK, glyph_link);
        row_text(
            p,
            pal,
            rect,
            TEXT_X,
            tr("GitHub deposu", "GitHub repository"),
            Some("github.com/Seesternn/lephycrypy-plus"),
        );
        chevron(p, rect, pal);
        if resp.clicked() {
            app.settings_note = logic::open_repo_page().err().map(|e| e.to_string());
        }
    });
    footer(
        ui,
        pal,
        tr(
            "Kaynak kod, sürüm notları ve güvenlik bildirimleri. Tarayıcınızda açılır.",
            "Source code, release notes and security reports. Opens in your browser.",
        ),
    );
}

impl App {
    /// The settings page (list or one of its pages).
    pub(super) fn settings_view(&mut self, ui: &mut Ui, pal: Palette) {
        if self.settings_pane != Pane::Root {
            if super::link_button(ui, pal, tr("‹ Ayarlar", "‹ Settings")).clicked() {
                self.settings_pane = Pane::Root;
                self.lock_edit = false;
                self.confirm_shell = false;
                return;
            }
            ui.add_space(4.0);
        }
        match self.settings_pane {
            Pane::Root => self.settings_root(ui, pal),
            Pane::Language => self.pane_language(ui, pal),
            Pane::Appearance => self.pane_appearance(ui, pal),
            Pane::Lock => self.pane_lock(ui, pal),
            Pane::Vault => self.pane_vault(ui, pal),
            Pane::Integration => self.pane_integration(ui, pal),
            Pane::Maintenance => self.pane_maintenance(ui, pal),
            Pane::About => self.pane_about(ui, pal),
        }
        if let Some(note) = &self.settings_note {
            ui.add_space(8.0);
            ui.label(RichText::new(note.as_str()).color(pal.muted).size(12.5));
        }
    }

    #[allow(clippy::too_many_lines, reason = "one list laid out top to bottom")]
    fn settings_root(&mut self, ui: &mut Ui, pal: Palette) {
        page_head(ui, pal, tr("Ayarlar", "Settings"));
        // Header card: app icon and version.
        group(ui, pal, |ui| {
            let (rect, _) =
                ui.allocate_exact_size(vec2(ui.available_width(), 64.0), Sense::hover());
            let c = pos2(rect.left() + 34.0, rect.center().y);
            let p = ui.painter();
            p.rect_filled(
                Rect::from_center_size(c, vec2(44.0, 44.0)),
                11.0,
                pal.accent,
            );
            draw_lock(p, c, 0.75, pal.on_accent);
            p.text(
                pos2(rect.left() + 68.0, rect.center().y - 9.0),
                egui::Align2::LEFT_CENTER,
                "lephycrypy+",
                fonts::semibold(16.0),
                pal.ink,
            );
            p.text(
                pos2(rect.left() + 68.0, rect.center().y + 11.0),
                egui::Align2::LEFT_CENTER,
                format!("{} {}", tr("Sürüm", "Version"), env!("CARGO_PKG_VERSION")),
                fonts::regular(12.5),
                pal.muted,
            );
        });
        ui.add_space(16.0);
        let mut go = None;
        group(ui, pal, |ui| {
            let l = match lang() {
                Lang::Tr => "Türkçe",
                Lang::En => "English",
            };
            if nav_row(ui, pal, (tile::BLUE, glyph_globe), tr("Dil", "Language"), l) {
                go = Some(Pane::Language);
            }
            divider(ui, pal, TEXT_X);
            let anim = if self.prefs.anim_off || self.reduce_motion {
                tr("Animasyon kapalı", "No animation")
            } else {
                tr("Animasyonlu", "Animated")
            };
            if nav_row(
                ui,
                pal,
                (tile::PURPLE, glyph_appearance),
                tr("Görünüm", "Appearance"),
                anim,
            ) {
                go = Some(Pane::Appearance);
            }
        });
        ui.add_space(16.0);
        group(ui, pal, |ui| {
            let lock = if self.prefs.lock.is_some() {
                tr("Açık", "On")
            } else {
                tr("Kapalı", "Off")
            };
            if nav_row(
                ui,
                pal,
                (tile::RED, glyph_lock),
                tr("Uygulama kilidi", "App lock"),
                lock,
            ) {
                go = Some(Pane::Lock);
            }
            divider(ui, pal, TEXT_X);
            let m = self.prefs.vault_idle_minutes();
            let v = if m == 0 {
                tr("Elle", "Manual").to_owned()
            } else {
                match lang() {
                    Lang::Tr => format!("{m} dk"),
                    Lang::En => format!("{m} min"),
                }
            };
            if nav_row(ui, pal, (tile::BLUE, glyph_lock), tr("Kasa", "Vault"), &v) {
                go = Some(Pane::Vault);
            }
            #[cfg(any(target_os = "macos", windows))]
            {
                divider(ui, pal, TEXT_X);
                let added = if integration_on() {
                    tr("Ekli", "Added")
                } else {
                    tr("Ekli değil", "Not added")
                };
                let title = if cfg!(windows) {
                    tr("Gezgin entegrasyonu", "Explorer integration")
                } else {
                    tr("Finder Hızlı İşlemi", "Finder Quick Action")
                };
                if nav_row(ui, pal, (tile::GREEN, glyph_menu), title, added) {
                    go = Some(Pane::Integration);
                }
            }
            divider(ui, pal, TEXT_X);
            let n = self.stale.found.len();
            let value = if n == 0 {
                String::new()
            } else {
                match lang() {
                    Lang::Tr => format!("{n} artık"),
                    Lang::En => format!("{n} leftover"),
                }
            };
            if nav_row(
                ui,
                pal,
                (tile::ORANGE, glyph_broom),
                tr("Bakım", "Maintenance"),
                &value,
            ) {
                go = Some(Pane::Maintenance);
            }
        });
        ui.add_space(16.0);
        group(ui, pal, |ui| {
            if nav_row(
                ui,
                pal,
                (tile::GRAY, glyph_info),
                tr("Hakkında", "About"),
                "",
            ) {
                go = Some(Pane::About);
            }
        });
        ui.add_space(16.0);
        repo_row(self, ui, pal);
        if let Some(p) = go {
            self.settings_pane = p;
            self.settings_note = None;
            self.lock_edit = false;
            self.confirm_shell = false;
        }
    }

    fn pane_language(&mut self, ui: &mut Ui, pal: Palette) {
        page_head(ui, pal, tr("Dil", "Language"));
        let mut pick = None;
        group(ui, pal, |ui| {
            // Each language's name is written in that language.
            if choice_row(ui, pal, "Türkçe", lang() == Lang::Tr) {
                pick = Some(Lang::Tr);
            }
            divider(ui, pal, 12.0);
            if choice_row(ui, pal, "English", lang() == Lang::En) {
                pick = Some(Lang::En);
            }
        });
        footer(
            ui,
            pal,
            tr(
                "Uygulamanın dili. Seçiminiz kaydedilir.",
                "The app's language. Your choice is saved.",
            ),
        );
        if let Some(l) = pick.filter(|l| *l != lang()) {
            self.set_language(l);
            self.prefs.lang = Some(l);
            self.save_prefs();
        }
    }

    fn pane_appearance(&mut self, ui: &mut Ui, pal: Palette) {
        page_head(ui, pal, tr("Görünüm", "Appearance"));
        let mut flip = false;
        group(ui, pal, |ui| {
            flip = switch_row(
                ui,
                pal,
                None,
                tr("Animasyonlar", "Animations"),
                None,
                !self.prefs.anim_off,
            );
        });
        footer(
            ui,
            pal,
            if self.reduce_motion {
                tr(
                    "Sistemde \"hareketi azalt\" açık olduğu için animasyonlar gösterilmez.",
                    "Animations are not shown because the system asks to reduce motion.",
                )
            } else {
                tr(
                    "Sayfa geçişleri, kartlar, anahtarlar ve açılır kutular için kısa geçişler.",
                    "Short transitions for pages, cards, switches and folding boxes.",
                )
            },
        );
        if flip {
            self.prefs.anim_off = !self.prefs.anim_off;
            self.save_prefs();
        }
        let mut hist = false;
        group(ui, pal, |ui| {
            hist = switch_row(
                ui,
                pal,
                None,
                tr("Bu oturumdaki işler", "This session's jobs"),
                Some(tr("Ana sayfada göster", "Show on the home screen")),
                !self.prefs.history_off,
            );
        });
        footer(
            ui,
            pal,
            tr(
                "Son işler yalnızca bellekte tutulur ve uygulama kapanınca silinir; diske hiçbir dosya adı yazılmaz.",
                "Recent jobs are kept in memory only and are gone when the app closes; no file name is written to disk.",
            ),
        );
        if hist {
            self.prefs.history_off = !self.prefs.history_off;
            self.save_prefs();
        }
    }

    fn pane_lock(&mut self, ui: &mut Ui, pal: Palette) {
        page_head(ui, pal, tr("Uygulama kilidi", "App lock"));
        let on = self.prefs.lock.is_some();
        let mut flip = false;
        group(ui, pal, |ui| {
            // While a change waits for its password the switch shows where it is going.
            flip = switch_row(
                ui,
                pal,
                Some((tile::RED, glyph_lock)),
                tr("Parola iste", "Ask for a password"),
                Some(tr("Uygulama her açıldığında", "Every time the app starts")),
                on != self.lock_edit,
            );
            if self.lock_edit {
                divider(ui, pal, 12.0);
                padded(ui, |ui| self.lock_settings(ui, pal));
            }
        });
        footer(
            ui,
            pal,
            tr(
                "Yalnızca bu masaüstü uygulamasının kullanılmasını engeller; lephycrypy komut satırı aracı kilitten bağımsızdır. Şifreli dosyalarınız zaten kendi parolaları ve anahtarlarıyla korunur. Kilit ve yanlış deneme sayacı Anahtar Zinciri'nde (Windows'ta Kimlik Bilgisi Yöneticisi'nde) saklanır.",
                "It only keeps others from using this desktop app; the lephycrypy command-line tool does not use the lock. Your encrypted files are protected by their own passwords and keys. The lock and the wrong-try counter are kept in the keychain (Credential Manager on Windows).",
            ),
        );
        if !self.lock_edit
            && let Some(m) = &self.lock_msg
        {
            ui.label(RichText::new(m.as_str()).color(pal.muted).size(12.5));
        }
        if flip {
            self.lock_edit = !self.lock_edit;
            self.lock_msg = None;
            self.lock_pw.clear();
            self.lock_new.clear();
            self.lock_new2.clear();
        }
    }

    fn pane_vault(&mut self, ui: &mut Ui, pal: Palette) {
        page_head(ui, pal, tr("Kasa", "Vault"));
        let cur = self.prefs.vault_idle_minutes();
        let mut pick = None;
        ui.label(
            RichText::new(tr("Hareketsizlikte kilitle", "Lock after no input for"))
                .color(pal.muted)
                .size(12.5),
        );
        ui.add_space(4.0);
        group(ui, pal, |ui| {
            for (i, m) in [0u32, 5, 15, 30, 60].into_iter().enumerate() {
                if i > 0 {
                    divider(ui, pal, 12.0);
                }
                let label = if m == 0 {
                    tr("Hiçbir zaman (yalnızca elle)", "Never (manual only)").to_owned()
                } else {
                    match lang() {
                        Lang::Tr => format!("{m} dakika"),
                        Lang::En => format!("{m} minutes"),
                    }
                };
                if choice_row(ui, pal, &label, cur == m) {
                    pick = Some(m);
                }
            }
        });
        footer(
            ui,
            pal,
            tr(
                "Bilgisayarda bu süre boyunca hiç klavye ya da fare kullanılmazsa açık kasa kendiliğinden kaydedilip kilitlenir.",
                "If the keyboard and mouse are not used for this long, an open vault saves and locks itself.",
            ),
        );
        let mut flip = false;
        group(ui, pal, |ui| {
            flip = switch_row(
                ui,
                pal,
                None,
                tr("Ekran kilitlenince kilitle", "Lock when the screen locks"),
                Some(tr("Uykudan uyanınca da", "Also after waking from sleep")),
                !self.prefs.vault_keep_on_lock,
            );
        });
        footer(
            ui,
            pal,
            tr(
                "Kaydetme başarısız olursa (örneğin bir dosya başka bir programda açıksa) kasa açık kalır ve üstteki şerit uyarır.",
                "If saving fails (for example a file is open in another program) the vault stays open and the bar says so.",
            ),
        );
        if let Some(m) = pick {
            self.prefs.vault_idle = Some(m);
            self.save_prefs();
        }
        if flip {
            self.prefs.vault_keep_on_lock = !self.prefs.vault_keep_on_lock;
            self.save_prefs();
        }
    }

    fn pane_integration(&mut self, ui: &mut Ui, pal: Palette) {
        #[cfg(target_os = "macos")]
        page_head(ui, pal, tr("Finder Hızlı İşlemi", "Finder Quick Action"));
        #[cfg(windows)]
        page_head(ui, pal, tr("Gezgin entegrasyonu", "Explorer integration"));
        #[cfg(any(target_os = "macos", windows))]
        {
            let on = integration_on();
            let mut flip = false;
            group(ui, pal, |ui| {
                flip = switch_row(
                    ui,
                    pal,
                    Some((tile::GREEN, glyph_menu)),
                    tr("Sağ tık menüsünde göster", "Show in the right-click menu"),
                    Some(tr("Yalnızca bu kullanıcı için", "For this user only")),
                    on != self.confirm_shell,
                );
                if self.confirm_shell {
                    divider(ui, pal, 12.0);
                    padded(ui, |ui| {
                        #[cfg(target_os = "macos")]
                        self.quick_action(ui, pal);
                        #[cfg(windows)]
                        self.explorer_integration(ui, pal);
                    });
                }
            });
            footer(
                ui,
                pal,
                if cfg!(windows) {
                    tr(
                        ".lphy dosyaları çift tıklayınca bu uygulamayla açılır; her dosya ve klasörün sağ tık menüsüne \"lephycrypy+ ile şifrele / aç\" eklenir. Hiçbir şey kendiliğinden şifrelenmez.",
                        ".lphy files open with this app on a double-click; every file and folder gets \"Encrypt or open with lephycrypy+\" in its right-click menu. Nothing is encrypted by itself.",
                    )
                } else {
                    tr(
                        "Finder'da bir öğeye sağ tıklayınca Hızlı İşlemler altında \"lephycrypy+ ile şifrele / aç\" görünür. Seçilenleri yalnızca bu uygulamada açar; hiçbir şeyi kendiliğinden şifrelemez.",
                        "Right-clicking an item in Finder shows \"Encrypt or open with lephycrypy+\" under Quick Actions. It only opens the selection in this app; it never encrypts anything by itself.",
                    )
                },
            );
            if flip {
                self.confirm_shell = !self.confirm_shell;
                self.settings_note = None;
            }
        }
        #[cfg(not(any(target_os = "macos", windows)))]
        let _ = (ui, pal);
    }

    fn pane_maintenance(&mut self, ui: &mut Ui, pal: Palette) {
        page_head(ui, pal, tr("Bakım", "Maintenance"));
        let mut search = false;
        group(ui, pal, |ui| {
            let busy = self.stale_busy();
            search = action_row(
                ui,
                pal,
                if busy {
                    tr("Aranıyor…", "Searching…")
                } else {
                    tr(
                        "Bir klasörde yarım kalanları ara…",
                        "Search a folder for leftovers…",
                    )
                },
                !busy,
            );
            if self.stale_poll() {
                divider(ui, pal, 12.0);
                padded(ui, |ui| {
                    self.stale_results(ui, pal);
                });
            }
        });
        footer(
            ui,
            pal,
            tr(
                "Uygulama ya da bilgisayar bir şifre çözme sırasında kapanırsa, hedef klasörde şifresi çözülmüş veri içeren gizli bir .lphy-tmp öğesi kalabilir. Açılışta Masaüstü, İndirilenler, Belgeler ve ev klasörü kendiliğinden taranır.",
                "If the app or the computer stops during a decryption, a hidden .lphy-tmp item with decrypted data can be left in the destination folder. Desktop, Downloads, Documents and the home folder are checked at start.",
            ),
        );
        if search {
            self.stale_pick_folder(ui.ctx());
        }
    }

    fn pane_about(&mut self, ui: &mut Ui, pal: Palette) {
        page_head(ui, pal, tr("Hakkında", "About"));
        group(ui, pal, |ui| {
            info_row(ui, pal, tr("Sürüm", "Version"), env!("CARGO_PKG_VERSION"));
            divider(ui, pal, 12.0);
            info_row(ui, pal, tr("Lisans", "License"), "Apache License 2.0");
        });
        ui.add_space(16.0);
        group(ui, pal, |ui| {
            padded(ui, |ui| {
                ui.label(
                    RichText::new(tr("Gizlilik", "Privacy"))
                        .font(fonts::semibold(14.0))
                        .color(pal.ink),
                );
                for text in [
                    tr(
                        "Dosyalarınız bu bilgisayardan çıkmaz; parolanız hiçbir yere kaydedilmez.",
                        "Your files never leave this computer; your password is never stored.",
                    ),
                    tr(
                        "Kâğıt yedeği kelimeleri, üretilen parola ya da kilit ekranı açıkken pencere ekran görüntüsünden ve ekran paylaşımından gizlenir.",
                        "While paper-backup words, a generated password or the lock screen are shown, the window is hidden from screenshots and screen sharing.",
                    ),
                    tr(
                        "Kaydedilenler yalnızca dil, animasyon tercihi, karşılama ekranının görüldüğü ve (açıksa) kilit doğrulayıcısıdır; dosya adı ya da parola kaydedilmez.",
                        "Only the language, the animation choice, whether the welcome screen was seen and (if on) the lock verifier are saved; no file names or passwords.",
                    ),
                ] {
                    ui.add(
                        egui::Label::new(RichText::new(text).color(pal.muted).size(12.5)).wrap(),
                    );
                }
            });
        });
        if let Some(dir) = lephy_sys::fs::app_settings_dir() {
            footer(ui, pal, &escape_display(&dir.display().to_string()));
        } else {
            ui.add_space(16.0);
        }
        repo_row(self, ui, pal);
        let _ = StrokeKind::Inside;
    }
}

/// The system integration is installed (Quick Action / Explorer entries).
#[cfg(any(target_os = "macos", windows))]
fn integration_on() -> bool {
    #[cfg(target_os = "macos")]
    {
        lephy_sys::quick_action::services_dir()
            .is_ok_and(|d| lephy_sys::quick_action::is_installed(&d))
    }
    #[cfg(windows)]
    {
        lephy_sys::shell::is_registered(lephy_sys::shell::CLASSES)
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn panes_are_distinct() {
        use super::Pane;
        assert_ne!(Pane::Root, Pane::About);
        assert_eq!(Pane::default(), Pane::Root);
    }
}
