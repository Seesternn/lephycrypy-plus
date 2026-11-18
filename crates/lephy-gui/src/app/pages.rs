//! Start-screen pages: welcome (first launch), home with action cards, keys, settings, the
//! optional app lock and the quit confirmation.

use super::{
    App, Palette, draw_doc, draw_folder, draw_gear, draw_key, draw_lock, fonts, help, link_button,
    logic, primary_button, reveal_on_hover, secondary_button, segmented, theme,
};
use crate::i18n::{Lang, lang, tr};
use crate::settings::LockVerifier;
use eframe::egui::{
    self, Align, CornerRadius, CursorIcon, Layout, Response, RichText, Sense, Stroke, StrokeKind,
    Ui, WidgetInfo, vec2,
};
use lephy_core::names::escape_display;
use lephy_core::password::MIN_SCALARS;
use lephy_sys::mem::SecretBytes;
use std::path::PathBuf;

/// Start-screen page (while no file is chosen).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum Page {
    /// First launch: what the app does, language, "Start".
    Welcome,
    /// Action cards and the drop area.
    Home,
    /// Encrypt: choose files or a folder.
    Encrypt,
    /// Decrypt: choose an encrypted file.
    Decrypt,
    /// Help: every help topic, unfolded.
    Help,
    /// Key pairs: create one, show the keys of an identity, paper backup.
    Keys,
    /// Language, app lock, system integration, about.
    Settings,
}

/// A line icon painted at a centre point.
type Icon = fn(&egui::Painter, egui::Pos2, egui::Color32);

/// An identity opened on the keys page.
pub(super) struct LoadedId {
    name: String,
    public: String,
    signer: String,
    pq: String,
    paper: SecretBytes,
}

/// A rounded section with a title and a short description.
fn section(ui: &mut Ui, pal: Palette, title: &str, desc: &str, body: impl FnOnce(&mut Ui)) {
    egui::Frame::new()
        .fill(pal.surface)
        .stroke(Stroke::new(1.0, pal.line))
        .corner_radius(CornerRadius::same(theme::R_CARD))
        .inner_margin(egui::Margin::same(16))
        .show(ui, |ui| {
            ui.set_width(ui.available_width());
            ui.label(
                RichText::new(title)
                    .font(fonts::semibold(15.0))
                    .color(pal.ink),
            );
            if !desc.is_empty() {
                ui.label(RichText::new(desc).color(pal.muted).size(12.5));
            }
            ui.add_space(10.0);
            body(ui);
        });
    ui.add_space(12.0);
}

/// A large clickable card with an icon, a title and a subtitle.
fn action_card(
    ui: &mut Ui,
    pal: Palette,
    size: egui::Vec2,
    icon: Icon,
    title: &str,
    subtitle: &str,
) -> Response {
    let (rect, resp) = ui.allocate_exact_size(size, Sense::click());
    resp.widget_info(|| WidgetInfo::labeled(egui::Role::Button, true, title));
    let hovered = resp.hovered() || resp.has_focus();
    ui.painter().rect(
        rect,
        f32::from(theme::R_CARD),
        if hovered {
            pal.accent_soft
        } else {
            pal.surface
        },
        Stroke::new(1.0, if hovered { pal.accent } else { pal.line }),
        StrokeKind::Inside,
    );
    let icon_c = rect.left_top() + vec2(30.0, 32.0);
    ui.painter()
        .circle_filled(icon_c, 18.0, pal.accent_soft.gamma_multiply(1.4));
    icon(ui.painter(), icon_c, pal.accent);
    ui.painter().text(
        rect.left_top() + vec2(16.0, 62.0),
        egui::Align2::LEFT_TOP,
        title,
        fonts::semibold(15.5),
        pal.ink,
    );
    let galley = ui.painter().layout(
        subtitle.to_owned(),
        fonts::regular(12.5),
        pal.muted,
        rect.width() - 32.0,
    );
    ui.painter()
        .galley(rect.left_top() + vec2(16.0, 84.0), galley, pal.muted);
    resp.on_hover_cursor(CursorIcon::PointingHand)
}

/// The small lock drawn smaller for the cards.
fn icon_lock(p: &egui::Painter, c: egui::Pos2, color: egui::Color32) {
    draw_lock(p, c, 0.55, color);
}

/// Copyable key row: label, the key (shortened) and a Copy link.
fn key_row(ui: &mut Ui, pal: Palette, label: &str, key: &str) -> Option<bool> {
    ui.label(RichText::new(label).color(pal.muted).size(12.5));
    let mut copied = None;
    ui.horizontal(|ui| {
        let w = (ui.available_width() - 70.0).max(60.0);
        ui.allocate_ui_with_layout(vec2(w, 20.0), Layout::left_to_right(Align::Center), |ui| {
            ui.add(
                egui::Label::new(RichText::new(key).monospace().size(12.0).color(pal.ink))
                    .truncate(),
            );
        });
        if link_button(ui, pal, tr("Kopyala", "Copy")).clicked() {
            copied = Some(logic::copy_to_clipboard(key).is_ok());
        }
    });
    ui.add_space(4.0);
    copied
}

/// Step 2: how it works, as a small picture (file → lock → random-named `.lphy`) and three points.
fn welcome_how(ui: &mut Ui, pal: Palette) {
    welcome_heading(
        ui,
        pal,
        tr("Nasıl çalışır?", "How it works"),
        tr(
            "Bir dosya ya da klasör seçin, parola verin; gerisini uygulama yapar.",
            "Choose a file or folder, give a password; the app does the rest.",
        ),
    );
    ui.add_space(18.0);
    let (rect, _) = ui.allocate_exact_size(vec2(ui.available_width(), 104.0), Sense::hover());
    let p = ui.painter();
    let box_w = 92.0;
    let gap = (rect.width() - 3.0 * box_w) / 2.0;
    let tiles: [(&str, Icon); 3] = [
        ("foto.png", draw_doc),
        (tr("parola", "password"), icon_lock),
        ("7f3a9c2e.lphy", draw_doc),
    ];
    let mut centers = Vec::new();
    for (i, (label, icon)) in tiles.iter().enumerate() {
        #[allow(clippy::cast_precision_loss, reason = "i < 3")]
        let x = rect.left() + i as f32 * (box_w + gap);
        let r = egui::Rect::from_min_size(egui::pos2(x, rect.top()), vec2(box_w, 74.0));
        let accent = i == 2;
        p.rect(
            r,
            f32::from(theme::R_CARD),
            if accent { pal.accent_soft } else { pal.surface },
            Stroke::new(1.0, if accent { pal.accent } else { pal.line }),
            StrokeKind::Inside,
        );
        icon(p, r.center(), pal.accent);
        p.text(
            egui::pos2(r.center().x, r.bottom() + 14.0),
            egui::Align2::CENTER_CENTER,
            *label,
            fonts::regular(12.0),
            pal.muted,
        );
        centers.push(r);
    }
    for w in centers.windows(2) {
        let a = egui::pos2(w[0].right() + 8.0, w[0].center().y);
        let b = egui::pos2(w[1].left() - 8.0, w[1].center().y);
        let st = Stroke::new(1.6, pal.muted);
        p.line_segment([a, b], st);
        p.line_segment([b, b + vec2(-6.0, -5.0)], st);
        p.line_segment([b, b + vec2(-6.0, 5.0)], st);
    }
    ui.add_space(18.0);
    tick_row(
        ui,
        pal,
        tr("Adlar da gizlenir", "Names are hidden too"),
        tr(
            "Şifreli dosyanın adı rastgeledir; içindeki adlar ve klasör yapısı görünmez.",
            "The encrypted file gets a random name; the names and folders inside stay hidden.",
        ),
    );
    tick_row(
        ui,
        pal,
        tr("Olduğu gibi geri gelir", "Comes back as it was"),
        tr(
            "Çözünce foto.png yine foto.png, klasör yine klasör olur.",
            "Decrypted, photo.png is photo.png again and a folder is a folder.",
        ),
    );
    tick_row(
        ui,
        pal,
        tr("Paylaşmak için açık anahtar", "Public keys for sharing"),
        tr(
            "Ortak parola gerekmez; isterseniz imza ve kuantuma dayanıklı anahtar.",
            "No shared password needed; signatures and post-quantum keys if you want them.",
        ),
    );
}

/// Step 3: what stays private, where things are.
fn welcome_safe(ui: &mut Ui, pal: Palette) {
    welcome_heading(
        ui,
        pal,
        tr("Her şey sizde kalır", "Everything stays with you"),
        tr(
            "Hesap yok, bulut yok, izleme yok.",
            "No account, no cloud, no tracking.",
        ),
    );
    ui.add_space(16.0);
    let rows: [(Icon, &str, &str); 3] = [
        (
            icon_lock,
            tr("Bu bilgisayarda kalır", "Stays on this computer"),
            tr(
                "Dosyalarınız hiçbir yere gönderilmez; parolanız kaydedilmez.",
                "Your files are never sent anywhere; your password is never stored.",
            ),
        ),
        (
            draw_key,
            tr("Anahtarlarınız sizin", "Your keys are yours"),
            tr(
                "Anahtar çiftinizi oluşturup kâğıda yedekleyebilirsiniz.",
                "Create your key pair and back it up on paper.",
            ),
        ),
        (
            draw_gear,
            tr("İsterseniz uygulama kilidi", "An app lock, if you want one"),
            tr(
                "Ayarlar'dan açılır; kapalıyken parola sorulmaz.",
                "Turn it on in Settings; while off, nothing is asked.",
            ),
        ),
    ];
    for (icon, title, text) in rows {
        egui::Frame::new()
            .fill(pal.surface)
            .stroke(Stroke::new(1.0, pal.line))
            .corner_radius(CornerRadius::same(theme::R_CARD))
            .inner_margin(egui::Margin::symmetric(14, 12))
            .show(ui, |ui| {
                ui.set_width(ui.available_width());
                ui.horizontal(|ui| {
                    let (g, _) = ui.allocate_exact_size(vec2(40.0, 40.0), Sense::hover());
                    ui.painter()
                        .circle_filled(g.center(), 19.0, pal.accent_soft);
                    icon(ui.painter(), g.center(), pal.accent);
                    ui.add_space(6.0);
                    ui.vertical(|ui| {
                        ui.label(
                            RichText::new(title)
                                .font(fonts::semibold(14.0))
                                .color(pal.ink),
                        );
                        ui.add(
                            egui::Label::new(RichText::new(text).color(pal.muted).size(12.5))
                                .wrap(),
                        );
                    });
                });
            });
        ui.add_space(8.0);
    }
}

fn welcome_heading(ui: &mut Ui, pal: Palette, title: &str, sub: &str) {
    ui.label(
        RichText::new(title)
            .font(fonts::semibold(22.0))
            .color(pal.ink),
    );
    ui.add_space(2.0);
    ui.label(RichText::new(sub).color(pal.muted).size(14.0));
}

/// Progress dots under the welcome steps.
fn step_dots(ui: &mut Ui, pal: Palette, step: u8, steps: u8) {
    let (rect, _) = ui.allocate_exact_size(vec2(ui.available_width(), 10.0), Sense::hover());
    let w_on = 22.0;
    let d = 8.0;
    let gap = 6.0;
    let total = w_on + f32::from(steps - 1) * d + f32::from(steps - 1) * gap;
    let mut x = rect.center().x - total / 2.0;
    for i in 0..steps {
        let w = if i == step { w_on } else { d };
        let r = egui::Rect::from_min_size(egui::pos2(x, rect.top() + 1.0), vec2(w, d));
        ui.painter()
            .rect_filled(r, d / 2.0, if i == step { pal.accent } else { pal.line });
        x += w + gap;
    }
}

/// A row with a ticked circle, a bold title and a line of text.
fn tick_row(ui: &mut Ui, pal: Palette, title: &str, text: &str) {
    ui.horizontal(|ui| {
        let (g, _) = ui.allocate_exact_size(vec2(28.0, 34.0), Sense::hover());
        let c = g.center_top() + vec2(0.0, 10.0);
        ui.painter().circle_filled(c, 9.0, pal.accent_soft);
        let tick = Stroke::new(1.8, pal.accent);
        ui.painter()
            .line_segment([c + vec2(-4.0, 0.0), c + vec2(-1.0, 3.0)], tick);
        ui.painter()
            .line_segment([c + vec2(-1.0, 3.0), c + vec2(4.5, -3.5)], tick);
        ui.vertical(|ui| {
            ui.label(
                RichText::new(title)
                    .font(fonts::semibold(14.0))
                    .color(pal.ink),
            );
            ui.add(egui::Label::new(RichText::new(text).color(pal.muted).size(12.5)).wrap());
        });
    });
    ui.add_space(8.0);
}

/// Page title with a short line under it.
fn page_title(ui: &mut Ui, pal: Palette, title: &str, sub: &str) {
    ui.label(
        RichText::new(title)
            .font(fonts::semibold(20.0))
            .color(pal.ink),
    );
    ui.label(RichText::new(sub).color(pal.muted).size(13.0));
    ui.add_space(14.0);
}

impl App {
    /// The app with saved settings applied (language, welcome, lock).
    pub(super) fn with_prefs(prefs: crate::settings::Settings) -> Self {
        let mut app = Self::default();
        if let Some(l) = prefs.lang {
            crate::i18n::set_lang(l);
        }
        app.page = if prefs.welcome_done {
            Page::Home
        } else {
            Page::Welcome
        };
        app.locked = prefs.lock.is_some();
        app.prefs = prefs;
        app
    }

    fn save_prefs(&mut self) {
        if let Err(e) = self.prefs.save() {
            self.settings_note = Some(match lang() {
                Lang::Tr => format!("Ayarlar kaydedilemedi: {e}"),
                Lang::En => format!("Could not save the settings: {e}"),
            });
        }
    }

    pub(super) fn go_home(&mut self) {
        self.page = Page::Home;
        self.welcome_step = 0;
        self.confirm_shell = false;
        self.settings_note = None;
        self.lock_edit = false;
        self.lock_new.clear();
        self.lock_new2.clear();
        self.lock_pw.clear();
        self.lock_msg = None;
        self.show_keygen = false;
        self.password.clear();
        self.confirm.clear();
    }

    // -----------------------------------------------------------------------------------------
    // Welcome

    pub(super) fn welcome_view(&mut self, ui: &mut Ui, pal: Palette) {
        const STEPS: u8 = 3;
        let step = self.welcome_step.min(STEPS - 1);
        // Top line: step counter and "Skip".
        ui.horizontal(|ui| {
            ui.label(
                RichText::new(match lang() {
                    Lang::Tr => format!("Adım {} / {STEPS}", step + 1),
                    Lang::En => format!("Step {} of {STEPS}", step + 1),
                })
                .color(pal.muted)
                .size(12.5),
            );
            if step + 1 < STEPS {
                ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                    if link_button(ui, pal, tr("Atla", "Skip")).clicked() {
                        self.welcome_step = STEPS - 1;
                    }
                });
            }
        });
        ui.add_space(10.0);
        match step {
            0 => self.welcome_hello(ui, pal),
            1 => welcome_how(ui, pal),
            _ => welcome_safe(ui, pal),
        }
        ui.add_space(22.0);
        step_dots(ui, pal, step, STEPS);
        ui.add_space(14.0);
        let last = step + 1 == STEPS;
        ui.horizontal(|ui| {
            let gap = 10.0;
            let full = ui.available_width();
            let back_w = if step > 0 { 110.0 } else { 0.0 };
            if step > 0 && secondary_button(ui, pal, tr("‹ Geri", "‹ Back"), back_w, 42.0).clicked()
            {
                self.welcome_step = step - 1;
            }
            let w = if step > 0 { full - back_w - gap } else { full };
            ui.allocate_ui_with_layout(vec2(w, 42.0), Layout::top_down(Align::Min), |ui| {
                let label = match step {
                    0 => tr("Başlayalım", "Let's begin"),
                    _ if last => tr("Uygulamaya geç", "Open the app"),
                    _ => tr("İleri", "Next"),
                };
                if primary_button(ui, pal, label, true).clicked() {
                    if last {
                        self.prefs.welcome_done = true;
                        self.save_prefs();
                        self.page = Page::Home;
                    } else {
                        self.welcome_step = step + 1;
                    }
                }
            });
        });
    }

    /// Step 1: emblem, name, one line about the app, language.
    fn welcome_hello(&mut self, ui: &mut Ui, pal: Palette) {
        ui.with_layout(Layout::top_down(Align::Center), |ui| {
            ui.add_space(6.0);
            let (g, _) = ui.allocate_exact_size(vec2(150.0, 150.0), Sense::hover());
            let c = g.center();
            let p = ui.painter();
            p.circle_filled(c, 72.0, pal.accent_soft.gamma_multiply(0.45));
            p.circle_stroke(c, 72.0, Stroke::new(1.0, pal.accent.gamma_multiply(0.18)));
            p.circle_filled(c, 54.0, pal.accent_soft);
            p.circle_filled(c, 38.0, pal.accent);
            draw_lock(p, c, 1.15, pal.on_accent);
            // Small orbiting dots: files on their way in.
            for (a, r) in [(-2.4_f32, 3.5_f32), (-0.5, 2.5), (1.1, 3.0), (2.5, 2.0)] {
                p.circle_filled(c + vec2(a.cos(), a.sin()) * 63.0, r, pal.accent);
            }
            ui.add_space(16.0);
            ui.label(
                RichText::new(tr("lephycrypy+'a hoş geldiniz", "Welcome to lephycrypy+"))
                    .font(fonts::semibold(26.0))
                    .color(pal.ink),
            );
            ui.add_space(4.0);
            ui.label(
                RichText::new(tr(
                    "Dosyalarınız ve klasörleriniz için sade, güçlü şifreleme.",
                    "Simple, strong encryption for your files and folders.",
                ))
                .color(pal.muted)
                .size(15.0),
            );
        });
        ui.add_space(26.0);
        ui.label(
            RichText::new(tr("Dil", "Language"))
                .color(pal.muted)
                .size(12.5),
        );
        ui.add_space(4.0);
        self.language_choice(ui);
    }

    fn language_choice(&mut self, ui: &mut Ui) {
        let pal = theme::palette(ui.ctx());
        let mut l = lang();
        // Each language's name is written in that language.
        segmented(
            ui,
            pal,
            &mut l,
            &[(Lang::Tr, "Türkçe", true), (Lang::En, "English", true)],
        );
        if l != lang() {
            self.set_language(l);
            self.prefs.lang = Some(l);
            self.save_prefs();
        }
    }

    // -----------------------------------------------------------------------------------------
    // Home

    #[allow(clippy::too_many_lines, reason = "one page laid out top to bottom")]
    pub(super) fn home_view(&mut self, ui: &mut Ui, pal: Palette) {
        self.stale_banner(ui, pal);
        ui.label(
            RichText::new(tr("Ne yapmak istersiniz?", "What would you like to do?"))
                .font(fonts::semibold(20.0))
                .color(pal.ink),
        );
        ui.add_space(12.0);
        let gap = 12.0;
        let cw = (ui.available_width() - gap) / 2.0;
        let size = vec2(cw, 134.0);
        let mut clicked = [false; 4];
        ui.horizontal(|ui| {
            ui.spacing_mut().item_spacing.x = gap;
            clicked[0] = action_card(
                ui,
                pal,
                size,
                icon_lock,
                tr("Şifrele", "Encrypt"),
                tr(
                    "Dosya ya da klasörü parola veya açık anahtarla koruyun.",
                    "Protect a file or folder with a password or public keys.",
                ),
            )
            .clicked();
            clicked[1] = action_card(
                ui,
                pal,
                size,
                draw_doc,
                tr("Şifreyi çöz", "Decrypt"),
                tr(
                    "Bir .lphy dosyasını açın, içeriğine bakın ya da geri çıkarın.",
                    "Open a .lphy file, look inside or extract it.",
                ),
            )
            .clicked();
        });
        ui.add_space(gap);
        ui.horizontal(|ui| {
            ui.spacing_mut().item_spacing.x = gap;
            clicked[2] = action_card(
                ui,
                pal,
                size,
                draw_key,
                tr("Anahtarlarım", "My keys"),
                tr(
                    "Anahtar çifti oluşturun, açık anahtarınızı paylaşın, yedek alın.",
                    "Create a key pair, share your public key, keep a backup.",
                ),
            )
            .clicked();
            clicked[3] = action_card(
                ui,
                pal,
                size,
                draw_gear,
                tr("Ayarlar", "Settings"),
                tr(
                    "Dil, uygulama kilidi ve sistem entegrasyonu.",
                    "Language, app lock and system integration.",
                ),
            )
            .clicked();
        });
        if clicked[0] {
            self.page = Page::Encrypt;
        }
        if clicked[1] {
            self.page = Page::Decrypt;
        }
        if clicked[2] {
            self.page = Page::Keys;
        }
        if clicked[3] {
            self.page = Page::Settings;
        }
        ui.add_space(4.0);
        ui.horizontal(|ui| {
            if link_button(
                ui,
                pal,
                tr(
                    "? Yardım: parola, anahtarlar, kimlik dosyası",
                    "? Help: passwords, keys, identity files",
                ),
            )
            .clicked()
            {
                self.page = Page::Help;
            }
        });
        ui.add_space(14.0);
        Self::drop_area(
            ui,
            pal,
            tr(
                "…ya da dosya ve klasörleri buraya bırakın",
                "…or drop files and folders here",
            ),
            tr(
                "Şifreli .lphy dosyaları açılır, diğer her şey şifrelenir.",
                "Encrypted .lphy files are opened; everything else is encrypted.",
            ),
        );
        ui.add_space(12.0);
        ui.label(
            RichText::new(tr(
                "Dosyalarınız bu bilgisayardan çıkmaz; parolanız hiçbir yere kaydedilmez.",
                "Your files never leave this computer; your password is never stored.",
            ))
            .color(pal.muted)
            .size(12.5),
        );
    }

    /// Dashed area that also accepts dropped files (the whole window does).
    fn drop_area(ui: &mut Ui, pal: Palette, title: &str, sub: &str) {
        let hovering = ui.input(|i| !i.raw.hovered_files.is_empty());
        let (rect, _) = ui.allocate_exact_size(vec2(ui.available_width(), 92.0), Sense::hover());
        let (fill, stroke) = if hovering {
            (pal.accent_soft, Stroke::new(1.5, pal.accent))
        } else {
            (pal.bg, Stroke::new(1.0, pal.line))
        };
        ui.painter().rect(
            rect,
            f32::from(theme::R_ZONE),
            fill,
            stroke,
            StrokeKind::Inside,
        );
        ui.painter().text(
            rect.center() - vec2(0.0, 10.0),
            egui::Align2::CENTER_CENTER,
            title,
            fonts::semibold(14.0),
            pal.ink,
        );
        ui.painter().text(
            rect.center() + vec2(0.0, 12.0),
            egui::Align2::CENTER_CENTER,
            sub,
            fonts::regular(12.5),
            pal.muted,
        );
    }

    // -----------------------------------------------------------------------------------------
    // Encrypt / Decrypt start pages

    pub(super) fn encrypt_view(&mut self, ui: &mut Ui, pal: Palette) {
        page_title(
            ui,
            pal,
            tr("Şifrele", "Encrypt"),
            tr(
                "Neyi korumak istediğinizi seçin; sonra parola ya da açık anahtar verirsiniz.",
                "Choose what to protect; next you give a password or public keys.",
            ),
        );
        let gap = 12.0;
        let size = vec2((ui.available_width() - gap) / 2.0, 134.0);
        let (mut files, mut folder) = (false, false);
        ui.horizontal(|ui| {
            ui.spacing_mut().item_spacing.x = gap;
            files = action_card(
                ui,
                pal,
                size,
                draw_doc,
                tr("Dosya seç…", "Choose files…"),
                tr(
                    "Bir ya da birden çok dosya; her biri ayrı şifreli dosya olur.",
                    "One or more files; each becomes its own encrypted file.",
                ),
            )
            .clicked();
            folder = action_card(
                ui,
                pal,
                size,
                draw_folder,
                tr("Klasör seç…", "Choose a folder…"),
                tr(
                    "Klasörün tamamı tek bir şifreli dosya olur.",
                    "The whole folder becomes one encrypted file.",
                ),
            )
            .clicked();
        });
        if files {
            self.pick_file();
        }
        if folder {
            self.pick_folder();
        }
        ui.add_space(14.0);
        Self::drop_area(
            ui,
            pal,
            tr(
                "…ya da şifrelenecekleri buraya bırakın",
                "…or drop what to encrypt here",
            ),
            tr(
                "Dosyalar ve klasörler; şifreli .lphy bırakırsanız çözme ekranı açılır.",
                "Files and folders; dropping an encrypted .lphy opens it for decryption.",
            ),
        );
        ui.add_space(16.0);
        tick_row(
            ui,
            pal,
            tr(
                "Parolayla ya da açık anahtarla",
                "With a password or public keys",
            ),
            tr(
                "Kendiniz için parola; başkasına göndermek için onun açık anahtarı.",
                "A password for yourself; someone's public key to send it to them.",
            ),
        );
        tick_row(
            ui,
            pal,
            tr("Ad ve içerik gizli", "Name and content hidden"),
            tr(
                "Şifreli dosyanın adı rastgeledir; özgün ad içeride saklanır.",
                "The encrypted file gets a random name; the original is kept inside.",
            ),
        );
    }

    pub(super) fn decrypt_view(&mut self, ui: &mut Ui, pal: Palette) {
        page_title(
            ui,
            pal,
            tr("Şifreyi çöz", "Decrypt"),
            tr(
                "Bir .lphy dosyası seçin; parolası ya da anahtarı sorulur.",
                "Choose a .lphy file; you are asked for its password or key.",
            ),
        );
        let size = vec2(ui.available_width(), 120.0);
        if action_card(
            ui,
            pal,
            size,
            icon_lock,
            tr("Şifreli dosyayı seç…", "Choose the encrypted file…"),
            tr(
                ".lphy dosyası ya da parçalı bir dosyanın .001 parçası.",
                "A .lphy file, or the .001 part of a split file.",
            ),
        )
        .clicked()
            && let Some(p) = rfd::FileDialog::new()
                .set_title(tr("Şifreli dosyayı seçin", "Choose the encrypted file"))
                .add_filter("lephycrypy", &["lphy", "001"])
                .pick_file()
        {
            self.set_sources(&[p]);
        }
        ui.add_space(14.0);
        Self::drop_area(
            ui,
            pal,
            tr(
                "…ya da şifreli dosyaları buraya bırakın",
                "…or drop encrypted files here",
            ),
            tr(
                "Birden çok .lphy birlikte çözülebilir.",
                "Several .lphy files can be decrypted together.",
            ),
        );
        ui.add_space(16.0);
        tick_row(
            ui,
            pal,
            tr("Özgün adıyla geri gelir", "Comes back under its own name"),
            tr(
                "foto.png yine foto.png olur; aynı adda dosya varsa üzerine yazılmaz.",
                "photo.png comes back as photo.png; an existing file is never overwritten.",
            ),
        );
        tick_row(
            ui,
            pal,
            tr("Önce içine bakın", "Look inside first"),
            tr(
                "Klasörlerin içeriğini listeleyip yalnızca seçtiklerinizi çıkarabilirsiniz.",
                "List a folder's contents and extract only what you pick.",
            ),
        );
        tick_row(
            ui,
            pal,
            tr("Bozulmaya karşı denetim", "Checked against tampering"),
            tr(
                "Değiştirilmiş ya da bozulmuş bir dosya sessizce açılmaz.",
                "A changed or damaged file is never opened silently.",
            ),
        );
    }

    // -----------------------------------------------------------------------------------------
    // Help

    pub(super) fn help_view(&mut self, ui: &mut Ui, pal: Palette) {
        page_title(
            ui,
            pal,
            tr("Yardım", "Help"),
            tr(
                "Sık sorulanlar; her biri ilgili ekranda da \"?\" kutusu olarak bulunur.",
                "Common questions; each also appears as a \"?\" box on the screen it is about.",
            ),
        );
        for topic in help::Topic::ALL {
            section(ui, pal, topic.title(), "", |ui| {
                help::body_ui(ui, pal, topic);
            });
        }
        let w = (ui.available_width() - 10.0) / 2.0;
        ui.horizontal(|ui| {
            if secondary_button(ui, pal, tr("Anahtarlarım'a git", "Go to My keys"), w, 36.0)
                .clicked()
            {
                self.page = Page::Keys;
            }
            if secondary_button(
                ui,
                pal,
                tr("Şifrelemeye başla", "Start encrypting"),
                w,
                36.0,
            )
            .clicked()
            {
                self.page = Page::Encrypt;
            }
        });
    }

    // -----------------------------------------------------------------------------------------
    // Keys

    #[allow(clippy::too_many_lines, reason = "one page laid out top to bottom")]
    pub(super) fn keys_view(&mut self, ui: &mut Ui, pal: Palette) {
        self.poll_identity();
        ui.label(
            RichText::new(tr("Anahtarlarım", "My keys"))
                .font(fonts::semibold(20.0))
                .color(pal.ink),
        );
        ui.add_space(12.0);
        help::help_box(ui, pal, help::Topic::Identity);
        help::help_box(ui, pal, help::Topic::Backup);
        ui.add_space(4.0);
        let mut copied = None;
        section(
            ui,
            pal,
            tr("Yeni anahtar çifti", "New key pair"),
            tr(
                "Başkaları size dosyayı açık anahtarınıza şifreler; yalnızca kimlik dosyanızla açılır. Kimlik dosyası parolayla korunur.",
                "Others encrypt files to your public key; only your identity file opens them. The identity file is protected by a password.",
            ),
            |ui| {
                if self.show_keygen {
                    self.keygen_card(ui, pal);
                    if link_button(ui, pal, tr("Vazgeç", "Cancel")).clicked() {
                        self.show_keygen = false;
                        self.password.clear();
                        self.confirm.clear();
                    }
                } else if secondary_button(
                    ui,
                    pal,
                    tr("Anahtar çifti oluştur…", "Create a key pair…"),
                    ui.available_width(),
                    34.0,
                )
                .clicked()
                {
                    self.show_keygen = true;
                }
                if let Some(pk) = self.created_pub.clone() {
                    ui.add_space(8.0);
                    copied = copied.or(key_row(
                        ui,
                        pal,
                        tr(
                            "Açık anahtarınız (paylaşabilirsiniz):",
                            "Your public key (safe to share):",
                        ),
                        &pk,
                    ));
                    ui.label(
                        RichText::new(tr(
                            "İmza ve kuantuma dayanıklı anahtarlarınız .pub dosyasında.",
                            "Your signer and post-quantum keys are in the .pub file.",
                        ))
                        .color(pal.muted)
                        .size(12.0),
                    );
                }
                self.paper_card(ui, pal);
            },
        );
        section(
            ui,
            pal,
            tr("Kimliğimi aç", "Open my identity"),
            tr(
                "Bir kimlik dosyasının (.lphykey) açık anahtarlarını gösterir ve kâğıt yedeğini almanızı sağlar.",
                "Shows the public keys of an identity file (.lphykey) and lets you take its paper backup.",
            ),
            |ui| {
                if let Some(id) = &self.id_loaded {
                    ui.label(
                        RichText::new(&id.name)
                            .font(fonts::semibold(13.5))
                            .color(pal.ink),
                    );
                    ui.add_space(4.0);
                    let (public, signer, pq) =
                        (id.public.clone(), id.signer.clone(), id.pq.clone());
                    copied = copied.or(key_row(ui, pal, tr("Açık anahtar", "Public key"), &public));
                    copied =
                        copied.or(key_row(ui, pal, tr("İmza anahtarı", "Signer key"), &signer));
                    copied = copied.or(key_row(
                        ui,
                        pal,
                        tr("Kuantuma dayanıklı anahtar", "Post-quantum key"),
                        &pq,
                    ));
                    ui.add_space(6.0);
                    if self.id_show_paper {
                        egui::Frame::new()
                            .fill(pal.accent_soft)
                            .corner_radius(CornerRadius::same(theme::R_INPUT))
                            .inner_margin(egui::Margin::same(12))
                            .show(ui, |ui| {
                                ui.set_width(ui.available_width());
                                ui.label(
                                    RichText::new(tr(
                                        "Kâğıt yedeği (22 kelime)",
                                        "Paper backup (22 words)",
                                    ))
                                    .font(fonts::semibold(13.5))
                                    .color(pal.ink),
                                );
                                reveal_on_hover(ui, pal, id.paper.expose());
                                ui.label(
                                    RichText::new(tr(
                                        "Kelimelere sahip olan herkes bu anahtara şifrelenen her dosyayı açabilir. Kâğıda yazıp bilgisayardan ayrı saklayın.",
                                        "Anyone with the words can open every file encrypted to this key. Write them on paper and keep them apart from this computer.",
                                    ))
                                    .color(pal.muted)
                                    .size(12.5),
                                );
                            });
                    }
                    ui.horizontal(|ui| {
                        let label = if self.id_show_paper {
                            tr("Kâğıt yedeğini gizle", "Hide the paper backup")
                        } else {
                            tr("Kâğıt yedeğini göster", "Show the paper backup")
                        };
                        if link_button(ui, pal, label).clicked() {
                            self.id_show_paper = !self.id_show_paper;
                        }
                        ui.add_space(12.0);
                        if link_button(ui, pal, tr("Kapat", "Close")).clicked() {
                            self.id_loaded = None;
                            self.id_show_paper = false;
                        }
                    });
                    return;
                }
                let name = self.id_path.as_ref().map_or_else(
                    || tr("Kimlik dosyası seçilmedi", "No identity file selected").to_string(),
                    |p| {
                        p.file_name()
                            .map(|f| escape_display(&f.to_string_lossy()))
                            .unwrap_or_default()
                    },
                );
                ui.horizontal(|ui| {
                    ui.label(RichText::new(name).color(pal.ink).size(13.5));
                    if link_button(ui, pal, tr("Seç…", "Choose…")).clicked()
                        && let Some(p) = rfd::FileDialog::new()
                            .set_title(tr("Kimlik dosyasını seçin", "Choose the identity file"))
                            .add_filter("lephycrypy identity", &["lphykey"])
                            .pick_file()
                    {
                        self.id_path = Some(p);
                        self.error = None;
                    }
                });
                let busy = self.id_job.is_some();
                let (_, enter) = self.id_pw.ui(ui, !busy);
                ui.add_space(6.0);
                let can = self.id_path.is_some() && !self.id_pw.is_empty() && !busy;
                let label = if busy {
                    tr("Açılıyor…", "Opening…")
                } else {
                    tr("Anahtarlarımı göster", "Show my keys")
                };
                if (primary_button(ui, pal, label, can).clicked() || (enter && can))
                    && let Some(p) = self.id_path.clone()
                {
                    self.open_identity(ui.ctx(), p);
                }
            },
        );
        ui.label(
            RichText::new(tr(
                "Kâğıt yedeğinden geri yüklemek için: lephycrypy identity restore",
                "To restore from a paper backup: lephycrypy identity restore",
            ))
            .color(pal.muted)
            .size(12.0),
        );
        if let Some(ok) = copied {
            self.error = (!ok).then(|| {
                tr("Panoya kopyalanamadı.", "Could not copy to the clipboard.").to_string()
            });
        }
        if let Some(e) = &self.error {
            ui.add_space(6.0);
            ui.label(RichText::new(e).color(pal.danger).size(13.0));
        }
    }

    fn open_identity(&mut self, ctx: &egui::Context, path: PathBuf) {
        let pw = self.id_pw.take();
        let (tx, rx) = std::sync::mpsc::channel();
        let ctx = ctx.clone();
        std::thread::spawn(move || {
            let r = (|| {
                let nfc = lephy_core::password::normalize_nfc(&pw)?;
                drop(pw);
                let id = lephy_core::recipient::read_identity_file(
                    &path,
                    &nfc,
                    lephy_core::ops::UnlockOptions::default(),
                    &mut |_| {},
                )?;
                Ok::<_, lephy_core::error::Error>(LoadedId {
                    name: path
                        .file_name()
                        .map(|f| escape_display(&f.to_string_lossy()))
                        .unwrap_or_default(),
                    public: id.public().to_string(),
                    signer: id.signer().to_string(),
                    pq: id.hybrid_public()?.to_string(),
                    paper: id.paper_backup()?,
                })
            })()
            .map_err(|e| logic::describe_error(&e));
            let _ = tx.send(r);
            ctx.request_repaint();
        });
        self.id_job = Some(rx);
        self.error = None;
    }

    fn poll_identity(&mut self) {
        let Some(rx) = &self.id_job else { return };
        match rx.try_recv() {
            Ok(Ok(id)) => {
                self.id_loaded = Some(id);
                self.id_show_paper = false;
                self.id_job = None;
            }
            Ok(Err(e)) => {
                self.error = Some(e);
                self.id_job = None;
            }
            Err(std::sync::mpsc::TryRecvError::Empty) => {}
            Err(std::sync::mpsc::TryRecvError::Disconnected) => self.id_job = None,
        }
    }

    // -----------------------------------------------------------------------------------------
    // Settings

    pub(super) fn settings_view(&mut self, ui: &mut Ui, pal: Palette) {
        ui.label(
            RichText::new(tr("Ayarlar", "Settings"))
                .font(fonts::semibold(20.0))
                .color(pal.ink),
        );
        ui.add_space(12.0);
        section(
            ui,
            pal,
            tr("Dil", "Language"),
            tr(
                "Uygulamanın dili. Seçiminiz kaydedilir.",
                "The app's language. Your choice is saved.",
            ),
            |ui| self.language_choice(ui),
        );
        section(
            ui,
            pal,
            tr("Uygulama kilidi", "App lock"),
            tr(
                "Açıkken uygulama her başlatıldığında bir parola ister. Yalnızca uygulamanın kullanılmasını engeller; şifreli dosyalarınız zaten kendi parolaları ve anahtarlarıyla korunur.",
                "When on, the app asks for a password every time it starts. It only keeps others from using the app; your encrypted files are protected by their own passwords and keys anyway.",
            ),
            |ui| self.lock_settings(ui, pal),
        );
        #[cfg(any(target_os = "macos", windows))]
        section(
            ui,
            pal,
            tr("Sistem entegrasyonu", "System integration"),
            "",
            |ui| {
                #[cfg(target_os = "macos")]
                self.quick_action(ui, pal);
                #[cfg(windows)]
                self.explorer_integration(ui, pal);
            },
        );
        section(
            ui,
            pal,
            tr("Bakım", "Maintenance"),
            tr(
                "Uygulama ya da bilgisayar bir şifre çözme sırasında kapanırsa, hedef klasörde şifresi çözülmüş veri içeren gizli bir .lphy-tmp öğesi kalabilir. Açılışta Masaüstü, İndirilenler, Belgeler ve ev klasörü kendiliğinden taranır; başka bir klasörü buradan tarayabilirsiniz.",
                "If the app or the computer stops during a decryption, a hidden .lphy-tmp item with decrypted data can be left in the destination folder. Desktop, Downloads, Documents and the home folder are checked at start; search any other folder here.",
            ),
            |ui| self.stale_settings(ui, pal),
        );
        section(ui, pal, tr("Hakkında", "About"), "", |ui| {
            ui.label(
                RichText::new(format!(
                    "lephycrypy+ {} · Apache License 2.0",
                    env!("CARGO_PKG_VERSION")
                ))
                .color(pal.ink)
                .size(13.0),
            );
            ui.label(
                RichText::new(tr(
                    "Kaydedilenler yalnızca dil, karşılama ekranının görüldüğü ve (açıksa) kilit doğrulayıcısıdır; dosya adı ya da parola kaydedilmez.",
                    "Only the language, whether the welcome screen was seen and (if on) the lock verifier are saved; no file names or passwords.",
                ))
                .color(pal.muted)
                .size(12.5),
            );
            if let Some(dir) = lephy_sys::fs::app_settings_dir() {
                ui.label(
                    RichText::new(escape_display(&dir.display().to_string()))
                        .monospace()
                        .size(11.5)
                        .color(pal.muted),
                );
            }
        });
        if let Some(note) = &self.settings_note {
            ui.label(RichText::new(note.as_str()).color(pal.muted).size(12.5));
        }
    }

    #[allow(clippy::too_many_lines, reason = "one page laid out top to bottom")]
    fn lock_settings(&mut self, ui: &mut Ui, pal: Palette) {
        let on = self.prefs.lock.is_some();
        ui.label(
            RichText::new(if on {
                tr("Durum: açık", "Status: on")
            } else {
                tr("Durum: kapalı", "Status: off")
            })
            .color(if on { pal.ok } else { pal.muted })
            .size(13.0),
        );
        ui.add_space(6.0);
        if !self.lock_edit {
            let label = if on {
                tr("Kilidi kapat…", "Turn the lock off…")
            } else {
                tr("Kilidi aç…", "Turn the lock on…")
            };
            if link_button(ui, pal, label).clicked() {
                self.lock_edit = true;
                self.lock_msg = None;
            }
        } else if on {
            // Turning off needs the current password.
            self.lock_pw.ui(ui, true);
            ui.horizontal(|ui| {
                let off = link_button(ui, pal, tr("Kapat", "Turn off")).clicked();
                ui.add_space(12.0);
                if link_button(ui, pal, tr("Vazgeç", "Cancel")).clicked() {
                    self.lock_edit = false;
                    self.lock_pw.clear();
                }
                if off {
                    let pw = self.lock_pw.take();
                    let ok = self.prefs.lock.is_some_and(|v| v.check(&pw));
                    if ok {
                        self.prefs.lock = None;
                        self.save_prefs();
                        self.lock_edit = false;
                        self.lock_msg = Some(tr("Kilit kapatıldı.", "The lock is off.").into());
                    } else {
                        self.lock_msg = Some(tr("Parola yanlış.", "Wrong password.").into());
                    }
                }
            });
        } else {
            self.lock_new.ui(ui, true);
            ui.add_space(2.0);
            self.lock_new2.ui(ui, true);
            let long = self.lock_new.char_count() >= MIN_SCALARS;
            let same = self.lock_new.same_as(&self.lock_new2);
            if !self.lock_new.is_empty() && !long {
                ui.label(
                    RichText::new(match lang() {
                        Lang::Tr => format!("En az {MIN_SCALARS} karakter."),
                        Lang::En => format!("At least {MIN_SCALARS} characters."),
                    })
                    .color(pal.muted)
                    .size(12.5),
                );
            }
            ui.label(
                RichText::new(tr(
                    "Parolayı unutursanız kilit, ayarlar dosyası silinerek kaldırılabilir; dosyalarınızı etkilemez.",
                    "If you forget it, the lock can be removed by deleting the settings file; your files are not affected.",
                ))
                .color(pal.muted)
                .size(12.0),
            );
            ui.horizontal(|ui| {
                let save = ui
                    .add_enabled(
                        long && same,
                        egui::Button::new(
                            RichText::new(tr("Kilidi aç", "Turn on"))
                                .color(pal.accent)
                                .size(14.0),
                        )
                        .frame(false),
                    )
                    .clicked();
                ui.add_space(12.0);
                if link_button(ui, pal, tr("Vazgeç", "Cancel")).clicked() {
                    self.lock_edit = false;
                    self.lock_new.clear();
                    self.lock_new2.clear();
                }
                if save {
                    let pw = self.lock_new.take();
                    self.lock_new2.clear();
                    match LockVerifier::new(&pw) {
                        Ok(v) => {
                            self.prefs.lock = Some(v);
                            self.save_prefs();
                            self.lock_edit = false;
                            self.lock_msg = Some(
                                tr(
                                    "Kilit açık: uygulama bir sonraki başlatılışta parola isteyecek.",
                                    "The lock is on: the app asks for the password next time it starts.",
                                )
                                .into(),
                            );
                        }
                        Err(e) => self.lock_msg = Some(logic::describe_error(&e)),
                    }
                }
            });
        }
        if let Some(m) = &self.lock_msg {
            ui.label(RichText::new(m.as_str()).color(pal.muted).size(12.5));
        }
    }

    // -----------------------------------------------------------------------------------------
    // Lock screen and quit confirmation

    pub(super) fn lock_view(&mut self, ui: &mut Ui, pal: Palette) {
        ui.add_space(30.0);
        ui.with_layout(Layout::top_down(Align::Center), |ui| {
            let (g, _) = ui.allocate_exact_size(vec2(64.0, 64.0), Sense::hover());
            ui.painter()
                .circle_filled(g.center(), 32.0, pal.accent_soft);
            draw_lock(ui.painter(), g.center(), 0.9, pal.accent);
            ui.add_space(14.0);
            ui.label(
                RichText::new(tr("Uygulama kilitli", "The app is locked"))
                    .font(fonts::semibold(20.0))
                    .color(pal.ink),
            );
            ui.label(
                RichText::new(tr(
                    "Devam etmek için uygulama parolasını girin.",
                    "Enter the app password to continue.",
                ))
                .color(pal.muted)
                .size(13.5),
            );
        });
        ui.add_space(18.0);
        let (_, enter) = self.lock_pw.ui(ui, true);
        ui.add_space(10.0);
        let can = !self.lock_pw.is_empty();
        if (primary_button(ui, pal, tr("Kilidi aç", "Unlock"), can).clicked() || (enter && can))
            && let Some(v) = self.prefs.lock
        {
            let pw = self.lock_pw.take();
            if v.check(&pw) {
                self.locked = false;
                self.lock_msg = None;
            } else {
                self.lock_msg = Some(tr("Parola yanlış.", "Wrong password.").into());
            }
        }
        if let Some(m) = &self.lock_msg {
            ui.add_space(6.0);
            ui.label(RichText::new(m.as_str()).color(pal.danger).size(13.0));
        }
    }

    pub(super) fn quit_confirm_view(&mut self, ui: &mut Ui, pal: Palette) {
        if !self.quit_confirm {
            return;
        }
        if !self.running() {
            // The job finished meanwhile: quit at once.
            self.quit_confirm = false;
            self.quitting = true;
            return;
        }
        let mut quit = false;
        let mut stay = false;
        egui::Frame::new()
            .fill(pal.accent_soft)
            .corner_radius(CornerRadius::same(theme::R_INPUT))
            .inner_margin(egui::Margin::same(12))
            .show(ui, |ui| {
                ui.set_width(ui.available_width());
                ui.label(
                    RichText::new(tr(
                        "Bir işlem sürüyor. Çıkarsanız iptal edilir ve yarım kalan dosya silinir.",
                        "A job is running. Quitting cancels it and deletes the partial file.",
                    ))
                    .font(fonts::semibold(13.5))
                    .color(pal.ink),
                );
                ui.horizontal(|ui| {
                    quit = link_button(ui, pal, tr("Yine de çık", "Quit anyway")).clicked();
                    ui.add_space(12.0);
                    stay = link_button(ui, pal, tr("Çalışmaya devam et", "Keep working")).clicked();
                });
            });
        ui.add_space(14.0);
        if quit {
            self.quit_confirm = false;
            self.quitting = true;
            self.cancel_requested = true;
            lephy_sys::signal::request_cancel();
        } else if stay {
            self.quit_confirm = false;
        }
    }
}
