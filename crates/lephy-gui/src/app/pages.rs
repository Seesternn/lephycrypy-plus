//! Start-screen pages: welcome (first launch), home with action cards, keys, settings, the
//! optional app lock and the quit confirmation.

use super::{
    App, Palette, draw_doc, draw_gear, draw_key, draw_lock, fonts, link_button, logic,
    primary_button, reveal_on_hover, secondary_button, segmented, theme,
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
    /// Key pairs: create one, show the keys of an identity, paper backup.
    Keys,
    /// Language, app lock, system integration, about.
    Settings,
}

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
    icon: fn(&egui::Painter, egui::Pos2, egui::Color32),
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
        ui.add_space(8.0);
        ui.with_layout(Layout::top_down(Align::Center), |ui| {
            let (g, _) = ui.allocate_exact_size(vec2(64.0, 64.0), Sense::hover());
            ui.painter()
                .circle_filled(g.center(), 32.0, pal.accent_soft);
            draw_lock(ui.painter(), g.center(), 0.9, pal.accent);
            ui.add_space(14.0);
            ui.label(
                RichText::new(tr("lephycrypy+'a hoş geldiniz", "Welcome to lephycrypy+"))
                    .font(fonts::semibold(22.0))
                    .color(pal.ink),
            );
            ui.label(
                RichText::new(tr(
                    "Dosya ve klasörlerinizi parolayla ya da açık anahtarla şifreleyin.",
                    "Encrypt your files and folders with a password or with public keys.",
                ))
                .color(pal.muted)
                .size(14.0),
            );
        });
        ui.add_space(20.0);
        let points = [
            (
                tr("Bu bilgisayarda kalır", "Stays on this computer"),
                tr(
                    "Dosyalarınız hiçbir sunucuya gönderilmez; parolanız kaydedilmez.",
                    "Your files are never sent anywhere; your password is never stored.",
                ),
            ),
            (
                tr("Adlar da gizlenir", "Names are hidden too"),
                tr(
                    "Şifreli dosyadan içindeki dosya adları ve klasör yapısı anlaşılmaz.",
                    "An encrypted file does not reveal the names or folder structure inside.",
                ),
            ),
            (
                tr("Paylaşmak için açık anahtar", "Public keys for sharing"),
                tr(
                    "Ortak parola olmadan, kuantuma dayanıklı seçenek ve imzayla.",
                    "No shared password; with a post-quantum option and signatures.",
                ),
            ),
        ];
        for (title, text) in points {
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
                    ui.label(RichText::new(text).color(pal.muted).size(12.5));
                });
            });
            ui.add_space(8.0);
        }
        ui.add_space(12.0);
        self.language_choice(ui);
        ui.add_space(18.0);
        if primary_button(ui, pal, tr("Başla", "Start"), true).clicked() {
            self.prefs.welcome_done = true;
            self.save_prefs();
            self.page = Page::Home;
        }
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
            self.encrypt_choice = !self.encrypt_choice;
        }
        if clicked[1] {
            self.encrypt_choice = false;
            if let Some(p) = rfd::FileDialog::new()
                .set_title(tr("Şifreli dosyayı seçin", "Choose the encrypted file"))
                .add_filter("lephycrypy", &["lphy", "001"])
                .pick_file()
            {
                self.set_sources(&[p]);
            }
        }
        if clicked[2] {
            self.page = Page::Keys;
            self.encrypt_choice = false;
        }
        if clicked[3] {
            self.page = Page::Settings;
            self.encrypt_choice = false;
        }
        if self.encrypt_choice {
            ui.add_space(10.0);
            ui.horizontal(|ui| {
                let bw = (ui.available_width() - 10.0) / 2.0;
                if secondary_button(ui, pal, tr("Dosya seç…", "Choose files…"), bw, 34.0).clicked()
                {
                    self.pick_file();
                }
                if secondary_button(ui, pal, tr("Klasör seç…", "Choose a folder…"), bw, 34.0)
                    .clicked()
                {
                    self.pick_folder();
                }
            });
        }
        ui.add_space(14.0);
        Self::drop_area(ui, pal);
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
    fn drop_area(ui: &mut Ui, pal: Palette) {
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
            tr(
                "…ya da dosya ve klasörleri buraya bırakın",
                "…or drop files and folders here",
            ),
            fonts::semibold(14.0),
            pal.ink,
        );
        ui.painter().text(
            rect.center() + vec2(0.0, 12.0),
            egui::Align2::CENTER_CENTER,
            tr(
                "Şifreli .lphy dosyaları açılır, diğer her şey şifrelenir.",
                "Encrypted .lphy files are opened; everything else is encrypted.",
            ),
            fonts::regular(12.5),
            pal.muted,
        );
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
