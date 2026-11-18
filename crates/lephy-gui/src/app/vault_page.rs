//! Home › Vault: open an existing vault or create a new, empty one. While a vault is open the
//! page shows it (the bar at the top has the actions).

use super::{App, Palette, link_button, primary_button, secondary_button};
use crate::i18n::{Lang, lang, tr};
use crate::secret_field::SecretField;
use eframe::egui::{self, RichText, Stroke, Ui};
use lephy_core::names::escape_display;
use lephy_core::password::MIN_SCALARS;
use std::path::PathBuf;

/// What the page is preparing.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub(super) enum Form {
    /// Two choices.
    #[default]
    Choose,
    /// Open an existing vault.
    Open,
    /// Create a new one.
    Create,
}

/// The page's form fields.
pub(super) struct PageForm {
    pub(super) form: Form,
    path: Option<PathBuf>,
    why: Option<&'static str>,
    pw: SecretField,
    pw2: SecretField,
    keyfile: Option<PathBuf>,
}

impl Default for PageForm {
    fn default() -> Self {
        Self {
            form: Form::Choose,
            path: None,
            why: None,
            pw: SecretField::new("Kasa parolası", "Vault password"),
            pw2: SecretField::new("Parolayı tekrar girin", "Repeat the password"),
            keyfile: None,
        }
    }
}

impl PageForm {
    /// Back to the two choices; passwords wiped.
    pub(super) fn reset(&mut self) {
        *self = Self::default();
    }
}

fn card(ui: &mut Ui, pal: Palette, body: impl FnOnce(&mut Ui)) {
    egui::Frame::new()
        .fill(pal.surface)
        .stroke(Stroke::new(1.0, pal.line))
        .corner_radius(egui::CornerRadius::same(super::theme::R_CARD))
        .inner_margin(egui::Margin::same(14))
        .show(ui, |ui| {
            ui.set_width(ui.available_width());
            body(ui);
        });
    ui.add_space(12.0);
}

impl App {
    /// The vault page.
    #[allow(
        clippy::too_many_lines,
        reason = "one page: open, create and the open vault"
    )]
    pub(super) fn vault_page(&mut self, ui: &mut Ui, pal: Palette) {
        let ctx = ui.ctx().clone();
        ui.label(
            RichText::new(tr("Kasa", "Vault"))
                .font(crate::fonts::semibold(20.0))
                .color(pal.ink),
        );
        ui.label(
            RichText::new(tr(
                "Şifreli bir klasörü bir kez açıp içinde çalışın; \"Kaydet ve kilitle\" aynı parolayla yeniden şifreler.",
                "Open an encrypted folder once and work in it; \"Save and lock\" encrypts it again with the same password.",
            ))
            .color(pal.muted)
            .size(13.0),
        );
        ui.add_space(12.0);
        super::help::help_box(ui, pal, super::help::Topic::Vault);
        if let Some(v) = &self.vault.open {
            let root = v.root.clone();
            card(ui, pal, |ui| {
                ui.label(
                    RichText::new(tr("Bir kasa açık", "A vault is open"))
                        .font(crate::fonts::semibold(14.5))
                        .color(pal.ink),
                );
                ui.label(
                    RichText::new(escape_display(&root.display().to_string()))
                        .monospace()
                        .size(12.0)
                        .color(pal.muted),
                );
                ui.label(
                    RichText::new(tr(
                        "Üstteki şeritten kaydedin ya da kilitleyin. Aynı anda tek kasa açık olabilir.",
                        "Save or lock it from the bar at the top. One vault can be open at a time.",
                    ))
                    .color(pal.muted)
                    .size(12.5),
                );
            });
            return;
        }
        if self.vault.busy() {
            return;
        }
        let f = &mut self.vault.page;
        match f.form {
            Form::Choose => {
                let w = (ui.available_width() - 10.0) / 2.0;
                ui.horizontal(|ui| {
                    if secondary_button(ui, pal, tr("Kasa aç…", "Open a vault…"), w, 40.0).clicked()
                        && let Some(p) = rfd::FileDialog::new()
                            .set_title(tr("Kasayı seçin", "Choose the vault"))
                            .add_filter("lephycrypy", &["lphy"])
                            .pick_file()
                    {
                        f.why = crate::vault::unsuitable(&p);
                        f.path = Some(p);
                        f.form = Form::Open;
                    }
                    if secondary_button(
                        ui,
                        pal,
                        tr("Yeni boş kasa oluştur…", "Create a new vault…"),
                        w,
                        40.0,
                    )
                    .clicked()
                        && let Some(p) = rfd::FileDialog::new()
                            .set_title(tr("Yeni kasayı kaydedin", "Save the new vault"))
                            .set_file_name(tr("Kasam.lphy", "MyVault.lphy"))
                            .add_filter("lephycrypy", &["lphy"])
                            .save_file()
                    {
                        let p = if p.extension().is_some_and(|e| e == "lphy") {
                            p
                        } else {
                            p.with_extension("lphy")
                        };
                        f.why = p.symlink_metadata().is_ok().then(|| {
                            tr(
                                "Bu adda bir dosya zaten var.",
                                "A file with this name exists.",
                            )
                        });
                        f.path = Some(p);
                        f.form = Form::Create;
                    }
                });
            }
            Form::Open | Form::Create => {
                let create = f.form == Form::Create;
                let name = f
                    .path
                    .as_ref()
                    .and_then(|p| p.file_name())
                    .map(|n| escape_display(&n.to_string_lossy()))
                    .unwrap_or_default();
                let mut go = false;
                let mut back = false;
                card(ui, pal, |ui| {
                    ui.label(
                        RichText::new(if create {
                            match lang() {
                                Lang::Tr => format!("Yeni kasa: {name}"),
                                Lang::En => format!("New vault: {name}"),
                            }
                        } else {
                            match lang() {
                                Lang::Tr => format!("Kasa: {name}"),
                                Lang::En => format!("Vault: {name}"),
                            }
                        })
                        .font(crate::fonts::semibold(14.5))
                        .color(pal.ink),
                    );
                    if let Some(why) = f.why {
                        ui.label(RichText::new(why).color(pal.danger).size(12.5));
                    } else {
                        let (_, enter) = f.pw.ui(ui, true);
                        let mut ok = !f.pw.is_empty();
                        if create {
                            ui.add_space(4.0);
                            f.pw2.ui(ui, true);
                            ok = f.pw.char_count() >= MIN_SCALARS && f.pw.same_as(&f.pw2);
                            ui.label(
                                RichText::new(tr(
                                    "En az 12 karakter. Bu parolayı unutursanız kasa açılamaz.",
                                    "At least 12 characters. If you forget it the vault cannot be opened.",
                                ))
                                .color(pal.muted)
                                .size(12.0),
                            );
                        }
                        ui.horizontal(|ui| {
                            let kf = f.keyfile.as_ref().map_or_else(
                                || tr("Anahtar dosyası yok", "No key file").to_owned(),
                                |p| {
                                    p.file_name()
                                        .map(|n| escape_display(&n.to_string_lossy()))
                                        .unwrap_or_default()
                                },
                            );
                            ui.label(RichText::new(kf).color(pal.muted).size(12.5));
                            if link_button(ui, pal, tr("Seç…", "Choose…")).clicked() {
                                f.keyfile = rfd::FileDialog::new()
                                    .set_title(tr("Anahtar dosyası", "Key file"))
                                    .pick_file();
                            }
                        });
                        ui.add_space(6.0);
                        let label = if create {
                            tr("Oluştur ve aç", "Create and open")
                        } else {
                            tr("Aç", "Open")
                        };
                        go = primary_button(ui, pal, label, ok).clicked() || (enter && ok);
                    }
                    back = link_button(ui, pal, tr("‹ Geri", "‹ Back")).clicked();
                });
                if back {
                    f.reset();
                } else if go && let Some(path) = f.path.clone() {
                    let pw = f.pw.take();
                    f.pw2.clear();
                    let keyfile = f.keyfile.clone();
                    f.reset();
                    self.start_vault_job(&ctx, path, pw, keyfile, create);
                }
            }
        }
    }
}
