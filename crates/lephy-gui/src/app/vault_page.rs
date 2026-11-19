//! Home › Vault: open an existing vault or create a new, empty one. While a vault is open the
//! page shows it (the bar at the top has the actions).

use super::buttons::{self as b, Icon, Kind};
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
    /// Turn a USB stick into a vault (then [`Form::Create`]).
    Usb,
}

/// The page's form fields.
pub(super) struct PageForm {
    pub(super) form: Form,
    path: Option<PathBuf>,
    why: Option<&'static str>,
    pw: SecretField,
    pw2: SecretField,
    keyfile: Option<PathBuf>,
    /// Locked to public keys: opened with an identity file.
    use_identity: bool,
    identity: Option<PathBuf>,
    idpw: SecretField,
    /// Creating: post-quantum hybrid keys.
    pq: bool,
    /// The USB form.
    make: super::usb_vault::MakeUsb,
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
            use_identity: false,
            identity: None,
            idpw: SecretField::new("Kimlik dosyasının parolası", "Identity file password"),
            pq: false,
            make: super::usb_vault::MakeUsb::default(),
        }
    }
}

impl PageForm {
    /// Back to the two choices; passwords wiped.
    pub(super) fn reset(&mut self) {
        *self = Self::default();
    }

    /// Prepares opening the vault file `p` (asks for its password or identity).
    pub(super) fn open_path(&mut self, p: PathBuf) {
        self.reset();
        self.why = crate::vault::unsuitable(&p);
        self.use_identity = crate::logic::needs_identity(&p);
        self.path = Some(p);
        self.form = Form::Open;
    }

    /// Prepares creating a vault at `p`.
    fn create_at(&mut self, p: PathBuf) {
        self.reset();
        self.why = p.symlink_metadata().is_ok().then(|| {
            tr(
                "Bu adda bir dosya zaten var.",
                "A file with this name exists.",
            )
        });
        self.path = Some(p);
        self.form = Form::Create;
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
        let names = self.vault.names();
        if !names.is_empty() {
            card(ui, pal, |ui| {
                ui.label(
                    RichText::new(match lang() {
                        Lang::Tr => format!("Açık kasalar ({})", names.len()),
                        Lang::En => format!("Open vaults ({})", names.len()),
                    })
                    .font(crate::fonts::semibold(14.5))
                    .color(pal.ink),
                );
                for n in &names {
                    ui.label(RichText::new(n).monospace().size(12.0).color(pal.muted));
                }
                ui.label(
                    RichText::new(tr(
                        "Her birini üstteki kartından kaydedin ya da kilitleyin. Başka bir kasa da açabilirsiniz.",
                        "Save or lock each one from its card at the top. You can open another vault too.",
                    ))
                    .color(pal.muted)
                    .size(12.5),
                );
            });
        }
        if self.vault.opening() {
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
                        f.open_path(p);
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
                        f.create_at(p);
                    }
                });
                ui.add_space(10.0);
                if secondary_button(
                    ui,
                    pal,
                    tr("USB belleği kasa yap…", "Turn a USB stick into a vault…"),
                    ui.available_width(),
                    40.0,
                )
                .clicked()
                {
                    f.reset();
                    f.form = Form::Usb;
                }
            }
            Form::Usb => {
                let mut done = None;
                card(ui, pal, |ui| done = f.make.ui(ui, pal));
                match done {
                    Some(super::usb_vault::MakeDone::Create(p)) => f.create_at(p),
                    Some(super::usb_vault::MakeDone::Back) => f.reset(),
                    None => {}
                }
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
                        if create {
                            b::row(ui, |ui| {
                                for (on, label) in [
                                    (false, tr("Parolayla kilitle", "Lock with a password")),
                                    (true, tr("Açık anahtarlarla kilitle", "Lock to public keys")),
                                ] {
                                    let kind = if f.use_identity == on {
                                        Kind::Primary
                                    } else {
                                        Kind::Secondary
                                    };
                                    if b::action(ui, pal, kind, Icon::None, label).clicked() {
                                        f.use_identity = on;
                                    }
                                }
                            });
                            ui.add_space(4.0);
                        }
                        let (ok, enter) = if f.use_identity {
                            identity_fields(ui, pal, f, create)
                        } else {
                            password_fields(ui, pal, f, create)
                        };
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
                    let how = match (&f.identity, f.use_identity) {
                        (Some(id), true) => {
                            super::vault_ui::OpenHow::Identity(id.clone(), f.idpw.take(), f.pq)
                        }
                        _ => super::vault_ui::OpenHow::Password(f.pw.take(), f.keyfile.clone()),
                    };
                    f.reset();
                    self.start_vault_job(&ctx, path, how, create);
                }
            }
        }
    }
}

/// Password, repeat (creating) and key file. Returns (ready, Enter pressed).
fn password_fields(ui: &mut Ui, pal: Palette, f: &mut PageForm, create: bool) -> (bool, bool) {
    let (_, enter) = f.pw.ui(ui, true);
    let mut ok = !f.pw.is_empty();
    if create {
        ui.add_space(4.0);
        f.pw2.ui(ui, true);
        ok = f.pw.char_count() >= MIN_SCALARS && f.pw.same_as(&f.pw2);
        ui.label(
            RichText::new(tr(
                "En az 8 karakter; uzun bir parola cümlesi daha iyidir. Bu parolayı unutursanız kasa açılamaz.",
                "At least 8 characters; a long passphrase is better. If you forget it the vault cannot be opened.",
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
        if b::action(ui, pal, Kind::Secondary, Icon::File, tr("Seç…", "Choose…")).clicked() {
            f.keyfile = rfd::FileDialog::new()
                .set_title(tr("Anahtar dosyası", "Key file"))
                .pick_file();
        }
    });
    (ok, enter)
}

/// Identity file and its password (vaults locked to public keys). Returns (ready, Enter).
fn identity_fields(ui: &mut Ui, pal: Palette, f: &mut PageForm, create: bool) -> (bool, bool) {
    ui.label(
        RichText::new(if create {
            tr(
                "Kasa, kimlik dosyanızın açık anahtarına kilitlenir. Başka kişilerin anahtarlarını sonra kasanın içindeki alıcı listesine ekleyebilirsiniz.",
                "The vault is locked to your identity file's public key. You can add other people's keys to the recipient list inside the vault later.",
            )
        } else {
            tr(
                "Bu kasa açık anahtarlara kilitli; kimlik dosyanızla açılır.",
                "This vault is locked to public keys; open it with your identity file.",
            )
        })
        .color(pal.muted)
        .size(12.5),
    );
    ui.horizontal(|ui| {
        let name = f.identity.as_ref().map_or_else(
            || tr("Kimlik dosyası seçilmedi", "No identity file chosen").to_owned(),
            |p| {
                p.file_name()
                    .map(|n| escape_display(&n.to_string_lossy()))
                    .unwrap_or_default()
            },
        );
        ui.label(RichText::new(name).color(pal.muted).size(12.5));
        if b::action(ui, pal, Kind::Secondary, Icon::File, tr("Seç…", "Choose…")).clicked()
            && let Some(p) = rfd::FileDialog::new()
                .set_title(tr("Kimlik dosyasını seçin", "Choose the identity file"))
                .add_filter("lephycrypy identity", &["lphykey"])
                .pick_file()
        {
            f.identity = Some(p);
        }
    });
    let (_, enter) = f.idpw.ui(ui, true);
    if create {
        ui.checkbox(
            &mut f.pq,
            tr(
                "Kuantuma dayanıklı anahtarlar (lphypq1…)",
                "Post-quantum keys (lphypq1…)",
            ),
        );
    }
    let ok = f.identity.is_some() && !f.idpw.is_empty();
    (ok, enter)
}
