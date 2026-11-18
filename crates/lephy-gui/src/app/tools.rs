//! "More actions" on the decrypt screen: verify only, change the password, renew the file key.
//! They use the password (or identity) typed above and change the file in place.

use super::{App, Palette, link_button, primary_button};
use crate::i18n::tr;
use crate::logic::{Tool, ToolKind};
use crate::secret_field::SecretField;
use eframe::egui::{self, RichText, Ui};
use lephy_core::password::MIN_SCALARS;
use std::path::PathBuf;

/// State of the "More actions" group.
pub(super) struct Tools {
    /// The group is unfolded.
    pub(super) open: bool,
    /// Rekey / Reencrypt chosen: asking for the new password.
    pub(super) kind: Option<ToolKind>,
    new_pw: SecretField,
    new_pw2: SecretField,
    new_keyfile: Option<PathBuf>,
    /// Handed to the next job.
    pub(super) pending: Option<Tool>,
}

impl Default for Tools {
    fn default() -> Self {
        Self {
            open: false,
            kind: None,
            new_pw: SecretField::new("Yeni parola", "New password"),
            new_pw2: SecretField::new("Yeni parolayı tekrar girin", "Repeat the new password"),
            new_keyfile: None,
            pending: None,
        }
    }
}

impl Tools {
    /// Folds the group and wipes the new passwords.
    pub(super) fn reset(&mut self) {
        self.open = false;
        self.kind = None;
        self.new_pw.clear();
        self.new_pw2.clear();
        self.new_keyfile = None;
        self.pending = None;
    }
}

impl App {
    /// The old credentials typed above are enough to unlock the file.
    fn tool_ready(&self) -> bool {
        !self.password.is_empty()
            && (!self.keyfile_required || self.keyfile.is_some())
            && (!self.identity_required || self.identity.is_some())
    }

    /// The group under the main button (single encrypted file).
    #[allow(clippy::too_many_lines, reason = "one group laid out top to bottom")]
    pub(super) fn tools_view(&mut self, ui: &mut Ui, ctx: &egui::Context, pal: Palette) {
        ui.add_space(10.0);
        let label = if self.tools.open {
            tr("Diğer işlemleri gizle", "Hide more actions")
        } else {
            tr("Diğer işlemler…", "More actions…")
        };
        if link_button(ui, pal, label).clicked() {
            self.tools.open = !self.tools.open;
            self.tools.kind = None;
        }
        if !self.tools.open {
            return;
        }
        let ready = self.tool_ready();
        let mut start = None;
        egui::Frame::new()
            .fill(pal.surface)
            .stroke(egui::Stroke::new(1.0, pal.line))
            .corner_radius(egui::CornerRadius::same(super::theme::R_INPUT))
            .inner_margin(egui::Margin::same(12))
            .show(ui, |ui| {
                ui.set_width(ui.available_width());
                if !ready {
                    ui.label(
                        RichText::new(tr(
                            "Önce yukarıya dosyanın parolasını (ya da kimliğini) girin.",
                            "Enter the file's password (or identity) above first.",
                        ))
                        .color(pal.muted)
                        .size(12.5),
                    );
                }
                let row = |ui: &mut Ui, title: &str, text: &str| -> bool {
                    let clicked = ui
                        .add_enabled(
                            ready,
                            egui::Button::new(RichText::new(title).color(pal.accent).size(14.0))
                                .frame(false),
                        )
                        .clicked();
                    ui.label(RichText::new(text).color(pal.muted).size(12.0));
                    ui.add_space(4.0);
                    clicked
                };
                if row(
                    ui,
                    tr("Yalnızca doğrula", "Verify only"),
                    tr(
                        "Dosyanın tamamını çözüp denetler, hiçbir şey yazmaz.",
                        "Decrypts and checks the whole file; writes nothing.",
                    ),
                ) {
                    start = Some(ToolKind::Verify);
                }
                // A file locked to public keys has no password to change.
                if !self.identity_required {
                    if row(
                        ui,
                        tr("Parolayı değiştir…", "Change the password…"),
                        tr(
                            "Yalnızca dosya anahtarını saran kısım yeniden yazılır; hızlıdır. İçerik aynı anahtarla kalır.",
                            "Only the wrapping of the file key is rewritten; quick. The content keeps its key.",
                        ),
                    ) {
                        self.tools.kind = Some(ToolKind::Rekey);
                    }
                    if row(
                        ui,
                        tr("Dosya anahtarını yenile…", "Renew the file key…"),
                        tr(
                            "Bütün içerik yeni bir anahtarla yeniden şifrelenir. Eski parola ve dosyanın eski bir kopyası birlikte sızdıysa bunu seçin.",
                            "Every part is encrypted again with a new key. Choose this if the old password and an old copy of the file may both have leaked.",
                        ),
                    ) {
                        self.tools.kind = Some(ToolKind::Reencrypt);
                    }
                }
                if let Some(kind) = self.tools.kind {
                    ui.separator();
                    self.tools.new_pw.ui(ui, true);
                    ui.add_space(4.0);
                    self.tools.new_pw2.ui(ui, true);
                    ui.horizontal(|ui| {
                        let name = self.tools.new_keyfile.as_ref().map_or_else(
                            || tr("Yeni anahtar dosyası yok", "No new key file").to_owned(),
                            |p| {
                                p.file_name()
                                    .map(|f| f.to_string_lossy().into_owned())
                                    .unwrap_or_default()
                            },
                        );
                        ui.label(RichText::new(name).color(pal.muted).size(12.5));
                        if link_button(ui, pal, tr("Seç…", "Choose…")).clicked() {
                            self.tools.new_keyfile = rfd::FileDialog::new()
                                .set_title(tr("Yeni anahtar dosyası", "New key file"))
                                .pick_file();
                        }
                    });
                    let ok = self.tools.new_pw.char_count() >= MIN_SCALARS
                        && self.tools.new_pw.same_as(&self.tools.new_pw2);
                    let label = if kind == ToolKind::Rekey {
                        tr("Parolayı değiştir", "Change the password")
                    } else {
                        tr("Anahtarı yenile", "Renew the key")
                    };
                    if primary_button(ui, pal, label, ok && ready).clicked() {
                        start = Some(kind);
                    }
                }
            });
        if let Some(kind) = start {
            let (new_password, new_confirm) = if kind == ToolKind::Verify {
                (None, None)
            } else {
                (
                    Some(self.tools.new_pw.take()),
                    Some(self.tools.new_pw2.take()),
                )
            };
            self.tools.pending = Some(Tool {
                kind,
                new_password,
                new_confirm,
                new_keyfile: self.tools.new_keyfile.take(),
            });
            self.tools.kind = None;
            self.start(ctx);
        }
    }
}
