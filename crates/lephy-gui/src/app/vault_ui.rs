//! Vault in the app: "Open as vault" on the decrypt screen, a bar on every page while a vault is
//! open (show folder, save and lock, close without saving), the quit prompt, and leftovers from
//! an earlier run.

use super::{App, Palette, link_button, logic};
use crate::i18n::{Lang, lang, tr};
use crate::vault::{self, Place, Vault};
use eframe::egui::{self, CornerRadius, RichText, Stroke, Ui};
use lephy_core::names::escape_display;
use std::sync::mpsc::{Receiver, TryRecvError};

/// What a finished background step hands back.
enum Done {
    Opened(Result<Vault, String>),
    Saved(Vault, Result<(), String>),
}

/// What to do after saving.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum After {
    /// Keep the vault open.
    Stay,
    /// Close it (lock).
    Close,
    /// Close it and quit the app.
    Quit,
}

/// Vault state of the app.
#[derive(Default)]
pub(super) struct VaultUi {
    pub(super) open: Option<Vault>,
    job: Option<(Receiver<Done>, Option<After>)>,
    confirm_discard: bool,
    msg: Option<String>,
    /// Places left from an earlier run.
    pub(super) leftovers: Vec<Place>,
    leftover_confirm: bool,
    /// Vault page: what is being prepared.
    pub(super) page: super::vault_page::PageForm,
    /// Auto-lock: last check (monotonic and wall clock, to notice sleep).
    last_check: Option<(std::time::Instant, std::time::SystemTime)>,
    /// Seconds without input at the last check.
    pub(super) idle: Option<u64>,
    /// The last lock happened by itself, and why.
    auto_reason: Option<AutoLock>,
}

/// Why an open vault is locked by itself.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum AutoLock {
    /// No input for the set time.
    Idle,
    /// The screen was locked.
    ScreenLocked,
    /// The computer slept.
    Woke,
}

/// Decides whether an open vault locks itself now.
pub(super) fn should_auto_lock(
    idle_s: Option<u64>,
    screen_locked: bool,
    woke: bool,
    idle_minutes: u32,
    on_lock: bool,
) -> Option<AutoLock> {
    if on_lock && screen_locked {
        return Some(AutoLock::ScreenLocked);
    }
    if on_lock && woke {
        return Some(AutoLock::Woke);
    }
    match idle_s {
        Some(s) if idle_minutes > 0 && s >= u64::from(idle_minutes) * 60 => Some(AutoLock::Idle),
        _ => None,
    }
}

impl VaultUi {
    /// Opening or saving runs.
    pub(super) fn busy(&self) -> bool {
        self.job.is_some()
    }
}

fn bar(ui: &mut Ui, pal: Palette, warn: bool, body: impl FnOnce(&mut Ui)) {
    egui::Frame::new()
        .fill(if warn { pal.surface } else { pal.accent_soft })
        .stroke(Stroke::new(
            1.0,
            if warn {
                pal.danger.gamma_multiply(0.6)
            } else {
                pal.accent.gamma_multiply(0.5)
            },
        ))
        .corner_radius(CornerRadius::same(super::theme::R_CARD))
        .inner_margin(egui::Margin::same(12))
        .show(ui, |ui| {
            ui.set_width(ui.available_width());
            body(ui);
        });
    ui.add_space(12.0);
}

impl App {
    /// The chosen file can be opened as a vault (shown on the decrypt screen).
    pub(super) fn vault_offer(&mut self, ui: &mut Ui, ctx: &egui::Context, pal: Palette) {
        let Some(src) = &self.source else { return };
        if self.vault.open.is_some() || self.vault.busy() || self.identity_required {
            return;
        }
        let path = src.path.clone();
        let why = vault::unsuitable(&path);
        let can = why.is_none() && !self.password.is_empty();
        let resp = ui
            .add_enabled(
                can,
                egui::Button::new(
                    RichText::new(tr("Kasa olarak aç…", "Open as a vault…"))
                        .color(pal.accent)
                        .size(14.0),
                )
                .frame(false)
                .min_size(egui::vec2(0.0, 28.0)),
            )
            .on_hover_text(why.unwrap_or(tr(
                "Klasörü bir kez açıp içinde çalışın; \"Kaydet ve kilitle\" aynı parolayla yeniden şifreler. macOS'ta açık kopya yalnızca bellekte (RAM disk) durur.",
                "Open the folder once and work in it; \"Save and lock\" encrypts it again with the same password. On macOS the open copy stays in memory only (RAM disk).",
            )));
        if resp.clicked() {
            self.start_vault_open(ctx, path);
        }
    }

    fn start_vault_open(&mut self, ctx: &egui::Context, path: std::path::PathBuf) {
        let Ok(pw) = lephy_sys::mem::SecretBytes::from_slice(self.password.expose()) else {
            return;
        };
        let keyfile = self.keyfile.clone();
        self.start_vault_job(ctx, path, pw, keyfile, false);
    }

    /// Opens (`create = false`) or creates and opens a vault in the background.
    pub(super) fn start_vault_job(
        &mut self,
        ctx: &egui::Context,
        path: std::path::PathBuf,
        pw: lephy_sys::mem::SecretBytes,
        keyfile: Option<std::path::PathBuf>,
        create: bool,
    ) {
        let folder = if cfg!(target_os = "macos") {
            None
        } else {
            vault::folder_base()
        };
        let (tx, rx) = std::sync::mpsc::channel();
        let ctx2 = ctx.clone();
        std::thread::spawn(move || {
            let r = if create {
                Vault::create(&path, &pw, keyfile.as_deref(), folder.as_deref())
            } else {
                Vault::open(&path, &pw, keyfile.as_deref(), folder.as_deref())
            }
            .map_err(|e| logic::describe_error(&e));
            drop(pw);
            let _ = tx.send(Done::Opened(r));
            ctx2.request_repaint();
        });
        self.vault.job = Some((rx, None));
        self.vault.msg = None;
    }

    fn start_vault_save(&mut self, ctx: &egui::Context, after: After) {
        let Some(mut v) = self.vault.open.take() else {
            return;
        };
        let (tx, rx) = std::sync::mpsc::channel();
        let ctx2 = ctx.clone();
        std::thread::spawn(move || {
            let r = if v.changed() {
                v.save().map_err(|e| logic::describe_error(&e))
            } else {
                Ok(())
            };
            let _ = tx.send(Done::Saved(v, r));
            ctx2.request_repaint();
        });
        self.vault.job = Some((rx, Some(after)));
        self.vault.msg = None;
    }

    /// Destroys the open copy; on a busy RAM disk the vault stays open with a note.
    fn close_vault(&mut self, force: bool) -> bool {
        let Some(v) = self.vault.open.take() else {
            return true;
        };
        match v.close(force) {
            Ok(()) => true,
            Err(e) => {
                self.vault.msg = Some(match lang() {
                    Lang::Tr => format!(
                        "Kasa kapatılamadı; bir program içindeki bir dosyayı hâlâ açık tutuyor olabilir. Programları kapatıp yeniden deneyin. ({e})"
                    ),
                    Lang::En => format!(
                        "The vault could not be closed; a program may still have a file in it open. Close it and try again. ({e})"
                    ),
                });
                self.vault.open = Some(v);
                false
            }
        }
    }

    /// Every few seconds while a vault is open: lock it when the user is away, the screen locks
    /// or the computer woke from sleep (it was asleep with the vault open).
    pub(super) fn auto_lock_vault(&mut self, ctx: &egui::Context) {
        if self.vault.open.is_none() || self.vault.busy() {
            self.vault.last_check = None;
            return;
        }
        ctx.request_repaint_after(std::time::Duration::from_secs(5));
        let now = (std::time::Instant::now(), std::time::SystemTime::now());
        let Some((mono, wall)) = self.vault.last_check else {
            self.vault.last_check = Some(now);
            return;
        };
        let mono_d = now.0.duration_since(mono);
        if mono_d < std::time::Duration::from_secs(5) {
            return;
        }
        // The monotonic clock stops during sleep; the wall clock does not.
        let wall_d = now.1.duration_since(wall).unwrap_or_default();
        let woke = wall_d.saturating_sub(mono_d) > std::time::Duration::from_secs(30);
        self.vault.last_check = Some(now);
        self.vault.idle = lephy_sys::idle::idle_seconds();
        let why = should_auto_lock(
            self.vault.idle,
            lephy_sys::idle::screen_locked(),
            woke,
            self.prefs.vault_idle_minutes(),
            !self.prefs.vault_keep_on_lock,
        );
        if let Some(w) = why {
            self.start_vault_save(ctx, After::Close);
            self.vault.auto_reason = Some(w);
        }
    }

    /// Finished background steps.
    pub(super) fn poll_vault(&mut self) {
        let Some((rx, after)) = &self.vault.job else {
            return;
        };
        let after = *after;
        let done = match rx.try_recv() {
            Ok(d) => d,
            Err(TryRecvError::Empty) => return,
            Err(TryRecvError::Disconnected) => {
                self.vault.job = None;
                return;
            }
        };
        self.vault.job = None;
        match done {
            Done::Opened(Ok(v)) => {
                let _ = logic::reveal_in_folder(&v.root);
                self.vault.open = Some(v);
                self.reset();
                self.go_home();
            }
            Done::Opened(Err(e)) => self.vault.msg = Some(e),
            Done::Saved(v, Err(e)) => {
                self.vault.open = Some(v);
                self.vault.auto_reason = None;
                self.vault.msg = Some(match lang() {
                    Lang::Tr => format!("Kaydedilemedi; şifreli dosya değişmedi, kasa açık. ({e})"),
                    Lang::En => format!(
                        "Not saved; the encrypted file is unchanged and the vault stays open. ({e})"
                    ),
                });
            }
            Done::Saved(v, Ok(())) => {
                self.vault.open = Some(v);
                match after {
                    Some(After::Close) => {
                        if self.close_vault(false) {
                            self.vault.msg = Some(
                                match self.vault.auto_reason.take() {
                                    Some(AutoLock::Idle) => tr(
                                        "Kasa, hareketsizlik nedeniyle kaydedilip kilitlendi.",
                                        "The vault was saved and locked after a period without input.",
                                    ),
                                    Some(AutoLock::ScreenLocked) => tr(
                                        "Ekran kilitlendiği için kasa kaydedilip kilitlendi.",
                                        "The vault was saved and locked because the screen locked.",
                                    ),
                                    Some(AutoLock::Woke) => tr(
                                        "Bilgisayar uykudan uyandığı için kasa kaydedilip kilitlendi.",
                                        "The vault was saved and locked because the computer woke from sleep.",
                                    ),
                                    None => tr("Kaydedildi ve kilitlendi.", "Saved and locked."),
                                }
                                .into(),
                            );
                        } else {
                            self.vault.auto_reason = None;
                        }
                    }
                    Some(After::Quit) => {
                        if self.close_vault(false) {
                            self.quitting = true;
                        }
                    }
                    Some(After::Stay) | None => {
                        self.vault.msg = Some(tr("Kaydedildi.", "Saved.").into());
                    }
                }
            }
        }
    }

    /// The bar shown on every page while a vault is open (and leftovers / notes).
    #[allow(clippy::too_many_lines, reason = "one bar with its confirmation")]
    pub(super) fn vault_bar(&mut self, ui: &mut Ui, ctx: &egui::Context, pal: Palette) {
        self.leftover_bar(ui, pal);
        if let Some(m) = self.vault.msg.clone()
            && self.vault.open.is_none()
        {
            ui.horizontal(|ui| {
                ui.label(RichText::new(m).color(pal.muted).size(12.5));
                if link_button(ui, pal, tr("Tamam", "OK")).clicked() {
                    self.vault.msg = None;
                }
            });
            ui.add_space(6.0);
        }
        if self.vault.busy() && self.vault.open.is_none() {
            bar(ui, pal, false, |ui| {
                ui.horizontal(|ui| {
                    ui.spinner();
                    ui.label(tr("Kasa işleniyor…", "Working on the vault…"));
                });
            });
            return;
        }
        let Some(v) = &self.vault.open else { return };
        let name = v
            .source
            .file_name()
            .map(|f| escape_display(&f.to_string_lossy()))
            .unwrap_or_default();
        let place = match v.place {
            Place::Ram(_) => tr(
                "RAM diskte (yalnızca bellekte)",
                "on a RAM disk (memory only)",
            ),
            Place::Folder(_) => tr("özel bir uygulama klasöründe", "in a private app folder"),
        };
        let root = v.root.clone();
        let changed = v.changed();
        let mut act = None;
        bar(ui, pal, false, |ui| {
            ui.label(
                RichText::new(match lang() {
                    Lang::Tr => format!("Kasa açık: {name}"),
                    Lang::En => format!("Vault open: {name}"),
                })
                .font(crate::fonts::semibold(14.0))
                .color(pal.ink),
            );
            ui.label(
                RichText::new(format!(
                    "{place}{}",
                    if changed {
                        tr(" · kaydedilmemiş değişiklikler var", " · unsaved changes")
                    } else {
                        ""
                    }
                ))
                .color(pal.muted)
                .size(12.5),
            );
            let minutes = self.prefs.vault_idle_minutes();
            if minutes > 0 {
                let left = (u64::from(minutes) * 60)
                    .saturating_sub(self.vault.idle.unwrap_or(0))
                    .div_ceil(60);
                ui.label(
                    RichText::new(match lang() {
                        Lang::Tr => format!(
                            "{minutes} dk hareketsizlikte kendiliğinden kaydedilip kilitlenir (kalan ~{left} dk)."
                        ),
                        Lang::En => format!(
                            "Saves and locks itself after {minutes} min without input (~{left} min left)."
                        ),
                    })
                    .color(pal.muted)
                    .size(12.0),
                );
            }
            if let Some(m) = &self.vault.msg {
                ui.label(RichText::new(m).color(pal.danger).size(12.5));
            }
            ui.horizontal_wrapped(|ui| {
                if link_button(ui, pal, tr("Klasörü göster", "Show folder")).clicked() {
                    let _ = logic::reveal_in_folder(&root);
                }
                if link_button(ui, pal, tr("Kaydet", "Save")).clicked() {
                    act = Some(After::Stay);
                }
                if link_button(ui, pal, tr("Kaydet ve kilitle", "Save and lock")).clicked() {
                    act = Some(After::Close);
                }
                if link_button(ui, pal, tr("Kaydetmeden kapat…", "Close without saving…")).clicked()
                {
                    self.vault.confirm_discard = true;
                }
            });
            if self.vault.confirm_discard {
                ui.label(
                    RichText::new(if changed {
                        tr(
                            "Kaydedilmemiş değişiklikler kalıcı olarak gidecek. Emin misiniz?",
                            "Unsaved changes will be lost for good. Are you sure?",
                        )
                    } else {
                        tr(
                            "Değişiklik yok; şifreli dosya olduğu gibi kalır.",
                            "Nothing changed; the encrypted file stays as it is.",
                        )
                    })
                    .color(pal.danger)
                    .size(12.5),
                );
                ui.horizontal(|ui| {
                    if link_button(ui, pal, tr("Evet, kapat", "Yes, close")).clicked() {
                        self.vault.confirm_discard = false;
                        if self.close_vault(false) {
                            self.vault.msg = Some(tr("Kasa kapatıldı.", "Vault closed.").into());
                        }
                    }
                    if link_button(ui, pal, tr("Vazgeç", "Cancel")).clicked() {
                        self.vault.confirm_discard = false;
                    }
                });
            }
        });
        if self.vault.busy() {
            ui.horizontal(|ui| {
                ui.spinner();
                ui.label(tr("Kaydediliyor…", "Saving…"));
            });
        }
        if let Some(a) = act {
            self.start_vault_save(ctx, a);
        }
    }

    fn leftover_bar(&mut self, ui: &mut Ui, pal: Palette) {
        if self.vault.leftovers.is_empty() {
            return;
        }
        let n = self.vault.leftovers.len();
        let mut show = false;
        let mut close = false;
        bar(ui, pal, true, |ui| {
            ui.label(
                RichText::new(match lang() {
                    Lang::Tr => format!("Önceki oturumdan açık kalmış {n} kasa var"),
                    Lang::En => format!("{n} vault(s) left open from an earlier session"),
                })
                .font(crate::fonts::semibold(14.0))
                .color(pal.ink),
            );
            ui.label(
                RichText::new(tr(
                    "Kaydedilmemiş değişiklikler içerebilir. Gerekenleri klasörden kopyalayıp sonra kapatın.",
                    "They may hold unsaved changes. Copy what you need from the folder, then close them.",
                ))
                .color(pal.muted)
                .size(12.5),
            );
            if self.vault.leftover_confirm {
                ui.label(
                    RichText::new(tr(
                        "İçlerindeki her şey kalıcı olarak silinecek. Emin misiniz?",
                        "Everything in them will be deleted for good. Are you sure?",
                    ))
                    .color(pal.danger)
                    .size(12.5),
                );
                ui.horizontal(|ui| {
                    close = link_button(ui, pal, tr("Evet, kapat", "Yes, close")).clicked();
                    if link_button(ui, pal, tr("Vazgeç", "Cancel")).clicked() {
                        self.vault.leftover_confirm = false;
                    }
                });
            } else {
                ui.horizontal(|ui| {
                    show = link_button(ui, pal, tr("Göster", "Show")).clicked();
                    if link_button(ui, pal, tr("Kapat…", "Close…")).clicked() {
                        self.vault.leftover_confirm = true;
                    }
                });
            }
        });
        if show {
            for p in &self.vault.leftovers {
                let _ = logic::reveal_in_folder(p.base());
            }
        }
        if close {
            self.vault.leftover_confirm = false;
            self.vault
                .leftovers
                .retain(|p| vault::destroy_place(p, true).is_err());
        }
    }

    /// Quit asked while a vault is open (and no job runs): save and lock first, or not.
    pub(super) fn vault_quit_prompt(&mut self, ui: &mut Ui, ctx: &egui::Context, pal: Palette) {
        let changed = self.vault.open.as_ref().is_some_and(Vault::changed);
        let mut choice = None;
        bar(ui, pal, true, |ui| {
            ui.label(
                RichText::new(tr(
                    "Bir kasa açık. Çıkmadan önce kaydedip kilitleyin.",
                    "A vault is open. Save and lock it before quitting.",
                ))
                .font(crate::fonts::semibold(13.5))
                .color(pal.ink),
            );
            ui.horizontal_wrapped(|ui| {
                if link_button(ui, pal, tr("Kaydet, kilitle ve çık", "Save, lock and quit"))
                    .clicked()
                {
                    choice = Some(0);
                }
                let label = if changed {
                    tr(
                        "Kaydetmeden çık (değişiklikler gider)",
                        "Quit without saving (changes are lost)",
                    )
                } else {
                    tr("Kilitle ve çık", "Lock and quit")
                };
                if link_button(ui, pal, label).clicked() {
                    choice = Some(1);
                }
                if link_button(ui, pal, tr("Vazgeç", "Cancel")).clicked() {
                    choice = Some(2);
                }
            });
        });
        match choice {
            Some(0) => {
                self.quit_confirm = false;
                self.start_vault_save(ctx, After::Quit);
            }
            Some(1) => {
                self.quit_confirm = false;
                if self.close_vault(true) {
                    self.quitting = true;
                }
            }
            Some(2) => self.quit_confirm = false,
            _ => {}
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{AutoLock, should_auto_lock};

    #[test]
    fn auto_lock_decision() {
        assert_eq!(should_auto_lock(Some(10), false, false, 15, true), None);
        assert_eq!(
            should_auto_lock(Some(900), false, false, 15, true),
            Some(AutoLock::Idle)
        );
        assert_eq!(
            should_auto_lock(Some(9000), false, false, 0, true),
            None,
            "never"
        );
        assert_eq!(should_auto_lock(None, false, false, 15, true), None);
        assert_eq!(
            should_auto_lock(Some(0), true, false, 15, true),
            Some(AutoLock::ScreenLocked)
        );
        assert_eq!(
            should_auto_lock(Some(0), true, false, 15, false),
            None,
            "screen lock off"
        );
        assert_eq!(
            should_auto_lock(Some(0), false, true, 15, true),
            Some(AutoLock::Woke)
        );
    }
}
