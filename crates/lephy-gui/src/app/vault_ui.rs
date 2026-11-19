//! Vault in the app: "Open as vault" on the decrypt screen, a bar on every page while a vault is
//! open (show folder, save and lock, close without saving), the quit prompt, and leftovers from
//! an earlier run.

use super::buttons::{self as b, Icon, Kind};
use super::{App, Palette, logic};
use crate::i18n::{Lang, lang, tr};
use crate::vault::{self, Place, Vault};
use eframe::egui::{self, CornerRadius, RichText, Stroke, Ui};
use lephy_core::names::escape_display;
use std::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, Ordering};
use std::sync::mpsc::{Receiver, TryRecvError};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant, SystemTime};

/// How often the background watch looks.
const WATCH_EVERY: Duration = Duration::from_secs(2);

/// What the background watch reports.
enum WatchEvent {
    /// It saved and locked the vault.
    Locked(AutoLock),
    /// Saving failed; the vault stays open (it tries again later).
    Failed(String),
}

/// Background watch of an open vault. It runs on its own thread because the window draws
/// nothing (and so runs no code) while it is hidden or the screen is locked — exactly when the
/// vault must lock. It holds its own handle on the vault and saves and locks it itself.
struct Watch {
    stop: Arc<AtomicBool>,
    /// The window is saving or closing the vault: the watch waits.
    ui_busy: Arc<AtomicBool>,
    /// The watch is saving: the window waits.
    active: Arc<AtomicBool>,
    minutes: Arc<AtomicU32>,
    on_lock: Arc<AtomicBool>,
    /// Seconds without input at the last look (`u64::MAX`: unknown).
    idle: Arc<AtomicU64>,
    event: Arc<Mutex<Option<WatchEvent>>>,
}

impl Drop for Watch {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::SeqCst);
        lephy_sys::lifecycle::keep_running(false);
    }
}

/// What the watch thread shares with the window: stop, window busy, watch saving, minutes,
/// lock-on-screen-lock, idle seconds, the reported event.
type WatchHandles = (
    Arc<AtomicBool>,
    Arc<AtomicBool>,
    Arc<AtomicBool>,
    Arc<AtomicU32>,
    Arc<AtomicBool>,
    Arc<AtomicU64>,
    Arc<Mutex<Option<WatchEvent>>>,
);

/// Reads the system: seconds without input, screen locked.
type Probe = fn() -> (Option<u64>, bool);

fn system_probe() -> (Option<u64>, bool) {
    (
        lephy_sys::idle::idle_seconds(),
        lephy_sys::idle::screen_locked(),
    )
}

/// The watch loop: every few seconds decide; on a decision save (if changed) and lock.
#[allow(clippy::needless_pass_by_value, reason = "the thread owns its handles")]
fn watch_loop(mut v: Vault, w: WatchHandles, ctx: egui::Context, probe: Probe) {
    let (stop, ui_busy, active, minutes, on_lock, idle, event) = w;
    let mut last = (Instant::now(), SystemTime::now());
    loop {
        std::thread::sleep(WATCH_EVERY);
        if stop.load(Ordering::SeqCst) {
            return;
        }
        let now = (Instant::now(), SystemTime::now());
        // The monotonic clock stops during sleep; the wall clock does not.
        let mono_d = now.0.duration_since(last.0);
        let wall_d = now.1.duration_since(last.1).unwrap_or_default();
        let woke = wall_d.saturating_sub(mono_d) > Duration::from_secs(30);
        last = now;
        let (secs, locked) = probe();
        idle.store(secs.unwrap_or(u64::MAX), Ordering::Relaxed);
        if ui_busy.load(Ordering::SeqCst) {
            continue;
        }
        let Some(why) = should_auto_lock(
            secs,
            locked,
            woke,
            minutes.load(Ordering::Relaxed),
            on_lock.load(Ordering::Relaxed),
        ) else {
            continue;
        };
        active.store(true, Ordering::SeqCst);
        if stop.load(Ordering::SeqCst) || ui_busy.load(Ordering::SeqCst) {
            active.store(false, Ordering::SeqCst);
            continue;
        }
        let r = if v.changed() { v.save() } else { Ok(()) };
        let ev = match r {
            Ok(()) => {
                // Saved: the open copy goes even if a program still has a file in it open.
                let _ = v.close(true);
                lephy_sys::lifecycle::keep_running(false);
                WatchEvent::Locked(why)
            }
            Err(e) => WatchEvent::Failed(logic::describe_error(&e)),
        };
        let done = matches!(ev, WatchEvent::Locked(_));
        if let Ok(mut slot) = event.lock() {
            *slot = Some(ev);
        }
        active.store(false, Ordering::SeqCst);
        ctx.request_repaint();
        if done {
            return;
        }
        // Try again a little later.
        std::thread::sleep(Duration::from_secs(30));
    }
}

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
    /// Background watch of the open vault (auto-lock).
    watch: Option<Watch>,
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
        if self.watch_saving() {
            return;
        }
        if let Some(w) = &self.vault.watch {
            w.ui_busy.store(true, Ordering::SeqCst);
        }
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
        if self.watch_saving() {
            return false;
        }
        let Some(v) = self.vault.open.take() else {
            return true;
        };
        match v.close(force) {
            Ok(()) => {
                self.vault.watch = None;
                true
            }
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

    /// Starts the background watch for the vault just opened.
    fn start_watch(&mut self, ctx: &egui::Context) {
        self.vault.watch = None;
        let Some(copy) = self.vault.open.as_ref().and_then(Vault::duplicate) else {
            return;
        };
        let w = Watch {
            stop: Arc::new(AtomicBool::new(false)),
            ui_busy: Arc::new(AtomicBool::new(false)),
            active: Arc::new(AtomicBool::new(false)),
            minutes: Arc::new(AtomicU32::new(self.prefs.vault_idle_minutes())),
            on_lock: Arc::new(AtomicBool::new(!self.prefs.vault_keep_on_lock)),
            idle: Arc::new(AtomicU64::new(u64::MAX)),
            event: Arc::new(Mutex::new(None)),
        };
        let handles = (
            Arc::clone(&w.stop),
            Arc::clone(&w.ui_busy),
            Arc::clone(&w.active),
            Arc::clone(&w.minutes),
            Arc::clone(&w.on_lock),
            Arc::clone(&w.idle),
            Arc::clone(&w.event),
        );
        let ctx = ctx.clone();
        // Not napped while hidden: the watch must keep its pace when the screen is locked.
        lephy_sys::lifecycle::keep_running(true);
        std::thread::spawn(move || watch_loop(copy, handles, ctx, system_probe));
        self.vault.watch = Some(w);
    }

    /// Each frame: pass the settings to the watch and take what it reports.
    pub(super) fn auto_lock_vault(&mut self, ctx: &egui::Context) {
        let Some(w) = &self.vault.watch else { return };
        w.minutes
            .store(self.prefs.vault_idle_minutes(), Ordering::Relaxed);
        w.on_lock
            .store(!self.prefs.vault_keep_on_lock, Ordering::Relaxed);
        w.ui_busy.store(self.vault.busy(), Ordering::SeqCst);
        ctx.request_repaint_after(Duration::from_secs(5));
        let ev = w.event.lock().ok().and_then(|mut e| e.take());
        match ev {
            Some(WatchEvent::Locked(why)) => {
                // The watch saved and locked it; the window's handle is just dropped.
                self.vault.watch = None;
                self.vault.open = None;
                self.vault.confirm_discard = false;
                self.vault.msg = Some(
                    match why {
                        AutoLock::Idle => tr(
                            "Kasa, hareketsizlik nedeniyle kaydedilip kilitlendi.",
                            "The vault was saved and locked after a period without input.",
                        ),
                        AutoLock::ScreenLocked => tr(
                            "Ekran kilitlendiği için kasa kaydedilip kilitlendi.",
                            "The vault was saved and locked because the screen locked.",
                        ),
                        AutoLock::Woke => tr(
                            "Bilgisayar uykudan uyandığı için kasa kaydedilip kilitlendi.",
                            "The vault was saved and locked because the computer woke from sleep.",
                        ),
                    }
                    .into(),
                );
            }
            Some(WatchEvent::Failed(e)) => {
                self.vault.msg = Some(match lang() {
                    Lang::Tr => format!(
                        "Kasa kendiliğinden kilitlenemedi; açık kalıyor, birazdan yeniden denenecek. ({e})"
                    ),
                    Lang::En => format!(
                        "The vault could not lock itself; it stays open and will try again shortly. ({e})"
                    ),
                });
            }
            None => {}
        }
    }

    /// Seconds without input seen by the watch.
    fn watch_idle(&self) -> Option<u64> {
        self.vault
            .watch
            .as_ref()
            .map(|w| w.idle.load(Ordering::Relaxed))
            .filter(|s| *s != u64::MAX)
    }

    /// The watch is saving right now.
    fn watch_saving(&self) -> bool {
        self.vault
            .watch
            .as_ref()
            .is_some_and(|w| w.active.load(Ordering::SeqCst))
    }

    /// Finished background steps.
    pub(super) fn poll_vault(&mut self, ctx: &egui::Context) {
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
                self.start_watch(ctx);
                self.reset();
                self.go_home();
            }
            Done::Opened(Err(e)) => self.vault.msg = Some(e),
            Done::Saved(v, Err(e)) => {
                self.vault.open = Some(v);
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
                            self.vault.msg =
                                Some(tr("Kaydedildi ve kilitlendi.", "Saved and locked.").into());
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
                if b::action(ui, pal, Kind::Secondary, Icon::Check, tr("Tamam", "OK")).clicked() {
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
                    .saturating_sub(self.watch_idle().unwrap_or(0))
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
            ui.add_space(6.0);
            b::row(ui, |ui| {
                if b::action(
                    ui,
                    pal,
                    Kind::Primary,
                    Icon::Lock,
                    tr("Kaydet ve kilitle", "Save and lock"),
                )
                .clicked()
                {
                    act = Some(After::Close);
                }
                if b::action(
                    ui,
                    pal,
                    Kind::Secondary,
                    Icon::Folder,
                    tr("Klasörü aç", "Open folder"),
                )
                .clicked()
                {
                    let _ = logic::reveal_in_folder(&root);
                }
                let more = b::action(ui, pal, Kind::Secondary, Icon::More, "")
                    .on_hover_text(tr("Diğer seçenekler", "More options"));
                egui::Popup::menu(&more).show(|ui| {
                    ui.set_min_width(200.0);
                    if b::action(
                        ui,
                        pal,
                        Kind::Secondary,
                        Icon::Save,
                        tr("Yalnızca kaydet (açık kalsın)", "Save only (keep it open)"),
                    )
                    .clicked()
                    {
                        act = Some(After::Stay);
                        ui.close();
                    }
                    if b::action(
                        ui,
                        pal,
                        Kind::Danger,
                        Icon::Close,
                        tr("Kaydetmeden kapat…", "Close without saving…"),
                    )
                    .clicked()
                    {
                        self.vault.confirm_discard = true;
                        ui.close();
                    }
                });
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
                b::row(ui, |ui| {
                    if b::action(
                        ui,
                        pal,
                        Kind::Danger,
                        Icon::Close,
                        tr("Evet, kapat", "Yes, close"),
                    )
                    .clicked()
                    {
                        self.vault.confirm_discard = false;
                        if self.close_vault(false) {
                            self.vault.msg = Some(tr("Kasa kapatıldı.", "Vault closed.").into());
                        }
                    }
                    if b::action(ui, pal, Kind::Secondary, Icon::None, tr("Vazgeç", "Cancel"))
                        .clicked()
                    {
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
                b::row(ui, |ui| {
                    close = b::action(
                        ui,
                        pal,
                        Kind::Danger,
                        Icon::Trash,
                        tr("Evet, sil ve kapat", "Yes, delete and close"),
                    )
                    .clicked();
                    if b::action(ui, pal, Kind::Secondary, Icon::None, tr("Vazgeç", "Cancel"))
                        .clicked()
                    {
                        self.vault.leftover_confirm = false;
                    }
                });
            } else {
                b::row(ui, |ui| {
                    show = b::action(
                        ui,
                        pal,
                        Kind::Secondary,
                        Icon::Folder,
                        tr("Klasörü aç", "Open folder"),
                    )
                    .clicked();
                    if b::action(ui, pal, Kind::Danger, Icon::Trash, tr("Kapat…", "Close…"))
                        .clicked()
                    {
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
            b::row(ui, |ui| {
                if b::action(
                    ui,
                    pal,
                    Kind::Primary,
                    Icon::Lock,
                    tr("Kaydet, kilitle ve çık", "Save, lock and quit"),
                )
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
                let kind = if changed {
                    Kind::Danger
                } else {
                    Kind::Secondary
                };
                if b::action(ui, pal, kind, Icon::None, label).clicked() {
                    choice = Some(1);
                }
                if b::action(ui, pal, Kind::Secondary, Icon::None, tr("Vazgeç", "Cancel")).clicked()
                {
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
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    /// The watch saves and locks on its own thread, with no window drawing at all (as when the
    /// screen is locked).
    #[test]
    fn watch_locks_without_the_window() {
        let d = std::env::temp_dir().join(format!("lphy-watch-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        let pw = lephy_sys::mem::SecretBytes::from_slice(b"watch pass 12345").unwrap();
        let dest = d.join("w.lphy");
        let v = Vault::create(&dest, &pw, None, Some(&d.join("p"))).unwrap();
        std::fs::write(v.root.join("note.txt"), b"written before the lock").unwrap();
        let root = v.root.clone();
        let event = Arc::new(Mutex::new(None));
        let handles = (
            Arc::new(AtomicBool::new(false)),
            Arc::new(AtomicBool::new(false)),
            Arc::new(AtomicBool::new(false)),
            Arc::new(AtomicU32::new(15)),
            Arc::new(AtomicBool::new(true)),
            Arc::new(AtomicU64::new(u64::MAX)),
            Arc::clone(&event),
        );
        let copy = v.duplicate().unwrap();
        drop(v);
        // The screen "locks" (no input seconds known).
        let t = std::thread::spawn(move || {
            watch_loop(copy, handles, egui::Context::default(), || (None, true));
        });
        t.join().unwrap();
        assert!(matches!(
            event.lock().unwrap().take(),
            Some(WatchEvent::Locked(AutoLock::ScreenLocked))
        ));
        assert!(!root.exists(), "the open copy is gone");
        let v = Vault::open(&dest, &pw, None, Some(&d.join("p"))).unwrap();
        assert_eq!(
            std::fs::read(v.root.join("note.txt")).unwrap(),
            b"written before the lock"
        );
        v.close(false).unwrap();
        let _ = std::fs::remove_dir_all(&d);
    }

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
