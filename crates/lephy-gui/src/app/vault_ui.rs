//! Vault in the app: "Open as vault" on the decrypt screen, a bar on every page while a vault is
//! open (show folder, save and lock, close without saving), the quit prompt, and leftovers from
//! an earlier run.

use super::buttons::{self as b, Icon, Kind};
use super::{App, Palette, logic};
use crate::folder_watch;
use crate::i18n::{Lang, lang, tr};
use crate::vault::{self, Place, Vault};
use eframe::egui::{self, CornerRadius, RichText, Stroke, Ui};
use lephy_core::names::escape_display;
use std::sync::atomic::{AtomicBool, AtomicU8, AtomicU32, AtomicU64, Ordering};
use std::sync::mpsc::{Receiver, TryRecvError};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant, SystemTime};

/// How often the background watch looks.
const WATCH_EVERY: Duration = Duration::from_secs(2);
/// How often the folder-closed check looks (it starts small programs).
const FOLDER_EVERY: Duration = Duration::from_secs(10);
/// Longest the sleep hook waits for the vaults to lock.
const SLEEP_WAIT: Duration = Duration::from_secs(25);

/// What the background watch reports.
enum WatchEvent {
    /// It saved and locked the vault.
    Locked(AutoLock),
    /// Saving failed; the vault stays open (it tries again later).
    Failed(String),
    /// The folder-closed check cannot run (permission refused or tool missing).
    FolderCheckOff(folder_watch::Unavailable),
}

/// Asked to lock now: nothing, before sleep, window hidden.
const NOW_NONE: u8 = 0;
const NOW_SLEEP: u8 = 1;
const NOW_HIDDEN: u8 = 2;

/// What a watch thread shares with the window and with the sleep hook.
struct Shared {
    stop: AtomicBool,
    /// The window is saving or closing the vault: the watch waits.
    ui_busy: AtomicBool,
    /// The watch is saving: the window waits.
    active: AtomicBool,
    minutes: AtomicU32,
    on_lock: AtomicBool,
    /// Lock when the vault folder is closed.
    on_folder: AtomicBool,
    /// Seconds without input at the last look (`u64::MAX`: unknown).
    idle: AtomicU64,
    /// Lock now (`NOW_*`).
    lock_now: AtomicU8,
    /// The thread has ended.
    finished: AtomicBool,
    event: Mutex<Option<WatchEvent>>,
}

impl Shared {
    fn new(minutes: u32, on_lock: bool, on_folder: bool) -> Self {
        Self {
            stop: AtomicBool::new(false),
            ui_busy: AtomicBool::new(false),
            active: AtomicBool::new(false),
            minutes: AtomicU32::new(minutes),
            on_lock: AtomicBool::new(on_lock),
            on_folder: AtomicBool::new(on_folder),
            idle: AtomicU64::new(u64::MAX),
            lock_now: AtomicU8::new(NOW_NONE),
            finished: AtomicBool::new(false),
            event: Mutex::new(None),
        }
    }

    fn report(&self, ev: WatchEvent) {
        if let Ok(mut slot) = self.event.lock() {
            *slot = Some(ev);
        }
    }
}

/// Live watches, for the sleep hook (which runs on a system thread).
static LIVE: Mutex<Vec<Arc<Shared>>> = Mutex::new(Vec::new());

/// Watches running: App Nap is held off while there is one.
static RUNNING: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);

/// Asks every live watch to lock now for `why` (`NOW_*`). Returns the watches asked.
fn lock_all_now(why: u8) -> Vec<Arc<Shared>> {
    let Ok(mut live) = LIVE.lock() else {
        return Vec::new();
    };
    live.retain(|s| !s.finished.load(Ordering::SeqCst));
    live.iter()
        .filter(|s| why != NOW_SLEEP || s.on_lock.load(Ordering::Relaxed))
        .map(|s| {
            s.lock_now.store(why, Ordering::SeqCst);
            Arc::clone(s)
        })
        .collect()
}

/// The window is being closed or hidden: every open vault saves and locks (by its watch, as the
/// window stops drawing).
pub(super) fn lock_on_hide() {
    let _ = lock_all_now(NOW_HIDDEN);
}

/// The sleep hook: every open vault whose "lock when the screen locks" is on saves and locks
/// before the computer sleeps; the system waits (up to [`SLEEP_WAIT`]).
fn before_sleep() {
    let asked = lock_all_now(NOW_SLEEP);
    let t = Instant::now();
    while t.elapsed() < SLEEP_WAIT
        && asked.iter().any(|s| {
            !s.finished.load(Ordering::SeqCst) && s.lock_now.load(Ordering::SeqCst) != NOW_NONE
        })
    {
        std::thread::sleep(Duration::from_millis(50));
    }
}

/// Registers [`before_sleep`] with the system once.
pub(super) fn install_sleep_hook() {
    static ONCE: std::sync::Once = std::sync::Once::new();
    ONCE.call_once(|| {
        let _ = lephy_sys::power::on_will_sleep(Box::new(before_sleep));
    });
}

/// Background watch of an open vault. It runs on its own thread because the window draws
/// nothing (and so runs no code) while it is hidden or the screen is locked — exactly when the
/// vault must lock. It holds its own handle on the vault and saves and locks it itself.
struct Watch(Arc<Shared>);

impl std::ops::Deref for Watch {
    type Target = Shared;
    fn deref(&self) -> &Shared {
        &self.0
    }
}

impl Drop for Watch {
    fn drop(&mut self) {
        self.0.stop.store(true, Ordering::SeqCst);
        if RUNNING.fetch_sub(1, Ordering::SeqCst) == 1 {
            lephy_sys::lifecycle::keep_running(false);
        }
    }
}

/// Reads the system: seconds without input, screen locked.
type Probe = fn() -> (Option<u64>, bool);

fn system_probe() -> (Option<u64>, bool) {
    (
        lephy_sys::idle::idle_seconds(),
        lephy_sys::idle::screen_locked(),
    )
}

/// Looks at the vault folder (file-manager windows, open files).
type FolderProbe = fn(&Vault) -> Result<folder_watch::Seen, folder_watch::Unavailable>;

fn system_folder_probe(v: &Vault) -> Result<folder_watch::Seen, folder_watch::Unavailable> {
    let volume = match &v.place {
        Place::Ram(d) => Some(d.mount.as_path()),
        Place::Folder(_) => None,
    };
    folder_watch::look(&v.root, volume)
}

/// Sleeps up to `d`, waking early when asked to stop or to lock now.
fn nap(s: &Shared, d: Duration) {
    let t = Instant::now();
    while t.elapsed() < d {
        if s.stop.load(Ordering::SeqCst) || s.lock_now.load(Ordering::SeqCst) != NOW_NONE {
            return;
        }
        std::thread::sleep(Duration::from_millis(100));
    }
}

/// The watch loop: every few seconds decide; on a decision save (if changed) and lock.
#[allow(clippy::needless_pass_by_value, reason = "the thread owns its handles")]
fn watch_loop(mut v: Vault, s: Arc<Shared>, ctx: egui::Context, probe: Probe, fp: FolderProbe) {
    let mut last = (Instant::now(), SystemTime::now());
    let mut folder = folder_watch::Tracker::default();
    let mut folder_at: Option<Instant> = None;
    loop {
        nap(&s, WATCH_EVERY);
        if s.stop.load(Ordering::SeqCst) {
            break;
        }
        let now = (Instant::now(), SystemTime::now());
        // The monotonic clock stops during sleep; the wall clock does not.
        let mono_d = now.0.duration_since(last.0);
        let wall_d = now.1.duration_since(last.1).unwrap_or_default();
        let woke = wall_d.saturating_sub(mono_d) > Duration::from_secs(30);
        last = now;
        let (secs, locked) = probe();
        s.idle.store(secs.unwrap_or(u64::MAX), Ordering::Relaxed);
        if s.ui_busy.load(Ordering::SeqCst) {
            // The window saves or closes it; a pending request is done by that.
            s.lock_now.store(NOW_NONE, Ordering::SeqCst);
            continue;
        }
        let mut folder_closed = false;
        if s.on_folder.load(Ordering::Relaxed)
            && folder_at.is_none_or(|t| t.elapsed() >= FOLDER_EVERY)
        {
            folder_at = Some(now.0);
            match fp(&v) {
                Ok(seen) => folder_closed = folder.step(seen, now.0),
                Err(e) => {
                    s.on_folder.store(false, Ordering::Relaxed);
                    s.report(WatchEvent::FolderCheckOff(e));
                    ctx.request_repaint();
                }
            }
        }
        let asked = match s.lock_now.load(Ordering::SeqCst) {
            NOW_SLEEP => Some(AutoLock::Sleep),
            NOW_HIDDEN => Some(AutoLock::Hidden),
            _ => None,
        };
        let Some(why) = asked
            .or_else(|| folder_closed.then_some(AutoLock::FolderClosed))
            .or_else(|| {
                should_auto_lock(
                    secs,
                    locked,
                    woke,
                    s.minutes.load(Ordering::Relaxed),
                    s.on_lock.load(Ordering::Relaxed),
                )
            })
        else {
            continue;
        };
        s.active.store(true, Ordering::SeqCst);
        if s.stop.load(Ordering::SeqCst) || s.ui_busy.load(Ordering::SeqCst) {
            s.active.store(false, Ordering::SeqCst);
            continue;
        }
        let r = if v.changed() { v.save() } else { Ok(()) };
        let ev = match r {
            Ok(()) => {
                // Saved: the open copy goes even if a program still has a file in it open.
                let _ = v.close(true);
                WatchEvent::Locked(why)
            }
            Err(e) => WatchEvent::Failed(logic::describe_error(&e)),
        };
        let done = matches!(ev, WatchEvent::Locked(_));
        s.report(ev);
        s.lock_now.store(NOW_NONE, Ordering::SeqCst);
        s.active.store(false, Ordering::SeqCst);
        ctx.request_repaint();
        if done {
            break;
        }
        // Try again a little later.
        nap(&s, Duration::from_secs(30));
    }
    s.finished.store(true, Ordering::SeqCst);
}

/// A finished save: the vault handed back and the result.
type Saved = (Vault, Result<(), String>);

/// What to do after saving.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum After {
    /// Keep the vault open.
    Stay,
    /// Close it (lock).
    Close,
    /// Close it as part of quitting the app.
    Quit,
}

/// One open vault with its own watch, save step, note and confirmation.
#[allow(
    clippy::struct_excessive_bools,
    reason = "independent flags of one card"
)]
pub(super) struct OpenVault {
    /// Stable id while it is open.
    pub(super) id: u64,
    /// The vault (`None` while a save step holds it).
    pub(super) v: Option<Vault>,
    /// The archive it was opened from.
    source: std::path::PathBuf,
    /// Its name (file name of the archive), escaped for display.
    name: String,
    watch: Option<Watch>,
    saving: Option<(Receiver<Saved>, After)>,
    confirm_discard: bool,
    msg: Option<String>,
    /// Shown in full when three or more vaults are open.
    expanded: bool,
    /// The recipient editor is open (vaults locked to public keys).
    pub(super) editing: bool,
    /// Key typed into the recipient editor.
    new_key: String,
    /// The stick it came from was pulled out.
    detached: bool,
}

impl OpenVault {
    fn new(id: u64, v: Vault) -> Self {
        let name = v
            .source
            .file_name()
            .map(|f| escape_display(&f.to_string_lossy()))
            .unwrap_or_default();
        Self {
            id,
            source: v.source.clone(),
            v: Some(v),
            name,
            watch: None,
            saving: None,
            confirm_discard: false,
            msg: None,
            expanded: false,
            editing: false,
            new_key: String::new(),
            detached: false,
        }
    }

    /// A save step runs.
    fn busy(&self) -> bool {
        self.saving.is_some()
    }

    /// The watch is saving right now.
    fn watch_saving(&self) -> bool {
        self.watch
            .as_ref()
            .is_some_and(|w| w.active.load(Ordering::SeqCst))
    }

    /// Seconds without input seen by the watch.
    fn watch_idle(&self) -> Option<u64> {
        self.watch
            .as_ref()
            .map(|w| w.idle.load(Ordering::Relaxed))
            .filter(|s| *s != u64::MAX)
    }

    /// Unsaved changes.
    fn changed(&self) -> bool {
        self.v.as_ref().is_some_and(Vault::changed)
    }
}

/// Vault state of the app.
#[derive(Default)]
pub(super) struct VaultUi {
    /// The open vaults (any number).
    pub(super) open: Vec<OpenVault>,
    /// Opening or creating one runs.
    opening: Option<Receiver<Result<Vault, String>>>,
    /// A note not tied to an open vault.
    msg: Option<String>,
    /// Places left from an earlier run.
    pub(super) leftovers: Vec<Place>,
    leftover_confirm: bool,
    /// Vault page: what is being prepared.
    pub(super) page: super::vault_page::PageForm,
    /// Quit once every vault has been saved and locked.
    quit_after: bool,
    /// The folder-closed check could not run; off for this session.
    folder_check_off: bool,
    next_id: u64,
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
    /// The computer is about to sleep.
    Sleep,
    /// The window was closed or hidden.
    Hidden,
    /// The vault folder was closed and nothing in it is open.
    FolderClosed,
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
        self.opening.is_some() || self.open.iter().any(OpenVault::busy)
    }

    /// Opening or creating a vault runs.
    pub(super) fn opening(&self) -> bool {
        self.opening.is_some()
    }

    /// Names of the open vaults.
    pub(super) fn names(&self) -> Vec<String> {
        self.open.iter().map(|o| o.name.clone()).collect()
    }

    /// Any vault is open.
    pub(super) fn any_open(&self) -> bool {
        !self.open.is_empty()
    }

    /// Adds an opened vault; returns its id.
    pub(super) fn add(&mut self, v: Vault) -> u64 {
        self.next_id += 1;
        let id = self.next_id;
        self.open.push(OpenVault::new(id, v));
        id
    }

    fn get(&mut self, id: u64) -> Option<&mut OpenVault> {
        self.open.iter_mut().find(|o| o.id == id)
    }

    /// The vault opened from `source`, if it is open.
    fn is_open(&self, source: &std::path::Path) -> bool {
        self.open.iter().any(|o| o.source == source)
    }

    /// A vault file is open (for the stick bar).
    pub(super) fn is_open_path(&self, source: &std::path::Path) -> bool {
        self.is_open(source)
    }

    /// The stick at `mount` was pulled out: its vaults cannot be saved there now.
    pub(super) fn stick_gone(&mut self, mount: &std::path::Path) {
        for o in &mut self.open {
            if o.source.starts_with(mount) {
                o.detached = true;
            }
        }
    }

    /// The stick at `mount` is back.
    pub(super) fn stick_back(&mut self, mount: &std::path::Path) {
        for o in &mut self.open {
            if o.source.starts_with(mount) {
                o.detached = false;
            }
        }
    }
}

pub(super) fn bar(ui: &mut Ui, pal: Palette, warn: bool, body: impl FnOnce(&mut Ui)) {
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

/// How a vault is opened or created.
pub(super) enum OpenHow {
    /// Password and optional key file.
    Password(lephy_sys::mem::SecretBytes, Option<std::path::PathBuf>),
    /// Identity file, its password, and (creating) post-quantum keys.
    Identity(std::path::PathBuf, lephy_sys::mem::SecretBytes, bool),
}

/// What a vault card asks for.
enum CardAct {
    Save(After),
    SaveAs,
    Discard,
    Confirm(bool),
    Expand(bool),
    DismissMsg,
}

impl App {
    /// The chosen file can be opened as a vault (shown on the decrypt screen).
    pub(super) fn vault_offer(&mut self, ui: &mut Ui, ctx: &egui::Context, pal: Palette) {
        let Some(src) = &self.source else { return };
        if self.vault.opening.is_some() || (self.identity_required && self.identity.is_none()) {
            return;
        }
        let path = src.path.clone();
        let why = if self.vault.is_open(&path) {
            Some(tr("Bu kasa zaten açık.", "This vault is already open."))
        } else {
            vault::unsuitable(&path)
        };
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
        let how = match (&self.identity, self.identity_required) {
            (Some(id), true) => OpenHow::Identity(id.clone(), pw, false),
            _ => OpenHow::Password(pw, self.keyfile.clone()),
        };
        self.start_vault_job(ctx, path, how, false);
    }

    /// Opens (`create = false`) or creates and opens a vault in the background.
    pub(super) fn start_vault_job(
        &mut self,
        ctx: &egui::Context,
        path: std::path::PathBuf,
        how: OpenHow,
        create: bool,
    ) {
        if self.vault.opening.is_some() {
            return;
        }
        if self.vault.is_open(&path) {
            self.vault.msg = Some(tr("Bu kasa zaten açık.", "This vault is already open.").into());
            return;
        }
        let folder = if cfg!(target_os = "macos") {
            None
        } else {
            vault::folder_base()
        };
        let (tx, rx) = std::sync::mpsc::channel();
        let ctx2 = ctx.clone();
        std::thread::spawn(move || {
            let folder = folder.as_deref();
            let r = match (&how, create) {
                (OpenHow::Password(pw, kf), true) => {
                    Vault::create(&path, pw, kf.as_deref(), folder)
                }
                (OpenHow::Password(pw, kf), false) => Vault::open(&path, pw, kf.as_deref(), folder),
                (OpenHow::Identity(id, pw, pq), true) => {
                    Vault::create_for_identity(&path, id, pw, *pq, folder)
                }
                (OpenHow::Identity(id, pw, _), false) => {
                    Vault::open_with_identity(&path, id, pw, folder)
                }
            }
            .map_err(|e| logic::describe_error(&e));
            drop(how);
            let _ = tx.send(r);
            ctx2.request_repaint();
        });
        self.vault.opening = Some(rx);
        self.vault.msg = None;
    }

    /// Saves vault `id` in the background, then does `after`.
    fn start_vault_save(&mut self, ctx: &egui::Context, id: u64, after: After) {
        let Some(o) = self.vault.get(id) else { return };
        if o.watch_saving() || o.busy() {
            return;
        }
        if let Some(w) = &o.watch {
            w.ui_busy.store(true, Ordering::SeqCst);
        }
        let Some(mut v) = o.v.take() else { return };
        let (tx, rx) = std::sync::mpsc::channel();
        let ctx2 = ctx.clone();
        std::thread::spawn(move || {
            let r = if v.changed() {
                v.save().map_err(|e| logic::describe_error(&e))
            } else {
                Ok(())
            };
            let _ = tx.send((v, r));
            ctx2.request_repaint();
        });
        o.saving = Some((rx, after));
        o.msg = None;
    }

    /// Asks where to save vault `id` (its stick was removed), then saves it there; the vault
    /// stays open and from now on belongs to the new file.
    fn save_vault_as(&mut self, ctx: &egui::Context, id: u64) {
        let Some(o) = self.vault.get(id) else { return };
        if o.busy() || o.watch_saving() {
            return;
        }
        let Some(p) = rfd::FileDialog::new()
            .set_title(tr("Kasayı kaydedin", "Save the vault"))
            .set_file_name(o.name.clone())
            .add_filter("lephycrypy", &["lphy"])
            .save_file()
        else {
            return;
        };
        let p = if p.extension().is_some_and(|e| e == "lphy") {
            p
        } else {
            p.with_extension("lphy")
        };
        let Some(v) = o.v.as_mut() else { return };
        v.source.clone_from(&p);
        o.source.clone_from(&p);
        o.name = p
            .file_name()
            .map(|f| escape_display(&f.to_string_lossy()))
            .unwrap_or_default();
        o.detached = false;
        // A changed source counts as a change: the file there must be written.
        v.mark_changed();
        // The watch holds its own copy with the old file: start a new one.
        self.start_watch(ctx, id);
        self.start_vault_save(ctx, id, After::Stay);
    }

    /// Destroys the open copy of vault `id`; on a busy RAM disk it stays open with a note.
    fn close_vault(&mut self, id: u64, force: bool) -> bool {
        let Some(i) = self.vault.open.iter().position(|o| o.id == id) else {
            return true;
        };
        let o = &mut self.vault.open[i];
        if o.watch_saving() || o.busy() {
            return false;
        }
        let r = o.v.as_ref().map_or(Ok(()), |v| v.close(force));
        match r {
            Ok(()) => {
                self.vault.open.remove(i);
                true
            }
            Err(e) => {
                o.msg = Some(match lang() {
                    Lang::Tr => format!(
                        "Kasa kapatılamadı; bir program içindeki bir dosyayı hâlâ açık tutuyor olabilir. Programları kapatıp yeniden deneyin. ({e})"
                    ),
                    Lang::En => format!(
                        "The vault could not be closed; a program may still have a file in it open. Close it and try again. ({e})"
                    ),
                });
                false
            }
        }
    }

    /// Starts the background watch for vault `id`.
    fn start_watch(&mut self, ctx: &egui::Context, id: u64) {
        let minutes = self.prefs.vault_idle_minutes();
        let on_lock = !self.prefs.vault_keep_on_lock;
        let on_folder = !self.prefs.vault_keep_on_folder_close && !self.vault.folder_check_off;
        let Some(o) = self.vault.get(id) else { return };
        o.watch = None;
        let Some(copy) = o.v.as_ref().and_then(Vault::duplicate) else {
            return;
        };
        let shared = Arc::new(Shared::new(minutes, on_lock, on_folder));
        if let Ok(mut live) = LIVE.lock() {
            live.push(Arc::clone(&shared));
        }
        let ctx = ctx.clone();
        // Not napped while hidden: the watch must keep its pace when the screen is locked.
        if RUNNING.fetch_add(1, Ordering::SeqCst) == 0 {
            lephy_sys::lifecycle::keep_running(true);
        }
        let s2 = Arc::clone(&shared);
        std::thread::spawn(move || {
            watch_loop(copy, s2, ctx, system_probe, system_folder_probe);
        });
        let w = Watch(shared);
        o.watch = Some(w);
    }

    /// Each frame: pass the settings to the watches and take what they report.
    pub(super) fn auto_lock_vault(&mut self, ctx: &egui::Context) {
        if self.vault.open.is_empty() {
            return;
        }
        let minutes = self.prefs.vault_idle_minutes();
        let on_lock = !self.prefs.vault_keep_on_lock;
        let on_folder = !self.prefs.vault_keep_on_folder_close && !self.vault.folder_check_off;
        ctx.request_repaint_after(Duration::from_secs(5));
        let mut locked = Vec::new();
        let mut folder_off = None;
        for o in &mut self.vault.open {
            let busy = o.busy();
            let Some(w) = &o.watch else { continue };
            w.minutes.store(minutes, Ordering::Relaxed);
            w.on_lock.store(on_lock, Ordering::Relaxed);
            w.on_folder.store(on_folder, Ordering::Relaxed);
            w.ui_busy.store(busy, Ordering::SeqCst);
            let ev = w.event.lock().ok().and_then(|mut e| e.take());
            match ev {
                Some(WatchEvent::Locked(why)) => locked.push((o.id, o.name.clone(), why)),
                Some(WatchEvent::Failed(e)) => {
                    o.msg = Some(match lang() {
                        Lang::Tr => format!(
                            "Kasa kendiliğinden kilitlenemedi; açık kalıyor, birazdan yeniden denenecek. ({e})"
                        ),
                        Lang::En => format!(
                            "The vault could not lock itself; it stays open and will try again shortly. ({e})"
                        ),
                    });
                }
                Some(WatchEvent::FolderCheckOff(e)) => folder_off = Some(e),
                None => {}
            }
        }
        if let Some(e) = folder_off {
            self.vault.folder_check_off = true;
            self.vault.msg = Some(
                match e {
                    folder_watch::Unavailable::NotAllowed => tr(
                        "\"Kasa klasörü kapatılınca kilitle\" çalışamıyor: Finder'ı denetleme izni verilmedi. Sistem Ayarları › Gizlilik ve Güvenlik › Otomasyon'dan izin verip uygulamayı yeniden açın.",
                        "\"Lock when the vault folder is closed\" cannot work: permission to control Finder was not given. Allow it in System Settings › Privacy & Security › Automation and reopen the app.",
                    ),
                    folder_watch::Unavailable::Failed => tr(
                        "\"Kasa klasörü kapatılınca kilitle\" bu sistemde çalışamıyor; bu oturumda kapatıldı.",
                        "\"Lock when the vault folder is closed\" cannot work on this system; it is off for this session.",
                    ),
                }
                .into(),
            );
        }
        for (id, name, why) in locked {
            // The watch saved and locked it; the window's handle is just dropped.
            self.vault.open.retain(|o| o.id != id);
            let why = match (lang(), why) {
                (Lang::Tr, AutoLock::Idle) => "hareketsizlik nedeniyle",
                (Lang::Tr, AutoLock::ScreenLocked) => "ekran kilitlendiği için",
                (Lang::Tr, AutoLock::Woke) => "bilgisayar uykudan uyandığı için",
                (Lang::Tr, AutoLock::Sleep) => "bilgisayar uykuya geçerken",
                (Lang::Tr, AutoLock::Hidden) => "pencere kapatıldığı için",
                (Lang::Tr, AutoLock::FolderClosed) => "klasörü kapatıldığı için",
                (Lang::En, AutoLock::Sleep) => "as the computer went to sleep",
                (Lang::En, AutoLock::Hidden) => "because the window was closed",
                (Lang::En, AutoLock::FolderClosed) => "because its folder was closed",
                (Lang::En, AutoLock::Idle) => "after a period without input",
                (Lang::En, AutoLock::ScreenLocked) => "because the screen locked",
                (Lang::En, AutoLock::Woke) => "because the computer woke from sleep",
            };
            self.vault.msg = Some(match lang() {
                Lang::Tr => format!("{name} {why} kaydedilip kilitlendi."),
                Lang::En => format!("{name} was saved and locked {why}."),
            });
        }
    }

    /// Finished background steps.
    pub(super) fn poll_vault(&mut self, ctx: &egui::Context) {
        if let Some(rx) = &self.vault.opening {
            match rx.try_recv() {
                Ok(Ok(v)) => {
                    self.vault.opening = None;
                    let _ = logic::reveal_in_folder(&v.root);
                    let id = self.vault.add(v);
                    self.start_watch(ctx, id);
                    self.reset();
                    self.go_home();
                }
                Ok(Err(e)) => {
                    self.vault.opening = None;
                    self.vault.msg = Some(e);
                }
                Err(TryRecvError::Disconnected) => self.vault.opening = None,
                Err(TryRecvError::Empty) => {}
            }
        }
        let mut finished = Vec::new();
        for o in &mut self.vault.open {
            let Some((rx, after)) = &o.saving else {
                continue;
            };
            let after = *after;
            match rx.try_recv() {
                Ok(d) => {
                    o.saving = None;
                    finished.push((o.id, after, d));
                }
                Err(TryRecvError::Disconnected) => o.saving = None,
                Err(TryRecvError::Empty) => {}
            }
        }
        for (id, after, (v, r)) in finished {
            let Some(o) = self.vault.get(id) else {
                continue;
            };
            o.v = Some(v);
            if let Err(e) = r {
                o.msg = Some(match lang() {
                    Lang::Tr => format!("Kaydedilemedi; şifreli dosya değişmedi, kasa açık. ({e})"),
                    Lang::En => format!(
                        "Not saved; the encrypted file is unchanged and the vault stays open. ({e})"
                    ),
                });
                if after == After::Quit && self.vault.quit_after {
                    // Saving failed while quitting: ask instead.
                    self.vault.quit_after = false;
                    self.quit_confirm = true;
                }
                continue;
            }
            match after {
                After::Stay => o.msg = Some(tr("Kaydedildi.", "Saved.").into()),
                After::Close | After::Quit => {
                    let name = o.name.clone();
                    if self.close_vault(id, false) {
                        if after == After::Close {
                            self.vault.msg = Some(match lang() {
                                Lang::Tr => format!("{name} kaydedildi ve kilitlendi."),
                                Lang::En => format!("{name} was saved and locked."),
                            });
                        }
                    } else if after == After::Quit && self.vault.quit_after {
                        self.vault.quit_after = false;
                        self.quit_confirm = true;
                    }
                }
            }
        }
        if self.vault.quit_after && self.vault.open.is_empty() {
            self.vault.quit_after = false;
            self.quitting = true;
        }
    }

    /// The cards shown on every page while vaults are open (and leftovers / notes).
    pub(super) fn vault_bar(&mut self, ui: &mut Ui, ctx: &egui::Context, pal: Palette) {
        self.leftover_bar(ui, pal);
        if let Some(m) = self.vault.msg.clone() {
            ui.horizontal(|ui| {
                ui.label(RichText::new(m).color(pal.muted).size(12.5));
                if b::action(ui, pal, Kind::Secondary, Icon::Check, tr("Tamam", "OK")).clicked() {
                    self.vault.msg = None;
                }
            });
            ui.add_space(6.0);
        }
        if self.vault.opening.is_some() {
            bar(ui, pal, false, |ui| {
                ui.horizontal(|ui| {
                    ui.spinner();
                    ui.label(tr("Kasa açılıyor…", "Opening the vault…"));
                });
            });
        }
        let compact = self.vault.open.len() >= 3;
        let minutes = self.prefs.vault_idle_minutes();
        let mut acts = Vec::new();
        for o in &mut self.vault.open {
            if let Some(a) = vault_card(ui, pal, o, compact, minutes) {
                acts.push((o.id, a));
            }
        }
        for (id, a) in acts {
            match a {
                CardAct::Save(after) => self.start_vault_save(ctx, id, after),
                CardAct::SaveAs => self.save_vault_as(ctx, id),
                CardAct::Discard => {
                    let name = self.vault.get(id).map(|o| o.name.clone());
                    if self.close_vault(id, false) {
                        self.vault.msg = name.map(|n| match lang() {
                            Lang::Tr => format!("{n} kaydedilmeden kapatıldı."),
                            Lang::En => format!("{n} was closed without saving."),
                        });
                    }
                }
                CardAct::Confirm(on) => {
                    if let Some(o) = self.vault.get(id) {
                        o.confirm_discard = on;
                    }
                }
                CardAct::Expand(on) => {
                    if let Some(o) = self.vault.get(id) {
                        o.expanded = on;
                    }
                }
                CardAct::DismissMsg => {
                    if let Some(o) = self.vault.get(id) {
                        o.msg = None;
                    }
                }
            }
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

    /// Quit asked while vaults are open (and no job runs): save and lock them first, or not.
    pub(super) fn vault_quit_prompt(&mut self, ui: &mut Ui, ctx: &egui::Context, pal: Palette) {
        let n = self.vault.open.len();
        let changed = self.vault.open.iter().any(OpenVault::changed);
        let mut choice = None;
        bar(ui, pal, true, |ui| {
            ui.label(
                RichText::new(match (lang(), n) {
                    (Lang::Tr, 1) => "Bir kasa açık. Çıkmadan önce kaydedip kilitleyin.".to_owned(),
                    (Lang::Tr, _) => format!("{n} kasa açık. Çıkmadan önce kaydedip kilitleyin."),
                    (Lang::En, 1) => {
                        "A vault is open. Save and lock it before quitting.".to_owned()
                    }
                    (Lang::En, _) => {
                        format!("{n} vaults are open. Save and lock them before quitting.")
                    }
                })
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
                self.save_all_and_quit(ctx);
            }
            Some(1) => {
                self.quit_confirm = false;
                let ids: Vec<u64> = self.vault.open.iter().map(|o| o.id).collect();
                let mut all = true;
                for id in ids {
                    all &= self.close_vault(id, true);
                }
                if all {
                    self.quitting = true;
                }
            }
            Some(2) => self.quit_confirm = false,
            _ => {}
        }
    }

    /// Saves and locks every open vault, then quits (unless one fails).
    pub(super) fn save_all_and_quit(&mut self, ctx: &egui::Context) {
        self.vault.quit_after = true;
        let ids: Vec<u64> = self.vault.open.iter().map(|o| o.id).collect();
        for id in ids {
            self.start_vault_save(ctx, id, After::Quit);
        }
        if self.vault.open.is_empty() {
            self.vault.quit_after = false;
            self.quitting = true;
        }
    }
}

/// One open vault: name, place, state and its buttons.
#[allow(clippy::too_many_lines, reason = "one card with its confirmation")]
fn vault_card(
    ui: &mut Ui,
    pal: Palette,
    o: &mut OpenVault,
    compact: bool,
    minutes: u32,
) -> Option<CardAct> {
    let mut act = None;
    let full = !compact || o.expanded;
    let changed = o.changed();
    bar(ui, pal, o.detached, |ui| {
        ui.horizontal(|ui| {
            ui.label(
                RichText::new(match lang() {
                    Lang::Tr => format!("Kasa açık: {}", o.name),
                    Lang::En => format!("Vault open: {}", o.name),
                })
                .font(crate::fonts::semibold(14.0))
                .color(pal.ink),
            );
            if changed && !full {
                ui.label(
                    RichText::new(tr("· kaydedilmemiş değişiklik", "· unsaved changes"))
                        .color(pal.accent)
                        .size(12.0),
                );
            }
            if compact {
                ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                    let label = if o.expanded {
                        tr("Daralt", "Collapse")
                    } else {
                        tr("Ayrıntılar", "Details")
                    };
                    if super::link_button(ui, pal, label).clicked() {
                        act = Some(CardAct::Expand(!o.expanded));
                    }
                });
            }
        });
        if o.detached {
            ui.label(
                RichText::new(tr(
                    "Bellek çıkarıldı: değişiklikler oraya kaydedilemiyor. Belleği yeniden takın ya da kasayı başka bir yere kaydedin.",
                    "The stick was removed: changes cannot be saved to it. Plug it back in or save the vault somewhere else.",
                ))
                .color(pal.danger)
                .size(12.5),
            );
            b::row(ui, |ui| {
                if b::action(
                    ui,
                    pal,
                    Kind::Primary,
                    Icon::Save,
                    tr("Başka yere kaydet…", "Save somewhere else…"),
                )
                .clicked()
                {
                    act = Some(CardAct::SaveAs);
                }
            });
        }
        if full {
            let place = match o.v.as_ref().map(|v| &v.place) {
                Some(Place::Ram(_)) => tr(
                    "RAM diskte (yalnızca bellekte)",
                    "on a RAM disk (memory only)",
                ),
                Some(Place::Folder(_)) => {
                    tr("özel bir uygulama klasöründe", "in a private app folder")
                }
                None => tr("kaydediliyor…", "saving…"),
            };
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
            if minutes > 0 {
                let left = (u64::from(minutes) * 60)
                    .saturating_sub(o.watch_idle().unwrap_or(0))
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
        }
        if let Some(m) = &o.msg {
            ui.horizontal_wrapped(|ui| {
                ui.label(RichText::new(m).color(pal.danger).size(12.5));
                if super::link_button(ui, pal, tr("Tamam", "OK")).clicked() {
                    act = Some(CardAct::DismissMsg);
                }
            });
        }
        if o.busy() || o.watch_saving() {
            ui.horizontal(|ui| {
                ui.spinner();
                ui.label(tr("Kaydediliyor…", "Saving…"));
            });
            return;
        }
        ui.add_space(6.0);
        let root = o.v.as_ref().map(|v| v.root.clone());
        b::row(ui, |ui| {
            if b::action(
                ui,
                pal,
                if o.detached {
                    Kind::Secondary
                } else {
                    Kind::Primary
                },
                Icon::Lock,
                tr("Kaydet ve kilitle", "Save and lock"),
            )
            .clicked()
            {
                act = Some(CardAct::Save(After::Close));
            }
            if b::action(
                ui,
                pal,
                Kind::Secondary,
                Icon::Folder,
                tr("Klasörü aç", "Open folder"),
            )
            .clicked()
                && let Some(r) = &root
            {
                let _ = logic::reveal_in_folder(r);
            }
            if o.v.as_ref().is_some_and(Vault::uses_recipients) {
                let n =
                    o.v.as_ref()
                        .map_or(0, |v| read_list(v).map_or(0, |l| l.len()));
                let label = match lang() {
                    Lang::Tr => format!("Alıcılar ({n})"),
                    Lang::En => format!("Recipients ({n})"),
                };
                if b::action(ui, pal, Kind::Secondary, Icon::Add, &label).clicked() {
                    o.editing = !o.editing;
                }
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
                    act = Some(CardAct::Save(After::Stay));
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
                    act = Some(CardAct::Confirm(true));
                    ui.close();
                }
            });
        });
        if o.v.as_ref().is_some_and(Vault::uses_recipients) {
            recipients_editor(ui, pal, o);
        }
        if o.confirm_discard {
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
                    act = Some(CardAct::Discard);
                }
                if b::action(ui, pal, Kind::Secondary, Icon::None, tr("Vazgeç", "Cancel")).clicked()
                {
                    act = Some(CardAct::Confirm(false));
                }
            });
        }
    });
    act
}

/// Key lines of an open vault's recipient list (`None`: unreadable).
fn read_list(v: &Vault) -> Option<Vec<String>> {
    let text = std::fs::read_to_string(v.root.join(vault::RECIPIENTS_FILE)).ok()?;
    Some(
        text.lines()
            .map(str::trim)
            .filter(|l| !l.is_empty() && !l.starts_with('#'))
            .map(str::to_owned)
            .collect(),
    )
}

fn write_list(v: &Vault, keys: &[String]) -> std::io::Result<()> {
    let mut text = String::from("# lephycrypy+ vault recipients: one public key per line\n");
    for k in keys {
        text.push_str(k);
        text.push('\n');
    }
    std::fs::write(v.root.join(vault::RECIPIENTS_FILE), text)
}

/// Shortened key for display.
fn short_key(k: &str) -> String {
    let n = k.chars().count();
    if n <= 28 {
        return k.to_owned();
    }
    let head: String = k.chars().take(16).collect();
    let tail: String = k.chars().skip(n - 8).collect();
    format!("{head}…{tail}")
}

/// The recipient list of a vault locked to public keys: remove (not the opener's own key) and
/// add keys. Changes are written to the list inside the vault and take effect on save.
#[allow(clippy::too_many_lines, reason = "one small editor: list, add, write")]
fn recipients_editor(ui: &mut Ui, pal: Palette, o: &mut OpenVault) {
    if !o.editing {
        return;
    }
    let Some(v) = o.v.as_ref() else { return };
    let pq = v.pq();
    let own = v.own_key().unwrap_or_default();
    let Some(mut keys) = read_list(v) else {
        ui.label(
            RichText::new(tr(
                "Alıcı listesi okunamadı.",
                "The recipient list could not be read.",
            ))
            .color(pal.danger)
            .size(12.5),
        );
        return;
    };
    ui.add_space(6.0);
    ui.label(
        RichText::new(tr(
            "Bu kasayı açabilecek açık anahtarlar. Değişiklik bir sonraki kaydetmede geçerli olur; listeden çıkarılan biri eski kopyaları açmaya devam eder.",
            "Public keys that can open this vault. Changes apply on the next save; someone removed from the list can still open older copies.",
        ))
        .color(pal.muted)
        .size(12.0),
    );
    let mut remove = None;
    for (i, k) in keys.iter().enumerate() {
        ui.horizontal(|ui| {
            ui.label(
                RichText::new(short_key(k))
                    .monospace()
                    .size(12.0)
                    .color(pal.ink),
            );
            if *k == own {
                ui.label(
                    RichText::new(tr("(siz)", "(you)"))
                        .size(12.0)
                        .color(pal.muted),
                );
            } else if b::action(ui, pal, Kind::Secondary, Icon::Close, tr("Çıkar", "Remove"))
                .clicked()
            {
                remove = Some(i);
            }
        });
    }
    let mut add = None;
    ui.horizontal(|ui| {
        let hint = if pq { "lphypq1…" } else { "lphy1…" };
        ui.add(
            egui::TextEdit::singleline(&mut o.new_key)
                .hint_text(hint)
                .desired_width((ui.available_width() - 240.0).max(120.0)),
        );
        if b::action(ui, pal, Kind::Secondary, Icon::Add, tr("Ekle", "Add")).clicked() {
            add = Some(o.new_key.trim().to_owned());
        }
        if b::action(
            ui,
            pal,
            Kind::Secondary,
            Icon::File,
            tr("Dosyadan…", "From file…"),
        )
        .clicked()
            && let Some(p) = rfd::FileDialog::new()
                .set_title(tr("Açık anahtar dosyası (.pub)", "Public key file (.pub)"))
                .pick_file()
        {
            add = std::fs::read_to_string(p).ok();
        }
    });
    let mut changed = false;
    if let Some(i) = remove {
        keys.remove(i);
        changed = true;
    }
    if let Some(text) = add {
        let found: Result<Vec<String>, String> = if pq {
            logic::parse_hybrid(&text).map(|ks| ks.iter().map(ToString::to_string).collect())
        } else {
            logic::parse_recipients(&text).map(|ks| ks.iter().map(ToString::to_string).collect())
        };
        match found {
            Ok(ks) if !ks.is_empty() => {
                for k in ks {
                    if !keys.contains(&k) {
                        keys.push(k);
                        changed = true;
                    }
                }
                o.new_key.clear();
                o.msg = None;
            }
            Ok(_) => {}
            Err(e) => o.msg = Some(e),
        }
    }
    if changed && let Err(e) = write_list(v, &keys) {
        o.msg = Some(e.to_string());
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
        let shared = Arc::new(Shared::new(15, true, false));
        let copy = v.duplicate().unwrap();
        drop(v);
        // The screen "locks" (no input seconds known).
        let s2 = Arc::clone(&shared);
        let t = std::thread::spawn(move || {
            watch_loop(
                copy,
                s2,
                egui::Context::default(),
                || (None, true),
                |_| Err(folder_watch::Unavailable::Failed),
            );
        });
        t.join().unwrap();
        assert!(matches!(
            shared.event.lock().unwrap().take(),
            Some(WatchEvent::Locked(AutoLock::ScreenLocked))
        ));
        assert!(shared.finished.load(Ordering::SeqCst));
        assert!(!root.exists(), "the open copy is gone");
        let v = Vault::open(&dest, &pw, None, Some(&d.join("p"))).unwrap();
        assert_eq!(
            std::fs::read(v.root.join("note.txt")).unwrap(),
            b"written before the lock"
        );
        v.close(false).unwrap();
        let _ = std::fs::remove_dir_all(&d);
    }

    /// Asked to lock now (window hidden, before sleep): the watch saves and locks at once, with
    /// no idle time and an unlocked screen; the sleep hook waits until it is done.
    #[test]
    fn lock_now_request() {
        let d = std::env::temp_dir().join(format!("lphy-watch-now-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        let pw = lephy_sys::mem::SecretBytes::from_slice(b"watch pass 12345").unwrap();
        let v = Vault::create(&d.join("n.lphy"), &pw, None, Some(&d.join("p"))).unwrap();
        std::fs::write(v.root.join("x.txt"), b"x").unwrap();
        let shared = Arc::new(Shared::new(0, true, false));
        LIVE.lock().unwrap().push(Arc::clone(&shared));
        let copy = v.duplicate().unwrap();
        drop(v);
        let s2 = Arc::clone(&shared);
        let t = std::thread::spawn(move || {
            watch_loop(
                copy,
                s2,
                egui::Context::default(),
                || (Some(0), false),
                |_| Err(folder_watch::Unavailable::Failed),
            );
        });
        before_sleep();
        t.join().unwrap();
        assert!(matches!(
            shared.event.lock().unwrap().take(),
            Some(WatchEvent::Locked(AutoLock::Sleep))
        ));
        let v = Vault::open(&d.join("n.lphy"), &pw, None, Some(&d.join("p"))).unwrap();
        assert_eq!(std::fs::read(v.root.join("x.txt")).unwrap(), b"x");
        v.close(false).unwrap();
        let _ = std::fs::remove_dir_all(&d);
    }

    /// Two vaults open side by side; one is saved and locked, the other stays open; the cards
    /// draw for one, two and three vaults.
    #[test]
    fn several_vaults() {
        let d = std::env::temp_dir().join(format!("lphy-vaults-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        let pw = lephy_sys::mem::SecretBytes::from_slice(b"several vaults 1234").unwrap();
        let ctx = egui::Context::default();
        let mut app = App::default();
        let mut ids = Vec::new();
        for n in ["a", "b", "c"] {
            let v =
                Vault::create(&d.join(format!("{n}.lphy")), &pw, None, Some(&d.join("p"))).unwrap();
            std::fs::write(v.root.join("note.txt"), n.as_bytes()).unwrap();
            ids.push(app.vault.add(v));
            let mut out = ctx.run_ui(egui::RawInput::default(), |ui| app.draw(ui));
            out.textures_delta.clear();
        }
        assert!(app.vault.is_open(&d.join("b.lphy")));
        app.start_vault_save(&ctx, ids[0], After::Close);
        let t = Instant::now();
        while app.vault.open.len() == 3 && t.elapsed() < Duration::from_mins(1) {
            std::thread::sleep(Duration::from_millis(20));
            app.poll_vault(&ctx);
        }
        assert_eq!(app.vault.open.len(), 2, "only the first one locked");
        assert!(!app.vault.is_open(&d.join("a.lphy")));
        assert!(app.vault.is_open(&d.join("b.lphy")));
        let v = Vault::open(&d.join("a.lphy"), &pw, None, Some(&d.join("q"))).unwrap();
        assert_eq!(std::fs::read(v.root.join("note.txt")).unwrap(), b"a");
        v.close(false).unwrap();
        for id in [ids[1], ids[2]] {
            assert!(app.close_vault(id, true));
        }
        assert!(!app.vault.any_open());
        // A vault locked to public keys, with its recipient editor open.
        crate::logic::create_identity(&d.join("me.lphykey"), &pw, 64).unwrap();
        let v = Vault::create_for_identity(
            &d.join("r.lphy"),
            &d.join("me.lphykey"),
            &pw,
            false,
            Some(&d.join("p")),
        )
        .unwrap();
        let id = app.vault.add(v);
        app.vault.get(id).unwrap().editing = true;
        let mut out = ctx.run_ui(egui::RawInput::default(), |ui| app.draw(ui));
        out.textures_delta.clear();
        assert!(app.close_vault(id, true));
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
