//! Single-window UI. Flow: drop/choose → password → encrypt/decrypt → result.
//! The visual language is in `theme.rs`; icons are drawn with a few lines, not images.

use crate::i18n::{Lang, lang, tr};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::mpsc::{Receiver, TryRecvError};
use std::time::{Duration, Instant};

use eframe::egui::{
    self, Align, Color32, CornerRadius, CursorIcon, Layout, Pos2, Rect, Response, RichText, Sense,
    Stroke, StrokeKind, Ui, WidgetInfo, pos2, vec2,
};
use lephy_core::names::escape_display;
use lephy_core::password::MIN_SCALARS;

use crate::fonts;
use crate::logic::{self, Job, Mode, Outcome};
use crate::secret_field::SecretField;
use crate::theme::{self, Palette};

/// Maximum width of the content column.
const COLUMN_W: f32 = 460.0;

/// Password-derivation memory presets (MiB, Turkish name, English name).
const KDF_PRESETS: [(u32, &str, &str); 4] = [
    (256, "Hızlı", "Fast"),
    (512, "Önerilen", "Recommended"),
    (1024, "Güçlü", "Strong"),
    (2048, "En güçlü", "Strongest"),
];

/// The chosen source.
struct Source {
    path: PathBuf,
    /// All sources (several in a batch; the first is `path`).
    paths: Vec<PathBuf>,
    mode: Mode,
    name: String,
    detail: String,
    /// Header summary of an encrypted file (algorithm, memory, content type).
    summary: Option<String>,
}

enum Stage {
    Pick,
    Ready,
    Running { since: Instant },
    Done(Outcome),
}

type JobResult = Result<Outcome, String>;

/// Uygulama durumu.
#[allow(clippy::struct_excessive_bools)]
pub struct App {
    source: Option<Source>,
    output: Option<PathBuf>,
    stage: Stage,
    password: SecretField,
    confirm: SecretField,
    kdf_mib: u32,
    aes: bool,
    pad: bool,
    allow_cloud: bool,
    show_advanced: bool,
    error: Option<String>,
    job: Option<Receiver<JobResult>>,
    /// Whether the interruption came from the Cancel button (not a signal → the window stays open).
    cancel_requested: bool,
    /// Selected key file.
    keyfile: Option<PathBuf>,
    /// Securely delete the original after encryption (advanced settings).
    secure_delete: bool,
    /// Part size for splitting (MiB; 0 = off).
    split_mib: u64,
    /// Compress before encrypting.
    compress: bool,
    /// Add an error-correction envelope.
    ecc: bool,
    /// Recovery mode when decrypting.
    recover: bool,
    /// Waiting for secure-deletion confirmation (Encrypt was pressed).
    confirm_delete: bool,
    /// Generated passphrase: shown once so the user can write it down (in locked memory).
    generated: Option<lephy_sys::mem::SecretBytes>,
    /// The file to open needs a key file.
    keyfile_required: bool,
    /// Content height measured in the last frame (for vertical centring).
    content_h: f32,
    /// Whether term explanations are open in the advanced settings.
    show_help: bool,
    /// Physical memory (MiB; 0 if unknown). KDF options that are too large are disabled.
    ram_mib: u64,
    /// Estimated total stream bytes of the job (0: unknown).
    total: Arc<AtomicU64>,
    /// Encrypt to public keys instead of a password.
    use_keys: bool,
    /// Recipient public keys, one per line.
    recipients_text: String,
    /// Identity file for opening a file encrypted to a public key.
    identity: Option<PathBuf>,
    /// The chosen encrypted file needs an identity.
    identity_required: bool,
    /// The key-pair creation card is open.
    show_keygen: bool,
    /// Public key of the key pair created in this session (shown with a copy link).
    created_pub: Option<String>,
    /// Paper backup (22 words) of the key pair created in this session, until hidden.
    paper: Option<lephy_sys::mem::SecretBytes>,
    /// Files received from the operating system, not yet applied.
    pending_open: Vec<PathBuf>,
    /// Which start-screen page is shown while nothing is chosen.
    page: pages::Page,
    /// Saved settings (welcome seen, language, app lock).
    prefs: crate::settings::Settings,
    /// The app lock is on and not yet opened in this session.
    locked: bool,
    /// Lock screen / lock settings: password fields and the last message.
    lock_pw: SecretField,
    lock_new: SecretField,
    lock_new2: SecretField,
    lock_msg: Option<String>,
    /// The lock settings are being changed (turning on, or off).
    lock_edit: bool,
    /// Quitting was requested while a job runs: ask first.
    quit_confirm: bool,
    /// Quitting was confirmed (or a signal arrived): close once the job has stopped.
    quitting: bool,
    /// Welcome screen step (0-based).
    welcome_step: u8,
    /// Keys page: identity to open, its password, the result and the background job.
    id_path: Option<PathBuf>,
    id_pw: SecretField,
    id_loaded: Option<pages::LoadedId>,
    id_job: Option<Receiver<std::result::Result<pages::LoadedId, String>>>,
    id_show_paper: bool,
    /// Encrypting to public keys: use the recipients' post-quantum hybrid keys.
    pq: bool,
    /// The chosen encrypted file uses post-quantum hybrid recipients.
    file_pq: bool,
    /// Encrypting: sign with `sign_identity`.
    sign: bool,
    /// Signing identity file.
    sign_identity: Option<PathBuf>,
    /// Password of the signing identity.
    sign_password: SecretField,
    /// The chosen encrypted file is an archive (its contents can be listed).
    is_archive: bool,
    /// The user picked the destination with "Change" (single item): it is used as is; otherwise a
    /// decrypted file gets its stored original name.
    output_custom: bool,
    /// Contents of the chosen archive, after "List contents".
    listing: Option<Vec<lephy_core::archive::ListEntry>>,
    /// Paths chosen for extraction from `listing` (empty = everything).
    selected: std::collections::BTreeSet<String>,
    /// Filter text for the listing.
    list_filter: String,
    /// Decrypting a file encrypted to public keys: replace its recipient list instead.
    edit_recipients: bool,
    /// The system integration change (Explorer on Windows, Quick Action on macOS) awaits
    /// confirmation.
    #[cfg_attr(not(any(windows, target_os = "macos")), allow(dead_code))]
    confirm_shell: bool,
    /// Result of the last integration change, shown on the settings page.
    #[cfg_attr(not(any(windows, target_os = "macos")), allow(dead_code))]
    settings_note: Option<String>,
    /// Leftover temp items (crash leftovers) found by a scan.
    stale: maintenance::Stale,
    /// Scan the usual folders for leftovers on the first frame (the real app, not tests).
    scan_on_start: bool,
    /// The window is currently kept out of screenshots and screen sharing.
    capture_protected: bool,
    /// My keys › restore from paper backup.
    restore: restore::Restore,
    /// App-lock password checks (background, with back-off).
    lock_gate: lockgate::LockGate,
    /// The system asks to reduce motion (read once at start, on the main thread).
    reduce_motion: bool,
    /// Short message that fades out (e.g. "Copied"): text and the time it appeared.
    toast: Option<(String, f64)>,
    /// Settings: the list or one of its pages.
    settings_pane: settings_ui::Pane,
}

impl Default for App {
    fn default() -> Self {
        Self {
            source: None,
            output: None,
            stage: Stage::Pick,
            password: SecretField::new("Parola", "Password"),
            confirm: SecretField::new("Parolayı tekrar girin", "Repeat the password"),
            kdf_mib: 512,
            aes: false,
            pad: true,
            allow_cloud: false,
            show_advanced: false,
            error: None,
            job: None,
            cancel_requested: false,
            keyfile: None,
            keyfile_required: false,
            generated: None,
            secure_delete: false,
            split_mib: 0,
            compress: false,
            ecc: false,
            recover: false,
            confirm_delete: false,
            content_h: 0.0,
            show_help: false,
            ram_mib: lephy_sys::platform::physical_memory_bytes().map_or(0, |b| b / (1024 * 1024)),
            total: Arc::new(AtomicU64::new(0)),
            use_keys: false,
            recipients_text: String::new(),
            identity: None,
            identity_required: false,
            show_keygen: false,
            created_pub: None,
            paper: None,
            pending_open: Vec::new(),
            page: pages::Page::Home,
            prefs: crate::settings::Settings::default(),
            locked: false,
            lock_pw: SecretField::new("Uygulama parolası", "App password"),
            lock_new: SecretField::new("Yeni uygulama parolası", "New app password"),
            lock_new2: SecretField::new("Parolayı tekrar girin", "Repeat the password"),
            lock_msg: None,
            lock_edit: false,
            quit_confirm: false,
            quitting: false,
            welcome_step: 0,
            id_path: None,
            id_pw: SecretField::new("Kimlik parolası", "Identity password"),
            id_loaded: None,
            id_job: None,
            id_show_paper: false,
            pq: false,
            file_pq: false,
            sign: false,
            sign_identity: None,
            sign_password: SecretField::new(
                "İmza kimliğinin parolası",
                "Signing identity password",
            ),
            is_archive: false,
            output_custom: false,
            listing: None,
            selected: std::collections::BTreeSet::new(),
            list_filter: String::new(),
            edit_recipients: false,
            confirm_shell: false,
            settings_note: None,
            stale: maintenance::Stale::default(),
            scan_on_start: false,
            capture_protected: false,
            restore: restore::Restore::default(),
            lock_gate: lockgate::LockGate::default(),
            reduce_motion: false,
            toast: None,
            settings_pane: settings_ui::Pane::Root,
        }
    }
}

// ---------------------------------------------------------------------------------------------
// State transitions
// ---------------------------------------------------------------------------------------------

impl App {
    fn set_source(&mut self, p: &Path) {
        if logic::is_identity_file(p) {
            // Decrypting it would write the secret key to disk unprotected.
            self.reset();
            self.error = Some(
                tr(
                    "Bu bir kimlik dosyası (.lphykey); çözülmez. Açık anahtarlı dosyaları açmak için şifreli dosyayı bırakın, kimliği o ekranda seçin.",
                    "This is an identity file (.lphykey); it is not decrypted. To open a file encrypted to a public key, drop that file and choose the identity on its screen.",
                )
                .into(),
            );
            return;
        }
        let mode = logic::detect_mode(p);
        let (name, detail) = logic::describe_source(p, mode);
        self.output = Some(logic::default_output(p, mode));
        self.output_custom = false;
        let summary = (mode == Mode::Decrypt)
            .then(|| logic::header_summary(p))
            .flatten();
        self.source = Some(Source {
            path: p.to_path_buf(),
            paths: vec![p.to_path_buf()],
            mode,
            name,
            detail,
            summary,
        });
        self.stage = Stage::Ready;
        self.error = None;
        self.allow_cloud = false;
        self.keyfile = None;
        self.generated = None;
        self.recover = false;
        self.keyfile_required = mode == Mode::Decrypt && logic::needs_keyfile(p);
        self.identity = None;
        self.identity_required = mode == Mode::Decrypt && logic::needs_identity(p);
        self.show_keygen = false;
        self.password.clear();
        self.confirm.clear();
        self.is_archive = mode == Mode::Decrypt
            && lephy_core::ops::info(p)
                .is_ok_and(|h| h.content_type == lephy_core::header::ContentType::Archive);
        self.listing = None;
        self.selected.clear();
        self.list_filter.clear();
        self.edit_recipients = false;
        self.file_pq = mode == Mode::Decrypt && lephy_core::ops::info(p).is_ok_and(|h| h.pq);
    }

    /// Several sources: all must suit the same operation (all encrypted or none).
    fn set_sources(&mut self, paths: &[PathBuf]) {
        self.confirm_shell = false;
        // Every part of a split set stands for the set (its first part).
        let paths = logic::collapse_parts(paths);
        match paths.as_slice() {
            [] => {}
            [one] => self.set_source(one),
            many => {
                let modes: Vec<Mode> = many.iter().map(|p| logic::detect_mode(p)).collect();
                let mode = modes[0];
                if modes.iter().any(|m| *m != mode) {
                    self.reset();
                    self.error = Some(
                        tr(
                            "Şifreli (.lphy) ve şifresiz dosyalar birlikte seçilemez. Önce birini, sonra diğerini işleyin.",
                            "Encrypted (.lphy) and unencrypted files cannot be mixed. Process one group, then the other.",
                        )
                        .to_string(),
                    );
                    return;
                }
                self.set_source(&many[0]);
                let names: Vec<String> = many
                    .iter()
                    .take(4)
                    .map(|p| logic::describe_source(p, mode).0)
                    .collect();
                let more = many.len().saturating_sub(4);
                if let Some(src) = &mut self.source {
                    src.paths = many.to_vec();
                    src.name = match lang() {
                        Lang::Tr => format!("{} öğe", many.len()),
                        Lang::En => format!("{} items", many.len()),
                    };
                    src.detail = if more > 0 {
                        match lang() {
                            Lang::Tr => format!("{} ve {more} öğe daha", names.join(", ")),
                            Lang::En => format!("{} and {more} more", names.join(", ")),
                        }
                    } else {
                        names.join(", ")
                    };
                    src.summary = None;
                }
                // In a batch the output is a folder: each source is written there as its own file.
                self.output = many[0].parent().map(Path::to_path_buf);
                self.keyfile_required =
                    mode == Mode::Decrypt && many.iter().any(|p| logic::needs_keyfile(p));
                self.identity_required =
                    mode == Mode::Decrypt && many.iter().any(|p| logic::needs_identity(p));
            }
        }
        // "Change" and "Another file" come back to the page that fits what was chosen.
        self.page = match self.mode() {
            Some(Mode::Encrypt) => pages::Page::Encrypt,
            Some(Mode::Decrypt) => pages::Page::Decrypt,
            None => pages::Page::Home,
        };
    }

    fn batch(&self) -> bool {
        self.source.as_ref().is_some_and(|s| s.paths.len() > 1)
    }

    fn reset(&mut self) {
        self.source = None;
        self.output = None;
        self.stage = Stage::Pick;
        self.error = None;
        self.allow_cloud = false;
        self.keyfile = None;
        self.keyfile_required = false;
        self.identity = None;
        self.identity_required = false;
        self.show_keygen = false;
        self.generated = None;
        self.password.clear();
        self.confirm.clear();
    }

    fn running(&self) -> bool {
        self.job.is_some()
    }

    fn mode(&self) -> Option<Mode> {
        self.source.as_ref().map(|s| s.mode)
    }

    fn cloud_root(&self) -> Option<PathBuf> {
        if self.mode() != Some(Mode::Decrypt) {
            return None;
        }
        self.output
            .as_deref()
            .and_then(lephy_sys::fs::cloud_root_of)
    }

    fn can_start(&self) -> bool {
        let Some(src) = &self.source else {
            return false;
        };
        if self.running() || self.output.is_none() {
            return false;
        }
        match src.mode {
            Mode::Encrypt
                if self.sign && (self.sign_identity.is_none() || self.sign_password.is_empty()) =>
            {
                false
            }
            Mode::Encrypt if self.use_keys => {
                !self.show_keygen && self.key_count().is_ok_and(|n| n > 0)
            }
            Mode::Encrypt => {
                !self.password.is_empty()
                    && self.password.char_count() >= MIN_SCALARS
                    && self.password.same_as(&self.confirm)
            }
            Mode::Decrypt if self.identity_required && self.edit_recipients => {
                !self.password.is_empty()
                    && self.identity.is_some()
                    && self.key_count().is_ok_and(|n| n > 0)
            }
            Mode::Decrypt => {
                !self.password.is_empty()
                    && (!self.keyfile_required || self.keyfile.is_some())
                    && (!self.identity_required || self.identity.is_some())
                    && (self.cloud_root().is_none() || self.allow_cloud)
            }
        }
    }

    fn start(&mut self, ctx: &egui::Context) {
        self.start_job(ctx, false);
    }

    /// Starts a job; `list_only` lists the archive's contents instead of extracting.
    fn start_job(&mut self, ctx: &egui::Context, list_only: bool) {
        let (Some(src), Some(output)) = (&self.source, &self.output) else {
            return;
        };
        let mode = src.mode;
        let items: Vec<logic::Item> = if src.paths.len() > 1 {
            src.paths
                .iter()
                .map(|p| {
                    let name = logic::default_output(p, mode)
                        .file_name()
                        .map(std::ffi::OsStr::to_os_string)
                        .unwrap_or_default();
                    logic::Item {
                        input: p.clone(),
                        output: output.join(name),
                    }
                })
                .collect()
        } else {
            vec![logic::Item {
                input: src.path.clone(),
                output: output.clone(),
            }]
        };
        let key_mode = (mode == Mode::Encrypt && self.use_keys)
            || (mode == Mode::Decrypt && self.identity_required && self.edit_recipients);
        let (recipients, hybrid) = self.job_keys(key_mode);
        let job = Job {
            hybrid,
            recipients,
            identity: if mode == Mode::Decrypt && self.identity_required {
                self.identity.clone()
            } else {
                None
            },
            mode,
            items,
            password: self.password.take(),
            confirm: (mode == Mode::Encrypt && !key_mode).then(|| self.confirm.take()),
            kdf_mib: self.kdf_mib,
            aes: self.aes,
            pad: self.pad,
            allow_cloud: self.allow_cloud,
            keyfile: self.keyfile.clone(),
            secure_delete: self.secure_delete && !key_mode,
            split: (self.split_mib > 0).then_some(self.split_mib * 1024 * 1024),
            compress: self.compress,
            ecc: self.ecc,
            recover: self.recover,
            sign_identity: (mode == Mode::Encrypt && self.sign)
                .then(|| self.sign_identity.clone())
                .flatten(),
            sign_password: (mode == Mode::Encrypt && self.sign).then(|| self.sign_password.take()),
            restore_name: mode == Mode::Decrypt && (src.paths.len() > 1 || !self.output_custom),
            list_only,
            only: if list_only || self.listing.is_none() {
                Vec::new()
            } else {
                self.selected.iter().cloned().collect()
            },
        };
        self.confirm_delete = false;
        self.confirm.clear();
        // A cancellation left over from the previous job is cleared before the job starts (on the UI
        // thread), so a Cancel pressed during size estimation is not lost.
        lephy_sys::signal::reset_cancel();
        self.cancel_requested = false;
        let (tx, rx) = std::sync::mpsc::channel();
        let ctx2 = ctx.clone();
        self.total.store(0, Ordering::Relaxed);
        lephy_core::pipeline::reset_progress();
        let total = Arc::clone(&self.total);
        std::thread::spawn(move || {
            let sum = job
                .items
                .iter()
                .map(|i| logic::estimate_total(job.mode, &i.input))
                .sum();
            total.store(sum, Ordering::Relaxed);
            let r = if lephy_sys::signal::interrupted() {
                // Cancelled during size estimation: key derivation never starts.
                Err(logic::describe_error(
                    &lephy_core::error::Error::Interrupted,
                ))
            } else {
                logic::run(job).map_err(|e| logic::describe_error(&e))
            };
            let _ = tx.send(r);
            ctx2.request_repaint();
        });
        self.job = Some(rx);
        self.error = None;
        self.stage = Stage::Running {
            since: Instant::now(),
        };
    }

    fn poll(&mut self, ctx: &egui::Context) {
        let Some(rx) = &self.job else { return };
        match rx.try_recv() {
            Ok(Ok(mut out)) => {
                if let Some(entries) = out.listing.take() {
                    // A listing: back to the decryption screen with the contents shown.
                    self.listing = Some(entries);
                    self.selected.clear();
                    self.stage = Stage::Ready;
                } else {
                    self.stage = Stage::Done(out);
                }
                self.job = None;
            }
            Ok(Err(msg)) => {
                self.error = Some(msg);
                self.stage = Stage::Ready;
                self.job = None;
            }
            Err(TryRecvError::Empty) => ctx.request_repaint_after(Duration::from_millis(16)),
            Err(TryRecvError::Disconnected) => {
                self.error = Some(
                    tr(
                        "İşlem beklenmedik biçimde sona erdi.",
                        "The operation ended unexpectedly.",
                    )
                    .into(),
                );
                self.stage = Stage::Ready;
                self.job = None;
            }
        }
        if self.job.is_none() && self.cancel_requested {
            // Cancel button: the flag is cleared and the app stays open.
            lephy_sys::signal::reset_cancel();
            self.cancel_requested = false;
        }
    }

    /// SIGINT/SIGTERM/Ctrl+C: when idle, close the window; when a job runs, the job stops first (temp
    /// files removed), then it closes. Repaints regularly to notice a signal while idle.
    fn handle_signal(&mut self, ctx: &egui::Context) {
        lephy_sys::lifecycle::set_busy(self.running());
        // SIGINT/SIGTERM: the job (if any) stops on its own; then the app closes.
        if lephy_sys::signal::signalled() {
            self.quitting = true;
        }
        // Cmd+Q / Dock → Quit while a job runs: ask first.
        if lephy_sys::lifecycle::take_quit_request() {
            self.quit_confirm = true;
            ctx.send_viewport_cmd(egui::ViewportCommand::Focus);
        }
        // The close button only hides the window; the job continues and the Dock icon brings the
        // window back. Quitting is Cmd+Q or Dock → Quit (Windows: closing while a job runs
        // minimises instead).
        if !self.quitting && ctx.input(|i| i.viewport().close_requested()) {
            if cfg!(target_os = "macos") {
                ctx.send_viewport_cmd(egui::ViewportCommand::CancelClose);
                let _ = lephy_sys::lifecycle::hide_app();
            } else if self.running() {
                ctx.send_viewport_cmd(egui::ViewportCommand::CancelClose);
                ctx.send_viewport_cmd(egui::ViewportCommand::Minimized(true));
            }
        }
        if self.quitting && !self.running() {
            lephy_sys::lifecycle::allow_quit();
            ctx.send_viewport_cmd(egui::ViewportCommand::Close);
        }
        ctx.request_repaint_after(Duration::from_millis(400));
    }

    /// Files the operating system asked us to open (Finder, Explorer, Dock). They wait while a
    /// job runs or a deletion is being confirmed.
    fn handle_open_requests(&mut self, ctx: &egui::Context) {
        self.pending_open
            .extend(lephy_sys::open_docs::take_pending());
        if self.pending_open.is_empty() || self.running() || self.confirm_delete {
            return;
        }
        // An item is already chosen (a password may be typed): another program must not swap it
        // silently. The banner in `open_request_banner` asks first.
        if self.awaits_open_confirmation() {
            ctx.request_repaint();
            return;
        }
        let paths = std::mem::take(&mut self.pending_open);
        self.set_sources(&paths);
        ctx.send_viewport_cmd(egui::ViewportCommand::Focus);
    }

    /// Items from the operating system wait for the user's decision (see `handle_open_requests`).
    fn awaits_open_confirmation(&self) -> bool {
        !self.pending_open.is_empty() && matches!(self.stage, Stage::Ready) && self.source.is_some()
    }

    /// Asks before replacing the chosen item with items sent by the operating system.
    fn open_request_banner(&mut self, ui: &mut Ui, ctx: &egui::Context, pal: Palette) {
        if !self.awaits_open_confirmation() || self.running() {
            return;
        }
        let first = self.pending_open[0]
            .file_name()
            .map(|n| n.to_string_lossy().into_owned())
            .unwrap_or_default();
        let n = self.pending_open.len();
        let mut replace = false;
        let mut ignore = false;
        egui::Frame::new()
            .fill(pal.accent_soft)
            .corner_radius(CornerRadius::same(theme::R_INPUT))
            .inner_margin(egui::Margin::same(12))
            .show(ui, |ui| {
                ui.set_width(ui.available_width());
                ui.label(
                    RichText::new(match (lang(), n) {
                        (Lang::Tr, 1) => format!("“{first}” açılmak isteniyor."),
                        (Lang::Tr, _) => {
                            format!("“{first}” ve {} öğe daha açılmak isteniyor.", n - 1)
                        }
                        (Lang::En, 1) => format!("A request to open “{first}” arrived."),
                        (Lang::En, _) => {
                            format!("A request to open “{first}” and {} more arrived.", n - 1)
                        }
                    })
                    .font(fonts::semibold(13.5))
                    .color(pal.ink),
                );
                ui.label(
                    RichText::new(tr(
                        "Değiştirirseniz şu anki seçim ve yazdığınız parola silinir.",
                        "Replacing clears the current choice and the password you typed.",
                    ))
                    .color(pal.muted)
                    .size(12.5),
                );
                ui.horizontal(|ui| {
                    replace = link_button(ui, pal, tr("Değiştir", "Replace")).clicked();
                    ui.add_space(12.0);
                    ignore = link_button(ui, pal, tr("Yoksay", "Ignore")).clicked();
                });
            });
        ui.add_space(14.0);
        if replace {
            let paths = std::mem::take(&mut self.pending_open);
            self.set_sources(&paths);
            ctx.send_viewport_cmd(egui::ViewportCommand::Focus);
        } else if ignore {
            self.pending_open.clear();
        }
    }

    fn handle_drop(&mut self, ctx: &egui::Context) {
        if self.running() {
            return;
        }
        let dropped: Vec<PathBuf> = ctx.input(|i| {
            i.raw
                .dropped_files
                .iter()
                .map(|f| f.path().to_path_buf())
                .collect()
        });
        if !dropped.is_empty() {
            self.set_sources(&dropped);
        }
    }

    fn pick_file(&mut self) {
        if let Some(ps) = rfd::FileDialog::new()
            .set_title(tr("Dosya seçin", "Choose files"))
            .pick_files()
        {
            self.set_sources(&ps);
        }
    }

    fn pick_folder(&mut self) {
        if let Some(p) = rfd::FileDialog::new()
            .set_title(tr(
                "Şifrelenecek klasörü seçin",
                "Choose a folder to encrypt",
            ))
            .pick_folder()
        {
            self.set_sources(&[p]);
        }
    }

    fn choose_output(&mut self) {
        let Some(cur) = &self.output else { return };
        if self.batch() {
            // In a batch the output is a folder.
            if let Some(p) = rfd::FileDialog::new()
                .set_title(tr("Çıktı klasörünü seçin", "Choose the output folder"))
                .set_directory(cur)
                .pick_folder()
            {
                self.output = Some(p);
                self.allow_cloud = false;
                self.error = None;
            }
            return;
        }
        let mut d =
            rfd::FileDialog::new().set_title(tr("Kaydedilecek yeri seçin", "Choose where to save"));
        if let Some(dir) = cur.parent() {
            d = d.set_directory(dir);
        }
        if let Some(name) = cur.file_name() {
            d = d.set_file_name(name.to_string_lossy());
        }
        if let Some(p) = d.save_file() {
            self.output = Some(p);
            self.output_custom = true;
            self.allow_cloud = false;
            self.error = None;
        }
    }
}

// ---------------------------------------------------------------------------------------------
// Drawing
// ---------------------------------------------------------------------------------------------

impl App {
    /// The whole UI for one frame.
    pub fn draw(&mut self, ui: &mut Ui) {
        let ctx = ui.ctx().clone();
        if std::mem::take(&mut self.scan_on_start) {
            self.stale.scan(&ctx, logic::usual_output_dirs());
        }
        crate::motion::set_enabled(!self.prefs.anim_off && !self.reduce_motion);
        self.poll(&ctx);
        self.poll_lock_check(&ctx);
        self.handle_escape(&ctx);
        self.guard_capture();
        self.handle_signal(&ctx);
        self.handle_open_requests(&ctx);
        self.handle_drop(&ctx);
        if !self.running()
            && ctx.input_mut(|i| i.consume_key(egui::Modifiers::COMMAND, egui::Key::O))
        {
            self.pick_file();
        }
        let pal = theme::palette(&ctx);

        let view = ui.available_rect_before_wrap();
        let w = COLUMN_W.min(view.width() - 40.0).max(240.0);
        let pad_x = ((view.width() - w) / 2.0).max(0.0);
        let top = ((view.height() - self.content_h) / 2.0 - 8.0).max(22.0);
        egui::ScrollArea::vertical()
            .auto_shrink([false, false])
            .show(ui, |ui| {
                ui.horizontal(|ui| {
                    ui.add_space(pad_x);
                    ui.vertical(|ui| {
                        ui.set_width(w);
                        ui.add_space(top);
                        let r = ui.vertical(|ui| {
                            ui.horizontal(|ui| {
                                ui.label(
                                    RichText::new("lephycrypy+")
                                        .font(fonts::semibold(15.0))
                                        .color(pal.ink),
                                );
                                let home_link = !self.locked
                                    && match self.stage {
                                        Stage::Pick => !matches!(
                                            self.page,
                                            pages::Page::Home | pages::Page::Welcome
                                        ),
                                        Stage::Ready | Stage::Done(_) => true,
                                        Stage::Running { .. } => false,
                                    };
                                if home_link {
                                    ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                                        if link_button(ui, pal, tr("‹ Ana sayfa", "‹ Home"))
                                            .clicked()
                                        {
                                            self.reset();
                                            self.go_home();
                                        }
                                    });
                                }
                            });
                            ui.add_space(10.0);
                            // New page, step or stage: fade in and slide up a little.
                            let t = crate::motion::since_change(
                                &ctx,
                                egui::Id::unique("page-transition"),
                                self.view_key(),
                                crate::motion::PAGE_SECS,
                            );
                            ui.set_opacity(t);
                            ui.add_space(8.0 * (1.0 - t));
                            self.quit_confirm_view(ui, pal);
                            if self.locked {
                                self.lock_view(ui, pal);
                                return;
                            }
                            self.open_request_banner(ui, &ctx, pal);
                            match self.stage {
                                Stage::Pick => match self.page {
                                    pages::Page::Welcome => self.welcome_view(ui, pal),
                                    pages::Page::Home => self.home_view(ui, pal),
                                    pages::Page::Encrypt => self.encrypt_view(ui, pal),
                                    pages::Page::Decrypt => self.decrypt_view(ui, pal),
                                    pages::Page::Help => self.help_view(ui, pal),
                                    pages::Page::Keys => self.keys_view(ui, pal),
                                    pages::Page::Settings => self.settings_view(ui, pal),
                                },
                                Stage::Ready => self.ready_view(ui, &ctx, pal),
                                Stage::Running { since } => self.running_view(ui, pal, since),
                                Stage::Done(_) => self.done_view(ui, pal),
                            }
                        });
                        self.toast_view(&ctx, pal);
                        let h = r.response.rect.height();
                        if (h - self.content_h).abs() > 1.0 {
                            self.content_h = h;
                            ctx.request_repaint();
                        }
                        ui.add_space(24.0);
                    });
                });
            });
    }

    /// Identifies what is on screen (page, stage, welcome step) for the page transition.
    fn view_key(&self) -> u64 {
        let stage = match self.stage {
            Stage::Pick => 0u64,
            Stage::Ready => 1,
            Stage::Running { .. } => 2,
            Stage::Done(_) => 3,
        };
        (self.page as u64)
            | (stage << 8)
            | (u64::from(self.welcome_step) << 16)
            | (u64::from(self.locked) << 24)
            | ((self.settings_pane as u64) << 32)
    }

    /// Esc goes one step back: from a chosen file to its page, from a page to Home.
    fn handle_escape(&mut self, ctx: &egui::Context) {
        if self.running()
            || self.locked
            || !ctx.input_mut(|i| i.consume_key(egui::Modifiers::NONE, egui::Key::Escape))
        {
            return;
        }
        match self.stage {
            Stage::Ready | Stage::Done(_) => self.reset(),
            Stage::Pick
                if self.page == pages::Page::Settings
                    && self.settings_pane != settings_ui::Pane::Root =>
            {
                self.settings_pane = settings_ui::Pane::Root;
                self.lock_edit = false;
                self.confirm_shell = false;
            }
            Stage::Pick if !matches!(self.page, pages::Page::Home | pages::Page::Welcome) => {
                self.go_home();
            }
            _ => {}
        }
    }

    /// Shows a short message that fades out after two seconds.
    pub(super) fn show_toast(&mut self, ctx: &egui::Context, text: &str) {
        self.toast = Some((text.to_owned(), ctx.input(|i| i.time)));
    }

    fn toast_view(&mut self, ctx: &egui::Context, pal: Palette) {
        let Some((text, at)) = &self.toast else {
            return;
        };
        let age = ctx.input(|i| i.time) - at;
        if age > 2.2 {
            self.toast = None;
            return;
        }
        ctx.request_repaint();
        #[allow(clippy::cast_possible_truncation, reason = "a fraction of a second")]
        let alpha = if crate::motion::enabled() {
            ((2.2 - age) / 0.4)
                .clamp(0.0, 1.0)
                .min((age / 0.15).clamp(0.0, 1.0)) as f32
        } else {
            1.0
        };
        let screen = ctx.content_rect();
        egui::Area::new(egui::Id::unique("toast"))
            .order(egui::Order::Foreground)
            .fixed_pos(pos2(screen.center().x, screen.bottom() - 56.0))
            .pivot(egui::Align2::CENTER_CENTER)
            .interactable(false)
            .show(ctx, |ui| {
                ui.set_opacity(alpha);
                egui::Frame::new()
                    .fill(pal.ink)
                    .corner_radius(CornerRadius::same(theme::R_INPUT))
                    .inner_margin(egui::Margin::symmetric(14, 8))
                    .show(ui, |ui| {
                        ui.label(RichText::new(text.as_str()).color(pal.bg).size(13.0));
                    });
            });
    }

    /// Secrets that would be readable in a screenshot are on screen: paper-backup words, a
    /// generated password, the lock screen.
    fn secret_on_screen(&self) -> bool {
        self.paper.is_some()
            || self.generated.is_some()
            || (self.id_show_paper && self.page == pages::Page::Keys)
            || self.restore.words_visible()
            || self.locked
    }

    /// Keeps the window out of screenshots and screen sharing while a secret is on screen.
    fn guard_capture(&mut self) {
        let want = self.secret_on_screen();
        if want != self.capture_protected {
            self.capture_protected = want;
            // Tests run off the main thread, where AppKit must not be touched.
            #[cfg(not(test))]
            let _ = lephy_sys::capture::set_protected(want);
        }
    }

    fn set_language(&mut self, next: Lang) {
        crate::i18n::set_lang(next);
        if let Some(src) = &mut self.source {
            let (n, d) = logic::describe_source(&src.path, src.mode);
            src.name = n;
            src.detail = d;
            if src.mode == Mode::Decrypt {
                src.summary = logic::header_summary(&src.path);
            }
        }
    }

    /// macOS: add or remove the Finder Quick Action (current user only), after confirmation.
    #[cfg(target_os = "macos")]
    fn quick_action(&mut self, ui: &mut Ui, pal: Palette) {
        use lephy_sys::quick_action as qa;
        let in_bundle = std::env::current_exe()
            .is_ok_and(|p| p.to_string_lossy().contains(".app/Contents/MacOS/"));
        if !in_bundle {
            ui.label(
                RichText::new(tr(
                    "Yalnızca uygulama paketi (.app) olarak çalışırken kullanılabilir.",
                    "Available only when running as an app bundle (.app).",
                ))
                .color(pal.muted)
                .size(12.5),
            );
            return;
        }
        let Ok(dir) = qa::services_dir() else { return };
        let installed = qa::is_installed(&dir);
        if !self.confirm_shell {
            let label = if installed {
                tr("Hızlı İşlemi kaldır", "Remove the Quick Action")
            } else {
                tr("Hızlı İşlemi ekle", "Add the Quick Action")
            };
            if link_button(ui, pal, label).clicked() {
                self.confirm_shell = true;
                self.settings_note = None;
            }
            return;
        }
        ui.label(
            RichText::new(if installed {
                tr(
                    "Hızlı İşlem bu kullanıcı için kaldırılacak.",
                    "The Quick Action will be removed for this user.",
                )
            } else {
                tr(
                    "~/Library/Services/lephycrypy+.workflow oluşturulacak. Seçilen öğeleri yalnızca bu uygulamada açar; hiçbir şeyi kendiliğinden şifrelemez.",
                    "~/Library/Services/lephycrypy+.workflow will be created. It only opens the selected items in this app; it never encrypts anything by itself.",
                )
            })
            .color(pal.muted)
            .size(12.5),
        );
        ui.horizontal(|ui| {
            let ok = link_button(ui, pal, tr("Onayla", "Confirm")).clicked();
            ui.add_space(12.0);
            if link_button(ui, pal, tr("Vazgeç", "Cancel")).clicked() {
                self.confirm_shell = false;
            }
            if ok {
                self.confirm_shell = false;
                let r = if installed {
                    qa::uninstall(&dir)
                } else {
                    qa::install(
                        &dir,
                        tr(
                            "lephycrypy+ ile şifrele / aç",
                            "Encrypt or open with lephycrypy+",
                        ),
                        BUNDLE_ID,
                    )
                };
                self.settings_note = Some(match (r, installed) {
                    (Ok(()), false) => tr(
                        "Eklendi. Finder'da bir öğeye sağ tıklayıp Hızlı İşlemler'e bakın.",
                        "Added. Right-click an item in Finder and look under Quick Actions.",
                    )
                    .to_owned(),
                    (Ok(()), true) => tr("Kaldırıldı.", "Removed.").to_owned(),
                    (Err(e), _) => e.to_string(),
                });
            }
        });
    }

    /// Windows: add or remove the Explorer integration (current user only), after confirmation.
    #[cfg(windows)]
    fn explorer_integration(&mut self, ui: &mut Ui, pal: Palette) {
        use lephy_sys::shell;
        let registered = shell::is_registered(shell::CLASSES);
        if !self.confirm_shell {
            let label = if registered {
                tr(
                    "Gezgin entegrasyonunu kaldır",
                    "Remove the Explorer integration",
                )
            } else {
                tr(
                    "Gezgin'e ekle: .lphy dosyalarını çift tıkla aç, sağ tık menüsünden şifrele",
                    "Add to Explorer: open .lphy files with a double-click, encrypt from the right-click menu",
                )
            };
            if link_button(ui, pal, label).clicked() {
                self.confirm_shell = true;
            }
            return;
        }
        ui.label(
            RichText::new(if registered {
                tr(
                    "Sağ tık menüsü girişi ve .lphy ilişkilendirmesi bu kullanıcı için kaldırılacak.",
                    "The right-click entry and the .lphy association will be removed for this user.",
                )
            } else {
                tr(
                    "Yalnızca bu kullanıcı için kayıt defterine (HKCU) yazılır: .lphy dosyaları bu uygulamayla açılır ve her dosya ile klasörün sağ tık menüsüne bir giriş eklenir. Uygulamayı taşırsanız yeniden ekleyin.",
                    "Written to the registry for this user only (HKCU): .lphy files open with this app and every file and folder gets a right-click entry. Add it again if you move the app.",
                )
            })
            .color(pal.muted)
            .size(12.5),
        );
        ui.horizontal(|ui| {
            let ok = link_button(ui, pal, tr("Onayla", "Confirm")).clicked();
            ui.add_space(12.0);
            if link_button(ui, pal, tr("Vazgeç", "Cancel")).clicked() {
                self.confirm_shell = false;
            }
            if ok {
                self.confirm_shell = false;
                let r = if registered {
                    shell::unregister(shell::CLASSES)
                } else {
                    std::env::current_exe().and_then(|exe| {
                        shell::register(
                            shell::CLASSES,
                            &exe,
                            shell::Labels {
                                file_type: tr(
                                    "lephycrypy+ şifreli dosya",
                                    "lephycrypy+ encrypted file",
                                ),
                                menu: tr(
                                    "lephycrypy+ ile şifrele / aç",
                                    "Encrypt or open with lephycrypy+",
                                ),
                            },
                        )
                    })
                };
                self.settings_note = Some(match r {
                    Ok(()) => tr("Tamam.", "Done.").to_owned(),
                    Err(e) => e.to_string(),
                });
            }
        });
    }

    fn source_card(&mut self, ui: &mut Ui, pal: Palette, can_change: bool) {
        let hovering = ui.input(|i| !i.raw.hovered_files.is_empty());
        let Some(src) = &self.source else { return };
        let (name, detail, mode, is_dir) = (
            src.name.clone(),
            src.detail.clone(),
            src.mode,
            src.path.is_dir(),
        );
        let summary = src.summary.clone();
        let mut change = false;
        egui::Frame::new()
            .fill(pal.surface)
            .stroke(Stroke::new(
                if hovering { 1.5 } else { 1.0 },
                if hovering { pal.accent } else { pal.line },
            ))
            .corner_radius(CornerRadius::same(theme::R_CARD))
            .inner_margin(egui::Margin::symmetric(14, 12))
            .show(ui, |ui| {
                ui.set_width(ui.available_width());
                ui.horizontal(|ui| {
                    let (g, _) = ui.allocate_exact_size(vec2(40.0, 40.0), Sense::hover());
                    ui.painter().rect_filled(g, 9.0, pal.accent_soft);
                    match (mode, is_dir) {
                        (Mode::Decrypt, _) => draw_lock(ui.painter(), g.center(), 0.62, pal.accent),
                        (Mode::Encrypt, true) => draw_folder(ui.painter(), g.center(), pal.accent),
                        (Mode::Encrypt, false) => draw_doc(ui.painter(), g.center(), pal.accent),
                    }
                    ui.add_space(4.0);
                    let right_w = if can_change { 70.0 } else { 0.0 };
                    let text_w = (ui.available_width() - right_w).max(60.0);
                    ui.allocate_ui_with_layout(
                        vec2(text_w, 40.0),
                        Layout::top_down(Align::Min),
                        |ui| {
                            ui.spacing_mut().item_spacing.y = 1.0;
                            ui.add(
                                egui::Label::new(
                                    RichText::new(&name)
                                        .font(fonts::semibold(15.5))
                                        .color(pal.ink),
                                )
                                .truncate(),
                            );
                            ui.label(RichText::new(&detail).color(pal.muted).size(13.0));
                        },
                    );
                    if can_change {
                        ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                            change = link_button(ui, pal, tr("Değiştir", "Change")).clicked();
                        });
                    }
                });
                if let Some(sm) = &summary {
                    ui.add_space(6.0);
                    ui.add(egui::Label::new(RichText::new(sm).color(pal.muted).size(12.5)).wrap());
                }
            });
        if change {
            self.reset();
        }
    }

    fn ready_view(&mut self, ui: &mut Ui, ctx: &egui::Context, pal: Palette) {
        let Some(mode) = self.mode() else { return };
        self.source_card(ui, pal, true);
        ui.add_space(22.0);
        if mode == Mode::Encrypt {
            let before = self.use_keys;
            segmented(
                ui,
                pal,
                &mut self.use_keys,
                &[
                    (false, tr("Parolayla", "With a password"), true),
                    (true, tr("Açık anahtarla", "With public keys"), true),
                ],
            );
            if before != self.use_keys {
                self.password.clear();
                self.confirm.clear();
                self.show_keygen = false;
                self.error = None;
            }
            ui.add_space(8.0);
            help::help_box(ui, pal, help::Topic::PasswordOrKeys);
            ui.add_space(8.0);
        }
        let mut submit = false;
        if mode == Mode::Encrypt && self.use_keys {
            self.recipients_view(ui, pal);
        } else if mode == Mode::Decrypt && self.identity_required {
            self.identity_view(ui, pal, &mut submit);
        } else {
            self.password_view(ui, pal, mode, &mut submit);
        }
        self.after_credentials(ui, ctx, pal, mode, submit);
    }

    fn password_view(&mut self, ui: &mut Ui, pal: Palette, mode: Mode, submit: &mut bool) {
        self.password.set_label("Parola", "Password");
        self.confirm
            .set_label("Parolayı tekrar girin", "Repeat the password");
        let (title, sub) = match mode {
            Mode::Encrypt => (
                tr("Bir parola belirleyin", "Choose a password"),
                tr(
                    "Bu parolayı unutursanız dosya açılamaz; kurtarma yolu yoktur.",
                    "If you forget this password the file cannot be opened; there is no recovery.",
                ),
            ),
            Mode::Decrypt => (
                tr("Parolayı girin", "Enter the password"),
                tr(
                    "Dosya şifrelenirken kullanılan parola.",
                    "The password used when the file was encrypted.",
                ),
            ),
        };
        ui.label(
            RichText::new(title)
                .font(fonts::semibold(16.5))
                .color(pal.ink),
        );
        ui.label(RichText::new(sub).color(pal.muted).size(13.0));
        if mode == Mode::Encrypt {
            self.generator(ui, pal);
        }
        ui.add_space(10.0);

        let (r1, s1) = self.password.ui(ui, true);
        if self.source.is_some() && ui.memory(|m| m.focused().is_none()) {
            r1.request_focus();
        }
        *submit = s1;
        if mode == Mode::Encrypt {
            ui.add_space(2.0);
            let (_, s2) = self.confirm.ui(ui, true);
            *submit |= s2;
            self.password_hint(ui, pal);
        }

        if mode == Mode::Decrypt && self.keyfile_required {
            ui.add_space(12.0);
            self.keyfile_row(ui, pal, true);
        }
    }

    fn after_credentials(
        &mut self,
        ui: &mut Ui,
        ctx: &egui::Context,
        pal: Palette,
        mode: Mode,
        submit: bool,
    ) {
        ui.add_space(14.0);
        if self.editing_recipients() {
            self.recipient_editor(ui, pal);
        } else {
            self.output_row(ui, pal);
        }
        if let Some(root) = self.cloud_root() {
            ui.add_space(6.0);
            ui.label(
                RichText::new({
                    let r = escape_display(&root.display().to_string());
                    match lang() {
                        Lang::Tr => format!(
                            "Bu konum bir bulut senkron klasöründe ({r}). Çözülen dosyalar buluta yüklenebilir."
                        ),
                        Lang::En => format!(
                            "This location is in a cloud-sync folder ({r}). Decrypted files may be uploaded."
                        ),
                    }
                })
                .color(pal.danger)
                .size(13.0),
            );
            ui.checkbox(
                &mut self.allow_cloud,
                tr("Yine de bu konuma çöz", "Decrypt to this location anyway"),
            );
        }

        if mode == Mode::Encrypt {
            ui.add_space(8.0);
            self.advanced(ui, pal);
        }

        ui.add_space(18.0);
        let picked = match lang() {
            Lang::Tr => format!("Seçilenleri çıkar ({})", self.selected.len()),
            Lang::En => format!("Extract selected ({})", self.selected.len()),
        };
        let label = match mode {
            Mode::Encrypt => tr("Şifrele", "Encrypt"),
            Mode::Decrypt if self.editing_recipients() => {
                tr("Alıcıları güncelle", "Update recipients")
            }
            Mode::Decrypt if !self.selected.is_empty() && self.listing.is_some() => &picked,
            Mode::Decrypt => tr("Şifreyi çöz", "Decrypt"),
        };
        if mode == Mode::Decrypt && !self.batch() && !self.editing_recipients() {
            self.contents_view(ui, ctx, pal);
            self.recover_option(ui, pal);
        }
        let enabled = self.can_start();
        if self.confirm_delete && mode == Mode::Encrypt {
            self.delete_confirmation(ui, ctx, pal);
        } else if primary_button(ui, pal, label, enabled).clicked() || (submit && enabled) {
            if self.secure_delete && mode == Mode::Encrypt && !self.use_keys {
                // Irreversible step: explicit confirmation first.
                self.confirm_delete = true;
            } else {
                self.start(ctx);
            }
        }
        if let Some(e) = &self.error {
            ui.add_space(8.0);
            ui.label(RichText::new(e).color(pal.danger).size(13.5));
        }
    }

    /// Archive contents: "List contents" (decrypts and checks the whole file, writes nothing),
    /// then a filterable list with check boxes to extract only some entries.
    #[allow(
        clippy::too_many_lines,
        reason = "one card; splitting it would scatter the layout"
    )]
    fn contents_view(&mut self, ui: &mut Ui, ctx: &egui::Context, pal: Palette) {
        const MAX_ROWS: usize = 400;
        if !self.is_archive || self.recover {
            return;
        }
        let Some(entries) = &self.listing else {
            let can = self.can_start();
            let resp = ui.add_enabled(
                can,
                egui::Button::new(
                    RichText::new(tr(
                        "İçeriği listele (hiçbir şey yazılmaz)",
                        "List contents (nothing is written)",
                    ))
                    .color(pal.accent)
                    .size(14.0),
                )
                .frame(false)
                .min_size(vec2(0.0, 28.0)),
            );
            if resp.clicked() {
                self.start_job(ctx, true);
            }
            ui.add_space(6.0);
            return;
        };
        let files = entries
            .iter()
            .filter(|e| e.kind == lephy_core::archive::EntryKind::File)
            .count();
        let bytes: u64 = entries.iter().map(|e| e.size).sum();
        let mut clear = false;
        egui::Frame::new()
            .fill(pal.surface)
            .stroke(Stroke::new(1.0, pal.line))
            .corner_radius(CornerRadius::same(theme::R_INPUT))
            .inner_margin(egui::Margin::same(12))
            .show(ui, |ui| {
                ui.set_width(ui.available_width());
                ui.label(
                    RichText::new(match lang() {
                        Lang::Tr => format!(
                            "{} öğe, {files} dosya, {}",
                            entries.len(),
                            logic::human_size(bytes)
                        ),
                        Lang::En => format!(
                            "{} entries, {files} files, {}",
                            entries.len(),
                            logic::human_size(bytes)
                        ),
                    })
                    .font(fonts::semibold(13.5))
                    .color(pal.ink),
                );
                ui.add(
                    egui::TextEdit::singleline(&mut self.list_filter)
                        .hint_text(tr("Ada göre süz…", "Filter by name…"))
                        .desired_width(f32::INFINITY),
                );
                ui.add_space(4.0);
                let needle = self.list_filter.to_lowercase();
                let shown: Vec<&lephy_core::archive::ListEntry> = entries
                    .iter()
                    .filter(|e| needle.is_empty() || e.path.to_lowercase().contains(&needle))
                    .take(MAX_ROWS + 1)
                    .collect();
                let rows = shown.len().min(MAX_ROWS);
                #[allow(clippy::cast_precision_loss)]
                let height = (rows as f32 * 28.0).clamp(28.0, 240.0);
                egui::ScrollArea::vertical()
                    .max_height(height)
                    .min_scrolled_height(height)
                    .auto_shrink([false, false])
                    .show(ui, |ui| {
                        ui.spacing_mut().item_spacing.y = 2.0;
                        for e in shown.iter().take(MAX_ROWS) {
                            let mut on = self.selected.contains(&e.path);
                            let shown_path = escape_display(&e.path);
                            let text = match e.kind {
                                lephy_core::archive::EntryKind::Dir => format!("{shown_path}/"),
                                lephy_core::archive::EntryKind::Symlink => {
                                    format!("{shown_path} →")
                                }
                                lephy_core::archive::EntryKind::File => {
                                    format!("{shown_path}  ·  {}", logic::human_size(e.size))
                                }
                            };
                            if ui
                                .checkbox(&mut on, RichText::new(text).size(13.0))
                                .changed()
                            {
                                if on {
                                    self.selected.insert(e.path.clone());
                                } else {
                                    self.selected.remove(&e.path);
                                }
                            }
                        }
                    });
                if shown.len() > MAX_ROWS {
                    ui.label(
                        RichText::new(tr(
                            "Yalnızca ilk 400 satır gösteriliyor; daraltmak için süzün.",
                            "Only the first 400 rows are shown; filter to narrow down.",
                        ))
                        .color(pal.muted)
                        .size(12.5),
                    );
                }
                ui.label(
                    RichText::new(if self.selected.is_empty() {
                        tr(
                            "Hiçbir şey seçilmezse her şey çıkarılır. Bir klasör seçmek altındaki her şeyi seçer.",
                            "If nothing is selected, everything is extracted. Selecting a folder selects everything below it.",
                        )
                    } else {
                        tr(
                            "Yalnızca seçilenler ve üst klasörleri çıkarılır.",
                            "Only the selected entries and their parent folders are extracted.",
                        )
                    })
                    .color(pal.muted)
                    .size(12.5),
                );
                if !self.selected.is_empty() {
                    clear = link_button(ui, pal, tr("Seçimi temizle", "Clear selection")).clicked();
                }
            });
        if clear {
            self.selected.clear();
        }
        if self.password.char_count() == 0 {
            ui.label(
                RichText::new(tr(
                    "Çıkarmak için parolayı yeniden girin (parola listelemeden sonra bellekten silindi).",
                    "Enter the password again to extract (it was wiped from memory after listing).",
                ))
                .color(pal.muted)
                .size(12.5),
            );
        }
        ui.add_space(8.0);
    }

    /// The keys a job uses: classic or post-quantum, from the list (none outside key mode).
    fn job_keys(
        &self,
        key_mode: bool,
    ) -> (
        Vec<lephy_core::ops::PublicKey>,
        Vec<lephy_core::hybrid::HybridKey>,
    ) {
        match (key_mode, self.keys_pq()) {
            (true, false) => (
                logic::parse_recipients(&self.recipients_text).unwrap_or_default(),
                Vec::new(),
            ),
            (true, true) => (
                Vec::new(),
                logic::parse_hybrid(&self.recipients_text).unwrap_or_default(),
            ),
            (false, _) => (Vec::new(), Vec::new()),
        }
    }

    /// Which kind of keys counts: the file's when replacing its recipients, else the switch.
    fn keys_pq(&self) -> bool {
        if self.mode() == Some(Mode::Decrypt) {
            self.file_pq
        } else {
            self.pq
        }
    }

    /// Number of valid keys of the current kind in the list.
    fn key_count(&self) -> std::result::Result<usize, String> {
        if self.keys_pq() {
            logic::parse_hybrid(&self.recipients_text).map(|k| k.len())
        } else {
            logic::parse_recipients(&self.recipients_text).map(|k| k.len())
        }
    }

    /// Adds the keys of the current kind from a `.pub` file's text.
    fn append_keys_from(&mut self, text: &str) -> bool {
        let prefix = if self.keys_pq() {
            lephy_core::hybrid::HYBRID_PREFIX
        } else {
            lephy_core::recipient::PUBLIC_PREFIX
        };
        let lines: Vec<&str> = text
            .lines()
            .map(str::trim)
            .filter(|l| l.starts_with(prefix))
            .collect();
        let ok = !lines.is_empty()
            && if self.keys_pq() {
                logic::parse_hybrid(&lines.join("\n")).is_ok()
            } else {
                logic::parse_recipients(&lines.join("\n")).is_ok()
            };
        if ok {
            for l in lines {
                self.append_key(l);
            }
        }
        ok
    }

    fn editing_recipients(&self) -> bool {
        self.edit_recipients && self.identity_required && !self.batch()
    }

    /// Public-key file: switch between opening it and replacing its recipient list.
    fn recipient_editor(&mut self, ui: &mut Ui, pal: Palette) {
        ui.label(
            RichText::new(tr("Yeni alıcı listesi", "New recipient list"))
                .font(fonts::semibold(13.5))
                .color(pal.ink),
        );
        ui.label(
            RichText::new(tr(
                "Açık anahtarlar dosyada saklanmaz; bu yüzden tam listeyi yazın: erişimi kalacak herkes, siz de dahil. İçerik yeniden şifrelenmez. Çıkarılan biri dosyanın eski bir kopyasını sakladıysa onu açabilir.",
                "Public keys are not stored in the file, so write the complete list: everyone who keeps access, yourself included. The content is not re-encrypted. A removed recipient who kept a copy of the old file can still open that copy.",
            ))
            .color(pal.muted)
            .size(12.5),
        );
        ui.add_space(6.0);
        ui.add(
            egui::TextEdit::multiline(&mut self.recipients_text)
                .hint_text("lphy1…")
                .desired_rows(4)
                .desired_width(f32::INFINITY)
                .font(egui::TextStyle::Monospace),
        );
        if self.file_pq {
            ui.label(
                RichText::new(tr(
                    "Bu dosya kuantuma dayanıklı: alıcıların lphypq1… anahtarlarını yazın.",
                    "This file is post-quantum: write the recipients' lphypq1… keys.",
                ))
                .color(pal.muted)
                .size(12.5),
            );
        }
        match self.key_count() {
            Ok(n) if n > 0 => {
                ui.label(
                    RichText::new(match lang() {
                        Lang::Tr => format!("{n} geçerli anahtar."),
                        Lang::En => format!("{n} valid key(s)."),
                    })
                    .color(pal.accent)
                    .size(12.5),
                );
            }
            Ok(_) => {}
            Err(e) => {
                ui.label(RichText::new(e).color(pal.danger).size(12.5));
            }
        }
        if link_button(ui, pal, tr("Vazgeç, dosyayı aç", "Cancel, open the file")).clicked() {
            self.edit_recipients = false;
        }
    }

    /// Recovery-mode option (single-file decryption).
    fn recover_option(&mut self, ui: &mut Ui, pal: Palette) {
        let before = self.recover;
        ui.checkbox(
            &mut self.recover,
            tr(
                "Kurtarma modu: bozuk dosyadan kurtarılabileni çıkar",
                "Recovery mode: extract what can be saved from a damaged file",
            ),
        );
        if self.recover != before
            && let Some(src) = &self.source
        {
            let base = logic::default_output(&src.path, Mode::Decrypt);
            self.output = Some(if self.recover {
                let mut n = base.as_os_str().to_os_string();
                n.push(".recovered");
                PathBuf::from(n)
            } else {
                base
            });
        }
        if self.recover {
            ui.label(
                RichText::new(tr(
                    "Doğrulanamayan bölümler sıfırla doldurulur; çıktı güvenilmez veri içerebilir. Yalnızca dosya açılamıyorsa kullanın.",
                    "Parts that fail verification are filled with zeros; the output may contain untrustworthy data. Use only when the file will not open.",
                ))
                .color(pal.danger)
                .size(12.5),
            );
        }
        ui.add_space(6.0);
    }

    /// Secure-deletion confirmation: lists what will be deleted; starts only on explicit confirmation.
    fn delete_confirmation(&mut self, ui: &mut Ui, ctx: &egui::Context, pal: Palette) {
        let names: Vec<String> = self
            .source
            .as_ref()
            .map(|s| {
                s.paths
                    .iter()
                    .take(8)
                    .map(|p| escape_display(&logic::short_dir(p)))
                    .collect()
            })
            .unwrap_or_default();
        let total = self.source.as_ref().map_or(0, |s| s.paths.len());
        let mut go = false;
        let mut back = false;
        egui::Frame::new()
            .fill(pal.surface)
            .stroke(Stroke::new(1.5, pal.danger))
            .corner_radius(CornerRadius::same(theme::R_CARD))
            .inner_margin(egui::Margin::same(14))
            .show(ui, |ui| {
                ui.set_width(ui.available_width());
                ui.label(
                    RichText::new(tr(
                        "Şifreleme doğrulandıktan sonra bunlar kalıcı olarak silinecek:",
                        "After encryption is verified, these will be permanently deleted:",
                    ))
                    .font(fonts::semibold(14.5))
                    .color(pal.ink),
                );
                for n in &names {
                    ui.add(egui::Label::new(RichText::new(n).color(pal.ink).size(13.0)).truncate());
                }
                if total > names.len() {
                    ui.label(
                        RichText::new(match lang() {
                            Lang::Tr => format!("ve {} öğe daha", total - names.len()),
                            Lang::En => format!("and {} more", total - names.len()),
                        })
                        .color(pal.muted)
                        .size(13.0),
                    );
                }
                ui.add_space(4.0);
                ui.label(
                    RichText::new(tr(
                        "Her dosyanın üzerine bir kez rastgele veri yazılır. SSD'lerde, APFS gibi dosya sistemlerinde, anlık görüntülerde ve bulut geçmişinde eski içerik yine de kalabilir. Bu işlem geri alınamaz.",
                        "Each file is overwritten once with random data. Old content may still remain on SSDs, on file systems such as APFS, in snapshots and in cloud history. This cannot be undone.",
                    ))
                    .color(pal.muted)
                    .size(12.5),
                );
                ui.add_space(8.0);
                go = primary_button(ui, pal, tr("Şifrele ve sil", "Encrypt and delete"), true)
                    .clicked();
                ui.add_space(4.0);
                back = secondary_button(ui, pal, tr("Vazgeç", "Cancel"), ui.available_width(), 38.0)
                    .clicked();
            });
        if go {
            self.start(ctx);
        } else if back {
            self.confirm_delete = false;
        }
    }

    /// "Generate a strong password": a 6-word passphrase is written to both fields and shown once.
    fn generator(&mut self, ui: &mut Ui, pal: Palette) {
        if self.generated.is_none() {
            if link_button(
                ui,
                pal,
                tr("Güçlü bir parola üret", "Generate a strong password"),
            )
            .clicked()
                && let Ok(p) = lephy_core::passphrase::generate(
                    &mut lephy_core::entropy::OsEntropy,
                    lephy_core::passphrase::DEFAULT_WORDS,
                    '-',
                )
            {
                self.password.set(p.expose());
                self.confirm.set(p.expose());
                self.generated = Some(p);
            }
            return;
        }
        let mut hide = false;
        egui::Frame::new()
            .fill(pal.accent_soft)
            .corner_radius(CornerRadius::same(theme::R_INPUT))
            .inner_margin(egui::Margin::same(12))
            .show(ui, |ui| {
                ui.set_width(ui.available_width());
                if let Some(p) = &self.generated {
                    reveal_on_hover(ui, pal, p.expose());
                }
                ui.label(
                    RichText::new(tr(
                        "Bu parolayı şimdi bir yere yazın. Pencere kapanınca bir daha gösterilmez.",
                        "Write this password down now. It will not be shown again.",
                    ))
                    .color(pal.muted)
                    .size(12.5),
                );
                hide =
                    link_button(ui, pal, tr("Yazdım, gizle", "I wrote it down, hide it")).clicked();
            });
        if hide {
            self.generated = None;
        }
    }

    /// Strength bar: five segments, filled by level.
    fn strength_bar(&self, ui: &mut Ui, pal: Palette) {
        use lephy_core::strength::Level;
        let e = self.password.strength();
        let (n, label, color) = match e.level {
            Level::VeryWeak => (1, tr("Çok zayıf", "Very weak"), pal.danger),
            Level::Weak => (2, tr("Zayıf", "Weak"), pal.danger),
            Level::Fair => (3, tr("Orta", "Fair"), pal.muted),
            Level::Strong => (4, tr("Güçlü", "Strong"), pal.ok),
            Level::VeryStrong => (5, tr("Çok güçlü", "Very strong"), pal.ok),
        };
        ui.horizontal(|ui| {
            let (rect, _) = ui.allocate_exact_size(vec2(120.0, 6.0), Sense::hover());
            let w = (rect.width() - 4.0 * 4.0) / 5.0;
            for i in 0..5 {
                #[allow(clippy::cast_precision_loss)]
                let r = Rect::from_min_size(
                    pos2(rect.left() + (w + 4.0) * i as f32, rect.top()),
                    vec2(w, rect.height()),
                );
                let c = if i < n { color } else { pal.line };
                ui.painter().rect_filled(r, 3.0, c);
            }
            ui.label(
                RichText::new(match lang() {
                    Lang::Tr => format!("{label} (tahmini ~{:.0} bit)", e.bits),
                    Lang::En => format!("{label} (estimated ~{:.0} bits)", e.bits),
                })
                .color(pal.muted)
                .size(12.5),
            );
        });
    }

    fn password_hint(&self, ui: &mut Ui, pal: Palette) {
        let n = self.password.char_count();
        if n > 0 {
            self.strength_bar(ui, pal);
        }
        let (text, color) = if n == 0 {
            (
                match lang() {
                    Lang::Tr => format!("En az {MIN_SCALARS} karakter."),
                    Lang::En => format!("At least {MIN_SCALARS} characters."),
                },
                pal.muted,
            )
        } else if n < MIN_SCALARS {
            (
                match lang() {
                    Lang::Tr => format!("En az {MIN_SCALARS} karakter (şu an {n})."),
                    Lang::En => format!("At least {MIN_SCALARS} characters (now {n})."),
                },
                pal.muted,
            )
        } else if self.confirm.is_empty() {
            (
                tr(
                    "Doğrulamak için parolayı tekrar girin.",
                    "Enter the password again to confirm.",
                )
                .to_string(),
                pal.muted,
            )
        } else if self.password.same_as(&self.confirm) {
            (
                tr("Parolalar eşleşiyor.", "Passwords match.").to_string(),
                pal.ok,
            )
        } else {
            (
                tr("Parolalar eşleşmiyor.", "Passwords do not match.").to_string(),
                pal.danger,
            )
        };
        ui.label(RichText::new(text).color(color).size(13.0));
    }

    fn output_row(&mut self, ui: &mut Ui, pal: Palette) {
        let batch = self.batch();
        // A decrypted file gets the name stored inside the encrypted file (not known before).
        let restore = self.mode() == Some(Mode::Decrypt) && !self.output_custom && !self.recover;
        let Some(out) = &self.output else { return };
        let name = if restore && !batch {
            tr(
                "Özgün adıyla, bu klasöre",
                "Under its original name, in this folder",
            )
            .to_owned()
        } else {
            out.file_name()
                .map(|f| escape_display(&f.to_string_lossy()))
                .unwrap_or_default()
        };
        let dir = if batch {
            // The folder itself: each item is written into it as its own file.
            escape_display(&logic::short_dir(out))
        } else {
            out.parent()
                .map(|d| escape_display(&logic::short_dir(d)))
                .unwrap_or_default()
        };
        ui.label(
            RichText::new(if batch {
                tr("Kaydedilecek klasör", "Save to folder")
            } else {
                tr("Kaydedilecek yer", "Save to")
            })
            .color(pal.muted)
            .size(13.0),
        );
        let mut change = false;
        egui::Frame::new()
            .fill(pal.surface)
            .stroke(Stroke::new(1.0, pal.line))
            .corner_radius(CornerRadius::same(theme::R_INPUT))
            .inner_margin(egui::Margin::symmetric(12, 8))
            .show(ui, |ui| {
                ui.set_width(ui.available_width());
                ui.horizontal(|ui| {
                    let text_w = (ui.available_width() - 76.0).max(60.0);
                    ui.allocate_ui_with_layout(
                        vec2(text_w, 36.0),
                        Layout::top_down(Align::Min),
                        |ui| {
                            ui.spacing_mut().item_spacing.y = 1.0;
                            ui.add(
                                egui::Label::new(RichText::new(&name).color(pal.ink).size(14.0))
                                    .truncate(),
                            );
                            ui.add(
                                egui::Label::new(RichText::new(&dir).color(pal.muted).size(12.5))
                                    .truncate(),
                            );
                        },
                    );
                    ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                        change = link_button(ui, pal, tr("Değiştir", "Change")).clicked();
                    });
                });
            });
        if change {
            self.choose_output();
        }
    }

    #[allow(clippy::too_many_lines)]
    fn advanced(&mut self, ui: &mut Ui, pal: Palette) {
        let label = if self.show_advanced {
            tr("Gelişmiş ayarları gizle", "Hide advanced settings")
        } else {
            tr("Gelişmiş ayarlar", "Advanced settings")
        };
        if link_button(ui, pal, label).clicked() {
            self.show_advanced = !self.show_advanced;
        }
        if !self.show_advanced {
            return;
        }
        egui::Frame::new()
            .fill(pal.surface)
            .stroke(Stroke::new(1.0, pal.line))
            .corner_radius(CornerRadius::same(theme::R_CARD))
            .inner_margin(egui::Margin::same(16))
            .show(ui, |ui| {
                ui.set_width(ui.available_width());
                ui.horizontal(|ui| {
                    ui.label(
                        RichText::new(tr("Algoritma", "Algorithm"))
                            .color(pal.muted)
                            .size(13.0),
                    );
                    if help_button(ui, pal, self.show_help).clicked() {
                        self.show_help = !self.show_help;
                    }
                });
                if self.show_help {
                    help_card(ui, pal);
                }
                segmented(
                    ui,
                    pal,
                    &mut self.aes,
                    &[
                        (false, "XChaCha20-Poly1305", true),
                        (true, "AES-256-GCM", true),
                    ],
                );
                ui.add_space(12.0);
                ui.label(
                    RichText::new(match lang() {
                        Lang::Tr => format!("Parola türetme belleği: {} MiB", self.kdf_mib),
                        Lang::En => format!("Password derivation memory: {} MiB", self.kdf_mib),
                    })
                    .color(pal.muted)
                    .size(13.0),
                );
                // Options above 75 % of physical memory are not offered (the CLI budget rule).
                let fits = |m: u32| self.ram_mib == 0 || u64::from(m) * 4 <= self.ram_mib * 3;
                let opts = KDF_PRESETS.map(|(m, t, e)| (m, tr(t, e), fits(m)));
                segmented(ui, pal, &mut self.kdf_mib, &opts);
                ui.add_space(12.0);
                ui.checkbox(
                    &mut self.pad,
                    tr(
                        "Dosya boyutunu gizle (PADMÉ dolgusu)",
                        "Hide the file size (PADMÉ padding)",
                    ),
                );
                ui.checkbox(
                    &mut self.compress,
                    tr(
                        "Şifrelemeden önce sıkıştır (boyut içerik hakkında ipucu verebilir)",
                        "Compress before encrypting (the size may hint at the content)",
                    ),
                );
                ui.checkbox(
                    &mut self.ecc,
                    tr(
                        "Hata düzeltme ekle (dosya ~%7 büyür; bozulan USB/diskte onarır)",
                        "Add error correction (about 7% larger; repairs damage on USB sticks and disks)",
                    ),
                );
                ui.add_space(4.0);
                ui.label(
                    RichText::new(tr("Parçalara böl", "Split into parts"))
                        .color(pal.muted)
                        .size(13.0),
                );
                segmented(
                    ui,
                    pal,
                    &mut self.split_mib,
                    &[
                        (0, tr("Kapalı", "Off"), true),
                        (100, "100 MB", true),
                        (1024, "1 GB", true),
                        // FAT32 file limit is 4 GiB − 1 byte.
                        (4095, tr("FAT32 (4 GB)", "FAT32 (4 GB)"), true),
                    ],
                );
                if !self.use_keys {
                    ui.add_space(8.0);
                    ui.checkbox(
                        &mut self.secure_delete,
                        tr(
                            "Şifreledikten sonra orijinali güvenli sil",
                            "Securely delete the original after encryption",
                        ),
                    );
                    ui.add_space(12.0);
                    self.keyfile_row(ui, pal, false);
                }
                ui.add_space(12.0);
                self.signing_row(ui, pal);
            });
    }

    /// Optional sender signature: an identity file and its password.
    fn signing_row(&mut self, ui: &mut Ui, pal: Palette) {
        ui.checkbox(
            &mut self.sign,
            tr("Kimliğimle imzala", "Sign with my identity"),
        );
        if !self.sign {
            return;
        }
        ui.label(
            RichText::new(tr(
                "Dosyayı açan herkes kimin imzaladığını (lphysig1…) görür ve dosyanın sonradan değiştirilmediğini doğrular.",
                "Whoever opens the file sees who signed it (lphysig1…) and can check that it was not changed afterwards.",
            ))
            .color(pal.muted)
            .size(12.5),
        );
        help::help_box(ui, pal, help::Topic::Signatures);
        ui.horizontal(|ui| {
            let name = self.sign_identity.as_ref().map_or_else(
                || tr("Kimlik dosyası seçilmedi", "No identity file selected").to_string(),
                |p| {
                    p.file_name()
                        .map(|f| escape_display(&f.to_string_lossy()))
                        .unwrap_or_default()
                },
            );
            ui.label(RichText::new(name).color(pal.ink).size(13.5));
            if link_button(ui, pal, tr("Seç", "Choose")).clicked()
                && let Some(p) = rfd::FileDialog::new()
                    .set_title(tr("İmza kimliğini seçin", "Choose the signing identity"))
                    .add_filter("lephycrypy identity", &["lphykey"])
                    .pick_file()
            {
                self.sign_identity = Some(p);
            }
        });
        self.sign_password.ui(ui, true);
    }

    fn append_key(&mut self, text: &str) {
        if !self.recipients_text.is_empty() && !self.recipients_text.ends_with('\n') {
            self.recipients_text.push('\n');
        }
        self.recipients_text.push_str(text.trim());
        self.recipients_text.push('\n');
    }

    /// Encrypt to public keys: the recipients list and key-pair creation.
    #[allow(clippy::too_many_lines)] // one screen section, read top to bottom
    fn recipients_view(&mut self, ui: &mut Ui, pal: Palette) {
        ui.label(
            RichText::new(tr("Kimler açabilsin?", "Who can open it?"))
                .font(fonts::semibold(16.5))
                .color(pal.ink),
        );
        ui.label(
            RichText::new(tr(
                "Alıcıların açık anahtarlarını yapıştırın, her satıra bir tane. Dosyayı yalnızca bu anahtarların sahipleri açabilir; parola gerekmez.",
                "Paste the recipients' public keys, one per line. Only the owners of these keys can open the file; no password is needed.",
            ))
            .color(pal.muted)
            .size(13.0),
        );
        ui.add_space(8.0);
        help::help_box(ui, pal, help::Topic::PublicKeys);
        help::help_box(ui, pal, help::Topic::Identity);
        ui.checkbox(
            &mut self.pq,
            tr(
                "Kuantuma dayanıklı (ML-KEM-768 + X25519)",
                "Post-quantum (ML-KEM-768 + X25519)",
            ),
        )
        .on_hover_text(tr(
            "Alıcıların lphypq1… anahtarları kullanılır (.pub dosyalarının üçüncü satırı). Dosyayı açmak için hem X25519 hem ML-KEM kırılmalıdır; gelecekteki kuantum bilgisayarlara karşı koruma sağlar.",
            "Uses the recipients' lphypq1… keys (the third line of their .pub files). Opening the file needs breaking both X25519 and ML-KEM, which protects against future quantum computers.",
        ));
        ui.add_space(6.0);
        egui::Frame::new()
            .fill(pal.surface)
            .stroke(Stroke::new(1.0, pal.line))
            .corner_radius(CornerRadius::same(theme::R_INPUT))
            .inner_margin(egui::Margin::symmetric(10, 8))
            .show(ui, |ui| {
                ui.add(
                    egui::TextEdit::multiline(&mut self.recipients_text)
                        .hint_text(if self.pq { "lphypq1…" } else { "lphy1…" })
                        .font(egui::TextStyle::Monospace)
                        .desired_rows(3)
                        .desired_width(f32::INFINITY)
                        .frame(egui::Frame::NONE),
                );
            });
        let (status, color) = match self.key_count() {
            Ok(0) => (
                if self.pq {
                    tr(
                        "Henüz kuantuma dayanıklı (lphypq1…) anahtar yok.",
                        "No post-quantum (lphypq1…) keys yet.",
                    )
                } else {
                    tr("Henüz anahtar yok.", "No keys yet.")
                }
                .to_string(),
                pal.muted,
            ),
            Ok(n) => (
                match lang() {
                    Lang::Tr => format!("{n} geçerli anahtar."),
                    Lang::En => format!("{n} valid key(s)."),
                },
                pal.ok,
            ),
            Err(e) => (e, pal.danger),
        };
        ui.label(RichText::new(status).color(color).size(13.0));
        let mut add = false;
        let mut toggle = false;
        ui.horizontal(|ui| {
            add = link_button(ui, pal, tr("Dosyadan ekle…", "Add from file…")).clicked();
            ui.add_space(12.0);
            let label = if self.show_keygen {
                tr("Anahtar çifti oluşturmayı kapat", "Close key-pair creation")
            } else {
                tr("Kendi anahtar çiftimi oluştur", "Create my own key pair")
            };
            toggle = link_button(ui, pal, label).clicked();
        });
        if add
            && let Some(p) = rfd::FileDialog::new()
                .set_title(tr("Açık anahtar dosyası (.pub)", "Public key file (.pub)"))
                .pick_file()
        {
            match std::fs::read_to_string(&p) {
                Ok(t) if self.append_keys_from(&t) => {
                    self.error = None;
                }
                _ => {
                    self.error = Some(
                        tr(
                            "Bu dosyada geçerli bir açık anahtar yok.",
                            "This file has no valid public key.",
                        )
                        .to_string(),
                    );
                }
            }
        }
        if toggle {
            self.show_keygen = !self.show_keygen;
            self.password.clear();
            self.confirm.clear();
        }
        let mut copied = None;
        if let Some(pk) = self.created_pub.clone() {
            ui.add_space(8.0);
            ui.label(
                RichText::new(tr(
                    "Açık anahtarınız (paylaşabilirsiniz):",
                    "Your public key (safe to share):",
                ))
                .color(pal.muted)
                .size(13.0),
            );
            ui.horizontal(|ui| {
                let w = (ui.available_width() - 70.0).max(60.0);
                ui.allocate_ui_with_layout(
                    vec2(w, 20.0),
                    Layout::left_to_right(Align::Center),
                    |ui| {
                        ui.add(
                            egui::Label::new(
                                RichText::new(&pk).monospace().size(12.0).color(pal.ink),
                            )
                            .truncate(),
                        );
                    },
                );
                if link_button(ui, pal, tr("Kopyala", "Copy")).clicked() {
                    copied = Some(logic::copy_to_clipboard(&pk).is_ok());
                }
            });
        }
        self.paper_card(ui, pal);
        if let Some(ok) = copied {
            self.error = (!ok).then(|| {
                tr("Panoya kopyalanamadı.", "Could not copy to the clipboard.").to_string()
            });
            if ok {
                self.show_toast(ui.ctx(), tr("Panoya kopyalandı", "Copied to the clipboard"));
            }
        }
        if self.show_keygen {
            ui.add_space(10.0);
            self.keygen_card(ui, pal);
        }
    }

    fn keygen_card(&mut self, ui: &mut Ui, pal: Palette) {
        self.password
            .set_label("Kimlik parolası", "Identity password");
        self.confirm.set_label(
            "Kimlik parolasını tekrar girin",
            "Repeat the identity password",
        );
        let mut save = false;
        egui::Frame::new()
            .fill(pal.surface)
            .stroke(Stroke::new(1.0, pal.line))
            .corner_radius(CornerRadius::same(theme::R_CARD))
            .inner_margin(egui::Margin::same(16))
            .show(ui, |ui| {
                ui.set_width(ui.available_width());
                ui.label(
                    RichText::new(tr(
                        "Gizli anahtarınız parolayla korunan bir kimlik dosyasına (.lphykey) yazılır; açık anahtar yanına .pub olarak kaydedilir ve listeye eklenir. Kimlik dosyasını ya da parolasını kaybederseniz bu anahtara şifrelenen dosyalar açılamaz.",
                        "Your secret key is written to a password-protected identity file (.lphykey); the public key is saved next to it as .pub and added to the list. If you lose the identity file or its password, files encrypted to this key cannot be opened.",
                    ))
                    .color(pal.muted)
                    .size(12.5),
                );
                ui.add_space(8.0);
                self.password.ui(ui, true);
                ui.add_space(2.0);
                self.confirm.ui(ui, true);
                self.password_hint(ui, pal);
                ui.add_space(8.0);
                let ok = self.password.char_count() >= MIN_SCALARS
                    && self.password.same_as(&self.confirm);
                save = primary_button(ui, pal, tr("Kaydet…", "Save…"), ok).clicked();
            });
        if save
            && let Some(path) = rfd::FileDialog::new()
                .set_title(tr("Kimlik dosyasını kaydedin", "Save the identity file"))
                .set_file_name("lephycrypy.lphykey")
                .save_file()
        {
            let pwd = self.password.take();
            self.confirm.clear();
            match logic::create_identity(&path, &pwd, self.kdf_mib) {
                Ok((pk, paper)) => {
                    let pub_text =
                        std::fs::read_to_string(path.with_extension("pub")).unwrap_or_default();
                    if !(self.pq && self.append_keys_from(&pub_text)) {
                        self.append_key(&pk);
                    }
                    self.created_pub = Some(pk);
                    self.paper = Some(paper);
                    self.show_keygen = false;
                    self.error = None;
                }
                Err(e) => self.error = Some(logic::describe_error(&e)),
            }
        }
    }

    /// Paper backup of the key pair just created: 22 words, shown only while the pointer rests on
    /// them, until "I wrote them down" hides them for good.
    fn paper_card(&mut self, ui: &mut Ui, pal: Palette) {
        let Some(words) = &self.paper else { return };
        let mut hide = false;
        ui.add_space(10.0);
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
                reveal_on_hover(ui, pal, words.expose());
                ui.label(
                    RichText::new(tr(
                        "Bu kelimeleri kâğıda yazıp bilgisayardan ayrı saklayın. Kimlik dosyası ya da parolası kaybolursa `lephycrypy identity restore` ile geri getirilir. Kelimelere sahip olan herkes bu anahtara şifrelenen her dosyayı açabilir; bir daha gösterilmez.",
                        "Write these words on paper and keep them apart from this computer. If the identity file or its password is lost, `lephycrypy identity restore` brings it back. Anyone with the words can open every file encrypted to this key; they are not shown again.",
                    ))
                    .color(pal.muted)
                    .size(12.5),
                );
                hide = link_button(ui, pal, tr("Yazdım, gizle", "I wrote them down, hide them"))
                    .clicked();
            });
        if hide {
            self.paper = None;
        }
    }

    /// Decrypt a file encrypted to a public key: identity file and its password.
    fn identity_view(&mut self, ui: &mut Ui, pal: Palette, submit: &mut bool) {
        self.password
            .set_label("Kimlik parolası", "Identity password");
        ui.label(
            RichText::new(tr("Kimliğinizi seçin", "Choose your identity"))
                .font(fonts::semibold(16.5))
                .color(pal.ink),
        );
        ui.label(
            RichText::new(tr(
                "Bu dosya bir açık anahtara şifrelenmiş. Kimlik dosyanızı (.lphykey) seçip parolasını girin.",
                "This file was encrypted to a public key. Choose your identity file (.lphykey) and enter its password.",
            ))
            .color(pal.muted)
            .size(13.0),
        );
        ui.add_space(8.0);
        help::help_box(ui, pal, help::Topic::OpenWithIdentity);
        help::help_box(ui, pal, help::Topic::Identity);
        let name = self.identity.as_ref().map(|k| {
            k.file_name()
                .map(|f| escape_display(&f.to_string_lossy()))
                .unwrap_or_default()
        });
        let mut pick = false;
        egui::Frame::new()
            .fill(pal.surface)
            .stroke(Stroke::new(
                1.0,
                if name.is_none() { pal.accent } else { pal.line },
            ))
            .corner_radius(CornerRadius::same(theme::R_INPUT))
            .inner_margin(egui::Margin::symmetric(12, 4))
            .show(ui, |ui| {
                ui.set_width(ui.available_width());
                ui.horizontal(|ui| {
                    ui.set_min_height(32.0);
                    let text_w = (ui.available_width() - 120.0).max(60.0);
                    ui.allocate_ui_with_layout(
                        vec2(text_w, 32.0),
                        Layout::left_to_right(Align::Center),
                        |ui| {
                            match &name {
                                Some(n) => ui.add(
                                    egui::Label::new(RichText::new(n).color(pal.ink).size(14.0))
                                        .truncate(),
                                ),
                                None => ui.label(
                                    RichText::new(tr(
                                        "Kimlik dosyası seçilmedi",
                                        "No identity file selected",
                                    ))
                                    .color(pal.muted)
                                    .size(14.0),
                                ),
                            };
                        },
                    );
                    ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                        let label = if name.is_some() {
                            tr("Değiştir", "Change")
                        } else {
                            tr("Seç", "Choose")
                        };
                        pick = link_button(ui, pal, label).clicked();
                    });
                });
            });
        if pick
            && let Some(p) = rfd::FileDialog::new()
                .set_title(tr("Kimlik dosyasını seçin", "Choose the identity file"))
                .add_filter("lephycrypy identity", &["lphykey"])
                .pick_file()
        {
            self.identity = Some(p);
            self.error = None;
        }
        ui.add_space(10.0);
        let (_, s) = self.password.ui(ui, true);
        *submit = s;
        if !self.edit_recipients
            && !self.batch()
            && link_button(
                ui,
                pal,
                tr("Alıcı listesini değiştir…", "Change the recipient list…"),
            )
            .clicked()
        {
            self.edit_recipients = true;
            self.listing = None;
            self.selected.clear();
        }
    }

    fn keyfile_row(&mut self, ui: &mut Ui, pal: Palette, required: bool) {
        let title = if required {
            tr(
                "Anahtar dosyası (bu dosya için gerekli)",
                "Key file (required for this file)",
            )
        } else {
            tr("Anahtar dosyası (isteğe bağlı)", "Key file (optional)")
        };
        ui.label(RichText::new(title).color(pal.muted).size(13.0));
        let name = self.keyfile.as_ref().map(|k| {
            k.file_name()
                .map(|f| escape_display(&f.to_string_lossy()))
                .unwrap_or_default()
        });
        let mut pick = false;
        let mut clear = false;
        let mut create = false;
        egui::Frame::new()
            .fill(pal.surface)
            .stroke(Stroke::new(
                1.0,
                if required && name.is_none() {
                    pal.accent
                } else {
                    pal.line
                },
            ))
            .corner_radius(CornerRadius::same(theme::R_INPUT))
            .inner_margin(egui::Margin::symmetric(12, 4))
            .show(ui, |ui| {
                ui.set_width(ui.available_width());
                ui.horizontal(|ui| {
                    ui.set_min_height(32.0);
                    let text_w = (ui.available_width() - 120.0).max(60.0);
                    ui.allocate_ui_with_layout(
                        vec2(text_w, 32.0),
                        Layout::left_to_right(Align::Center),
                        |ui| {
                            match &name {
                                Some(n) => ui.add(
                                    egui::Label::new(RichText::new(n).color(pal.ink).size(14.0))
                                        .truncate(),
                                ),
                                None => ui.label(
                                    RichText::new(tr("Seçilmedi", "None selected"))
                                        .color(pal.muted)
                                        .size(14.0),
                                ),
                            };
                        },
                    );
                    ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                        if name.is_some() {
                            clear = link_button(ui, pal, tr("Kaldır", "Remove")).clicked();
                            pick = link_button(ui, pal, tr("Değiştir", "Change")).clicked();
                        } else {
                            pick = link_button(ui, pal, tr("Seç", "Choose")).clicked();
                            if !required {
                                create = link_button(ui, pal, tr("Yeni oluştur", "Create new"))
                                    .clicked();
                            }
                        }
                    });
                });
            });
        if pick
            && let Some(p) = rfd::FileDialog::new()
                .set_title(tr("Anahtar dosyasını seçin", "Choose the key file"))
                .pick_file()
        {
            self.keyfile = Some(p);
            self.error = None;
        }
        if clear {
            self.keyfile = None;
        }
        if create
            && let Some(p) = rfd::FileDialog::new()
                .set_title(tr(
                    "Yeni anahtar dosyasını kaydedin",
                    "Save the new key file",
                ))
                .set_file_name("lephycrypy.key")
                .save_file()
        {
            match lephy_core::password::generate_keyfile(&p, 64) {
                Ok(()) => {
                    self.keyfile = Some(p);
                    self.error = None;
                }
                Err(e) => self.error = Some(logic::describe_error(&e)),
            }
        }
    }

    fn running_view(&mut self, ui: &mut Ui, pal: Palette, since: Instant) {
        let mode = self.mode().unwrap_or(Mode::Encrypt);
        self.source_card(ui, pal, false);
        ui.add_space(28.0);
        let verb = match mode {
            Mode::Encrypt => tr("Şifreleniyor", "Encrypting"),
            Mode::Decrypt => tr("Şifre çözülüyor", "Decrypting"),
        };
        let total = self.total.load(Ordering::Relaxed);
        let done = lephy_core::pipeline::progress();
        #[allow(clippy::cast_precision_loss)]
        let frac = (total > 0 && done > 0).then(|| (done as f32 / total as f32).clamp(0.0, 0.99));
        let (title, sub) = match frac {
            Some(f) if f >= 0.99 => (
                tr("Diske yazılıyor…", "Writing to disk…").to_string(),
                tr(
                    "Son veriler kalıcı olarak kaydediliyor.",
                    "Saving the last data permanently.",
                )
                .to_string(),
            ),
            Some(f) => (
                match lang() {
                    Lang::Tr => format!("{verb}… %{}", (f * 100.0).floor()),
                    Lang::En => format!("{verb}… {}%", (f * 100.0).floor()),
                },
                format!(
                    "{} / {}",
                    logic::human_size(done.min(total)),
                    logic::human_size(total)
                ),
            ),
            None => (
                format!("{verb}…"),
                tr(
                    "Parolanın anahtara dönüştürülmesi birkaç saniye sürer.",
                    "Turning the password into a key takes a few seconds.",
                )
                .to_string(),
            ),
        };
        ui.label(
            RichText::new(title)
                .font(fonts::semibold(16.5))
                .color(pal.ink),
        );
        ui.label(RichText::new(sub).color(pal.muted).size(13.0));
        ui.add_space(12.0);
        let (track, _) = ui.allocate_exact_size(vec2(ui.available_width(), 4.0), Sense::hover());
        let p = ui.painter_at(track);
        p.rect_filled(track, 2.0, pal.line);
        if let Some(f) = frac {
            // Smooth: the bar glides to each new value instead of jumping.
            let f = crate::motion::follow(ui.ctx(), egui::Id::unique("progress-bar"), f, 0.35);
            p.rect_filled(
                Rect::from_min_size(track.min, vec2(track.width() * f, track.height())),
                2.0,
                pal.accent,
            );
        } else {
            let seg = track.width() * 0.28;
            let t = (since.elapsed().as_secs_f32() % 1.6) / 1.6;
            let x = track.left() - seg + (track.width() + seg) * t;
            p.rect_filled(
                Rect::from_min_size(pos2(x, track.top()), vec2(seg, track.height())),
                2.0,
                pal.accent,
            );
        }
        ui.ctx().request_repaint_after(Duration::from_millis(16));
        ui.add_space(12.0);
        ui.horizontal(|ui| {
            ui.label(
                RichText::new(format!("{} sn", since.elapsed().as_secs()))
                    .color(pal.muted)
                    .size(13.0),
            );
            ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                if self.cancel_requested {
                    ui.label(
                        RichText::new(tr("Durduruluyor…", "Stopping…"))
                            .color(pal.muted)
                            .size(13.0),
                    );
                } else if link_button(ui, pal, tr("İptal", "Cancel")).clicked() {
                    self.cancel_requested = true;
                    lephy_sys::signal::request_cancel();
                }
            });
        });
    }

    #[allow(clippy::too_many_lines)]
    fn done_view(&mut self, ui: &mut Ui, pal: Palette) {
        let Stage::Done(out) = &self.stage else {
            return;
        };
        let out = out.clone();
        let mode = self.mode().unwrap_or(Mode::Encrypt);
        ui.add_space(36.0);
        let mut reveal = false;
        let mut again = false;
        ui.with_layout(Layout::top_down(Align::Center), |ui| {
            let (g, _) = ui.allocate_exact_size(vec2(52.0, 52.0), Sense::hover());
            let t = crate::motion::since_change(
                ui.ctx(),
                egui::Id::unique("done-mark"),
                self.view_key(),
                0.45,
            );
            draw_check_animated(ui.painter(), g.center(), pal.accent, t);
            ui.add_space(14.0);
            ui.label(
                RichText::new(match mode {
                    _ if out.recipients_set.is_some() => {
                        tr("Alıcılar güncellendi", "Recipients updated")
                    }
                    Mode::Encrypt => tr("Şifrelendi", "Encrypted"),
                    Mode::Decrypt => tr("Şifre çözüldü", "Decrypted"),
                })
                .font(fonts::semibold(22.0))
                .color(pal.ink),
            );
            let name = if out.outputs.len() == 1 {
                out.outputs[0]
                    .file_name()
                    .map(|f| escape_display(&f.to_string_lossy()))
                    .unwrap_or_default()
            } else {
                match lang() {
                    Lang::Tr => format!("{} öğe", out.outputs.len()),
                    Lang::En => format!("{} items", out.outputs.len()),
                }
            };
            ui.label(RichText::new(name).color(pal.muted).size(14.0));
            if out.executables > 0 {
                ui.add_space(6.0);
                ui.label(
                    RichText::new(tr(
                        "Çıkan dosyalar arasında çalıştırılabilir program var. Yalnızca güvendiğiniz birinden geldiyse açın.",
                        "The output contains programs that can run. Open them only if they came from someone you trust.",
                    ))
                    .color(pal.danger)
                    .size(12.5),
                );
            }
            if let Some(k) = &out.signer {
                ui.add_space(6.0);
                ui.label(
                    RichText::new(tr("İmzalayan (doğrulandı):", "Signed by (verified):"))
                        .color(pal.accent)
                        .size(13.0),
                );
                ui.label(RichText::new(k).monospace().size(11.5).color(pal.ink));
            }
            if out.damaged > 0 || out.incomplete {
                ui.label(
                    RichText::new(match lang() {
                        Lang::Tr => format!(
                            "Kurtarıldı: {} bölüm doğrulanamadı ve sıfırla dolduruldu{}. Çıktı güvenilmez veri içerebilir.",
                            out.damaged,
                            if out.incomplete { "; dosya eksik" } else { "" }
                        ),
                        Lang::En => format!(
                            "Recovered: {} parts failed verification and were zero-filled{}. The output may contain untrustworthy data.",
                            out.damaged,
                            if out.incomplete { "; the file was incomplete" } else { "" }
                        ),
                    })
                    .color(pal.danger)
                    .size(12.5),
                );
            }
            if out.repaired > 0 {
                ui.label(
                    RichText::new(match lang() {
                        Lang::Tr => format!("Hata düzeltme {} baytı onardı.", out.repaired),
                        Lang::En => format!("Error correction repaired {} bytes.", out.repaired),
                    })
                    .color(pal.muted)
                    .size(12.5),
                );
            }
            for (n, why) in out.failed.iter().take(6) {
                ui.label(
                    RichText::new(format!("{n}: {why}"))
                        .color(pal.danger)
                        .size(12.5),
                );
            }
            if out.skipped > 0 {
                ui.label(
                    RichText::new(match lang() {
                        Lang::Tr => format!(
                            "{} öğe atlandı (özel dosyalar ya da kısayol bağlantıları).",
                            out.skipped
                        ),
                        Lang::En => format!(
                            "{} items skipped (special files or shortcuts).",
                            out.skipped
                        ),
                    })
                    .color(pal.muted)
                    .size(12.5),
                );
            }
            ui.add_space(24.0);
            reveal = primary_button(ui, pal, tr("Klasörde göster", "Show in folder"), true).clicked();
            ui.add_space(4.0);
            again = secondary_button(ui, pal, tr("Yeni işlem", "New"), ui.available_width(), 42.0).clicked();
            if mode == Mode::Encrypt {
                ui.add_space(14.0);
                let note = if out.deleted > 0 && out.kept == 0 {
                    tr(
                        "Özgün dosyaların üzerine yazıldı ve silindi. SSD ve anlık görüntülerde kalıntı olabilir.",
                        "The originals were overwritten and deleted. Traces may remain on SSDs and in snapshots.",
                    )
                } else if out.deleted > 0 {
                    tr(
                        "Özgünler silindi; şifrelemeden sonra değişen bazı öğeler yerinde bırakıldı.",
                        "The originals were deleted; some items that changed after encryption were left in place.",
                    )
                } else {
                    tr(
                        "Özgün dosya yerinde duruyor. Artık gerekmiyorsa kendiniz silebilirsiniz.",
                        "The original is still in place. Delete it yourself if you no longer need it.",
                    )
                };
                ui.label(RichText::new(note).color(pal.muted).size(12.5));
            }
        });
        if reveal
            && let Some(first) = out.outputs.first()
            && let Err(e) = logic::reveal_in_folder(first)
        {
            self.error = Some(match lang() {
                Lang::Tr => format!("Klasör açılamadı: {e}."),
                Lang::En => format!("Could not open the folder: {e}."),
            });
        }
        if again {
            self.reset();
        }
    }
}

/// Pencereye verilecek uygulama.
#[must_use]
pub fn boxed() -> Box<dyn eframe::App> {
    let mut app = App::with_prefs(crate::settings::Settings::load());
    app.scan_on_start = true;
    app.reduce_motion = lephy_sys::a11y::reduce_motion();
    if app.locked {
        app.lock_gate.persist = true;
        app.lock_gate.load_persisted();
    }
    Box::new(app)
}

mod help;
mod lockgate;
mod maintenance;
mod pages;
mod restore;
mod settings_ui;

impl eframe::App for App {
    fn ui(&mut self, ui: &mut Ui, _frame: &mut eframe::Frame) {
        let fill = theme::palette(ui.ctx()).bg;
        egui::CentralPanel::default()
            .frame(egui::Frame::new().fill(fill))
            .show(ui, |ui| self.draw(ui));
    }
}

// ---------------------------------------------------------------------------------------------
// Buttons
// ---------------------------------------------------------------------------------------------

fn focus_ring(ui: &Ui, resp: &Response, rect: Rect, pal: Palette) {
    if resp.has_focus() {
        ui.painter().rect_stroke(
            rect.expand(3.0),
            f32::from(theme::R_INPUT) + 3.0,
            Stroke::new(2.0, pal.accent.gamma_multiply(0.45)),
            StrokeKind::Outside,
        );
    }
}

/// Full-width primary button.
fn primary_button(ui: &mut Ui, pal: Palette, text: &str, enabled: bool) -> Response {
    let sense = if enabled {
        Sense::click()
    } else {
        Sense::hover()
    };
    let (rect, resp) = ui.allocate_exact_size(vec2(ui.available_width(), 42.0), sense);
    resp.widget_info(|| WidgetInfo::labeled(egui::Role::Button, enabled, text));
    let fill = if !enabled {
        pal.accent.gamma_multiply(0.35)
    } else if resp.is_pointer_button_down_on() {
        pal.accent.lerp_to_gamma(Color32::BLACK, 0.15)
    } else if resp.hovered() {
        pal.accent.lerp_to_gamma(Color32::BLACK, 0.07)
    } else {
        pal.accent
    };
    ui.painter()
        .rect_filled(rect, f32::from(theme::R_INPUT), fill);
    ui.painter().text(
        rect.center(),
        egui::Align2::CENTER_CENTER,
        text,
        fonts::semibold(15.0),
        pal.on_accent,
    );
    focus_ring(ui, &resp, rect, pal);
    if enabled {
        resp.on_hover_cursor(CursorIcon::PointingHand)
    } else {
        resp
    }
}

/// Framed secondary button.
fn secondary_button(ui: &mut Ui, pal: Palette, text: &str, w: f32, h: f32) -> Response {
    let (rect, resp) = ui.allocate_exact_size(vec2(w, h), Sense::click());
    resp.widget_info(|| WidgetInfo::labeled(egui::Role::Button, true, text));
    let stroke = if resp.hovered() { pal.muted } else { pal.line };
    let fill = if resp.is_pointer_button_down_on() {
        pal.accent_soft
    } else {
        pal.surface
    };
    ui.painter().rect(
        rect,
        f32::from(theme::R_INPUT),
        fill,
        Stroke::new(1.0, stroke),
        StrokeKind::Inside,
    );
    ui.painter().text(
        rect.center(),
        egui::Align2::CENTER_CENTER,
        text,
        fonts::regular(14.5),
        pal.ink,
    );
    focus_ring(ui, &resp, rect, pal);
    resp.on_hover_cursor(CursorIcon::PointingHand)
}

/// Segmented choice (radio group). Option: (value, name, enabled).
fn segmented<T: PartialEq + Copy>(
    ui: &mut Ui,
    pal: Palette,
    value: &mut T,
    opts: &[(T, &str, bool)],
) {
    let h = 36.0;
    let (outer, _) = ui.allocate_exact_size(vec2(ui.available_width(), h), Sense::hover());
    ui.painter().rect(
        outer,
        f32::from(theme::R_INPUT),
        pal.bg,
        Stroke::new(1.0, pal.line),
        StrokeKind::Inside,
    );
    #[allow(clippy::cast_precision_loss)]
    let seg_w = (outer.width() - 6.0) / opts.len() as f32;
    for (i, &(v, label, enabled)) in opts.iter().enumerate() {
        #[allow(clippy::cast_precision_loss)]
        let r = Rect::from_min_size(
            pos2(outer.left() + 3.0 + seg_w * i as f32, outer.top() + 3.0),
            vec2(seg_w, h - 6.0),
        );
        let id = ui.scope_id().with(("seg", label));
        let sense = if enabled {
            Sense::click()
        } else {
            Sense::hover()
        };
        let resp = ui.interact(r, id, sense);
        let selected = *value == v;
        resp.widget_info(|| {
            WidgetInfo::selected(egui::Role::RadioButton, enabled, selected, label)
        });
        if resp.clicked() {
            *value = v;
        }
        if selected {
            ui.painter().rect(
                r,
                f32::from(theme::R_INPUT) - 2.0,
                pal.surface,
                Stroke::new(1.0, pal.line),
                StrokeKind::Inside,
            );
        } else if resp.hovered() && enabled {
            ui.painter().rect_filled(
                r,
                f32::from(theme::R_INPUT) - 2.0,
                pal.line.gamma_multiply(0.5),
            );
        }
        let (font, color) = if selected {
            (fonts::semibold(13.5), pal.ink)
        } else if enabled {
            (fonts::regular(13.5), pal.muted)
        } else {
            (fonts::regular(13.5), pal.muted.gamma_multiply(0.45))
        };
        ui.painter()
            .text(r.center(), egui::Align2::CENTER_CENTER, label, font, color);
        if resp.has_focus() {
            ui.painter().rect_stroke(
                r,
                f32::from(theme::R_INPUT) - 2.0,
                Stroke::new(1.5, pal.accent),
                StrokeKind::Inside,
            );
        }
        if enabled {
            let _ = resp.on_hover_cursor(CursorIcon::PointingHand);
        } else {
            let _ = resp.on_hover_text(tr(
                "Bu bilgisayarın belleği bu seçenek için yetmiyor.",
                "This computer does not have enough memory for this option.",
            ));
        }
    }
}

/// The generated password, masked until the pointer rests on it (or it has keyboard focus), so
/// it is not readable over the shoulder or in a screen recording while the window is just open.
fn reveal_on_hover(ui: &mut Ui, pal: Palette, secret: &[u8]) {
    let font = fonts::semibold(15.5);
    let width = ui.available_width();
    // The displayed text ends up in the toolkit's memory copies; the zeroizing allocator wipes
    // them when freed (THREAT-MODEL).
    let text = String::from_utf8_lossy(secret);
    let shown = ui
        .painter()
        .layout(text.into_owned(), font.clone(), pal.ink, width);
    let (rect, resp) = ui.allocate_exact_size(vec2(width, shown.size().y), Sense::click());
    let visible = resp.hovered() || resp.has_focus();
    resp.widget_info(|| {
        WidgetInfo::labeled(
            egui::Role::Button,
            true,
            tr(
                "Gizli metin (görmek için üzerine gelin)",
                "Secret text (hover to show)",
            ),
        )
    });
    if visible {
        ui.painter().galley(rect.min, shown, pal.ink);
    } else {
        drop(shown);
        let n = secret.len().min(32);
        ui.painter().text(
            rect.left_top(),
            egui::Align2::LEFT_TOP,
            "•".repeat(n),
            font,
            pal.ink,
        );
    }
    let _ = resp.on_hover_cursor(CursorIcon::Default);
    ui.label(
        RichText::new(if visible {
            tr(
                "İmleci çekince yeniden gizlenir.",
                "Hidden again when the pointer leaves.",
            )
        } else {
            tr(
                "Görmek için imleci noktaların üzerine getirin.",
                "Hover over the dots to show it.",
            )
        })
        .color(pal.muted)
        .size(12.5),
    );
}

/// Gear icon (settings card).
fn draw_gear(p: &egui::Painter, c: Pos2, color: Color32) {
    let stroke = Stroke::new(1.8, color);
    p.circle_stroke(c, 8.0, stroke);
    p.circle_stroke(c, 3.2, stroke);
    for i in 0..8 {
        #[allow(clippy::cast_precision_loss)]
        let a = std::f32::consts::FRAC_PI_4 * i as f32;
        let d = vec2(a.cos(), a.sin());
        p.line_segment([c + d * 8.0, c + d * 11.5], Stroke::new(3.0, color));
    }
}

/// Key icon (keys card): a ring and a bit with two teeth.
fn draw_key(p: &egui::Painter, c: Pos2, color: Color32) {
    let stroke = Stroke::new(1.8, color);
    let ring = c + vec2(-6.0, 0.0);
    p.circle_stroke(ring, 5.5, stroke);
    let start = ring + vec2(5.5, 0.0);
    let end = c + vec2(11.0, 0.0);
    p.line_segment([start, end], stroke);
    p.line_segment([end, end + vec2(0.0, 5.0)], stroke);
    p.line_segment([end + vec2(-5.0, 0.0), end + vec2(-5.0, 4.0)], stroke);
}

/// "?" button in a circle.
fn help_button(ui: &mut Ui, pal: Palette, open: bool) -> Response {
    let (rect, resp) = ui.allocate_exact_size(vec2(20.0, 20.0), Sense::click());
    resp.widget_info(|| {
        WidgetInfo::labeled(
            egui::Role::Button,
            true,
            tr("Terimleri açıkla", "Explain the terms"),
        )
    });
    let c = rect.center();
    let (fill, fg) = if open {
        (pal.accent, pal.on_accent)
    } else if resp.hovered() {
        (pal.accent_soft, pal.accent)
    } else {
        (pal.surface, pal.muted)
    };
    ui.painter().circle(
        c,
        9.0,
        fill,
        Stroke::new(1.0, if open { pal.accent } else { pal.line }),
    );
    ui.painter().text(
        c + vec2(0.0, 0.5),
        egui::Align2::CENTER_CENTER,
        "?",
        fonts::semibold(12.5),
        fg,
    );
    focus_ring(ui, &resp, rect, pal);
    resp.on_hover_cursor(CursorIcon::PointingHand)
        .on_hover_text(tr(
            "Bu ayarlar ne anlama geliyor?",
            "What do these settings mean?",
        ))
}

/// Term explanations.
fn help_card(ui: &mut Ui, pal: Palette) {
    const TERMS: [(&str, &str, &str, &str); 5] = [
        (
            "XChaCha20-Poly1305",
            "XChaCha20-Poly1305",
            "Varsayılan şifreleme yöntemi. Her işlemcide hızlıdır ve yanlış kullanıma karşı daha dayanıklıdır.",
            "The default cipher. Fast on every processor and more forgiving of misuse.",
        ),
        (
            "AES-256-GCM",
            "AES-256-GCM",
            "Yaygın kullanılan standart. Donanım desteği olan işlemcilerde çok hızlıdır. İki yöntem de aynı güvenlik düzeyindedir.",
            "The widely used standard. Very fast on processors with hardware support. Both ciphers offer the same level of security.",
        ),
        (
            "Parola türetme belleği (Argon2id)",
            "Password derivation memory (Argon2id)",
            "Parolanız şifreleme anahtarına dönüştürülürken kullanılan bellek. Arttıkça parola tahmin denemeleri pahalılaşır; dosyayı açan bilgisayarda da bu kadar boş bellek gerekir.",
            "Memory used while turning your password into the encryption key. More memory makes password guessing more expensive; the computer that opens the file needs the same amount free.",
        ),
        (
            "Boyut gizleme (PADMÉ)",
            "Size hiding (PADMÉ)",
            "Şifreli dosyanın boyutunu yuvarlayarak gerçek boyutun anlaşılmasını zorlaştırır. Dosya en fazla yaklaşık %12 büyür.",
            "Rounds up the size of the encrypted file so the real size is harder to tell. The file grows by about 12% at most.",
        ),
        (
            "Anahtar dosyası",
            "Key file",
            "Parolaya ek olarak seçtiğiniz herhangi bir dosya (32 bayt ile 1 MiB arası). Şifreli dosyayı açmak için hem parola hem bu dosya gerekir; bu dosyayı kaybederseniz verinize ulaşamazsınız.",
            "Any file you choose in addition to the password (32 bytes to 1 MiB). Opening the encrypted file needs both; if you lose this file you lose access to your data.",
        ),
    ];
    egui::Frame::new()
        .fill(pal.bg)
        .corner_radius(CornerRadius::same(theme::R_INPUT))
        .inner_margin(egui::Margin::same(12))
        .show(ui, |ui| {
            ui.set_width(ui.available_width());
            for (i, (tt, te, dt, de)) in TERMS.iter().enumerate() {
                let (term, desc) = (tr(tt, te), tr(dt, de));
                if i > 0 {
                    ui.add_space(6.0);
                }
                ui.label(
                    RichText::new(term)
                        .font(fonts::semibold(13.5))
                        .color(pal.ink),
                );
                ui.label(RichText::new(desc).color(pal.muted).size(13.0));
            }
        });
    ui.add_space(8.0);
}

/// Bundle identifier of the macOS app (see `scripts/macos-app.sh`).
#[cfg(target_os = "macos")]
const BUNDLE_ID: &str = "io.github.seesternn.lephycrypy";

/// Frameless text button (in the accent colour).
fn link_button(ui: &mut Ui, pal: Palette, text: &str) -> Response {
    ui.add(
        egui::Button::new(RichText::new(text).color(pal.accent).size(14.0))
            .frame(false)
            .min_size(vec2(0.0, 28.0)),
    )
    .on_hover_cursor(CursorIcon::PointingHand)
}

// ---------------------------------------------------------------------------------------------
// Line icons
// ---------------------------------------------------------------------------------------------

fn arc(c: Pos2, r: f32, from: f32, to: f32) -> Vec<Pos2> {
    (0..=24)
        .map(|i| {
            #[allow(clippy::cast_precision_loss)]
            let t = from + (to - from) * (i as f32 / 24.0);
            pos2(c.x + r * t.cos(), c.y + r * t.sin())
        })
        .collect()
}

/// Padlock: body + shackle. `s` is the scale (1.0 ≈ 40 px).
fn draw_lock(p: &egui::Painter, c: Pos2, s: f32, color: Color32) {
    let w = 2.0 * s.max(0.8);
    let body = Rect::from_center_size(c + vec2(0.0, 6.0 * s), vec2(26.0 * s, 20.0 * s));
    p.rect_stroke(body, 4.0 * s, Stroke::new(w, color), StrokeKind::Middle);
    let top = body.top();
    let r = 7.5 * s;
    let mut pts = vec![pos2(c.x - r, top)];
    pts.push(pos2(c.x - r, top - 5.0 * s));
    pts.extend(arc(
        pos2(c.x, top - 5.0 * s),
        r,
        std::f32::consts::PI,
        2.0 * std::f32::consts::PI,
    ));
    pts.push(pos2(c.x + r, top));
    p.add(egui::Shape::line(pts, Stroke::new(w, color)));
    p.circle_filled(body.center() + vec2(0.0, -s), 2.2 * s, color);
}

/// Document: page with a folded corner.
fn draw_doc(p: &egui::Painter, c: Pos2, color: Color32) {
    let r = Rect::from_center_size(c, vec2(16.0, 21.0));
    let f = 5.0;
    let st = Stroke::new(1.6, color);
    let pts = vec![
        r.left_top(),
        pos2(r.right() - f, r.top()),
        pos2(r.right(), r.top() + f),
        r.right_bottom(),
        r.left_bottom(),
        r.left_top(),
    ];
    p.add(egui::Shape::line(pts, st));
    p.add(egui::Shape::line(
        vec![
            pos2(r.right() - f, r.top()),
            pos2(r.right() - f, r.top() + f),
            pos2(r.right(), r.top() + f),
        ],
        st,
    ));
}

/// Folder: body with a tab.
fn draw_folder(p: &egui::Painter, c: Pos2, color: Color32) {
    let r = Rect::from_center_size(c + vec2(0.0, 1.0), vec2(22.0, 16.0));
    let st = Stroke::new(1.6, color);
    let pts = vec![
        pos2(r.left(), r.top() - 2.0),
        pos2(r.left() + 7.0, r.top() - 2.0),
        pos2(r.left() + 9.5, r.top() + 1.0),
        pos2(r.right(), r.top() + 1.0),
        r.right_bottom(),
        r.left_bottom(),
        pos2(r.left(), r.top() - 2.0),
    ];
    p.add(egui::Shape::line(pts, st));
}

/// Check mark in a circle.
/// The done mark drawn over `t` (0 → 1): the ring sweeps round with a small pop, then the tick
/// is drawn stroke by stroke.
fn draw_check_animated(p: &egui::Painter, c: Pos2, color: Color32, t: f32) {
    if t >= 1.0 {
        draw_check(p, c, color);
        return;
    }
    let ring = (t / 0.6).clamp(0.0, 1.0);
    let r = 24.0 * (0.85 + 0.15 * ring);
    let steps = 48;
    #[allow(clippy::cast_precision_loss, reason = "small counts")]
    let pts: Vec<Pos2> = (0..=steps)
        .map(|i| {
            let a = -std::f32::consts::FRAC_PI_2
                + std::f32::consts::TAU * ring * (i as f32 / steps as f32);
            c + vec2(a.cos(), a.sin()) * r
        })
        .collect();
    p.add(egui::Shape::line(pts, Stroke::new(2.0, color)));
    let tick = ((t - 0.45) / 0.55).clamp(0.0, 1.0);
    if tick > 0.0 {
        let (a, b, e) = (
            c + vec2(-9.0, 0.5),
            c + vec2(-3.0, 6.5),
            c + vec2(9.5, -6.5),
        );
        let first = (tick / 0.35).clamp(0.0, 1.0);
        let mut line = vec![a, a + (b - a) * first];
        if tick > 0.35 {
            line.push(b + (e - b) * ((tick - 0.35) / 0.65));
        }
        p.add(egui::Shape::line(line, Stroke::new(2.4, color)));
    }
}

fn draw_check(p: &egui::Painter, c: Pos2, color: Color32) {
    p.circle_stroke(c, 24.0, Stroke::new(2.0, color));
    p.add(egui::Shape::line(
        vec![
            c + vec2(-9.0, 0.5),
            c + vec2(-3.0, 6.5),
            c + vec2(9.5, -6.5),
        ],
        Stroke::new(2.4, color),
    ));
}

#[cfg(test)]
mod tests {
    use super::*;

    fn frame(ctx: &egui::Context, app: &mut App) {
        let mut out = ctx.run_ui(egui::RawInput::default(), |ui| app.draw(ui));
        out.textures_delta.clear();
    }

    #[test]
    #[allow(clippy::unwrap_used)]
    #[allow(clippy::too_many_lines, reason = "one walk through every screen")]
    fn renders_every_stage_headless() {
        let ctx = egui::Context::default();
        theme::apply(&ctx);
        let mut app = App::default();
        let d = std::env::temp_dir().join(format!("lphy-gui-app-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap_or(());
        std::fs::write(d.join("a.txt"), b"x").unwrap_or(());

        frame(&ctx, &mut app);
        app.set_source(&d.join("a.txt"));
        assert_eq!(app.mode(), Some(Mode::Encrypt));
        assert!(!app.can_start(), "must not start without a password");
        app.show_advanced = true;
        app.error = Some("Örnek hata.".into());
        for _ in 0..2 {
            frame(&ctx, &mut app);
        }
        assert_eq!(
            app.output
                .as_deref()
                .and_then(Path::extension)
                .and_then(|e| e.to_str()),
            Some("lphy")
        );
        app.stage = Stage::Running {
            since: Instant::now(),
        };
        frame(&ctx, &mut app);
        app.stage = Stage::Done(Outcome {
            outputs: vec![d.join("x.lphy")],
            skipped: 2,
            ..Outcome::default()
        });
        frame(&ctx, &mut app);
        app.reset();
        assert!(matches!(app.stage, Stage::Pick));
        frame(&ctx, &mut app);
        // An open request while an item is chosen waits for confirmation.
        app.set_source(&d.join("a.txt"));
        app.password.set(b"typed password");
        app.pending_open.push(d.join("other.txt"));
        frame(&ctx, &mut app);
        assert_eq!(
            app.source.as_ref().map(|s| s.path.clone()),
            Some(d.join("a.txt"))
        );
        assert!(
            app.password.char_count() > 0,
            "the typed password must stay"
        );
        assert!(app.awaits_open_confirmation());
        app.pending_open.clear();
        app.reset();
        frame(&ctx, &mut app);
        for page in [
            pages::Page::Welcome,
            pages::Page::Encrypt,
            pages::Page::Decrypt,
            pages::Page::Help,
            pages::Page::Keys,
            pages::Page::Settings,
        ] {
            app.page = page;
            frame(&ctx, &mut app);
        }
        app.stale.found = vec![d.join(".lphy-tmp-x")];
        app.page = pages::Page::Home;
        frame(&ctx, &mut app);
        app.page = pages::Page::Settings;
        frame(&ctx, &mut app);
        app.stale.found.clear();
        assert!(!app.secret_on_screen());
        app.generated = Some(lephy_sys::mem::SecretBytes::from_slice(b"pw").unwrap());
        frame(&ctx, &mut app);
        assert!(
            app.capture_protected,
            "a visible password hides the window from capture"
        );
        app.generated = None;
        frame(&ctx, &mut app);
        assert!(!app.capture_protected);
        app.page = pages::Page::Keys;
        app.restore.open = true;
        frame(&ctx, &mut app);
        app.go_home();
        assert!(!app.restore.open);
        // Esc: from a page back home; motion off draws end states at once.
        for pane in [
            settings_ui::Pane::Language,
            settings_ui::Pane::Appearance,
            settings_ui::Pane::Lock,
            settings_ui::Pane::Maintenance,
            settings_ui::Pane::About,
        ] {
            app.page = pages::Page::Settings;
            app.settings_pane = pane;
            app.lock_edit = pane == settings_ui::Pane::Lock;
            frame(&ctx, &mut app);
        }
        app.lock_edit = false;
        // Esc: a settings page goes back to the list, then the list goes home.
        app.handle_escape(&ctx);
        ctx.input_mut(|i| {
            i.events.push(egui::Event::Key {
                key: egui::Key::Escape,
                physical_key: None,
                pressed: true,
                repeat: false,
                modifiers: egui::Modifiers::NONE,
            });
        });
        app.prefs.anim_off = true;
        frame(&ctx, &mut app);
        app.prefs.anim_off = false;
        app.show_toast(&ctx, "Copied");
        frame(&ctx, &mut app);
        assert!(app.toast.is_some());
        for step in 0..3 {
            app.page = pages::Page::Welcome;
            app.welcome_step = step;
            frame(&ctx, &mut app);
        }
        // Choosing something lands on its page, so "Change" comes back to the right one.
        app.page = pages::Page::Home;
        app.set_sources(&[d.join("a.txt")]);
        assert_eq!(app.page, pages::Page::Encrypt);
        app.reset();
        assert!(matches!(app.stage, Stage::Pick) && app.page == pages::Page::Encrypt);
        // The output is not custom until "Change" picks one: a decrypted file keeps its name.
        assert!(!app.output_custom);
        app.go_home();
        assert_eq!((app.page, app.welcome_step), (pages::Page::Home, 0));
        // App lock: locked at start when a verifier is saved; the right password opens it.
        let pw = lephy_sys::mem::SecretBytes::from_slice(b"app lock 123").unwrap();
        let mut prefs = crate::settings::Settings {
            welcome_done: true,
            ..Default::default()
        };
        prefs.lock = Some(crate::settings::LockVerifier::new(&pw).unwrap());
        let mut locked = App::with_prefs(prefs);
        assert!(locked.locked && locked.page == pages::Page::Home);
        frame(&ctx, &mut locked);
        // A wrong password waits before the next try; the right one opens the app.
        let wrong = lephy_sys::mem::SecretBytes::from_slice(b"app lock 124").unwrap();
        locked.start_lock_check(&ctx, wrong, lockgate::Purpose::Unlock);
        while locked.lock_gate.busy() {
            locked.poll_lock_check(&ctx);
            std::thread::sleep(Duration::from_millis(20));
        }
        assert!(locked.locked && locked.lock_gate.wait_left() > 0);
        // A try during the wait is ignored.
        locked.start_lock_check(
            &ctx,
            lephy_sys::mem::SecretBytes::from_slice(b"app lock 123").unwrap(),
            lockgate::Purpose::Unlock,
        );
        assert!(!locked.lock_gate.busy());
        frame(&ctx, &mut locked);
        assert!(!App::with_prefs(crate::settings::Settings::default()).locked);
        assert!(App::with_prefs(crate::settings::Settings::default()).page == pages::Page::Welcome);
        // Quit confirmation while a job runs, then quitting once it is confirmed.
        let (tx, rx) = std::sync::mpsc::channel();
        app.job = Some(rx);
        app.stage = Stage::Running {
            since: Instant::now(),
        };
        app.quit_confirm = true;
        frame(&ctx, &mut app);
        assert!(app.quit_confirm && !app.quitting);
        drop(tx);
        app.job = None;
        app.stage = Stage::Pick;
        frame(&ctx, &mut app);
        assert!(
            !app.quit_confirm && app.quitting,
            "a finished job quits at once"
        );
        app.quitting = false;
        app.page = pages::Page::Settings;
        app.confirm_shell = true;
        app.settings_note = Some("Not.".into());
        frame(&ctx, &mut app);
        app.page = pages::Page::Home;
        app.confirm_shell = false;

        // Public-key mode: the list decides, no password is needed.
        app.set_source(&d.join("a.txt"));
        app.use_keys = true;
        app.show_keygen = true;
        app.created_pub = Some("lphy1example".into());
        frame(&ctx, &mut app);
        assert!(!app.can_start(), "must not start without a key");
        app.show_keygen = false;
        let (pk, paper) = crate::logic::create_identity(
            &d.join("me.lphykey"),
            &lephy_sys::mem::SecretBytes::from_slice(b"identity pass 1").unwrap(),
            64,
        )
        .unwrap();
        app.paper = Some(paper);
        frame(&ctx, &mut app);
        app.paper = None;
        // An identity file is refused as a source.
        let mut other = App::default();
        other.set_source(&d.join("me.lphykey"));
        assert!(other.source.is_none() && other.error.is_some());
        app.recipients_text = format!("{pk}\n");
        frame(&ctx, &mut app);
        assert!(app.can_start());
        app.recipients_text.push_str("lphy1bozuk\n");
        frame(&ctx, &mut app);
        assert!(!app.can_start(), "must not start with an invalid key");
        let _ = std::fs::remove_dir_all(&d);
    }
}
