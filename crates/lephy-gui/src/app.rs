//! Tek pencere arayüzü. Akış: bırak/seç → parola → şifrele/çöz → sonuç.
//! Görsel dil `theme.rs`'de; ikonlar resim değil, birkaç çizgiyle çizilir.

use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::mpsc::{Receiver, TryRecvError};
use std::time::{Duration, Instant};

use eframe::egui::{
    self, Align, Color32, CornerRadius, CursorIcon, Layout, Pos2, Rect, Response, RichText, Sense,
    Stroke, StrokeKind, Ui, UiBuilder, WidgetInfo, pos2, vec2,
};
use lephy_core::names::escape_display;
use lephy_core::password::MIN_SCALARS;

use crate::fonts;
use crate::logic::{self, Job, Mode, Outcome};
use crate::secret_field::SecretField;
use crate::theme::{self, Palette};

/// İçerik sütununun en büyük genişliği.
const COLUMN_W: f32 = 460.0;

/// Parola türetme belleği seçenekleri (MiB, ad).
const KDF_PRESETS: [(u32, &str); 4] = [
    (256, "Hızlı"),
    (512, "Önerilen"),
    (1024, "Güçlü"),
    (2048, "En güçlü"),
];

/// Seçilen kaynak.
struct Source {
    path: PathBuf,
    mode: Mode,
    name: String,
    detail: String,
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
    /// Kesinti "İptal" düğmesinden mi geldi (sinyal değil → pencere kapanmaz).
    cancel_requested: bool,
    /// Seçili anahtar dosyası.
    keyfile: Option<PathBuf>,
    /// Açılacak dosya anahtar dosyası gerektiriyor.
    keyfile_required: bool,
    /// Son karede ölçülen içerik yüksekliği (dikey ortalama için).
    content_h: f32,
    /// Gelişmiş ayarlarda terim açıklamaları açık mı.
    show_help: bool,
    /// Fiziksel bellek (MiB; bilinmiyorsa 0). Fazla büyük KDF seçenekleri kapatılır.
    ram_mib: u64,
    /// Pencere iş sürerken kapatılmak istendi: iş durunca kapanır.
    close_after_job: bool,
    /// İşin tahmini toplam akış baytı (0: bilinmiyor).
    total: Arc<AtomicU64>,
}

impl Default for App {
    fn default() -> Self {
        Self {
            source: None,
            output: None,
            stage: Stage::Pick,
            password: SecretField::new("Parola"),
            confirm: SecretField::new("Parolayı tekrar girin"),
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
            content_h: 0.0,
            show_help: false,
            ram_mib: lephy_sys::platform::physical_memory_bytes().map_or(0, |b| b / (1024 * 1024)),
            close_after_job: false,
            total: Arc::new(AtomicU64::new(0)),
        }
    }
}

// ---------------------------------------------------------------------------------------------
// Durum geçişleri
// ---------------------------------------------------------------------------------------------

impl App {
    fn set_source(&mut self, p: &Path) {
        let mode = logic::detect_mode(p);
        let (name, detail) = logic::describe_source(p, mode);
        self.output = Some(logic::default_output(p, mode));
        self.source = Some(Source {
            path: p.to_path_buf(),
            mode,
            name,
            detail,
        });
        self.stage = Stage::Ready;
        self.error = None;
        self.allow_cloud = false;
        self.keyfile = None;
        self.keyfile_required = mode == Mode::Decrypt && logic::needs_keyfile(p);
        self.password.clear();
        self.confirm.clear();
    }

    fn reset(&mut self) {
        self.source = None;
        self.output = None;
        self.stage = Stage::Pick;
        self.error = None;
        self.allow_cloud = false;
        self.keyfile = None;
        self.keyfile_required = false;
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
        if self.running() || self.output.is_none() || self.password.is_empty() {
            return false;
        }
        if self.keyfile_required && self.keyfile.is_none() {
            return false;
        }
        match src.mode {
            Mode::Encrypt => {
                self.password.char_count() >= MIN_SCALARS && self.password.same_as(&self.confirm)
            }
            Mode::Decrypt => self.cloud_root().is_none() || self.allow_cloud,
        }
    }

    fn start(&mut self, ctx: &egui::Context) {
        let (Some(src), Some(output)) = (&self.source, &self.output) else {
            return;
        };
        let mode = src.mode;
        let job = Job {
            mode,
            input: src.path.clone(),
            output: output.clone(),
            password: self.password.take(),
            confirm: (mode == Mode::Encrypt).then(|| self.confirm.take()),
            kdf_mib: self.kdf_mib,
            aes: self.aes,
            pad: self.pad,
            allow_cloud: self.allow_cloud,
            keyfile: self.keyfile.clone(),
        };
        self.confirm.clear();
        // Önceki işten kalan iptal, iş başlamadan (UI iş parçacığında) temizlenir; böylece boyut
        // tahmini sırasında basılan İptal kaybolmaz.
        lephy_sys::signal::reset_cancel();
        self.cancel_requested = false;
        let (tx, rx) = std::sync::mpsc::channel();
        let ctx2 = ctx.clone();
        self.total.store(0, Ordering::Relaxed);
        lephy_core::pipeline::reset_progress();
        let total = Arc::clone(&self.total);
        std::thread::spawn(move || {
            total.store(
                logic::estimate_total(job.mode, &job.input),
                Ordering::Relaxed,
            );
            let r = if lephy_sys::signal::interrupted() {
                // Boyut tahmini sırasında iptal edildi: anahtar türetmeye hiç başlanmaz.
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
            Ok(Ok(out)) => {
                self.stage = Stage::Done(out);
                self.job = None;
            }
            Ok(Err(msg)) => {
                self.error = Some(msg);
                self.stage = Stage::Ready;
                self.job = None;
            }
            Err(TryRecvError::Empty) => ctx.request_repaint_after(Duration::from_millis(16)),
            Err(TryRecvError::Disconnected) => {
                self.error = Some("İşlem beklenmedik biçimde sona erdi.".into());
                self.stage = Stage::Ready;
                self.job = None;
            }
        }
        if self.job.is_none() && self.cancel_requested {
            // İptal düğmesi: bayrak temizlenir, uygulama açık kalır.
            lephy_sys::signal::reset_cancel();
            self.cancel_requested = false;
        }
    }

    /// SIGINT/SIGTERM/Ctrl+C: boştaysa pencereyi kapat; iş sürüyorsa iş önce durur (tmp
    /// temizlenir), sonra kapanır. Boşta sinyali fark etmek için düzenli yeniden çizim.
    fn handle_signal(&mut self, ctx: &egui::Context) {
        if lephy_sys::signal::signalled() && !self.running() {
            ctx.send_viewport_cmd(egui::ViewportCommand::Close);
        }
        // Pencere kapatma isteği iş sürerken gelirse: iş iptal edilir, yarım dosya silinir,
        // pencere ancak sonra kapanır.
        if self.running() && ctx.input(|i| i.viewport().close_requested()) {
            ctx.send_viewport_cmd(egui::ViewportCommand::CancelClose);
            self.close_after_job = true;
            self.cancel_requested = true;
            lephy_sys::signal::request_cancel();
        }
        if self.close_after_job && !self.running() {
            ctx.send_viewport_cmd(egui::ViewportCommand::Close);
        }
        ctx.request_repaint_after(Duration::from_millis(400));
    }

    fn handle_drop(&mut self, ctx: &egui::Context) {
        if self.running() {
            return;
        }
        let dropped = ctx.input(|i| i.raw.dropped_files.first().map(|f| f.path().to_path_buf()));
        if let Some(p) = dropped {
            self.set_source(&p);
        }
    }

    fn pick_file(&mut self) {
        if let Some(p) = rfd::FileDialog::new().set_title("Dosya seçin").pick_file() {
            self.set_source(&p);
        }
    }

    fn pick_folder(&mut self) {
        if let Some(p) = rfd::FileDialog::new()
            .set_title("Şifrelenecek klasörü seçin")
            .pick_folder()
        {
            self.set_source(&p);
        }
    }

    fn choose_output(&mut self) {
        let Some(cur) = &self.output else { return };
        let mut d = rfd::FileDialog::new().set_title("Kaydedilecek yeri seçin");
        if let Some(dir) = cur.parent() {
            d = d.set_directory(dir);
        }
        if let Some(name) = cur.file_name() {
            d = d.set_file_name(name.to_string_lossy());
        }
        if let Some(p) = d.save_file() {
            self.output = Some(p);
            self.allow_cloud = false;
            self.error = None;
        }
    }
}

// ---------------------------------------------------------------------------------------------
// Çizim
// ---------------------------------------------------------------------------------------------

impl App {
    /// Bir karede tüm arayüz.
    pub fn draw(&mut self, ui: &mut Ui) {
        let ctx = ui.ctx().clone();
        self.poll(&ctx);
        self.handle_signal(&ctx);
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
                            ui.label(
                                RichText::new("lephycrypy+")
                                    .font(fonts::semibold(15.0))
                                    .color(pal.ink),
                            );
                            ui.add_space(18.0);
                            match self.stage {
                                Stage::Pick => self.pick_view(ui, pal),
                                Stage::Ready => self.ready_view(ui, &ctx, pal),
                                Stage::Running { since } => self.running_view(ui, pal, since),
                                Stage::Done(_) => self.done_view(ui, pal),
                            }
                        });
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

    fn pick_view(&mut self, ui: &mut Ui, pal: Palette) {
        let hovering = ui.input(|i| !i.raw.hovered_files.is_empty());
        let h = (ui.ctx().content_rect().height() - 150.0).clamp(260.0, 380.0);
        let (rect, _) = ui.allocate_exact_size(vec2(ui.available_width(), h), Sense::hover());
        let (fill, stroke) = if hovering {
            (pal.accent_soft, Stroke::new(1.5, pal.accent))
        } else {
            (pal.surface, Stroke::new(1.0, pal.line))
        };
        ui.painter().rect(
            rect,
            f32::from(theme::R_ZONE),
            fill,
            stroke,
            StrokeKind::Inside,
        );
        let content_h = 168.0;
        let inner = Rect::from_center_size(rect.center(), vec2(rect.width() - 48.0, content_h));
        {
            let ui = &mut ui.new_child(
                UiBuilder::new()
                    .max_rect(inner)
                    .layout(Layout::top_down(Align::Center)),
            );
            {
                let (g, _) = ui.allocate_exact_size(vec2(40.0, 40.0), Sense::hover());
                draw_lock(ui.painter(), g.center(), 1.0, pal.accent);
                ui.add_space(12.0);
                ui.label(
                    RichText::new("Bir dosya ya da klasörü buraya bırakın")
                        .font(fonts::semibold(17.0))
                        .color(pal.ink),
                );
                ui.label(
                    RichText::new("Şifreli .lphy dosyaları açılır, diğer her şey şifrelenir.")
                        .color(pal.muted)
                        .size(13.5),
                );
                ui.add_space(14.0);
                let bw = 124.0;
                let row = Rect::from_center_size(
                    pos2(ui.max_rect().center().x, ui.cursor().top() + 17.0),
                    vec2(bw * 2.0 + 10.0, 34.0),
                );
                {
                    let ui = &mut ui.new_child(
                        UiBuilder::new()
                            .max_rect(row)
                            .layout(Layout::left_to_right(Align::Center)),
                    );
                    {
                        if secondary_button(ui, pal, "Dosya seç", bw, 34.0).clicked() {
                            self.pick_file();
                        }
                        ui.add_space(2.0);
                        if secondary_button(ui, pal, "Klasör seç", bw, 34.0).clicked() {
                            self.pick_folder();
                        }
                    }
                }
            }
        }
        ui.add_space(12.0);
        ui.label(
            RichText::new(
                "Dosyalarınız bu bilgisayardan çıkmaz; parolanız hiçbir yere kaydedilmez.",
            )
            .color(pal.muted)
            .size(12.5),
        );
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
                            change = link_button(ui, pal, "Değiştir").clicked();
                        });
                    }
                });
            });
        if change {
            self.reset();
        }
    }

    fn ready_view(&mut self, ui: &mut Ui, ctx: &egui::Context, pal: Palette) {
        let Some(mode) = self.mode() else { return };
        self.source_card(ui, pal, true);
        ui.add_space(22.0);

        let (title, sub) = match mode {
            Mode::Encrypt => (
                "Bir parola belirleyin",
                "Bu parolayı unutursanız dosya açılamaz; kurtarma yolu yoktur.",
            ),
            Mode::Decrypt => ("Parolayı girin", "Dosya şifrelenirken kullanılan parola."),
        };
        ui.label(
            RichText::new(title)
                .font(fonts::semibold(16.5))
                .color(pal.ink),
        );
        ui.label(RichText::new(sub).color(pal.muted).size(13.0));
        ui.add_space(10.0);

        let (r1, s1) = self.password.ui(ui, true);
        if self.source.is_some() && ui.memory(|m| m.focused().is_none()) {
            r1.request_focus();
        }
        let mut submit = s1;
        if mode == Mode::Encrypt {
            ui.add_space(2.0);
            let (_, s2) = self.confirm.ui(ui, true);
            submit |= s2;
            self.password_hint(ui, pal);
        }

        if mode == Mode::Decrypt && self.keyfile_required {
            ui.add_space(12.0);
            self.keyfile_row(ui, pal, true);
        }

        ui.add_space(14.0);
        self.output_row(ui, pal);
        if let Some(root) = self.cloud_root() {
            ui.add_space(6.0);
            ui.label(
                RichText::new(format!(
                    "Bu konum bir bulut senkron klasöründe ({}). Çözülen dosyalar buluta yüklenebilir.",
                    escape_display(&root.display().to_string())
                ))
                .color(pal.danger)
                .size(13.0),
            );
            ui.checkbox(&mut self.allow_cloud, "Yine de bu konuma çöz");
        }

        if mode == Mode::Encrypt {
            ui.add_space(8.0);
            self.advanced(ui, pal);
        }

        ui.add_space(18.0);
        let label = match mode {
            Mode::Encrypt => "Şifrele",
            Mode::Decrypt => "Şifreyi çöz",
        };
        let enabled = self.can_start();
        if primary_button(ui, pal, label, enabled).clicked() || (submit && enabled) {
            self.start(ctx);
        }
        if let Some(e) = &self.error {
            ui.add_space(8.0);
            ui.label(RichText::new(e).color(pal.danger).size(13.5));
        }
    }

    fn password_hint(&self, ui: &mut Ui, pal: Palette) {
        let n = self.password.char_count();
        let (text, color) = if n == 0 {
            (format!("En az {MIN_SCALARS} karakter."), pal.muted)
        } else if n < MIN_SCALARS {
            (
                format!("En az {MIN_SCALARS} karakter (şu an {n})."),
                pal.muted,
            )
        } else if self.confirm.is_empty() {
            (
                "Doğrulamak için parolayı tekrar girin.".to_string(),
                pal.muted,
            )
        } else if self.password.same_as(&self.confirm) {
            ("Parolalar eşleşiyor.".to_string(), pal.ok)
        } else {
            ("Parolalar eşleşmiyor.".to_string(), pal.danger)
        };
        ui.label(RichText::new(text).color(color).size(13.0));
    }

    fn output_row(&mut self, ui: &mut Ui, pal: Palette) {
        let Some(out) = &self.output else { return };
        let name = out
            .file_name()
            .map(|f| escape_display(&f.to_string_lossy()))
            .unwrap_or_default();
        let dir = out
            .parent()
            .map(|d| escape_display(&logic::short_dir(d)))
            .unwrap_or_default();
        ui.label(
            RichText::new("Kaydedilecek yer")
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
                        change = link_button(ui, pal, "Değiştir").clicked();
                    });
                });
            });
        if change {
            self.choose_output();
        }
    }

    fn advanced(&mut self, ui: &mut Ui, pal: Palette) {
        let label = if self.show_advanced {
            "Gelişmiş ayarları gizle"
        } else {
            "Gelişmiş ayarlar"
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
                    ui.label(RichText::new("Algoritma").color(pal.muted).size(13.0));
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
                    RichText::new(format!("Parola türetme belleği: {} MiB", self.kdf_mib))
                        .color(pal.muted)
                        .size(13.0),
                );
                // Fiziksel belleğin %75'ini aşan seçenek sunulmaz (CLI'deki bütçe kuralı).
                let fits = |m: u32| self.ram_mib == 0 || u64::from(m) * 4 <= self.ram_mib * 3;
                let opts = KDF_PRESETS.map(|(m, l)| (m, l, fits(m)));
                segmented(ui, pal, &mut self.kdf_mib, &opts);
                ui.add_space(12.0);
                ui.checkbox(&mut self.pad, "Dosya boyutunu gizle (PADMÉ dolgusu)");
                ui.add_space(12.0);
                self.keyfile_row(ui, pal, false);
            });
    }

    fn keyfile_row(&mut self, ui: &mut Ui, pal: Palette, required: bool) {
        let title = if required {
            "Anahtar dosyası (bu dosya için gerekli)"
        } else {
            "Anahtar dosyası (isteğe bağlı)"
        };
        ui.label(RichText::new(title).color(pal.muted).size(13.0));
        let name = self.keyfile.as_ref().map(|k| {
            k.file_name()
                .map(|f| escape_display(&f.to_string_lossy()))
                .unwrap_or_default()
        });
        let mut pick = false;
        let mut clear = false;
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
                                None => {
                                    ui.label(RichText::new("Seçilmedi").color(pal.muted).size(14.0))
                                }
                            };
                        },
                    );
                    ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                        if name.is_some() {
                            clear = link_button(ui, pal, "Kaldır").clicked();
                            pick = link_button(ui, pal, "Değiştir").clicked();
                        } else {
                            pick = link_button(ui, pal, "Seç").clicked();
                        }
                    });
                });
            });
        if pick
            && let Some(p) = rfd::FileDialog::new()
                .set_title("Anahtar dosyasını seçin")
                .pick_file()
        {
            self.keyfile = Some(p);
            self.error = None;
        }
        if clear {
            self.keyfile = None;
        }
    }

    fn running_view(&mut self, ui: &mut Ui, pal: Palette, since: Instant) {
        let mode = self.mode().unwrap_or(Mode::Encrypt);
        self.source_card(ui, pal, false);
        ui.add_space(28.0);
        let verb = match mode {
            Mode::Encrypt => "Şifreleniyor",
            Mode::Decrypt => "Şifre çözülüyor",
        };
        let total = self.total.load(Ordering::Relaxed);
        let done = lephy_core::pipeline::progress();
        #[allow(clippy::cast_precision_loss)]
        let frac = (total > 0 && done > 0).then(|| (done as f32 / total as f32).clamp(0.0, 0.99));
        let (title, sub) = match frac {
            Some(f) if f >= 0.99 => (
                "Diske yazılıyor…".to_string(),
                "Son veriler kalıcı olarak kaydediliyor.".to_string(),
            ),
            Some(f) => (
                format!("{verb}… %{}", (f * 100.0).floor()),
                format!(
                    "{} / {}",
                    logic::human_size(done.min(total)),
                    logic::human_size(total)
                ),
            ),
            None => (
                format!("{verb}…"),
                "Parolanın anahtara dönüştürülmesi birkaç saniye sürer.".to_string(),
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
                    ui.label(RichText::new("Durduruluyor…").color(pal.muted).size(13.0));
                } else if link_button(ui, pal, "İptal").clicked() {
                    self.cancel_requested = true;
                    lephy_sys::signal::request_cancel();
                }
            });
        });
    }

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
            draw_check(ui.painter(), g.center(), pal.accent);
            ui.add_space(14.0);
            ui.label(
                RichText::new(match mode {
                    Mode::Encrypt => "Şifrelendi",
                    Mode::Decrypt => "Şifre çözüldü",
                })
                .font(fonts::semibold(22.0))
                .color(pal.ink),
            );
            let name = out
                .output
                .file_name()
                .map(|f| escape_display(&f.to_string_lossy()))
                .unwrap_or_default();
            ui.label(RichText::new(name).color(pal.muted).size(14.0));
            if out.skipped > 0 {
                ui.label(
                    RichText::new(format!(
                        "{} öğe atlandı (özel dosyalar ya da kısayol bağlantıları).",
                        out.skipped
                    ))
                    .color(pal.muted)
                    .size(12.5),
                );
            }
            ui.add_space(24.0);
            reveal = primary_button(ui, pal, "Klasörde göster", true).clicked();
            ui.add_space(4.0);
            again = secondary_button(ui, pal, "Yeni işlem", ui.available_width(), 42.0).clicked();
            if mode == Mode::Encrypt {
                ui.add_space(14.0);
                ui.label(
                    RichText::new(
                        "Özgün dosya yerinde duruyor. Artık gerekmiyorsa kendiniz silebilirsiniz.",
                    )
                    .color(pal.muted)
                    .size(12.5),
                );
            }
        });
        if reveal && let Err(e) = logic::reveal_in_folder(&out.output) {
            self.error = Some(format!("Klasör açılamadı: {e}."));
        }
        if again {
            self.reset();
        }
    }
}

/// Pencereye verilecek uygulama.
#[must_use]
pub fn boxed() -> Box<dyn eframe::App> {
    Box::new(App::default())
}

impl eframe::App for App {
    fn ui(&mut self, ui: &mut Ui, _frame: &mut eframe::Frame) {
        let fill = theme::palette(ui.ctx()).bg;
        egui::CentralPanel::default()
            .frame(egui::Frame::new().fill(fill))
            .show(ui, |ui| self.draw(ui));
    }
}

// ---------------------------------------------------------------------------------------------
// Düğmeler
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

/// Tam genişlikte birincil düğme.
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

/// Çerçeveli ikincil düğme.
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

/// Bölümlü seçim (radyo grubu). Seçenek: (değer, ad, etkin mi).
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
            let _ = resp.on_hover_text("Bu bilgisayarın belleği bu seçenek için yetmiyor.");
        }
    }
}

/// Daire içinde "?" düğmesi.
fn help_button(ui: &mut Ui, pal: Palette, open: bool) -> Response {
    let (rect, resp) = ui.allocate_exact_size(vec2(20.0, 20.0), Sense::click());
    resp.widget_info(|| WidgetInfo::labeled(egui::Role::Button, true, "Terimleri açıkla"));
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
        .on_hover_text("Bu ayarlar ne anlama geliyor?")
}

/// Terim açıklamaları.
fn help_card(ui: &mut Ui, pal: Palette) {
    const TERMS: [(&str, &str); 5] = [
        (
            "XChaCha20-Poly1305",
            "Varsayılan şifreleme yöntemi. Her işlemcide hızlıdır ve yanlış kullanıma karşı daha dayanıklıdır.",
        ),
        (
            "AES-256-GCM",
            "Yaygın kullanılan standart. Donanım desteği olan işlemcilerde çok hızlıdır. İki yöntem de aynı güvenlik düzeyindedir.",
        ),
        (
            "Parola türetme belleği (Argon2id)",
            "Parolanız şifreleme anahtarına dönüştürülürken kullanılan bellek. Arttıkça parola tahmin denemeleri pahalılaşır; dosyayı açan bilgisayarda da bu kadar boş bellek gerekir.",
        ),
        (
            "Boyut gizleme (PADMÉ)",
            "Şifreli dosyanın boyutunu yuvarlayarak gerçek boyutun anlaşılmasını zorlaştırır. Dosya en fazla yaklaşık %12 büyür.",
        ),
        (
            "Anahtar dosyası",
            "Parolaya ek olarak seçtiğiniz herhangi bir dosya (32 bayt ile 1 MiB arası). Şifreli dosyayı açmak için hem parola hem bu dosya gerekir; bu dosyayı kaybederseniz verinize ulaşamazsınız.",
        ),
    ];
    egui::Frame::new()
        .fill(pal.bg)
        .corner_radius(CornerRadius::same(theme::R_INPUT))
        .inner_margin(egui::Margin::same(12))
        .show(ui, |ui| {
            ui.set_width(ui.available_width());
            for (i, (term, desc)) in TERMS.iter().enumerate() {
                if i > 0 {
                    ui.add_space(6.0);
                }
                ui.label(
                    RichText::new(*term)
                        .font(fonts::semibold(13.5))
                        .color(pal.ink),
                );
                ui.label(RichText::new(*desc).color(pal.muted).size(13.0));
            }
        });
    ui.add_space(8.0);
}

/// Çerçevesiz metin düğmesi (vurgu renginde).
fn link_button(ui: &mut Ui, pal: Palette, text: &str) -> Response {
    ui.add(
        egui::Button::new(RichText::new(text).color(pal.accent).size(14.0))
            .frame(false)
            .min_size(vec2(0.0, 28.0)),
    )
    .on_hover_cursor(CursorIcon::PointingHand)
}

// ---------------------------------------------------------------------------------------------
// Çizgi ikonlar
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

/// Asma kilit: gövde + kemer. `s` ölçek (1.0 ≈ 40 px).
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

/// Belge: köşesi kıvrık sayfa.
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

/// Klasör: sekmeli gövde.
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

/// Daire içinde onay işareti.
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
        assert!(!app.can_start(), "parola olmadan başlamamalı");
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
            output: d.join("x.lphy"),
            skipped: 2,
        });
        frame(&ctx, &mut app);
        app.reset();
        assert!(matches!(app.stage, Stage::Pick));
        frame(&ctx, &mut app);
        let _ = std::fs::remove_dir_all(&d);
    }
}
