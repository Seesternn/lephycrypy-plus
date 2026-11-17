//! Tek pencere arayüzü: sürükle-bırak, maskeli parola, şifrele/çöz.
//! Görsel dil: sistem yazı tipi, nötr gri/beyaz, tek vurgu rengi, animasyon yok, ikon yerine metin.

use std::path::{Path, PathBuf};
use std::sync::mpsc::{Receiver, TryRecvError};
use std::time::Duration;

use eframe::egui::{self, Color32, RichText};
use lephy_core::names::escape_display;

use crate::logic::{self, Job, Mode};
use crate::secret_field::SecretField;

/// Tek vurgu rengi.
pub const ACCENT: Color32 = Color32::from_rgb(0x2b, 0x5f, 0xb4);

enum Status {
    Idle,
    Running,
    Done(String),
    Failed(String),
}

/// Uygulama durumu. Bayraklar form alanlarının doğrudan yansımasıdır.
#[allow(clippy::struct_excessive_bools)]
pub struct App {
    input: String,
    output: String,
    mode: Option<Mode>,
    password: SecretField,
    confirm: SecretField,
    kdf_mib: u32,
    aes: bool,
    pad: bool,
    allow_cloud: bool,
    status: Status,
    job: Option<Receiver<Result<String, String>>>,
    /// Kesinti "İptal" düğmesinden mi geldi (sinyal değil → pencere kapanmaz).
    cancel_requested: bool,
}

impl Default for App {
    fn default() -> Self {
        Self {
            input: String::new(),
            output: String::new(),
            mode: None,
            password: SecretField::new("Parola"),
            confirm: SecretField::new("Parola (tekrar)"),
            kdf_mib: 512,
            aes: false,
            pad: true,
            allow_cloud: false,
            status: Status::Idle,
            job: None,
            cancel_requested: false,
        }
    }
}

/// Görsel tema: açık, nötr, tek vurgu, animasyonsuz.
pub fn apply_style(ctx: &egui::Context) {
    let mut v = egui::Visuals::light();
    v.selection.bg_fill = ACCENT.linear_multiply(0.35);
    v.selection.stroke = egui::Stroke::new(1.5, ACCENT);
    v.hyperlink_color = ACCENT;
    v.widgets.active.bg_fill = ACCENT;
    v.widgets.hovered.bg_stroke = egui::Stroke::new(1.0, ACCENT);
    ctx.set_visuals(v);
    ctx.all_styles_mut(|s| {
        s.animation_time = 0.0;
        s.spacing.item_spacing = egui::vec2(8.0, 8.0);
    });
}

impl App {
    fn set_input(&mut self, p: &Path) {
        let mode = logic::detect_mode(p);
        self.output = logic::default_output(p, mode).display().to_string();
        self.input = p.display().to_string();
        self.mode = Some(mode);
        self.status = Status::Idle;
        self.allow_cloud = false;
    }

    fn running(&self) -> bool {
        self.job.is_some()
    }

    fn start(&mut self, ctx: &egui::Context) {
        let Some(mode) = self.mode else { return };
        let job = Job {
            mode,
            input: PathBuf::from(self.input.trim()),
            output: PathBuf::from(self.output.trim()),
            password: self.password.take(),
            confirm: (mode == Mode::Encrypt).then(|| self.confirm.take()),
            kdf_mib: self.kdf_mib,
            aes: self.aes,
            pad: self.pad,
            allow_cloud: self.allow_cloud,
        };
        self.confirm.clear();
        let (tx, rx) = std::sync::mpsc::channel();
        let ctx2 = ctx.clone();
        std::thread::spawn(move || {
            let r = logic::run(job).map_err(|e| logic::describe_error(&e));
            let _ = tx.send(r);
            ctx2.request_repaint();
        });
        self.job = Some(rx);
        self.status = Status::Running;
    }

    fn poll(&mut self, ctx: &egui::Context) {
        let Some(rx) = &self.job else { return };
        match rx.try_recv() {
            Ok(Ok(msg)) => {
                self.status = Status::Done(msg);
                self.job = None;
            }
            Ok(Err(msg)) => {
                self.status = Status::Failed(msg);
                self.job = None;
            }
            Err(TryRecvError::Empty) => ctx.request_repaint_after(Duration::from_millis(150)),
            Err(TryRecvError::Disconnected) => {
                self.status = Status::Failed("iş beklenmedik biçimde sonlandı".into());
                self.job = None;
            }
        }
        if self.job.is_none() && self.cancel_requested {
            // İptal düğmesi: bayrak temizlenir, uygulama açık kalır.
            lephy_sys::signal::reset_interrupted();
            self.cancel_requested = false;
        }
    }

    /// SIGINT/SIGTERM/Ctrl+C: boştaysa pencereyi kapat; iş sürüyorsa iş önce durur
    /// (tmp temizlenir), sonra kapanır. Boşta sinyali fark etmek için düzenli yeniden çizim.
    fn handle_signal(&self, ctx: &egui::Context) {
        if lephy_sys::signal::interrupted() && !self.running() && !self.cancel_requested {
            ctx.send_viewport_cmd(egui::ViewportCommand::Close);
        }
        ctx.request_repaint_after(Duration::from_millis(400));
    }

    fn drop_zone(&mut self, ui: &mut egui::Ui) {
        let hovering = ui.input(|i| !i.raw.hovered_files.is_empty());
        let stroke = if hovering {
            egui::Stroke::new(2.0, ACCENT)
        } else {
            egui::Stroke::new(1.0, ui.visuals().widgets.noninteractive.bg_stroke.color)
        };
        egui::Frame::new()
            .stroke(stroke)
            .corner_radius(6.0)
            .inner_margin(egui::Margin::same(18))
            .show(ui, |ui| {
                ui.set_min_width(ui.available_width());
                ui.vertical_centered(|ui| {
                    ui.label(RichText::new("Bir dosya ya da klasörü buraya bırakın").strong());
                    ui.label(
                        RichText::new("Klasörler adları gizli bir arşiv olarak şifrelenir; .lphy dosyaları çözülür.")
                            .weak(),
                    );
                });
            });
        let dropped = ui.input(|i| i.raw.dropped_files.first().map(|f| f.path().to_path_buf()));
        if let (Some(p), false) = (dropped, self.running()) {
            self.set_input(&p);
        }
    }

    /// Bir karede tüm arayüz.
    pub fn draw(&mut self, ui: &mut egui::Ui) {
        let ctx = ui.ctx().clone();
        self.poll(&ctx);
        self.handle_signal(&ctx);
        let busy = self.running();
        ui.heading("lephycrypy+");
        ui.add_space(4.0);
        self.drop_zone(ui);

        self.form(ui, &ctx, busy);

        egui::CollapsingHeader::new("Gelişmiş").show(ui, |ui| {
            ui.add_enabled_ui(!busy && self.mode == Some(Mode::Encrypt), |ui| {
                ui.add(
                    egui::Slider::new(&mut self.kdf_mib, 64..=2048)
                        .step_by(64.0)
                        .text("Argon2id bellek (MiB)"),
                );
                ui.horizontal(|ui| {
                    ui.radio_value(&mut self.aes, false, "XChaCha20-Poly1305");
                    ui.radio_value(&mut self.aes, true, "AES-256-GCM");
                });
                ui.checkbox(&mut self.pad, "Boyutu gizle (PADMÉ)");
            });
        });

        if self.mode == Some(Mode::Decrypt) {
            let out = PathBuf::from(self.output.trim());
            if let Some(root) = lephy_sys::fs::cloud_root_of(&out) {
                ui.colored_label(
                    Color32::from_rgb(0x8a, 0x5a, 0x00),
                    format!(
                        "Hedef bir bulut senkron klasöründe ({}); düz metin buluta yüklenebilir.",
                        escape_display(&root.display().to_string())
                    ),
                );
                ui.checkbox(&mut self.allow_cloud, "Yine de bu klasöre çıkar");
            }
        }

        ui.add_space(6.0);
        ui.horizontal(|ui| {
            let label = match self.mode {
                Some(Mode::Decrypt) => "Çöz",
                _ => "Şifrele",
            };
            let button = egui::Button::new(RichText::new(label).color(Color32::WHITE)).fill(ACCENT);
            if ui.add_enabled(self.can_start(), button).clicked() {
                self.start(&ctx);
            }
            if busy {
                ui.spinner();
                if ui.button("İptal").clicked() {
                    self.cancel_requested = true;
                    lephy_sys::signal::request_interrupt();
                }
            }
        });

        match &self.status {
            Status::Idle => {}
            Status::Running => {
                ui.label(RichText::new("Çalışıyor… (Argon2id birkaç saniye sürebilir)").weak());
            }
            Status::Done(m) => {
                ui.label(RichText::new(m).color(Color32::from_rgb(0x1f, 0x6f, 0x3a)));
            }
            Status::Failed(m) => {
                ui.label(RichText::new(m).color(Color32::from_rgb(0xa1, 0x26, 0x26)));
            }
        }
    }

    fn form(&mut self, ui: &mut egui::Ui, ctx: &egui::Context, busy: bool) {
        egui::Grid::new("form")
            .num_columns(2)
            .spacing([12.0, 10.0])
            .show(ui, |ui| {
                ui.label("Kaynak");
                let r = ui.add_enabled(
                    !busy,
                    egui::TextEdit::singleline(&mut self.input)
                        .desired_width(360.0)
                        .hint_text("yol"),
                );
                if r.lost_focus() && !self.input.trim().is_empty() {
                    let p = PathBuf::from(self.input.trim());
                    self.set_input(&p);
                }
                ui.end_row();

                ui.label("İşlem");
                ui.label(match self.mode {
                    None => RichText::new("—").weak(),
                    Some(Mode::Encrypt) => RichText::new("Şifrele").color(ACCENT),
                    Some(Mode::Decrypt) => RichText::new("Çöz").color(ACCENT),
                });
                ui.end_row();

                ui.label("Parola");
                let (_, submit1) = self.password.ui(ui, !busy);
                ui.end_row();

                let mut submit2 = false;
                if self.mode == Some(Mode::Encrypt) {
                    ui.label("Parola (tekrar)");
                    let (_, s) = self.confirm.ui(ui, !busy);
                    submit2 = s;
                    ui.end_row();
                }

                ui.label("Çıktı");
                ui.add_enabled(
                    !busy,
                    egui::TextEdit::singleline(&mut self.output).desired_width(360.0),
                );
                ui.end_row();

                if (submit1 || submit2) && self.can_start() {
                    self.start(ctx);
                }
            });
    }

    fn can_start(&self) -> bool {
        !self.running()
            && self.mode.is_some()
            && !self.input.trim().is_empty()
            && !self.output.trim().is_empty()
            && !self.password.is_empty()
            && (self.mode != Some(Mode::Encrypt) || !self.confirm.is_empty())
    }
}

impl eframe::App for App {
    fn ui(&mut self, ui: &mut egui::Ui, _frame: &mut eframe::Frame) {
        egui::CentralPanel::default()
            .frame(egui::Frame::central_panel(ui.style()).inner_margin(egui::Margin::same(18)))
            .show(ui, |ui| self.draw(ui));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn renders_headless_and_start_requires_password() {
        let ctx = egui::Context::default();
        apply_style(&ctx);
        let mut app = App::default();
        let d = std::env::temp_dir().join(format!("lphy-gui-app-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap_or(());
        std::fs::write(d.join("a.txt"), b"x").unwrap_or(());
        app.set_input(&d.join("a.txt"));
        assert_eq!(app.mode, Some(Mode::Encrypt));
        assert!(!app.can_start(), "parola olmadan başlamamalı");
        for _ in 0..3 {
            let mut out = ctx.run_ui(egui::RawInput::default(), |ui| app.draw(ui));
            out.textures_delta.clear();
        }
        assert_eq!(
            Path::new(&app.output).extension().and_then(|e| e.to_str()),
            Some("lphy")
        );
        let _ = std::fs::remove_dir_all(&d);
    }
}
