//! "Write to USB": wipe (or format) a removable USB volume and write only one encrypted `.lphy`
//! file to it, with the same engine and checks as `lephycrypy usb write`: only eligible USB
//! volumes, a dry run of what will be deleted, the exact label and size typed to confirm, the
//! device identity re-read before each step, and a read-back of the written file.

use super::{App, Palette, link_button, logic, primary_button, secondary_button};
use crate::i18n::{Lang, lang, tr};
use eframe::egui::{self, RichText, Stroke, Ui};
use lephy_core::names::escape_display;
use lephy_usb::{Device, DryRun, WriteReport};
use std::path::PathBuf;
use std::sync::mpsc::{Receiver, TryRecvError};

pub(super) type Prepared = Result<(Device, DryRun), String>;
/// Sticks found, each with its eligibility (or why it cannot be used).
pub(super) type Found = Result<Vec<(Device, Result<(), String>)>, String>;

/// Messages from the write job.
pub(super) enum Msg {
    Step(String),
    Done(Result<WriteReport, String>),
}

/// State of the USB page.
#[derive(Default)]
pub(super) struct Usb {
    pub(super) source: Option<PathBuf>,
    pub(super) source_err: Option<String>,
    pub(super) devices: Option<Found>,
    pub(super) list_rx: Option<Receiver<Found>>,
    pub(super) prepared: Option<Prepared>,
    pub(super) prep_rx: Option<Receiver<Prepared>>,
    pub(super) format: bool,
    pub(super) fill: bool,
    pub(super) label: String,
    pub(super) gib: String,
    pub(super) run_rx: Option<Receiver<Msg>>,
    pub(super) steps: Vec<String>,
    pub(super) result: Option<Result<WriteReport, String>>,
}

impl Usb {
    /// A write is running (closing and quitting ask first, like any job).
    pub(super) fn busy(&self) -> bool {
        self.run_rx.is_some()
    }

    /// Back to the start of the page (nothing running).
    pub(super) fn reset(&mut self) {
        if !self.busy() {
            *self = Self::default();
        }
    }

    fn poll(&mut self) {
        if let Some(rx) = &self.list_rx
            && let Ok(r) = rx.try_recv()
        {
            self.devices = Some(r);
            self.list_rx = None;
        }
        if let Some(rx) = &self.prep_rx
            && let Ok(r) = rx.try_recv()
        {
            self.prepared = Some(r);
            self.prep_rx = None;
        }
        while let Some(rx) = &self.run_rx {
            match rx.try_recv() {
                Ok(Msg::Step(s)) => self.steps.push(s),
                Ok(Msg::Done(r)) => {
                    self.result = Some(r);
                    self.run_rx = None;
                }
                Err(TryRecvError::Empty) => break,
                Err(TryRecvError::Disconnected) => {
                    self.run_rx = None;
                }
            }
        }
    }

    fn scan(&mut self, ctx: &egui::Context) {
        let (tx, rx) = std::sync::mpsc::channel();
        let ctx = ctx.clone();
        std::thread::spawn(move || {
            let p = lephy_usb::native();
            let r = p
                .list()
                .map(|v| {
                    v.into_iter()
                        .map(|d| {
                            let ok = d.eligibility(p.require_serial());
                            (d, ok)
                        })
                        .collect()
                })
                .map_err(|e| logic::describe_error(&e));
            let _ = tx.send(r);
            ctx.request_repaint();
        });
        self.list_rx = Some(rx);
        self.devices = None;
        self.prepared = None;
    }

    fn prepare(&mut self, ctx: &egui::Context, mount: PathBuf) {
        let (tx, rx) = std::sync::mpsc::channel();
        let ctx = ctx.clone();
        std::thread::spawn(move || {
            let p = lephy_usb::native();
            let r = lephy_usb::engine::prepare(p.as_ref(), &mount)
                .map_err(|e| logic::describe_error(&e));
            let _ = tx.send(r);
            ctx.request_repaint();
        });
        self.prep_rx = Some(rx);
        self.prepared = None;
        self.label.clear();
        self.gib.clear();
    }

    /// The typed label and size match the volume.
    fn confirmed(&self, dev: &Device) -> bool {
        self.label == dev.label && self.gib.trim().parse::<u64>().ok() == Some(dev.size_gib())
    }

    fn start(&mut self, ctx: &egui::Context, dev: Device, dry: DryRun) {
        let Some(source) = self.source.clone() else {
            return;
        };
        let Ok(size_gib) = self.gib.trim().parse::<u64>() else {
            return;
        };
        let req = lephy_usb::WriteRequest {
            source,
            confirm: lephy_usb::Confirm {
                label: self.label.clone(),
                size_gib,
            },
            format: self.format,
            fill: self.fill,
            fill_opts: None,
        };
        let (tx, rx) = std::sync::mpsc::channel();
        let ctx = ctx.clone();
        lephy_sys::signal::reset_cancel();
        std::thread::spawn(move || {
            let p = lephy_usb::native();
            let step_tx = tx.clone();
            let step_ctx = ctx.clone();
            let mut say = move |m: &str| {
                let _ = step_tx.send(Msg::Step(m.to_owned()));
                step_ctx.request_repaint();
            };
            let r = lephy_usb::engine::execute(p.as_ref(), &dev, dry, &req, &mut say)
                .map_err(|e| logic::describe_error(&e));
            let _ = tx.send(Msg::Done(r));
            ctx.request_repaint();
        });
        self.run_rx = Some(rx);
        self.steps.clear();
        self.result = None;
    }
}

fn card(ui: &mut Ui, pal: Palette, title: &str, body: impl FnOnce(&mut Ui)) {
    egui::Frame::new()
        .fill(pal.surface)
        .stroke(Stroke::new(1.0, pal.line))
        .corner_radius(egui::CornerRadius::same(super::theme::R_CARD))
        .inner_margin(egui::Margin::same(14))
        .show(ui, |ui| {
            ui.set_width(ui.available_width());
            ui.label(
                RichText::new(title)
                    .font(crate::fonts::semibold(14.5))
                    .color(pal.ink),
            );
            ui.add_space(6.0);
            body(ui);
        });
    ui.add_space(12.0);
}

impl App {
    /// The "Write to USB" page.
    #[allow(clippy::too_many_lines, reason = "one page: four steps top to bottom")]
    pub(super) fn usb_view(&mut self, ui: &mut Ui, pal: Palette) {
        self.usb.poll();
        let ctx = ui.ctx().clone();
        if self.usb.busy() {
            ctx.request_repaint_after(std::time::Duration::from_millis(200));
        }
        ui.label(
            RichText::new(tr("USB belleğe yaz", "Write to a USB stick"))
                .font(crate::fonts::semibold(20.0))
                .color(pal.ink),
        );
        ui.label(
            RichText::new(tr(
                "Bellek silinir ve üzerine yalnızca seçtiğiniz şifreli dosya yazılır. Bellekteki her şey kalıcı olarak gider.",
                "The stick is wiped and only the encrypted file you choose is written to it. Everything on the stick is lost for good.",
            ))
            .color(pal.danger)
            .size(13.0),
        );
        ui.add_space(14.0);

        if let Some(r) = &self.usb.result {
            match r {
                Ok(rep) => card(
                    ui,
                    pal,
                    tr("Yazıldı ve doğrulandı", "Written and verified"),
                    |ui| {
                        ui.label(
                            RichText::new(escape_display(&rep.written.display().to_string()))
                                .monospace()
                                .size(12.0),
                        );
                        ui.label(
                            RichText::new(format!(
                                "{} · BLAKE3 {}",
                                logic::human_size(rep.bytes),
                                rep.blake3.get(..16).unwrap_or(&rep.blake3)
                            ))
                            .color(pal.muted)
                            .size(12.5),
                        );
                        let how = if rep.verification == lephy_usb::Verification::AfterRemount {
                            tr(
                                "Bellek çıkarılıp yeniden bağlandı ve dosya geri okunarak denetlendi.",
                                "The stick was ejected and remounted, and the file was read back and checked.",
                            )
                        } else {
                            tr(
                                "Bellek yeniden bağlanamadı; geri okuma işletim sisteminin önbelleğinden yapılmış olabilir.",
                                "The stick could not be remounted; the read-back may have come from the system cache.",
                            )
                        };
                        ui.label(RichText::new(how).color(pal.muted).size(12.5));
                    },
                ),
                Err(e) => card(ui, pal, tr("Yazılamadı", "Not written"), |ui| {
                    ui.label(RichText::new(e).color(pal.danger).size(13.0));
                }),
            }
            if secondary_button(
                ui,
                pal,
                tr("Yeni işlem", "New task"),
                ui.available_width(),
                36.0,
            )
            .clicked()
            {
                self.usb.reset();
            }
            return;
        }

        if self.usb.busy() {
            card(ui, pal, tr("Yazılıyor…", "Writing…"), |ui| {
                ui.horizontal(|ui| {
                    ui.spinner();
                    ui.label(
                        RichText::new(tr("Belleği çıkarmayın.", "Do not remove the stick."))
                            .color(pal.muted),
                    );
                });
                for s in self.usb.steps.iter().rev().take(6).rev() {
                    ui.label(RichText::new(s).monospace().size(11.5).color(pal.muted));
                }
            });
            if link_button(ui, pal, tr("İptal", "Cancel")).clicked() {
                lephy_sys::signal::request_cancel();
            }
            return;
        }

        // 1. Encrypted file.
        card(ui, pal, tr("1. Şifreli dosya", "1. Encrypted file"), |ui| {
            let name = self.usb.source.as_ref().map_or_else(
                || tr("Seçilmedi", "None selected").to_owned(),
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
                        .set_title(tr("Şifreli dosyayı seçin", "Choose the encrypted file"))
                        .add_filter("lephycrypy", &["lphy"])
                        .pick_file()
                {
                    match lephy_usb::engine::check_source(&p) {
                        Ok(_) => {
                            self.usb.source = Some(p);
                            self.usb.source_err = None;
                        }
                        Err(e) => {
                            self.usb.source = None;
                            self.usb.source_err = Some(logic::describe_error(&e));
                        }
                    }
                }
            });
            if let Some(e) = &self.usb.source_err {
                ui.label(RichText::new(e).color(pal.danger).size(12.5));
            }
            ui.label(
                RichText::new(tr(
                    "Yalnızca geçerli bir .lphy dosyası yazılır; şifresiz dosyalar kabul edilmez.",
                    "Only a valid .lphy file is written; unencrypted files are refused.",
                ))
                .color(pal.muted)
                .size(12.0),
            );
        });
        if self.usb.source.is_none() {
            return;
        }

        // 2. Stick.
        let mut pick = None;
        card(ui, pal, tr("2. USB bellek", "2. USB stick"), |ui| {
            if self.usb.list_rx.is_some() {
                ui.horizontal(|ui| {
                    ui.spinner();
                    ui.label(tr("Bellekler aranıyor…", "Looking for sticks…"));
                });
            }
            match &self.usb.devices {
                None => {}
                Some(Err(e)) => {
                    ui.label(RichText::new(e).color(pal.danger).size(12.5));
                }
                Some(Ok(v)) if v.is_empty() => {
                    ui.label(
                        RichText::new(tr(
                            "Takılı bir USB bellek bulunamadı.",
                            "No USB stick is plugged in.",
                        ))
                        .color(pal.muted),
                    );
                }
                Some(Ok(v)) => {
                    for (d, ok) in v {
                        let text = format!(
                            "{} — {} · {} GiB · {}",
                            escape_display(&d.label),
                            escape_display(&d.product),
                            d.size_gib(),
                            d.fs_type
                        );
                        match ok {
                            Ok(()) => {
                                if ui
                                    .add(egui::Button::new(
                                        RichText::new(text).size(13.0).color(pal.ink),
                                    ))
                                    .clicked()
                                {
                                    pick = Some(d.mount.clone());
                                }
                            }
                            Err(why) => {
                                ui.label(RichText::new(text).size(13.0).color(pal.muted));
                                ui.label(
                                    RichText::new(match lang() {
                                        Lang::Tr => format!("Uygun değil: {why}"),
                                        Lang::En => format!("Not eligible: {why}"),
                                    })
                                    .size(11.5)
                                    .color(pal.muted),
                                );
                            }
                        }
                    }
                }
            }
            if link_button(ui, pal, tr("Yeniden ara", "Search again")).clicked()
                || (self.usb.devices.is_none() && self.usb.list_rx.is_none())
            {
                self.usb.scan(&ctx);
            }
        });
        if let Some(m) = pick {
            self.usb.prepare(&ctx, m);
        }

        // 3. What will happen + 4. confirmation.
        if self.usb.prep_rx.is_some() {
            ui.horizontal(|ui| {
                ui.spinner();
                ui.label(tr("Bellek inceleniyor…", "Checking the stick…"));
            });
            return;
        }
        let Some(prepared) = self.usb.prepared.clone() else {
            return;
        };
        let (dev, dry) = match prepared {
            Ok(x) => x,
            Err(e) => {
                ui.label(RichText::new(e).color(pal.danger).size(13.0));
                return;
            }
        };
        card(ui, pal, tr("3. Ne olacak?", "3. What will happen"), |ui| {
            ui.label(
                RichText::new(format!(
                    "{} — {} GiB · {}",
                    escape_display(&dev.label),
                    dev.size_gib(),
                    escape_display(&dev.mount.display().to_string())
                ))
                .size(13.0)
                .color(pal.ink),
            );
            ui.checkbox(
                &mut self.usb.format,
                tr(
                    "exFAT olarak biçimlendir (silmek yerine)",
                    "Format as exFAT (instead of wiping)",
                ),
            );
            ui.checkbox(
                &mut self.usb.fill,
                tr(
                    "Sonra boş alanı rastgele veriyle doldur (yavaş)",
                    "Then fill the free space with random data (slow)",
                ),
            );
            let what = if self.usb.format {
                tr(
                    "Bellek biçimlendirilir; üzerindeki her şey gider.",
                    "The stick is formatted; everything on it is lost.",
                )
                .to_owned()
            } else {
                match lang() {
                    Lang::Tr => format!(
                        "Silinecek: {} dosya, {} klasör, {}.",
                        dry.files,
                        dry.dirs,
                        logic::human_size(dry.bytes)
                    ),
                    Lang::En => format!(
                        "To be deleted: {} files, {} folders, {}.",
                        dry.files,
                        dry.dirs,
                        logic::human_size(dry.bytes)
                    ),
                }
            };
            ui.label(RichText::new(what).color(pal.danger).size(12.5));
            if !self.usb.format {
                for p in dry.first.iter().take(8) {
                    ui.label(RichText::new(p).monospace().size(11.0).color(pal.muted));
                }
            }
            ui.label(
                RichText::new(tr(
                    "Flash belleklerde silinen verinin fiziksel olarak yok olduğu garanti edilemez.",
                    "On flash media physical erasure of deleted data cannot be guaranteed.",
                ))
                .color(pal.muted)
                .size(11.5),
            );
        });
        let mut go = false;
        card(ui, pal, tr("4. Onay", "4. Confirm"), |ui| {
            ui.label(
                RichText::new(match lang() {
                    Lang::Tr => format!(
                        "Onaylamak için belleğin adını ({}) ve boyutunu GiB olarak ({}) aynen yazın.",
                        escape_display(&dev.label),
                        dev.size_gib()
                    ),
                    Lang::En => format!(
                        "To confirm, type the stick's label ({}) and its size in GiB ({}) exactly.",
                        escape_display(&dev.label),
                        dev.size_gib()
                    ),
                })
                .color(pal.muted)
                .size(12.5),
            );
            ui.add(
                egui::TextEdit::singleline(&mut self.usb.label)
                    .hint_text(tr("Bellek adı", "Label")),
            );
            ui.add(
                egui::TextEdit::singleline(&mut self.usb.gib)
                    .hint_text(tr("Boyut (GiB)", "Size (GiB)")),
            );
            let ok = self.usb.confirmed(&dev);
            ui.add_space(6.0);
            go = primary_button(ui, pal, tr("Sil ve yaz", "Wipe and write"), ok).clicked();
        });
        if go {
            self.usb.start(&ctx, dev, dry);
        }
    }
}
