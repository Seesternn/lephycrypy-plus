//! Leftover temp items: a decryption that was cut short (crash, power loss, forced quit) can leave
//! a `.lphy-tmp-*` folder with decrypted data next to its destination. The usual folders are
//! scanned in the background at start; any folder can be scanned from Settings. Nothing is
//! deleted without confirmation, and no path is saved.

use super::{App, Palette, link_button, logic, secondary_button};
use crate::i18n::{Lang, lang, tr};
use eframe::egui::{self, CornerRadius, RichText, Stroke, Ui};
use lephy_core::names::escape_display;
use std::path::PathBuf;
use std::sync::mpsc::{Receiver, TryRecvError};
use std::time::Duration;

/// Items younger than this may belong to a job that is still running.
const MIN_AGE: Duration = Duration::from_mins(10);

/// Scan results and what the user is doing with them.
#[derive(Default)]
pub(super) struct Stale {
    /// Background scan in progress.
    rx: Option<Receiver<Vec<PathBuf>>>,
    /// Items found.
    pub(super) found: Vec<PathBuf>,
    /// The list is unfolded.
    show: bool,
    /// "Delete" was pressed: waiting for confirmation.
    confirm: bool,
    /// The banner was dismissed for this run.
    dismissed: bool,
    /// Last result line (deleted, nothing found, error).
    note: Option<String>,
}

impl Stale {
    /// Starts a background scan of `dirs`.
    pub(super) fn scan(&mut self, ctx: &egui::Context, dirs: Vec<PathBuf>) {
        let (tx, rx) = std::sync::mpsc::channel();
        let ctx = ctx.clone();
        std::thread::spawn(move || {
            let _ = tx.send(logic::find_stale_temps(&dirs, MIN_AGE));
            ctx.request_repaint();
        });
        self.rx = Some(rx);
        self.note = None;
        self.dismissed = false;
    }

    fn poll(&mut self) -> Option<usize> {
        let rx = self.rx.as_ref()?;
        match rx.try_recv() {
            Ok(found) => {
                self.rx = None;
                self.found = found;
                self.confirm = false;
                Some(self.found.len())
            }
            Err(TryRecvError::Disconnected) => {
                self.rx = None;
                None
            }
            Err(TryRecvError::Empty) => None,
        }
    }
}

impl App {
    /// Home banner when leftovers were found at start.
    pub(super) fn stale_banner(&mut self, ui: &mut Ui, pal: Palette) {
        self.stale.poll();
        if self.stale.found.is_empty() || self.stale.dismissed {
            return;
        }
        egui::Frame::new()
            .fill(pal.surface)
            .stroke(Stroke::new(1.0, pal.danger.gamma_multiply(0.6)))
            .corner_radius(CornerRadius::same(super::theme::R_CARD))
            .inner_margin(egui::Margin::same(14))
            .show(ui, |ui| {
                ui.set_width(ui.available_width());
                self.stale_panel(ui, pal, true);
            });
        ui.add_space(12.0);
    }

    /// Settings › Maintenance: scan a chosen folder.
    pub(super) fn stale_settings(&mut self, ui: &mut Ui, pal: Palette) {
        let scanned = self.stale.poll();
        if scanned == Some(0) {
            self.stale.note = Some(
                tr(
                    "Bu klasörde yarım kalmış öğe yok.",
                    "No leftover items in this folder.",
                )
                .into(),
            );
        }
        let busy = self.stale.rx.is_some();
        if secondary_button(
            ui,
            pal,
            if busy {
                tr("Aranıyor…", "Searching…")
            } else {
                tr(
                    "Bir klasörde yarım kalanları ara…",
                    "Search a folder for leftovers…",
                )
            },
            ui.available_width(),
            34.0,
        )
        .clicked()
            && !busy
            && let Some(dir) = rfd::FileDialog::new()
                .set_title(tr("Aranacak klasörü seçin", "Choose a folder to search"))
                .pick_folder()
        {
            self.stale.scan(ui.ctx(), vec![dir]);
        }
        if !self.stale.found.is_empty() {
            ui.add_space(8.0);
            self.stale_panel(ui, pal, false);
        }
        if let Some(n) = &self.stale.note {
            ui.add_space(6.0);
            ui.label(RichText::new(n).color(pal.muted).size(12.5));
        }
    }

    /// Count, list, delete with confirmation; `dismissable` adds "Ignore".
    fn stale_panel(&mut self, ui: &mut Ui, pal: Palette, dismissable: bool) {
        let n = self.stale.found.len();
        ui.label(
            RichText::new(match lang() {
                Lang::Tr => format!("Yarım kalmış {n} geçici öğe bulundu"),
                Lang::En => format!("{n} leftover temporary item(s) found"),
            })
            .font(crate::fonts::semibold(14.0))
            .color(pal.ink),
        );
        ui.label(
            RichText::new(tr(
                "Yarıda kesilen bir şifre çözmeden kalmış olabilir ve şifresi çözülmüş veri içerebilir.",
                "They may be left from a decryption that was cut short and may contain decrypted data.",
            ))
            .color(pal.muted)
            .size(12.5),
        );
        if self.stale.show {
            ui.add_space(4.0);
            for p in &self.stale.found {
                ui.add(
                    egui::Label::new(
                        RichText::new(escape_display(&logic::short_dir(p)))
                            .monospace()
                            .size(11.5)
                            .color(pal.ink),
                    )
                    .truncate(),
                );
            }
        }
        ui.add_space(6.0);
        if self.stale.confirm {
            ui.label(
                RichText::new(match lang() {
                    Lang::Tr => format!("{n} öğe kalıcı olarak silinecek. Emin misiniz?"),
                    Lang::En => format!("{n} item(s) will be deleted permanently. Are you sure?"),
                })
                .color(pal.danger)
                .size(12.5),
            );
            ui.horizontal(|ui| {
                if link_button(ui, pal, tr("Evet, sil", "Yes, delete")).clicked() {
                    let found = std::mem::take(&mut self.stale.found);
                    self.stale.confirm = false;
                    self.stale.note = Some(match lephy_core::io::cleanup(&found) {
                        Ok(k) => match lang() {
                            Lang::Tr => format!("{k} öğe silindi."),
                            Lang::En => format!("{k} item(s) deleted."),
                        },
                        Err(e) => match lang() {
                            Lang::Tr => format!("Silinemedi: {e}"),
                            Lang::En => format!("Could not delete: {e}"),
                        },
                    });
                }
                if link_button(ui, pal, tr("Vazgeç", "Cancel")).clicked() {
                    self.stale.confirm = false;
                }
            });
            return;
        }
        ui.horizontal(|ui| {
            let label = if self.stale.show {
                tr("Gizle", "Hide")
            } else {
                tr("Göster", "Show")
            };
            if link_button(ui, pal, label).clicked() {
                self.stale.show = !self.stale.show;
            }
            if link_button(ui, pal, tr("Sil…", "Delete…")).clicked() {
                self.stale.confirm = true;
            }
            if dismissable && link_button(ui, pal, tr("Yoksay", "Ignore")).clicked() {
                self.stale.dismissed = true;
            }
        });
    }
}
