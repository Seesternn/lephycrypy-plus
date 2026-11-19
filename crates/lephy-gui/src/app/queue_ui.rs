//! Queue: the items of a job with their states, files added while it runs (same kind, same
//! settings), a retry of the failed items, and a short history of this session kept in memory
//! only.

use super::buttons::{self as b, Icon, Kind};
use super::{App, Mode, Palette, logic};
use crate::i18n::{Lang, lang, tr};
use crate::logic::{ItemState, JobTemplate, QueueProgress};
use eframe::egui::{self, RichText, Ui};
use lephy_core::names::escape_display;
use std::path::PathBuf;
use std::sync::Arc;

/// Most history rows kept.
const HISTORY: usize = 20;

/// One finished item of this session.
pub(super) struct Hist {
    name: String,
    ok: bool,
    encrypt: bool,
    /// Seconds since the app started.
    at: u64,
}

/// Queue state.
#[derive(Default)]
pub(super) struct QueueUi {
    /// States of the running job's items.
    pub(super) progress: Option<Arc<QueueProgress>>,
    /// Its items.
    pub(super) items: Vec<logic::Item>,
    /// Settings for more items (secrets in locked memory; dropped with the queue).
    pub(super) template: Option<JobTemplate>,
    /// Added while the job runs; started when it ends.
    pub(super) pending: Vec<PathBuf>,
    /// Failed items of the last job (for a retry).
    pub(super) failed: Vec<logic::Item>,
    /// This session's finished items (memory only).
    history: Vec<Hist>,
    /// Outcome of the earlier jobs of this queue, merged into the last one.
    pub(super) acc: Option<logic::Outcome>,
}

impl QueueUi {
    /// Drops the settings (and their secrets) and the state of the last queue.
    pub(super) fn reset(&mut self) {
        self.progress = None;
        self.items.clear();
        self.template = None;
        self.pending.clear();
        self.failed.clear();
        self.acc = None;
    }

    /// Records the finished items in the history and keeps the failed ones for a retry.
    pub(super) fn finish(&mut self, started: std::time::Instant, keep_history: bool) {
        let Some(p) = self.progress.take() else {
            return;
        };
        let states = p.snapshot();
        let encrypt = self
            .template
            .as_ref()
            .is_some_and(|t| t.mode() == Mode::Encrypt);
        self.failed.clear();
        for (item, st) in self.items.iter().zip(states) {
            let ok = match st {
                ItemState::Done => true,
                ItemState::Failed(_) => {
                    self.failed.push(item.clone());
                    false
                }
                _ => continue,
            };
            if keep_history {
                self.history.push(Hist {
                    name: item
                        .input
                        .file_name()
                        .map(|f| escape_display(&f.to_string_lossy()))
                        .unwrap_or_default(),
                    ok,
                    encrypt,
                    at: started.elapsed().as_secs(),
                });
            }
        }
        let n = self.history.len();
        if n > HISTORY {
            self.history.drain(..n - HISTORY);
        }
    }
}

/// A small drawn state mark: ring (waiting), dot (running), tick (done), cross (failed), dash.
fn mark(ui: &mut Ui, pal: Palette, st: &ItemState) {
    let (r, _) = ui.allocate_exact_size(egui::vec2(16.0, 16.0), egui::Sense::hover());
    let c = r.center();
    let p = ui.painter();
    match st {
        ItemState::Waiting => {
            p.circle_stroke(c, 5.0, egui::Stroke::new(1.4, pal.muted));
        }
        ItemState::Running => {
            p.circle_filled(c, 5.0, pal.accent);
        }
        ItemState::Done => {
            let s = egui::Stroke::new(2.0, pal.ok);
            p.line_segment([c + egui::vec2(-5.0, 0.0), c + egui::vec2(-1.5, 3.5)], s);
            p.line_segment([c + egui::vec2(-1.5, 3.5), c + egui::vec2(5.0, -4.0)], s);
        }
        ItemState::Failed(_) => {
            let s = egui::Stroke::new(2.0, pal.danger);
            p.line_segment([c + egui::vec2(-4.0, -4.0), c + egui::vec2(4.0, 4.0)], s);
            p.line_segment([c + egui::vec2(4.0, -4.0), c + egui::vec2(-4.0, 4.0)], s);
        }
        ItemState::Skipped => {
            p.line_segment(
                [c + egui::vec2(-4.0, 0.0), c + egui::vec2(4.0, 0.0)],
                egui::Stroke::new(1.6, pal.muted),
            );
        }
    }
}

/// Merges `b` into `a` (outputs, failures, counters).
fn merge(a: &mut logic::Outcome, b: logic::Outcome) {
    a.outputs.extend(b.outputs);
    a.failed.extend(b.failed);
    a.skipped += b.skipped;
    a.deleted += b.deleted;
    a.kept += b.kept;
    a.repaired += b.repaired;
    a.executables += b.executables;
}

impl App {
    /// Called when a job starts: remember its items and settings, share per-item states.
    pub(super) fn queue_begin(&mut self, job: &mut logic::Job) {
        if let Some(t) = JobTemplate::from_job(job) {
            self.queue.template = Some(t);
        }
        if self.queue.template.is_none() {
            return;
        }
        let p = Arc::new(QueueProgress::new(job.items.len()));
        job.progress = Some(Arc::clone(&p));
        self.queue.progress = Some(p);
        self.queue.items.clone_from(&job.items);
    }

    /// Called when a job ends with `out`: start what was added meanwhile, or return the merged
    /// outcome to show.
    pub(super) fn queue_end(
        &mut self,
        ctx: &egui::Context,
        out: logic::Outcome,
    ) -> Option<logic::Outcome> {
        let keep = !self.prefs.history_off;
        self.queue.finish(self.started, keep);
        let mut acc = self.queue.acc.take().unwrap_or_default();
        merge(&mut acc, out);
        if self.queue.pending.is_empty() {
            return Some(acc);
        }
        let paths = std::mem::take(&mut self.queue.pending);
        self.queue.acc = Some(acc);
        if self.start_template_job(ctx, &paths) {
            None
        } else {
            self.queue.acc.take()
        }
    }

    /// Starts a job for `paths` with the kept settings. Returns `false` if there are none.
    fn start_template_job(&mut self, ctx: &egui::Context, paths: &[PathBuf]) -> bool {
        let Some(t) = &self.queue.template else {
            return false;
        };
        let mode = t.mode();
        let items: Vec<logic::Item> = paths
            .iter()
            .map(|p| logic::Item {
                input: p.clone(),
                output: logic::default_output(p, mode),
            })
            .collect();
        let Some(mut job) = t.job(items) else {
            return false;
        };
        self.queue_begin(&mut job);
        self.stage = super::Stage::Running {
            since: std::time::Instant::now(),
        };
        self.run_prepared_job(ctx, job);
        true
    }

    /// Retry: the failed items of the last queue, same settings.
    fn retry_failed(&mut self, ctx: &egui::Context) {
        let paths: Vec<PathBuf> = self.queue.failed.iter().map(|i| i.input.clone()).collect();
        self.queue.acc = None;
        let _ = self.start_template_job(ctx, &paths);
    }

    /// Files dropped while a job runs: same kind → queued; else a note.
    pub(super) fn queue_add(&mut self, paths: &[PathBuf]) {
        let Some(t) = &self.queue.template else {
            self.error = Some(
                tr(
                    "Bu işe dosya eklenemez; bitmesini bekleyin.",
                    "Files cannot be added to this job; wait for it to finish.",
                )
                .into(),
            );
            return;
        };
        let mode = t.mode();
        for p in logic::collapse_parts(paths) {
            if logic::detect_mode(&p) != mode {
                self.error = Some(
                    tr(
                        "Şifreli ve şifresiz dosyalar aynı kuyrukta olamaz; önce bu kuyruk bitsin.",
                        "Encrypted and unencrypted files cannot share a queue; let this one finish first.",
                    )
                    .into(),
                );
                continue;
            }
            if !self.queue.pending.contains(&p) && !self.queue.items.iter().any(|i| i.input == p) {
                self.queue.pending.push(p);
            }
        }
    }

    /// The item list under the progress bar (only for more than one item).
    pub(super) fn queue_view(&mut self, ui: &mut Ui, pal: Palette) {
        let Some(p) = self.queue.progress.clone() else {
            return;
        };
        let states = p.snapshot();
        if states.len() < 2 && self.queue.pending.is_empty() {
            return;
        }
        ui.add_space(10.0);
        let rows = |ui: &mut Ui| {
            for (i, (item, st)) in self.queue.items.iter().zip(&states).enumerate() {
                let name = item
                    .input
                    .file_name()
                    .map(|f| escape_display(&f.to_string_lossy()))
                    .unwrap_or_default();
                ui.horizontal(|ui| {
                    mark(ui, pal, st);
                    ui.label(RichText::new(name).size(13.0).color(pal.ink));
                    if let ItemState::Failed(e) = st {
                        ui.label(RichText::new(e).size(11.5).color(pal.danger));
                    }
                    if *st == ItemState::Waiting
                        && b::action(
                            ui,
                            pal,
                            Kind::Secondary,
                            Icon::Close,
                            tr("Kaldır", "Remove"),
                        )
                        .clicked()
                    {
                        p.remove(i);
                    }
                });
            }
            for path in &self.queue.pending {
                ui.horizontal(|ui| {
                    mark(ui, pal, &ItemState::Waiting);
                    ui.label(
                        RichText::new(
                            path.file_name()
                                .map(|f| escape_display(&f.to_string_lossy()))
                                .unwrap_or_default(),
                        )
                        .size(13.0)
                        .color(pal.muted),
                    );
                    ui.label(
                        RichText::new(tr("eklenecek", "to be added"))
                            .size(11.5)
                            .color(pal.muted),
                    );
                });
            }
        };
        if states.len() + self.queue.pending.len() > 8 {
            egui::ScrollArea::vertical()
                .max_height(240.0)
                .min_scrolled_height(240.0)
                .auto_shrink([false, true])
                .show(ui, rows);
        } else {
            rows(ui);
        }
        ui.label(
            RichText::new(tr(
                "Bırakılan dosyalar aynı ayarlarla sıraya eklenir.",
                "Dropped files are added to the queue with the same settings.",
            ))
            .color(pal.muted)
            .size(12.0),
        );
    }

    /// On the done screen: retry the failed items with the same settings.
    pub(super) fn retry_view(&mut self, ui: &mut Ui, ctx: &egui::Context, pal: Palette) {
        if self.queue.failed.is_empty() || self.queue.template.is_none() {
            return;
        }
        let n = self.queue.failed.len();
        let label = match lang() {
            Lang::Tr => format!("Başarısız olanları yeniden dene ({n})"),
            Lang::En => format!("Retry the failed ones ({n})"),
        };
        if b::action(ui, pal, Kind::Primary, Icon::Retry, &label).clicked() {
            self.retry_failed(ctx);
        }
    }

    /// Home: this session's finished items (memory only).
    pub(super) fn history_view(&self, ui: &mut Ui, pal: Palette) {
        let now = self.started.elapsed().as_secs();
        if self.prefs.history_off || self.queue.history.is_empty() {
            return;
        }
        ui.add_space(12.0);
        ui.label(
            RichText::new(tr("Bu oturumda", "This session"))
                .font(crate::fonts::semibold(14.0))
                .color(pal.ink),
        );
        for h in self.queue.history.iter().rev().take(8) {
            let mins = now.saturating_sub(h.at) / 60;
            ui.horizontal(|ui| {
                mark(
                    ui,
                    pal,
                    &if h.ok {
                        ItemState::Done
                    } else {
                        ItemState::Failed(String::new())
                    },
                );
                ui.label(RichText::new(&h.name).size(13.0).color(pal.ink));
                ui.label(
                    RichText::new(match (lang(), h.encrypt) {
                        (Lang::Tr, true) => format!("şifrelendi · {mins} dk önce"),
                        (Lang::Tr, false) => format!("çözüldü · {mins} dk önce"),
                        (Lang::En, true) => format!("encrypted · {mins} min ago"),
                        (Lang::En, false) => format!("decrypted · {mins} min ago"),
                    })
                    .size(12.0)
                    .color(pal.muted),
                );
            });
        }
        ui.label(
            RichText::new(tr(
                "Yalnızca bellekte tutulur; uygulama kapanınca silinir.",
                "Kept in memory only; gone when the app closes.",
            ))
            .color(pal.muted)
            .size(11.5),
        );
    }
}
