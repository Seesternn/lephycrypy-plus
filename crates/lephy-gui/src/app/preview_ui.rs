//! Preview window: decrypts one file into memory in the background and shows it (text, PNG,
//! JPEG) over the app. Closing it drops the texture and wipes the decrypted bytes.

use super::buttons::{self as b, Icon, Kind};
use super::{App, Palette, logic};
use crate::i18n::{Lang, lang, tr};
use crate::preview::{Content, Refusal};
use eframe::egui::{self, RichText, TextureHandle, TextureOptions};
use lephy_core::names::escape_display;
use std::sync::mpsc::{Receiver, TryRecvError};

type Result = std::result::Result<(String, Content), String>;

/// What the preview window shows.
pub(super) enum PreviewState {
    /// Decrypting in the background.
    Loading(Receiver<Result>),
    /// Text.
    Text {
        name: String,
        text: String,
        cut: bool,
    },
    /// Image as a texture.
    Image { name: String, tex: TextureHandle },
    /// Could not preview.
    Failed(String),
}

impl App {
    /// A preview can start: the file's credentials are typed above.
    pub(super) fn can_preview(&self) -> bool {
        !self.password.is_empty()
            && (!self.keyfile_required || self.keyfile.is_some())
            && (!self.identity_required || self.identity.is_some())
            && self.preview.is_none()
    }

    /// Decrypts `entry` (`None`: the first file) into memory and opens the preview window.
    pub(super) fn start_preview(&mut self, ctx: &egui::Context, entry: Option<String>) {
        let Some(src) = &self.source else { return };
        let input = src.path.clone();
        // The password stays in the field (a decrypt may follow); the job gets a copy in locked
        // memory.
        let Ok(pw) = lephy_sys::mem::SecretBytes::from_slice(self.password.expose()) else {
            return;
        };
        let keyfile = self.keyfile.clone();
        let identity = self.identity.clone().filter(|_| self.identity_required);
        let (tx, rx) = std::sync::mpsc::channel();
        let ctx2 = ctx.clone();
        std::thread::spawn(move || {
            let r = logic::run_preview(
                &input,
                &pw,
                keyfile.as_deref(),
                identity.as_deref(),
                entry.as_deref(),
            )
            .map_err(|e| logic::describe_error(&e))
            .and_then(|p| {
                crate::preview::decode(&p.data)
                    .map(|c| (p.name.clone(), c))
                    .map_err(|r| match r {
                        Refusal::Unsupported => tr(
                            "Bu dosya türü önizlenemiyor (yalnızca metin, PNG ve JPEG).",
                            "This kind of file cannot be previewed (text, PNG and JPEG only).",
                        )
                        .to_owned(),
                        Refusal::BadImage => tr(
                            "Görsel bozuk ya da çok büyük; önizlenemiyor.",
                            "The image is damaged or too large to preview.",
                        )
                        .to_owned(),
                    })
            });
            drop(pw);
            let _ = tx.send(r);
            ctx2.request_repaint();
        });
        self.preview = Some(PreviewState::Loading(rx));
    }

    /// Draws the preview window while one is open.
    #[allow(
        clippy::too_many_lines,
        reason = "one window: header, note and the content kinds"
    )]
    pub(super) fn preview_window(&mut self, ctx: &egui::Context, pal: Palette) {
        if let Some(PreviewState::Loading(rx)) = &self.preview {
            match rx.try_recv() {
                Ok(Ok((name, Content::Text(text, cut)))) => {
                    self.preview = Some(PreviewState::Text { name, text, cut });
                }
                Ok(Ok((name, Content::Image(img)))) => {
                    let tex = ctx.load_texture("lephy-preview", img, TextureOptions::LINEAR);
                    self.preview = Some(PreviewState::Image { name, tex });
                }
                Ok(Err(e)) => self.preview = Some(PreviewState::Failed(e)),
                Err(TryRecvError::Disconnected) => self.preview = None,
                Err(TryRecvError::Empty) => {}
            }
        }
        let Some(state) = &self.preview else { return };
        let fallback = self
            .source
            .as_ref()
            .map(|s| s.name.clone())
            .unwrap_or_default();
        let screen = ctx.content_rect();
        let mut close = false;
        let resp = egui::Modal::new(egui::Id::unique("lephy-preview-modal"))
            .backdrop_color(egui::Color32::BLACK.gamma_multiply(0.45))
            .show(ctx, |ui| {
                ui.set_width((screen.width() - 80.0).clamp(280.0, 900.0));
                ui.horizontal(|ui| {
                    let title = match state {
                        PreviewState::Text { name, .. } | PreviewState::Image { name, .. } => {
                            if name.is_empty() {
                                &fallback
                            } else {
                                name
                            }
                        }
                        _ => &fallback,
                    };
                    ui.label(
                        RichText::new(escape_display(title))
                            .font(crate::fonts::semibold(15.0))
                            .color(pal.ink),
                    );
                    ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                        close =
                            b::action(ui, pal, Kind::Secondary, Icon::Close, tr("Kapat", "Close"))
                                .clicked();
                    });
                });
                ui.label(
                    RichText::new(tr(
                        "Yalnızca bellekte açıldı; diske hiçbir şey yazılmadı.",
                        "Opened in memory only; nothing was written to disk.",
                    ))
                    .color(pal.muted)
                    .size(12.0),
                );
                ui.add_space(8.0);
                let max_h = (screen.height() - 180.0).max(160.0);
                match state {
                    PreviewState::Loading(_) => {
                        ui.horizontal(|ui| {
                            ui.spinner();
                            ui.label(tr("Çözülüyor…", "Decrypting…"));
                        });
                    }
                    PreviewState::Failed(e) => {
                        ui.label(RichText::new(e).color(pal.danger).size(13.0));
                    }
                    PreviewState::Text { text, cut, .. } => {
                        egui::ScrollArea::vertical()
                            .max_height(max_h)
                            .show(ui, |ui| {
                                ui.add(
                                    egui::Label::new(
                                        RichText::new(text.as_str()).monospace().size(12.5),
                                    )
                                    .wrap(),
                                );
                            });
                        if *cut {
                            ui.label(
                                RichText::new(tr(
                                    "Yalnızca ilk 1 MB gösteriliyor.",
                                    "Only the first 1 MB is shown.",
                                ))
                                .color(pal.muted)
                                .size(12.0),
                            );
                        }
                    }
                    PreviewState::Image { tex, .. } => {
                        let size = tex.size_vec2();
                        let scale = (ui.available_width() / size.x).min(max_h / size.y).min(1.0);
                        ui.vertical_centered(|ui| {
                            ui.image((tex.id(), size * scale));
                        });
                        let [w, h] = tex.size();
                        ui.label(
                            RichText::new(match lang() {
                                Lang::Tr => format!("{w} × {h} piksel"),
                                Lang::En => format!("{w} × {h} pixels"),
                            })
                            .color(pal.muted)
                            .size(12.0),
                        );
                    }
                }
            });
        if close || resp.should_close() {
            // Dropping the state frees the texture; the text and pixel copies were wiped or
            // are released through the zeroizing allocator.
            self.preview = None;
        }
    }
}
