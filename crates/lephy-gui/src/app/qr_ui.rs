//! QR codes on screen: a public key in a window (to scan with a phone), and the paper backup's
//! QR next to its words, with printing on macOS.

use super::buttons::{self as b, Icon, Kind};
use super::{App, Palette};
use crate::i18n::tr;
use crate::qr::Qr;
use eframe::egui::{self, Color32, Rect, RichText, Sense, Ui, pos2, vec2};
use std::sync::Mutex;

/// A key whose QR code was asked for (set by the key rows, shown by the keys page).
static ASKED: Mutex<Option<String>> = Mutex::new(None);

/// Asks for `key`'s QR window.
pub(super) fn ask(key: &str) {
    if let Ok(mut a) = ASKED.lock() {
        *a = Some(key.to_owned());
    }
}

/// Draws `qr` black on white with a quiet zone, about `side` points wide.
pub(super) fn draw(ui: &mut Ui, qr: &Qr, side: f32) {
    #[allow(clippy::cast_precision_loss, reason = "small sizes")]
    let total = (qr.size + 8) as f32;
    let m = (side / total).floor().max(1.0);
    let side = m * total;
    let (rect, _) = ui.allocate_exact_size(vec2(side, side), Sense::hover());
    let p = ui.painter();
    p.rect_filled(rect, 4.0, Color32::WHITE);
    let origin = rect.min + vec2(4.0 * m, 4.0 * m);
    for (row, col, len) in qr.runs() {
        #[allow(clippy::cast_precision_loss, reason = "small sizes")]
        let r = Rect::from_min_size(
            pos2(origin.x + col as f32 * m, origin.y + row as f32 * m),
            vec2(len as f32 * m, m),
        );
        p.rect_filled(r, 0.0, Color32::BLACK);
    }
}

/// Under the paper-backup words: show its QR code, print it (macOS).
pub(super) fn paper_extras(
    ui: &mut Ui,
    pal: Palette,
    words: &[u8],
    qr: &mut Option<Qr>,
    note: &mut Option<String>,
) {
    b::row(ui, |ui| {
        let label = if qr.is_some() {
            tr("QR'ı gizle", "Hide the QR code")
        } else {
            tr("QR göster", "Show QR code")
        };
        if b::action(ui, pal, Kind::Secondary, Icon::Qr, label).clicked() {
            *qr = if qr.is_some() {
                None
            } else {
                Qr::encode(words)
            };
        }
        if cfg!(target_os = "macos")
            && b::action(
                ui,
                pal,
                Kind::Secondary,
                Icon::Print,
                tr("Yazdır…", "Print…"),
            )
            .clicked()
        {
            let code = qr.take().or_else(|| Qr::encode(words));
            if let Some(code) = &code {
                let pdf = crate::qr::paper_pdf(
                    "lephycrypy+ paper backup",
                    words,
                    code,
                    "Anyone with these words can open every file encrypted to this key.\nKeep this page apart from the computer. Restore: lephycrypy identity restore",
                );
                *note = Some(match crate::qr::print_pdf(&pdf) {
                    Ok(()) => tr(
                        "Varsayılan yazıcıya gönderildi. Yazdırma kuyruğu bu sayfanın bir kopyasını yazdırılana dek diskte tutabilir.",
                        "Sent to the default printer. The print queue may keep a copy of this page on disk until it is printed.",
                    )
                    .into(),
                    Err(e) => format!("{}: {e}", tr("Yazdırılamadı", "Not printed")),
                });
            }
            *qr = code;
        }
    });
    if let Some(code) = qr.as_ref() {
        ui.add_space(6.0);
        draw(ui, code, 200.0_f32.min(ui.available_width()));
        ui.label(
            RichText::new(tr(
                "Bu QR, kelimelerin aynısını taşır: onu gören herkes anahtarınızı geri getirebilir.",
                "This QR code holds the same words: anyone who sees it can restore your key.",
            ))
            .color(pal.danger)
            .size(12.0),
        );
    }
    if let Some(n) = note {
        ui.label(RichText::new(n.as_str()).color(pal.muted).size(12.0));
    }
}

impl App {
    /// The QR window of a public key, if one was asked for.
    pub(super) fn qr_window(&mut self, ctx: &egui::Context, pal: Palette) {
        if let Some(k) = ASKED.lock().ok().and_then(|mut a| a.take()) {
            self.qr_key = Qr::encode(k.as_bytes()).map(|q| (k, q));
        }
        let Some((key, code)) = &self.qr_key else {
            return;
        };
        let mut close = false;
        let r = egui::Modal::new(egui::Id::unique("lephy-qr-window")).show(ctx, |ui| {
            ui.set_width(420.0);
            ui.label(
                RichText::new(tr("Açık anahtar", "Public key"))
                    .font(crate::fonts::semibold(15.0))
                    .color(pal.ink),
            );
            ui.label(
                RichText::new(tr(
                    "Karşı taraf bu kodu telefonuyla okutup anahtarı alabilir. Açık anahtar gizli değildir.",
                    "The other person can scan this code with a phone to get the key. A public key is not secret.",
                ))
                .color(pal.muted)
                .size(12.5),
            );
            ui.add_space(8.0);
            draw(ui, code, 400.0);
            ui.add_space(6.0);
            ui.add(
                egui::Label::new(RichText::new(key.as_str()).monospace().size(11.0))
                    .truncate(),
            );
            ui.add_space(6.0);
            b::row(ui, |ui| {
                if b::action(ui, pal, Kind::Secondary, Icon::Copy, tr("Kopyala", "Copy")).clicked()
                {
                    let _ = crate::logic::copy_to_clipboard(key);
                }
                if b::action(ui, pal, Kind::Primary, Icon::Close, tr("Kapat", "Close")).clicked() {
                    close = true;
                }
            });
        });
        if close || r.should_close() {
            self.qr_key = None;
        }
    }
}
