//! My keys › Restore from paper backup: type the 22 words, choose a new password and a place,
//! and the identity is written again (`.lphykey` and `.pub`). The words live in a buffer that is
//! wiped when the section is closed, after the job and when leaving the page.

use super::{App, Palette, link_button, logic, primary_button, secondary_button};
use crate::i18n::{Lang, lang, tr};
use crate::secret_field::SecretField;
use eframe::egui::{self, RichText, Ui};
use lephy_core::password::MIN_SCALARS;
use std::sync::mpsc::{Receiver, TryRecvError};

/// Words a paper backup has.
const WORDS: usize = 22;

/// State of the restore section.
pub(super) struct Restore {
    /// The section is unfolded.
    pub(super) open: bool,
    /// Typed words: locked memory, no undo history, not exposed to accessibility clients.
    words: SecretField,
    pw: SecretField,
    pw2: SecretField,
    job: Option<Receiver<Result<String, String>>>,
    /// Public key of the restored identity.
    done: Option<String>,
    error: Option<String>,
}

impl Default for Restore {
    fn default() -> Self {
        Self {
            open: false,
            words: SecretField::words("Kelimeler (abacus …)", "Words (abacus …)"),
            pw: SecretField::new("Yeni kimlik parolası", "New identity password"),
            pw2: SecretField::new("Yeni parolayı tekrar girin", "Repeat the new password"),
            job: None,
            done: None,
            error: None,
        }
    }
}

impl Restore {
    /// Words are on screen (the window is then kept out of screen capture).
    pub(super) fn words_visible(&self) -> bool {
        self.open && !self.words.is_empty()
    }

    /// Wipes the words and passwords and folds the section.
    pub(super) fn reset(&mut self) {
        self.words.clear();
        self.pw.clear();
        self.pw2.clear();
        self.open = false;
        self.error = None;
    }

    fn poll(&mut self) {
        let Some(rx) = &self.job else { return };
        match rx.try_recv() {
            Ok(Ok(pk)) => {
                self.job = None;
                self.done = Some(pk);
                self.words.clear();
            }
            Ok(Err(e)) => {
                self.job = None;
                self.error = Some(e);
            }
            Err(TryRecvError::Empty) => {}
            Err(TryRecvError::Disconnected) => self.job = None,
        }
    }
}

/// "N of 22 words", or the positions of words that are not in the list.
fn word_status(n: usize, bad: &[usize], pal: Palette) -> (String, egui::Color32) {
    if bad.is_empty() {
        return (
            match lang() {
                Lang::Tr => format!("{WORDS} kelimeden {n} tanesi girildi"),
                Lang::En => format!("{n} of {WORDS} words"),
            },
            if n == WORDS { pal.ok } else { pal.muted },
        );
    }
    let list: Vec<String> = bad.iter().map(ToString::to_string).collect();
    (
        match lang() {
            Lang::Tr => format!("Listede olmayan kelime: {}. sıradaki", list.join(", ")),
            Lang::En => format!("Not in the word list: word {}", list.join(", ")),
        },
        pal.danger,
    )
}

impl App {
    /// The restore section body (inside a `section` card on the keys page).
    pub(super) fn restore_section(&mut self, ui: &mut Ui, pal: Palette) {
        self.restore.poll();
        if let Some(pk) = self.restore.done.clone() {
            ui.label(
                RichText::new(tr(
                    "Kimliğiniz geri yüklendi. Açık anahtarı:",
                    "Your identity was restored. Its public key:",
                ))
                .color(pal.ok)
                .size(13.0),
            );
            ui.add(
                egui::Label::new(RichText::new(&pk).monospace().size(11.5).color(pal.ink))
                    .truncate(),
            );
            ui.horizontal(|ui| {
                if link_button(ui, pal, tr("Kopyala", "Copy")).clicked()
                    && logic::copy_to_clipboard(&pk).is_ok()
                {
                    self.show_toast(ui.ctx(), tr("Panoya kopyalandı", "Copied to the clipboard"));
                }
                if link_button(ui, pal, tr("Tamam", "Done")).clicked() {
                    self.restore.done = None;
                    self.restore.reset();
                }
            });
            return;
        }
        if !self.restore.open {
            if secondary_button(
                ui,
                pal,
                tr("Kelimelerden geri yükle…", "Restore from the words…"),
                ui.available_width(),
                34.0,
            )
            .clicked()
            {
                self.restore.open = true;
            }
            return;
        }
        let busy = self.restore.job.is_some();
        ui.label(
            RichText::new(tr(
                "22 kelimeyi kâğıttaki sırayla, boşlukla ayırarak yazın.",
                "Type the 22 words in the order on the paper, separated by spaces.",
            ))
            .color(pal.muted)
            .size(12.5),
        );
        ui.add_space(4.0);
        self.restore.words.ui(ui, !busy);
        let typed = std::str::from_utf8(self.restore.words.expose()).unwrap_or("");
        let (n, bad) = logic::check_paper_words(typed);
        let status = word_status(n, &bad, pal);
        ui.label(RichText::new(status.0).color(status.1).size(12.5));
        ui.add_space(6.0);
        self.restore.pw.ui(ui, !busy);
        ui.add_space(6.0);
        self.restore.pw2.ui(ui, !busy);
        let pw_ok = self.restore.pw.char_count() >= MIN_SCALARS
            && self.restore.pw.same_as(&self.restore.pw2);
        if !self.restore.pw2.is_empty() && !self.restore.pw.same_as(&self.restore.pw2) {
            ui.label(
                RichText::new(tr("Parolalar aynı değil.", "The passwords differ."))
                    .color(pal.danger)
                    .size(12.5),
            );
        }
        if let Some(e) = &self.restore.error {
            ui.label(RichText::new(e).color(pal.danger).size(12.5));
        }
        ui.add_space(8.0);
        let ready = !busy && n == WORDS && bad.is_empty() && pw_ok;
        let label = if busy {
            tr("Geri yükleniyor…", "Restoring…")
        } else {
            tr(
                "Kaydedilecek yeri seç ve geri yükle",
                "Choose where to save and restore",
            )
        };
        if primary_button(ui, pal, label, ready).clicked()
            && let Some(path) = rfd::FileDialog::new()
                .set_title(tr("Kimlik dosyasını kaydedin", "Save the identity file"))
                .set_file_name("identity.lphykey")
                .add_filter("lephycrypy identity", &["lphykey"])
                .save_file()
        {
            self.start_restore(ui.ctx(), path);
        }
        if !busy && link_button(ui, pal, tr("Vazgeç", "Cancel")).clicked() {
            self.restore.reset();
        }
    }

    fn start_restore(&mut self, ctx: &egui::Context, path: std::path::PathBuf) {
        let words = self.restore.words.take();
        let pw = self.restore.pw.take();
        self.restore.pw2.clear();
        let kdf = self.kdf_mib;
        let (tx, rx) = std::sync::mpsc::channel();
        let ctx = ctx.clone();
        std::thread::spawn(move || {
            let r = logic::restore_identity(words.expose(), &path, &pw, kdf)
                .map_err(|e| logic::describe_error(&e));
            drop(pw);
            let _ = tx.send(r);
            ctx.request_repaint();
        });
        self.restore.job = Some(rx);
        self.restore.error = None;
    }
}
