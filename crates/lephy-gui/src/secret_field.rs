//! Masked password field: the text is written straight into a locked `SecretBytes` buffer
//! (≤ 1024 B, never grown); only `•` is drawn; clipboard events (copy/cut/paste) are ignored;
//! AccessKit role `PasswordInput` with an empty value. egui/winit's `Event::Text` copies and IME
//! composition are outside the arena (THREAT-MODEL › Memory); the zeroizing global allocator wipes
//! them when freed.

use eframe::egui::{self, Event, Key, Response, Sense, Ui, Vec2, WidgetInfo};
use lephy_core::password::MAX_RAW_LEN;
use lephy_sys::mem::SecretBytes;

use crate::theme;

/// Effect of an event on the field.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Effect {
    /// Unrelated event (not consumed).
    Ignored,
    /// Consumed, content changed.
    Changed,
    /// Consumed, content unchanged (clipboard events, capacity exceeded).
    Swallowed,
    /// Enter: submit.
    Submit,
}

/// Pure event handling of a password field (testable).
#[cfg(test)]
pub fn apply_event(buf: &mut SecretBytes, ev: &Event) -> Effect {
    apply_event_with(buf, ev, false)
}

/// As [`apply_event`]; `paste` lets pasted text in (the words field: pasting from a password
/// manager is normal there). Copy and cut stay off.
pub fn apply_event_with(buf: &mut SecretBytes, ev: &Event, paste: bool) -> Effect {
    match ev {
        Event::Paste(t) if paste => {
            let t: String = t
                .chars()
                .map(|c| if c.is_whitespace() { ' ' } else { c })
                .filter(|c| !c.is_control())
                .collect();
            if buf.push_slice(t.as_bytes()).is_ok() {
                Effect::Changed
            } else {
                Effect::Swallowed
            }
        }
        Event::Text(t) => {
            if t.chars().any(char::is_control) {
                return Effect::Swallowed;
            }
            if buf.push_slice(t.as_bytes()).is_ok() {
                Effect::Changed
            } else {
                Effect::Swallowed
            }
        }
        Event::Key {
            key: Key::Backspace,
            pressed: true,
            ..
        } => {
            let len = buf.len();
            if len == 0 {
                return Effect::Swallowed;
            }
            // Delete the last Unicode scalar (undo the UTF-8 continuation bytes).
            let bytes = buf.expose();
            let mut i = len - 1;
            while i > 0 && (bytes[i] & 0b1100_0000) == 0b1000_0000 {
                i -= 1;
            }
            buf.truncate(i);
            Effect::Changed
        }
        Event::Key {
            key: Key::Enter,
            pressed: true,
            ..
        } => Effect::Submit,
        Event::Copy | Event::Cut | Event::Paste(_) => Effect::Swallowed,
        _ => Effect::Ignored,
    }
}

/// Password field.
pub struct SecretField {
    buf: SecretBytes,
    label_tr: &'static str,
    label_en: &'static str,
    /// Words field: the text is shown (wrapped) and pasting is allowed; it still lives only in
    /// locked memory, keeps no undo history and is not exposed to accessibility clients.
    words: bool,
    /// While the field has focus, macOS Secure Event Input is on (input-monitoring processes cannot read it).
    secure: Option<lephy_sys::secure_input::SecureInputGuard>,
}

impl SecretField {
    /// New field.
    ///
    /// # Panics
    /// If the locked arena cannot be set up (at process start; does not fail in practice).
    #[must_use]
    #[allow(clippy::expect_used)]
    pub fn new(label_tr: &'static str, label_en: &'static str) -> Self {
        Self {
            buf: SecretBytes::with_capacity(MAX_RAW_LEN).expect("locked arena"),
            label_tr,
            label_en,
            words: false,
            secure: None,
        }
    }

    /// A field for paper-backup words: shown in clear, wrapped, pasting allowed.
    #[must_use]
    pub fn words(label_tr: &'static str, label_en: &'static str) -> Self {
        Self {
            words: true,
            ..Self::new(label_tr, label_en)
        }
    }

    /// The content (stays in locked memory).
    #[must_use]
    pub fn expose(&self) -> &[u8] {
        self.buf.expose()
    }

    /// Changes the field's label.
    pub const fn set_label(&mut self, label_tr: &'static str, label_en: &'static str) {
        self.label_tr = label_tr;
        self.label_en = label_en;
    }

    /// Whether it is empty.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.buf.is_empty()
    }

    /// Takes the content (the field becomes empty); the copy stays in the locked arena.
    ///
    /// # Panics
    /// If the locked arena is full.
    #[allow(clippy::expect_used)]
    pub fn take(&mut self) -> SecretBytes {
        let fresh = SecretBytes::with_capacity(MAX_RAW_LEN).expect("locked arena");
        std::mem::replace(&mut self.buf, fresh)
    }

    /// Clears it.
    pub fn clear(&mut self) {
        self.buf.clear();
    }

    /// Replaces the content with the given bytes (a copy from locked memory to locked memory).
    ///
    /// # Panics
    /// If the locked arena is full.
    #[allow(clippy::expect_used)]
    pub fn set(&mut self, bytes: &[u8]) {
        self.buf.clear();
        self.buf.push_slice(bytes).expect("capacity");
    }

    /// Rough strength estimate.
    #[must_use]
    pub fn strength(&self) -> lephy_core::strength::Estimate {
        lephy_core::strength::estimate(self.buf.expose())
    }

    /// Number of Unicode scalar values (invalid UTF-8 → 0).
    #[must_use]
    pub fn char_count(&self) -> usize {
        std::str::from_utf8(self.buf.expose()).map_or(0, |s| s.chars().count())
    }

    /// Whether both fields have the same content (byte for byte; NFC is checked in the job).
    #[must_use]
    pub fn same_as(&self, other: &Self) -> bool {
        self.buf.expose() == other.buf.expose()
    }

    /// Draws the field and consumes keyboard events while focused. `true`: Enter was pressed.
    pub fn ui(&mut self, ui: &mut Ui, enabled: bool) -> (Response, bool) {
        let pal = theme::palette(ui.ctx());
        let width = ui.available_width();
        let height = if self.words {
            theme::CONTROL_H * 2.6
        } else {
            theme::CONTROL_H
        };
        let sense = if enabled {
            Sense::click()
        } else {
            Sense::hover()
        };
        let (rect, response) = ui.allocate_exact_size(Vec2::new(width, height), sense);
        if response.clicked() {
            response.request_focus();
        }
        let mut submit = false;
        match (enabled && response.has_focus(), self.secure.is_some()) {
            (true, false) => self.secure = Some(lephy_sys::secure_input::SecureInputGuard::new()),
            (false, true) => self.secure = None,
            _ => {}
        }
        if enabled && response.has_focus() {
            ui.input_mut(|i| {
                let buf = &mut self.buf;
                let paste = self.words;
                i.events
                    .retain(|ev| match apply_event_with(buf, ev, paste) {
                        Effect::Ignored => true,
                        Effect::Changed | Effect::Swallowed => false,
                        Effect::Submit => {
                            submit = true;
                            false
                        }
                    });
            });
        }
        let label = crate::i18n::tr(self.label_tr, self.label_en);
        let words = self.words;
        response.widget_info(|| {
            // Words are not handed to accessibility clients; their count is.
            let role = if words {
                egui::accesskit::Role::TextInput
            } else {
                egui::accesskit::Role::PasswordInput
            };
            let mut w = WidgetInfo::labeled(role, enabled, label);
            w.current_text_value = Some(String::new());
            w
        });
        if words {
            self.paint_words(ui, rect, &response, enabled, label);
            return (response, submit);
        }
        let focused = response.has_focus();
        let stroke = if focused {
            egui::Stroke::new(1.5, pal.accent)
        } else if response.hovered() && enabled {
            egui::Stroke::new(1.0, pal.muted)
        } else {
            egui::Stroke::new(1.0, pal.line)
        };
        let painter = ui.painter_at(rect.expand(2.0));
        painter.rect(
            rect,
            f32::from(theme::R_INPUT),
            pal.surface,
            stroke,
            egui::StrokeKind::Inside,
        );
        let count = self.char_count();
        let (text, color) = if count == 0 {
            (label.to_string(), pal.muted)
        } else {
            (
                "\u{2022}".repeat(count.min(48)),
                if enabled { pal.ink } else { pal.muted },
            )
        };
        let galley = painter.layout_no_wrap(text, crate::fonts::regular(15.0), color);
        let text_width = galley.size().x;
        let pos = egui::pos2(rect.left() + 12.0, rect.center().y - galley.size().y / 2.0);
        painter.galley(pos, galley, color);
        if focused {
            let text_width = if count == 0 { 0.0 } else { text_width };
            let x = (pos.x + text_width + 2.0).min(rect.right() - 10.0);
            painter.line_segment(
                [
                    egui::pos2(x, rect.top() + 10.0),
                    egui::pos2(x, rect.bottom() - 10.0),
                ],
                egui::Stroke::new(1.5, pal.accent),
            );
        }
        (response, submit)
    }
}

impl SecretField {
    /// The words field: the text wrapped inside the box, a caret at the end.
    fn paint_words(
        &self,
        ui: &Ui,
        rect: egui::Rect,
        response: &Response,
        enabled: bool,
        label: &str,
    ) {
        let pal = theme::palette(ui.ctx());
        let focused = response.has_focus();
        let stroke = if focused {
            egui::Stroke::new(1.5, pal.accent)
        } else {
            egui::Stroke::new(1.0, pal.line)
        };
        let painter = ui.painter_at(rect.expand(2.0));
        painter.rect(
            rect,
            f32::from(theme::R_INPUT),
            pal.surface,
            stroke,
            egui::StrokeKind::Inside,
        );
        let text = std::str::from_utf8(self.buf.expose()).unwrap_or("");
        let (shown, color) = if text.is_empty() {
            (label.to_owned(), pal.muted)
        } else {
            (text.to_owned(), if enabled { pal.ink } else { pal.muted })
        };
        let galley = painter.layout(
            shown,
            egui::FontId::monospace(13.5),
            color,
            rect.width() - 24.0,
        );
        let pos = rect.left_top() + egui::vec2(12.0, 10.0);
        let end = galley
            .rows
            .last()
            .map_or(pos, |r| pos + egui::vec2(r.rect().right(), r.rect().top()));
        painter.galley(pos, galley, color);
        if focused {
            let x = if text.is_empty() { pos.x } else { end.x + 1.0 };
            painter.line_segment(
                [egui::pos2(x, end.y + 1.0), egui::pos2(x, end.y + 17.0)],
                egui::Stroke::new(1.5, pal.accent),
            );
        }
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    fn key(k: Key) -> Event {
        Event::Key {
            key: k,
            physical_key: None,
            pressed: true,
            repeat: false,
            modifiers: egui::Modifiers::NONE,
        }
    }

    #[test]
    fn typing_backspace_paste_and_capacity() {
        let mut b = SecretBytes::with_capacity(8).unwrap();
        assert_eq!(
            apply_event(&mut b, &Event::Text("aş".into())),
            Effect::Changed
        );
        assert_eq!(b.expose(), "aş".as_bytes());
        assert_eq!(apply_event(&mut b, &key(Key::Backspace)), Effect::Changed);
        assert_eq!(b.expose(), b"a", "backspace tam scalar silmeli");
        assert_eq!(
            apply_event(&mut b, &Event::Paste("gizli".into())),
            Effect::Swallowed
        );
        assert_eq!(apply_event(&mut b, &Event::Copy), Effect::Swallowed);
        assert_eq!(b.expose(), b"a", "clipboard is off");
        assert_eq!(
            apply_event(&mut b, &Event::Text("1234567".into())),
            Effect::Changed
        );
        assert_eq!(
            apply_event(&mut b, &Event::Text("x".into())),
            Effect::Swallowed,
            "capacity is not exceeded"
        );
        assert_eq!(b.capacity(), 8);
        assert_eq!(apply_event(&mut b, &key(Key::Enter)), Effect::Submit);
        assert_eq!(apply_event(&mut b, &key(Key::A)), Effect::Ignored);
        assert_eq!(
            apply_event(&mut b, &Event::Text("\u{7}".into())),
            Effect::Swallowed
        );
    }

    #[test]
    fn words_field_allows_paste_but_not_copy() {
        let mut b = SecretBytes::with_capacity(64).unwrap();
        assert_eq!(
            apply_event_with(&mut b, &Event::Paste("abacus\nzebra".into()), true),
            Effect::Changed
        );
        assert_eq!(b.expose(), b"abacus zebra", "line breaks become spaces");
        assert_eq!(
            apply_event_with(&mut b, &Event::Copy, true),
            Effect::Swallowed
        );
        assert_eq!(
            apply_event_with(&mut b, &Event::Cut, true),
            Effect::Swallowed
        );
        assert_eq!(
            apply_event_with(&mut b, &Event::Paste("x".into()), false),
            Effect::Swallowed,
            "password fields still refuse paste"
        );
    }

    #[test]
    fn headless_widget_consumes_text_only_when_focused() {
        let ctx = egui::Context::default();
        let mut field = SecretField::new("Parola", "Password");
        let mut id = None;
        // Frame 1: draw, focus.
        let mut out = ctx.run_ui(egui::RawInput::default(), |ui| {
            let (r, _) = field.ui(ui, true);
            r.request_focus();
            id = Some(r.id);
        });
        out.textures_delta.clear();
        // Frame 2: text event.
        let mut input = egui::RawInput::default();
        input.events.push(Event::Text("şifre".into()));
        input.events.push(key(Key::Backspace));
        let mut out = ctx.run_ui(input, |ui| {
            let _ = field.ui(ui, true);
        });
        out.textures_delta.clear();
        assert!(!field.is_empty());
        let got = field.take();
        assert_eq!(got.expose(), "şifr".as_bytes());
        assert!(field.is_empty());
        assert!(id.is_some());
    }
}
