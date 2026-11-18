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

/// Pure event handling (testable).
pub fn apply_event(buf: &mut SecretBytes, ev: &Event) -> Effect {
    match ev {
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
            secure: None,
        }
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
        let sense = if enabled {
            Sense::click()
        } else {
            Sense::hover()
        };
        let (rect, response) = ui.allocate_exact_size(Vec2::new(width, theme::CONTROL_H), sense);
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
                i.events.retain(|ev| match apply_event(buf, ev) {
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
        response.widget_info(|| {
            let mut w = WidgetInfo::labeled(egui::accesskit::Role::PasswordInput, enabled, label);
            w.current_text_value = Some(String::new());
            w
        });
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
