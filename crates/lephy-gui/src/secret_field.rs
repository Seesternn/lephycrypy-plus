//! Maskeli parola alanı: metin doğrudan kilitli `SecretBytes` tamponuna yazılır
//! (≤ 1024 B, büyütme yok); ekranda yalnızca `•` çizilir; pano (kopyala/kes/yapıştır) yok sayılır;
//! AccessKit rolü `PasswordInput`, değer boş. egui/winit'in `Event::Text` kopyaları ve IME
//! kompozisyonu arena dışındadır (THREAT-MODEL › Bellek); sıfırlayan global ayırıcı bunları
//! serbest bırakılırken siler.

use eframe::egui::{self, Event, Key, Response, Sense, Ui, Vec2, WidgetInfo};
use lephy_core::password::MAX_RAW_LEN;
use lephy_sys::mem::SecretBytes;

/// Bir olayın alan üzerindeki etkisi.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Effect {
    /// İlgisiz olay (tüketilmez).
    Ignored,
    /// Tüketildi, içerik değişti.
    Changed,
    /// Tüketildi, içerik değişmedi (pano olayları, kapasite aşımı).
    Swallowed,
    /// Enter: gönder.
    Submit,
}

/// Saf olay işleme (test edilebilir).
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
            // Son Unicode scalar'ı sil (UTF-8 devam baytlarını geri al).
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

/// Parola alanı.
pub struct SecretField {
    buf: SecretBytes,
    label: &'static str,
}

impl SecretField {
    /// Yeni alan.
    ///
    /// # Panics
    /// Kilitli arena kurulamazsa (süreç başında; gerçekte başarısız olmaz).
    #[must_use]
    #[allow(clippy::expect_used)]
    pub fn new(label: &'static str) -> Self {
        Self {
            buf: SecretBytes::with_capacity(MAX_RAW_LEN).expect("kilitli arena"),
            label,
        }
    }

    /// Boş mu.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.buf.is_empty()
    }

    /// İçeriği alır (alan boşalır); kopya kilitli arenada kalır.
    ///
    /// # Panics
    /// Kilitli arena dolarsa.
    #[allow(clippy::expect_used)]
    pub fn take(&mut self) -> SecretBytes {
        let fresh = SecretBytes::with_capacity(MAX_RAW_LEN).expect("kilitli arena");
        std::mem::replace(&mut self.buf, fresh)
    }

    /// Temizler.
    pub fn clear(&mut self) {
        self.buf.clear();
    }

    /// Çizer ve odaktayken klavye olaylarını tüketir. `true`: Enter'a basıldı.
    pub fn ui(&mut self, ui: &mut Ui, enabled: bool) -> (Response, bool) {
        let width = ui.available_width().min(360.0);
        let height = ui.spacing().interact_size.y + 6.0;
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
        let label = self.label;
        response.widget_info(|| {
            let mut w = WidgetInfo::labeled(egui::accesskit::Role::PasswordInput, enabled, label);
            w.current_text_value = Some(String::new());
            w
        });
        let visuals = ui.style().interact(&response);
        let focused = response.has_focus();
        let stroke = if focused {
            ui.visuals().selection.stroke
        } else {
            visuals.bg_stroke
        };
        let painter = ui.painter_at(rect);
        painter.rect(
            rect,
            4.0,
            ui.visuals().extreme_bg_color,
            stroke,
            egui::StrokeKind::Inside,
        );
        let count = std::str::from_utf8(self.buf.expose()).map_or(0, |s| s.chars().count());
        let (text, color) = if count == 0 {
            (
                if focused {
                    String::new()
                } else {
                    "parola".to_string()
                },
                ui.visuals().weak_text_color(),
            )
        } else {
            ("•".repeat(count.min(64)), ui.visuals().text_color())
        };
        let font = egui::TextStyle::Body.resolve(ui.style());
        let galley = painter.layout_no_wrap(text, font, color);
        let text_width = galley.size().x;
        let pos = egui::pos2(rect.left() + 8.0, rect.center().y - galley.size().y / 2.0);
        painter.galley(pos, galley, color);
        if focused {
            let x = (pos.x + text_width + 2.0).min(rect.right() - 6.0);
            painter.line_segment(
                [
                    egui::pos2(x, rect.top() + 6.0),
                    egui::pos2(x, rect.bottom() - 6.0),
                ],
                egui::Stroke::new(1.0, ui.visuals().text_color()),
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
        assert_eq!(b.expose(), b"a", "pano kapalı");
        assert_eq!(
            apply_event(&mut b, &Event::Text("1234567".into())),
            Effect::Changed
        );
        assert_eq!(
            apply_event(&mut b, &Event::Text("x".into())),
            Effect::Swallowed,
            "kapasite aşılmaz"
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
        let mut field = SecretField::new("Parola");
        let mut id = None;
        // Kare 1: çiz, odakla.
        let mut out = ctx.run_ui(egui::RawInput::default(), |ui| {
            let (r, _) = field.ui(ui, true);
            r.request_focus();
            id = Some(r.id);
        });
        out.textures_delta.clear();
        // Kare 2: metin olayı.
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
