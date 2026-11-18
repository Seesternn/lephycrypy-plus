//! Short, quiet animations (150–300 ms): page fades, hover lifts, folding boxes, the done mark.
//! Off when the user turns them off in Settings or asks the system to reduce motion; then every
//! helper returns its end state at once.

use eframe::egui::{self, Id};
use std::sync::atomic::{AtomicBool, Ordering};

static ENABLED: AtomicBool = AtomicBool::new(true);

/// Page and step transitions.
pub const PAGE_SECS: f32 = 0.22;
/// Hover and press feedback.
pub const HOVER_SECS: f32 = 0.15;

/// Turns animations on or off (Settings and the system "reduce motion" setting).
pub fn set_enabled(on: bool) {
    ENABLED.store(on, Ordering::Relaxed);
}

/// Animations are on.
#[must_use]
pub fn enabled() -> bool {
    ENABLED.load(Ordering::Relaxed)
}

/// Ease-out cubic on `0..=1`.
#[must_use]
pub fn ease_out(t: f32) -> f32 {
    let t = t.clamp(0.0, 1.0);
    1.0 - (1.0 - t).powi(3)
}

/// 0 → 1 while `on` turns true (and back), over `secs`; the end value at once when off.
pub fn toggle(ctx: &egui::Context, id: Id, on: bool, secs: f32) -> f32 {
    if enabled() {
        ease_out(ctx.animate_bool_with_time(id, on, secs))
    } else {
        f32::from(u8::from(on))
    }
}

/// Smoothly follows `target`; jumps when animations are off.
pub fn follow(ctx: &egui::Context, id: Id, target: f32, secs: f32) -> f32 {
    if enabled() {
        ctx.animate_value_with_time(id, target, secs)
    } else {
        target
    }
}

/// Progress `0..=1` since `key` last changed (a page, a step, a result): eased, and repaints
/// until it reaches 1.
pub fn since_change(ctx: &egui::Context, id: Id, key: u64, secs: f32) -> f32 {
    if !enabled() {
        return 1.0;
    }
    let now = ctx.input(|i| i.time);
    let start = ctx.data_mut(|d| {
        let slot = d.get_temp_mut_or(id, (key, now));
        if slot.0 != key {
            *slot = (key, now);
        }
        slot.1
    });
    #[allow(clippy::cast_possible_truncation, reason = "a fraction of a second")]
    let t = ((now - start) as f32 / secs).clamp(0.0, 1.0);
    if t < 1.0 {
        ctx.request_repaint();
    }
    ease_out(t)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn easing_and_off_switch() {
        assert!((ease_out(0.0)).abs() < f32::EPSILON);
        assert!((ease_out(1.0) - 1.0).abs() < f32::EPSILON);
        assert!(ease_out(0.5) > 0.5, "ease-out runs ahead early");
        let ctx = egui::Context::default();
        set_enabled(false);
        assert!((toggle(&ctx, Id::NULL, true, 1.0) - 1.0).abs() < f32::EPSILON);
        assert!((since_change(&ctx, Id::NULL, 7, 1.0) - 1.0).abs() < f32::EPSILON);
        assert!((follow(&ctx, Id::NULL, 0.25, 1.0) - 0.25).abs() < f32::EPSILON);
        set_enabled(true);
    }
}
