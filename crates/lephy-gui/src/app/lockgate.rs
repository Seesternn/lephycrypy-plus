//! App-lock password checks: run off the UI thread (Argon2id takes a moment) and, after a wrong
//! password, wait 1, 2, 4… seconds (at most 30) before the next try.

use super::App;
use crate::i18n::{Lang, lang, tr};
use crate::settings::LockVerifier;
use eframe::egui;
use lephy_sys::mem::SecretBytes;
use std::sync::mpsc::{Receiver, TryRecvError};
use std::time::{Duration, Instant};

/// What a successful check does.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum Purpose {
    /// Open the locked app.
    Unlock,
    /// Turn the lock off (Settings).
    TurnOff,
}

/// Pending check and back-off state.
#[derive(Default)]
pub(super) struct LockGate {
    rx: Option<(Receiver<bool>, Purpose)>,
    fails: u32,
    until: Option<Instant>,
}

/// Wait after `fails` wrong passwords in a row.
pub(super) fn backoff(fails: u32) -> Duration {
    if fails == 0 {
        return Duration::ZERO;
    }
    Duration::from_secs((1u64 << (fails - 1).min(5)).min(30))
}

impl LockGate {
    /// A check is running.
    pub(super) fn busy(&self) -> bool {
        self.rx.is_some()
    }

    /// Seconds left before the next try (0: may try now).
    pub(super) fn wait_left(&self) -> u64 {
        self.until
            .and_then(|t| t.checked_duration_since(Instant::now()))
            .map_or(0, |d| d.as_secs() + 1)
    }
}

impl App {
    /// Starts checking `pw` against the lock (ignored while busy or waiting).
    pub(super) fn start_lock_check(&mut self, ctx: &egui::Context, pw: SecretBytes, p: Purpose) {
        let Some(v) = self.prefs.lock else { return };
        if self.lock_gate.busy() || self.lock_gate.wait_left() > 0 {
            return;
        }
        let (tx, rx) = std::sync::mpsc::channel();
        let ctx = ctx.clone();
        std::thread::spawn(move || {
            let ok = LockVerifier::check(&v, &pw);
            drop(pw);
            let _ = tx.send(ok);
            ctx.request_repaint();
        });
        self.lock_gate.rx = Some((rx, p));
        self.lock_msg = None;
    }

    /// Applies a finished check; keeps repainting while a wait runs down.
    pub(super) fn poll_lock_check(&mut self, ctx: &egui::Context) {
        if self.lock_gate.wait_left() > 0 {
            ctx.request_repaint_after(Duration::from_millis(250));
        }
        let Some((rx, purpose)) = &self.lock_gate.rx else {
            return;
        };
        let purpose = *purpose;
        let ok = match rx.try_recv() {
            Ok(ok) => ok,
            Err(TryRecvError::Empty) => return,
            Err(TryRecvError::Disconnected) => false,
        };
        self.lock_gate.rx = None;
        if !ok {
            self.lock_gate.fails += 1;
            let wait = backoff(self.lock_gate.fails);
            self.lock_gate.until = Some(Instant::now() + wait);
            self.lock_msg = Some(match lang() {
                Lang::Tr => format!(
                    "Parola yanlış. {} sn sonra yeniden deneyin.",
                    wait.as_secs()
                ),
                Lang::En => format!("Wrong password. Try again in {} s.", wait.as_secs()),
            });
            return;
        }
        self.lock_gate.fails = 0;
        self.lock_gate.until = None;
        match purpose {
            Purpose::Unlock => {
                self.locked = false;
                self.lock_msg = None;
            }
            Purpose::TurnOff => {
                self.prefs.lock = None;
                self.save_prefs();
                self.lock_edit = false;
                self.lock_msg = Some(match self.prefs.save_lock_store() {
                    Ok(()) => tr("Kilit kapatıldı.", "The lock is off.").into(),
                    Err(e) => match lang() {
                        Lang::Tr => {
                            format!("Kilit kapatıldı, ama Anahtar Zinciri kaydı silinemedi: {e}")
                        }
                        Lang::En => {
                            format!(
                                "The lock is off, but the keychain item could not be removed: {e}"
                            )
                        }
                    },
                });
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::backoff;
    use std::time::Duration;

    #[test]
    fn backoff_doubles_up_to_thirty_seconds() {
        let secs: Vec<u64> = (0..9).map(|n| backoff(n).as_secs()).collect();
        assert_eq!(secs, [0, 1, 2, 4, 8, 16, 30, 30, 30]);
        assert_eq!(backoff(u32::MAX), Duration::from_secs(30));
    }
}
