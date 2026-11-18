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
    /// Keep the state in the credential store (the real app; tests stay in memory).
    pub(super) persist: bool,
}

/// Name of the back-off state in the credential store (kept there, not in the settings file,
/// so neither restarting the app nor deleting the file resets it).
const STORE_NAME: &str = "app-lock-fails";

/// `fails` (u32 LE) ‖ end of the wait in Unix seconds (u64 LE).
fn encode(fails: u32, until_unix: u64) -> [u8; 12] {
    let mut b = [0u8; 12];
    b[..4].copy_from_slice(&fails.to_le_bytes());
    b[4..].copy_from_slice(&until_unix.to_le_bytes());
    b
}

fn decode(b: &[u8]) -> Option<(u32, u64)> {
    let fails = u32::from_le_bytes(b.get(..4)?.try_into().ok()?);
    let until = u64::from_le_bytes(b.get(4..12)?.try_into().ok()?);
    Some((fails, until))
}

fn unix_now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_secs())
}

/// Wait after `fails` wrong passwords in a row.
pub(super) fn backoff(fails: u32) -> Duration {
    if fails == 0 {
        return Duration::ZERO;
    }
    Duration::from_secs((1u64 << (fails - 1).min(5)).min(30))
}

impl LockGate {
    /// The back-off left over from an earlier run of the app (real app only).
    pub(super) fn load_persisted(&mut self) {
        if let Ok(lephy_sys::keystore::Read::Found(b)) = lephy_sys::keystore::get(STORE_NAME)
            && let Some((fails, until)) = decode(&b)
        {
            self.fails = fails;
            let left = until.saturating_sub(unix_now()).min(30);
            self.until = (left > 0).then(|| Instant::now() + Duration::from_secs(left));
            self.persist = true;
        }
    }

    fn save(&self) {
        if !self.persist {
            return;
        }
        let left = self.until.map_or(0, |t| {
            t.saturating_duration_since(Instant::now()).as_secs() + 1
        });
        let _ = if self.fails == 0 {
            lephy_sys::keystore::delete(STORE_NAME)
        } else {
            lephy_sys::keystore::put(STORE_NAME, &encode(self.fails, unix_now() + left))
        };
    }

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
            self.lock_gate.save();
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
        self.lock_gate.save();
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
    fn stored_state_roundtrip() {
        assert_eq!(
            super::decode(&super::encode(3, 1_700_000_000)),
            Some((3, 1_700_000_000))
        );
        assert_eq!(super::decode(&[1, 2, 3]), None);
    }

    #[test]
    fn backoff_doubles_up_to_thirty_seconds() {
        let secs: Vec<u64> = (0..9).map(|n| backoff(n).as_secs()).collect();
        assert_eq!(secs, [0, 1, 2, 4, 8, 16, 30, 30, 30]);
        assert_eq!(backoff(u32::MAX), Duration::from_secs(30));
    }
}
