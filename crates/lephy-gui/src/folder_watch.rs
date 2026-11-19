//! "The vault folder was closed": is a file-manager window showing the vault, and is a file in
//! it open in some program? Used to lock a vault once its folder is put away.
//!
//! macOS: Finder's window targets through `osascript` (the first call makes macOS ask for
//! permission to control Finder; a refusal turns the check off) and `lsof` for open files.
//! Windows: Explorer's windows through PowerShell's `Shell.Application`; open files are not
//! checked there.

use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

/// How long the folder must stay closed before the vault locks.
pub const GRACE: Duration = Duration::from_secs(30);

/// What a look found.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Seen {
    /// A file-manager window shows the vault folder (or a folder inside it).
    pub shown: bool,
    /// A program has a file in the vault open.
    pub files_open: bool,
}

/// Why the check cannot run.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Unavailable {
    /// The user did not allow controlling Finder.
    #[cfg_attr(
        not(target_os = "macos"),
        allow(dead_code, reason = "macOS permission only")
    )]
    NotAllowed,
    /// Not supported here, or the tool failed.
    Failed,
}

/// Looks once. `volume`: the vault's own volume (RAM disk), checked as a whole for open files.
///
/// # Errors
/// The check cannot run.
pub fn look(root: &Path, volume: Option<&Path>) -> Result<Seen, Unavailable> {
    let windows = imp::window_folders()?;
    let shown = windows.iter().any(|w| w.starts_with(root));
    let files_open = imp::files_open(root, volume);
    Ok(Seen { shown, files_open })
}

/// Decides from successive looks: armed once the folder was seen open; then closed with no open
/// file for [`GRACE`] → lock.
#[derive(Debug, Default)]
pub struct Tracker {
    armed: bool,
    closed_since: Option<Instant>,
}

impl Tracker {
    /// Feeds a look taken at `now`; `true`: lock now.
    pub fn step(&mut self, seen: Seen, now: Instant) -> bool {
        if seen.shown {
            self.armed = true;
            self.closed_since = None;
            return false;
        }
        if !self.armed || seen.files_open {
            self.closed_since = None;
            return false;
        }
        let since = *self.closed_since.get_or_insert(now);
        now.duration_since(since) >= GRACE
    }
}

#[cfg(target_os = "macos")]
mod imp {
    use super::{PathBuf, Unavailable};
    use std::path::Path;
    use std::process::{Command, Stdio};

    const SCRIPT: &str = r#"tell application "Finder"
set out to ""
repeat with w in (every Finder window)
try
set out to out & POSIX path of (target of w as alias) & linefeed
end try
end repeat
return out
end tell"#;

    pub(super) fn window_folders() -> Result<Vec<PathBuf>, Unavailable> {
        let out = Command::new("/usr/bin/osascript")
            .args(["-e", SCRIPT])
            .stdin(Stdio::null())
            .output()
            .map_err(|_| Unavailable::Failed)?;
        if !out.status.success() {
            let err = String::from_utf8_lossy(&out.stderr);
            return Err(if err.contains("-1743") || err.contains("-1744") {
                Unavailable::NotAllowed
            } else {
                Unavailable::Failed
            });
        }
        Ok(String::from_utf8_lossy(&out.stdout)
            .lines()
            .map(str::trim)
            .filter(|l| !l.is_empty())
            .map(PathBuf::from)
            .collect())
    }

    pub(super) fn files_open(root: &Path, volume: Option<&Path>) -> bool {
        let mut cmd = Command::new("/usr/sbin/lsof");
        cmd.arg("-Fn");
        match volume {
            Some(v) => cmd.arg("--").arg(v),
            None => cmd.arg("+D").arg(root),
        };
        cmd.stdin(Stdio::null()).stderr(Stdio::null());
        // lsof exits with 1 when nothing is open.
        cmd.output().is_ok_and(|o| {
            o.status.success()
                && o.stdout
                    .split(|b| *b == b'\n')
                    .any(|l| l.starts_with(b"n/"))
        })
    }
}

#[cfg(windows)]
mod imp {
    use super::{PathBuf, Unavailable};
    use std::path::Path;
    use std::process::{Command, Stdio};

    const SCRIPT: &str = "(New-Object -ComObject Shell.Application).Windows() | ForEach-Object { try { $_.Document.Folder.Self.Path } catch {} }";

    pub(super) fn window_folders() -> Result<Vec<PathBuf>, Unavailable> {
        let sys = lephy_sys::vol::win::system_directory().map_err(|_| Unavailable::Failed)?;
        let ps = sys.join("WindowsPowerShell\\v1.0\\powershell.exe");
        let out = Command::new(ps)
            .args(["-NoProfile", "-NonInteractive", "-Command", SCRIPT])
            .stdin(Stdio::null())
            .stderr(Stdio::null())
            .output()
            .map_err(|_| Unavailable::Failed)?;
        if !out.status.success() {
            return Err(Unavailable::Failed);
        }
        Ok(String::from_utf8_lossy(&out.stdout)
            .lines()
            .map(str::trim)
            .filter(|l| !l.is_empty())
            .map(PathBuf::from)
            .collect())
    }

    pub(super) const fn files_open(_root: &Path, _volume: Option<&Path>) -> bool {
        false
    }
}

#[cfg(not(any(target_os = "macos", windows)))]
mod imp {
    use super::{PathBuf, Unavailable};
    use std::path::Path;

    pub(super) const fn window_folders() -> Result<Vec<PathBuf>, Unavailable> {
        Err(Unavailable::Failed)
    }

    pub(super) const fn files_open(_root: &Path, _volume: Option<&Path>) -> bool {
        false
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const fn seen(shown: bool, files_open: bool) -> Seen {
        Seen { shown, files_open }
    }

    #[test]
    fn locks_after_the_folder_stays_closed() {
        let t0 = Instant::now();
        let mut t = Tracker::default();
        // Never seen open: nothing happens.
        assert!(!t.step(seen(false, false), t0));
        assert!(!t.step(seen(false, false), t0 + GRACE * 2));
        // Seen, then closed.
        assert!(!t.step(seen(true, false), t0 + GRACE * 2));
        let c = t0 + GRACE * 3;
        assert!(!t.step(seen(false, false), c));
        assert!(!t.step(seen(false, false), c + GRACE / 2));
        // A file still open resets the wait.
        assert!(!t.step(seen(false, true), c + GRACE));
        assert!(!t.step(seen(false, false), c + GRACE + Duration::from_secs(1)));
        assert!(t.step(seen(false, false), c + GRACE * 2 + Duration::from_secs(2)));
        // Shown again: armed, wait starts over.
        assert!(!t.step(seen(true, false), c + GRACE * 3));
    }
}
