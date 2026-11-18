//! The desktop app's few saved settings, in `lephy_sys::fs::app_settings_dir()/settings`:
//! whether the welcome screen was seen, the chosen language and, only if the user turned it on,
//! the app-lock verifier. No file names, paths or passwords are stored.
//!
//! Format: one `key=value` per line (`welcome=1`, `lang=tr|en`, `lock=<salt hex>:<tag hex>`);
//! unknown lines are ignored, so a damaged file only resets settings. Written atomically, mode
//! `0600`.
//!
//! App lock: `tag = HKDF-SHA512(Argon2id(password, salt, 64 MiB, t = 3, p = 1), "",
//! "lphy+/app-lock/v1")`. It only keeps people from using the app on an unlocked computer; the
//! encrypted files are protected by their own passwords and keys, not by this lock.
//!
//! The verifier is also kept in the system credential store (macOS keychain, Windows Credential
//! Manager) under [`LOCK_STORE_NAME`]. That copy wins: deleting the settings file does not remove
//! the lock, and writing another verifier into the file does not replace it.

use std::fmt::Write as _;
use std::path::PathBuf;

use lephy_core::kdf::{self, KdfParams};
use lephy_sys::mem::SecretBytes;
use subtle::ConstantTimeEq;

use crate::i18n::Lang;

const LOCK_KDF: KdfParams = KdfParams {
    m_kib: 64 * 1024,
    t: 3,
    p: 1,
};
const INFO_LOCK: &[u8] = b"lphy+/app-lock/v1";
/// Name of the lock verifier in the credential store.
pub const LOCK_STORE_NAME: &str = "app-lock";

/// App-lock verifier.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LockVerifier {
    salt: [u8; 32],
    tag: [u8; 32],
}

/// Saved settings.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
#[allow(clippy::struct_excessive_bools, reason = "independent preferences")]
pub struct Settings {
    /// The welcome screen was seen.
    pub welcome_done: bool,
    /// Chosen language (`None`: follow the system).
    pub lang: Option<Lang>,
    /// App lock (`None`: off).
    pub lock: Option<LockVerifier>,
    /// Animations turned off by the user.
    pub anim_off: bool,
    /// Lock an open vault after this many minutes without input (`None`: 15; `Some(0)`: never).
    pub vault_idle: Option<u32>,
    /// Do not lock an open vault when the screen locks or the computer wakes from sleep.
    pub vault_keep_on_lock: bool,
    /// Do not show this session's finished jobs on the home screen.
    pub history_off: bool,
}

impl Settings {
    /// Minutes of inactivity before an open vault is locked (0: never).
    #[must_use]
    pub fn vault_idle_minutes(&self) -> u32 {
        self.vault_idle.unwrap_or(15)
    }
}

fn path() -> Option<PathBuf> {
    lephy_sys::fs::app_settings_dir().map(|d| d.join("settings"))
}

fn hex(b: &[u8]) -> String {
    b.iter()
        .fold(String::with_capacity(b.len() * 2), |mut out, x| {
            let _ = write!(out, "{x:02x}");
            out
        })
}

fn unhex32(s: &str) -> Option<[u8; 32]> {
    if s.len() != 64 {
        return None;
    }
    let mut out = [0u8; 32];
    for (i, o) in out.iter_mut().enumerate() {
        *o = u8::from_str_radix(s.get(2 * i..2 * i + 2)?, 16).ok()?;
    }
    Some(out)
}

impl Settings {
    /// Parses the file content (unknown or bad lines are skipped).
    #[must_use]
    pub fn parse(text: &str) -> Self {
        let mut s = Self::default();
        for line in text.lines() {
            let Some((k, v)) = line.trim().split_once('=') else {
                continue;
            };
            match (k, v) {
                ("welcome", "1") => s.welcome_done = true,
                ("lang", "tr") => s.lang = Some(Lang::Tr),
                ("lang", "en") => s.lang = Some(Lang::En),
                ("anim", "0") => s.anim_off = true,
                ("vault_idle", v) => s.vault_idle = v.parse().ok().filter(|m| *m <= 24 * 60),
                ("vault_screen", "0") => s.vault_keep_on_lock = true,
                ("history", "0") => s.history_off = true,
                ("lock", v) => {
                    s.lock = v.split_once(':').and_then(|(a, b)| {
                        Some(LockVerifier {
                            salt: unhex32(a)?,
                            tag: unhex32(b)?,
                        })
                    });
                }
                _ => {}
            }
        }
        s
    }

    /// File content.
    #[must_use]
    pub fn to_text(&self) -> String {
        let mut out = String::new();
        if self.welcome_done {
            out.push_str("welcome=1\n");
        }
        match self.lang {
            Some(Lang::Tr) => out.push_str("lang=tr\n"),
            Some(Lang::En) => out.push_str("lang=en\n"),
            None => {}
        }
        if self.anim_off {
            out.push_str("anim=0\n");
        }
        if let Some(m) = self.vault_idle {
            let _ = writeln!(out, "vault_idle={m}");
        }
        if self.vault_keep_on_lock {
            out.push_str("vault_screen=0\n");
        }
        if self.history_off {
            out.push_str("history=0\n");
        }
        if let Some(l) = &self.lock {
            let _ = writeln!(out, "lock={}:{}", hex(&l.salt), hex(&l.tag));
        }
        out
    }

    /// Loads the settings (defaults if there is no file or it cannot be read); the lock comes
    /// from the credential store when it holds one.
    #[must_use]
    pub fn load() -> Self {
        let mut s = path()
            .and_then(|p| std::fs::read_to_string(p).ok())
            .map_or_else(Self::default, |t| Self::parse(&t));
        s.lock = merge_lock(s.lock, lephy_sys::keystore::get(LOCK_STORE_NAME));
        s
    }

    /// Writes the lock verifier to the credential store, or removes it when the lock is off.
    ///
    /// # Errors
    /// The store is unavailable or refused.
    pub fn save_lock_store(&self) -> std::io::Result<()> {
        match &self.lock {
            Some(v) => lephy_sys::keystore::put(LOCK_STORE_NAME, &v.to_bytes()),
            None => lephy_sys::keystore::delete(LOCK_STORE_NAME),
        }
    }

    /// Saves atomically (temporary file in the same folder, then rename), mode `0600`.
    ///
    /// # Errors
    /// The folder is unknown or cannot be written.
    pub fn save(&self) -> std::io::Result<()> {
        let p = path().ok_or_else(|| std::io::Error::other("settings folder unknown"))?;
        if let Some(d) = p.parent() {
            std::fs::create_dir_all(d)?;
        }
        let tmp = p.with_extension(format!("tmp-{}", std::process::id()));
        {
            let mut o = std::fs::OpenOptions::new();
            o.write(true).create(true).truncate(true);
            #[cfg(unix)]
            {
                use std::os::unix::fs::OpenOptionsExt;
                o.mode(0o600);
            }
            let mut f = o.open(&tmp)?;
            std::io::Write::write_all(&mut f, self.to_text().as_bytes())?;
            f.sync_all()?;
        }
        std::fs::rename(&tmp, &p)
    }
}

fn lock_tag(password_nfc: &[u8], salt: &[u8; 32]) -> lephy_core::error::Result<[u8; 32]> {
    let a = kdf::argon2_out(password_nfc, salt, &LOCK_KDF)?;
    let mut tag = [0u8; 32];
    kdf::hkdf32(a.expose(), b"", INFO_LOCK, &mut tag);
    Ok(tag)
}

/// The lock to use: the credential store's copy when there is one, else the file's.
fn merge_lock(
    file: Option<LockVerifier>,
    store: std::io::Result<lephy_sys::keystore::Read>,
) -> Option<LockVerifier> {
    match store {
        Ok(lephy_sys::keystore::Read::Found(b)) => LockVerifier::from_bytes(&b).or(file),
        _ => file,
    }
}

impl LockVerifier {
    /// `salt ‖ tag` (64 bytes), as kept in the credential store.
    #[must_use]
    pub fn to_bytes(self) -> [u8; 64] {
        let mut out = [0u8; 64];
        out[..32].copy_from_slice(&self.salt);
        out[32..].copy_from_slice(&self.tag);
        out
    }

    /// From [`Self::to_bytes`] (`None` if the length is wrong).
    #[must_use]
    pub fn from_bytes(b: &[u8]) -> Option<Self> {
        let (salt, tag) = (b.get(..32)?, b.get(32..)?);
        Some(Self {
            salt: salt.try_into().ok()?,
            tag: tag.try_into().ok()?,
        })
    }

    /// A verifier for a new lock password.
    ///
    /// # Errors
    /// RNG or key-derivation error.
    pub fn new(password: &SecretBytes) -> lephy_core::error::Result<Self> {
        let nfc = lephy_core::password::normalize_nfc(password)?;
        let mut salt = [0u8; 32];
        lephy_core::entropy::Entropy::fill(&mut lephy_core::entropy::OsEntropy, &mut salt)?;
        let tag = lock_tag(nfc.expose(), &salt)?;
        Ok(Self { salt, tag })
    }

    /// Whether `password` opens the lock.
    #[must_use]
    pub fn check(&self, password: &SecretBytes) -> bool {
        let Ok(nfc) = lephy_core::password::normalize_nfc(password) else {
            return false;
        };
        lock_tag(nfc.expose(), &self.salt).is_ok_and(|t| t.ct_eq(&self.tag).unwrap_u8() == 1)
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn text_roundtrip_and_tolerance() {
        let s = Settings {
            welcome_done: true,
            lang: Some(Lang::En),
            lock: Some(LockVerifier {
                salt: [1; 32],
                tag: [2; 32],
            }),
            anim_off: true,
            vault_idle: Some(30),
            vault_keep_on_lock: true,
            history_off: true,
        };
        assert_eq!(Settings::parse(&s.to_text()), s);
        assert_eq!(
            Settings::parse("garbage\nlang=xx\nlock=zz:yy\n"),
            Settings::default()
        );
        assert_eq!(Settings::parse(""), Settings::default());
        assert!(!Settings::default().to_text().contains("lock"));
    }

    #[test]
    fn store_copy_wins_over_the_file() {
        use lephy_sys::keystore::Read;
        let a = LockVerifier {
            salt: [1; 32],
            tag: [2; 32],
        };
        let b = LockVerifier {
            salt: [3; 32],
            tag: [4; 32],
        };
        assert_eq!(LockVerifier::from_bytes(&a.to_bytes()), Some(a));
        assert_eq!(LockVerifier::from_bytes(&[0; 10]), None);
        // The file was deleted: the store still locks.
        assert_eq!(
            merge_lock(None, Ok(Read::Found(a.to_bytes().to_vec()))),
            Some(a)
        );
        // Another verifier was written into the file: the store's copy is used.
        assert_eq!(
            merge_lock(Some(b), Ok(Read::Found(a.to_bytes().to_vec()))),
            Some(a)
        );
        // No store copy or no store: the file decides.
        assert_eq!(merge_lock(Some(b), Ok(Read::Missing)), Some(b));
        assert_eq!(
            merge_lock(Some(b), Err(std::io::Error::other("no store"))),
            Some(b)
        );
    }

    #[test]
    fn lock_accepts_only_its_password() {
        let pw = SecretBytes::from_slice(b"app lock 123").unwrap();
        let v = LockVerifier::new(&pw).unwrap();
        assert!(v.check(&pw));
        assert!(!v.check(&SecretBytes::from_slice(b"app lock 124").unwrap()));
    }
}
