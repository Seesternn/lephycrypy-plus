//! Reading passwords and key files; policy.
//!
//! - Raw password ≤ [`MAX_RAW_LEN`] B in locked `SecretBytes` (fixed capacity, never grown).
//! - Sources: terminal (`/dev/tty` / `CONIN$`, no echo, no trimming), stdin, fd (Unix only),
//!   file/named pipe. For non-terminal sources one trailing `\n` or `\r\n` is removed.
//! - NFC: into pre-allocated `SecretBytes` (4 × raw); the internal buffer of the
//!   `unicode-normalization` iterator is outside the arena (THREAT-MODEL).
//! - Encryption policy: < 8 Unicode scalar values after NFC → refused (no flag overrides it).
//! - Key file: 32 B..=1 MiB, the content is hashed with BLAKE3; the path/name is not used.

use std::io::Read;
use std::path::Path;

use lephy_sys::mem::SecretBytes;
use unicode_normalization::UnicodeNormalization;

use crate::error::{Error, Result};

/// Upper limit for a raw password (bytes).
pub const MAX_RAW_LEN: usize = 1024;
/// Minimum number of Unicode scalar values when encrypting (after NFC).
pub const MIN_SCALARS: usize = 8;
/// Key-file lower limit.
pub const KEYFILE_MIN: u64 = 32;
/// Key-file upper limit.
pub const KEYFILE_MAX: u64 = 1024 * 1024;

/// Password source.
#[derive(Debug, Clone)]
pub enum Source {
    /// Interactive terminal (no echo).
    Tty,
    /// Standard input (until EOF; an error if it is a TTY).
    Stdin,
    /// File descriptor (Unix only).
    #[cfg(unix)]
    Fd(i32),
    /// File or named pipe.
    File(std::path::PathBuf),
}

fn arena_err(e: impl std::fmt::Display) -> Error {
    Error::Environment(format!("locked memory: {e}"))
}

/// Reads one line from the terminal without echo; `prompt` is written to the tty.
///
/// # Errors
/// Terminal could not be opened, interruption (`Interrupted`), too long, EOF.
pub fn read_tty(prompt: &str) -> Result<SecretBytes> {
    let tty = open_tty()?;
    lephy_sys::term::write_all_raw(&tty, prompt.as_bytes())?;
    let guard = lephy_sys::term::RawModeGuard::enter(&tty)?;
    let mut raw = SecretBytes::with_capacity(MAX_RAW_LEN).map_err(arena_err)?;
    let r = lephy_sys::term::read_line_noecho(&tty, raw.spare_mut());
    drop(guard);
    let _ = lephy_sys::term::write_all_raw(&tty, b"\n");
    let n = match r {
        Ok(n) => n,
        Err(lephy_sys::term::ReadError::Interrupted) => return Err(Error::Interrupted),
        Err(lephy_sys::term::ReadError::TooLong) => {
            return Err(Error::Environment(format!(
                "the password exceeds {MAX_RAW_LEN} bytes"
            )));
        }
        Err(lephy_sys::term::ReadError::Eof) => {
            return Err(Error::Environment("no password entered (EOF)".into()));
        }
        Err(lephy_sys::term::ReadError::Io(e)) => return Err(Error::Io(e)),
    };
    raw.set_len(n).map_err(arena_err)?;
    Ok(raw)
}

#[cfg(unix)]
fn open_tty() -> Result<std::fs::File> {
    std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open("/dev/tty")
        .map_err(|e| Error::Environment(format!("could not open the terminal (/dev/tty): {e}")))
}

#[cfg(windows)]
fn open_tty() -> Result<std::fs::File> {
    std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open("CONIN$")
        .map_err(|e| Error::Environment(format!("could not open the console (CONIN$): {e}")))
}

/// Reads ≤ 1024 B from a `Read` source (never grown) and removes one trailing `\n`/`\r\n`.
fn read_bounded(mut r: impl Read) -> Result<SecretBytes> {
    let mut raw = SecretBytes::with_capacity(MAX_RAW_LEN + 1).map_err(arena_err)?;
    let mut total = 0usize;
    loop {
        let n = {
            let spare = raw.spare_mut();
            if spare.is_empty() {
                break;
            }
            r.read(spare)?
        };
        if n == 0 {
            break;
        }
        total += n;
        raw.set_len(total).map_err(arena_err)?;
    }
    if total > MAX_RAW_LEN {
        return Err(Error::Environment(format!(
            "the password exceeds {MAX_RAW_LEN} bytes"
        )));
    }
    let b = raw.expose();
    let trimmed = if b.ends_with(b"\r\n") {
        b.len() - 2
    } else if b.ends_with(b"\n") {
        b.len() - 1
    } else {
        b.len()
    };
    raw.truncate(trimmed);
    Ok(raw)
}

/// Reads the raw password from a source. `input_is_stdin`: if the input data also comes from
/// stdin, `Source::Stdin` is refused with code 1.
///
/// # Errors
/// Code 1 (TTY / used twice / I/O) or 130, depending on the source.
pub fn read_raw(source: &Source, prompt: &str, input_is_stdin: bool) -> Result<SecretBytes> {
    match source {
        Source::Tty => read_tty(prompt),
        Source::Stdin => {
            if input_is_stdin {
                return Err(Error::Environment(
                    "stdin cannot be both the input and the password source".into(),
                ));
            }
            let stdin = std::io::stdin();
            if lephy_sys::term::is_tty(&stdin) {
                return Err(Error::Environment(
                    "with --password-stdin, stdin cannot be a terminal".into(),
                ));
            }
            read_bounded(stdin.lock())
        }
        #[cfg(unix)]
        Source::Fd(fd) => {
            if *fd < 3 {
                return Err(Error::Environment(
                    "--password-fd cannot be 0, 1 or 2".into(),
                ));
            }
            // lephy-core cannot contain unsafe; lephy-sys validates the fd and returns a duplicate.
            let f = lephy_sys::fdio::dup_inherited_fd(*fd)
                .ok_or_else(|| Error::Environment(format!("--password-fd {fd} is invalid")))?;
            read_bounded(f)
        }
        Source::File(path) => {
            check_file_source(path);
            let f = std::fs::File::open(path)?;
            read_bounded(f)
        }
    }
}

/// `--password-file` warnings: broad permissions on Unix; residue on disk (README).
fn check_file_source(path: &Path) {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if let Ok(md) = std::fs::metadata(path) {
            if md.file_type().is_file() && md.permissions().mode() & 0o077 != 0 {
                eprintln!(
                    "warning: the password file is readable by others (mode {:o})",
                    md.permissions().mode() & 0o777
                );
            }
            if md.file_type().is_file() {
                eprintln!(
                    "warning: the password file stays on disk as plaintext; prefer tmpfs, a RAM disk or a pipe"
                );
            }
        }
    }
    #[cfg(windows)]
    {
        if let Some(s) = path.to_str() {
            let lower = s.to_ascii_lowercase();
            if lower.starts_with(r"\\") && !lower.starts_with(r"\\.\pipe\") {
                eprintln!("warning: remote pipe/share path; only local \\\\.\\pipe\\ is accepted");
            } else if !lower.starts_with(r"\\.\pipe\") {
                eprintln!(
                    "warning: the password file stays on disk as plaintext; prefer a named pipe"
                );
            }
        }
    }
}

/// Refuses remote pipes on Windows. Every path is accepted on Unix.
///
/// # Errors
/// `\\<host>\pipe\…` → code 1.
pub fn reject_remote_pipe(path: &Path) -> Result<()> {
    #[cfg(windows)]
    {
        if let Some(s) = path.to_str() {
            let lower = s.to_ascii_lowercase();
            if lower.starts_with(r"\\")
                && !lower.starts_with(r"\\.\")
                && !lower.starts_with(r"\\?\")
            {
                return Err(Error::Environment(
                    "remote pipe/UNC password path refused".into(),
                ));
            }
        }
    }
    let _ = path;
    Ok(())
}

/// Converts the UTF-8 raw password to NFC; output capacity 4 × raw (no reallocation).
///
/// # Errors
/// Invalid UTF-8 → code 1.
pub fn normalize_nfc(raw: &SecretBytes) -> Result<SecretBytes> {
    let s = std::str::from_utf8(raw.expose())
        .map_err(|_| Error::Environment("the password is not valid UTF-8".into()))?;
    let mut out = SecretBytes::with_capacity(raw.len().max(1) * 4).map_err(arena_err)?;
    let mut tmp = [0u8; 4];
    for ch in s.nfc() {
        let enc = ch.encode_utf8(&mut tmp);
        out.push_slice(enc.as_bytes()).map_err(arena_err)?;
    }
    tmp.fill(0);
    Ok(out)
}

/// Number of Unicode scalar values in an NFC password.
#[must_use]
pub fn scalar_count(nfc: &SecretBytes) -> usize {
    std::str::from_utf8(nfc.expose()).map_or(0, |s| s.chars().count())
}

/// Encryption policy: < 8 scalar values → refused (no flag overrides it).
///
/// # Errors
/// Code 1.
pub fn check_encrypt_policy(nfc: &SecretBytes) -> Result<()> {
    if scalar_count(nfc) < MIN_SCALARS {
        return Err(Error::Environment(format!(
            "the password must be at least {MIN_SCALARS} characters (Unicode scalar values after NFC)"
        )));
    }
    Ok(())
}

/// Reads the key file and returns its BLAKE3 digest; size 32 B..=1 MiB.
///
/// # Errors
/// Size limit or I/O → code 1.
pub fn keyfile_digest_from_path(path: &Path) -> Result<zeroize::Zeroizing<[u8; 32]>> {
    let md = std::fs::metadata(path)?;
    if !md.is_file() {
        return Err(Error::Environment(
            "the key file must be a regular file".into(),
        ));
    }
    if md.len() < KEYFILE_MIN {
        return Err(Error::Environment(format!(
            "the key file must be at least {KEYFILE_MIN} bytes"
        )));
    }
    if md.len() > KEYFILE_MAX {
        return Err(Error::Environment(
            "the key file cannot exceed 1 MiB".into(),
        ));
    }
    let mut f = std::fs::File::open(path)?;
    let mut h = blake3::Hasher::new();
    let mut buf = zeroize::Zeroizing::new(vec![0u8; 64 * 1024]);
    let mut total: u64 = 0;
    loop {
        let n = f.read(&mut buf[..])?;
        if n == 0 {
            break;
        }
        total += n as u64;
        if total > KEYFILE_MAX {
            return Err(Error::Environment(
                "the key file cannot exceed 1 MiB".into(),
            ));
        }
        h.update(&buf[..n]);
    }
    if total < KEYFILE_MIN {
        return Err(Error::Environment(format!(
            "the key file must be at least {KEYFILE_MIN} bytes"
        )));
    }
    let out = zeroize::Zeroizing::new(*h.finalize().as_bytes());
    zeroize::Zeroize::zeroize(&mut h);
    Ok(out)
}

/// Creates a new key file: `len` random bytes, readable only by the owner (0600), never
/// overwrites an existing file. Must be in `KEYFILE_MIN..=KEYFILE_MAX`.
///
/// # Errors
/// File already exists (code 7), length out of range, I/O or RNG error.
pub fn generate_keyfile(path: &Path, len: usize) -> Result<()> {
    let len64 = len as u64;
    if !(KEYFILE_MIN..=KEYFILE_MAX).contains(&len64) {
        return Err(Error::Environment(format!(
            "the key file must be {KEYFILE_MIN}..={KEYFILE_MAX} bytes"
        )));
    }
    let mut buf = zeroize::Zeroizing::new(vec![0u8; len]);
    crate::entropy::Entropy::fill(&mut crate::entropy::OsEntropy, &mut buf)?;
    let mut oo = std::fs::OpenOptions::new();
    oo.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        oo.mode(0o600);
    }
    let mut f = oo.open(path).map_err(|e| {
        if e.kind() == std::io::ErrorKind::AlreadyExists {
            Error::Exists(path.display().to_string())
        } else {
            Error::Io(e)
        }
    })?;
    std::io::Write::write_all(&mut f, &buf)?;
    f.sync_all()?;
    Ok(())
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::panic)]
mod tests {
    use super::*;

    #[test]
    fn trims_single_trailing_newline_only() {
        let r = read_bounded(&b"test\r\n"[..]).unwrap();
        assert_eq!(r.expose(), b"test");
        let r = read_bounded(&b"test\n"[..]).unwrap();
        assert_eq!(r.expose(), b"test");
        let r = read_bounded(&b"test\n\n"[..]).unwrap();
        assert_eq!(r.expose(), b"test\n");
        let r = read_bounded(&b"test"[..]).unwrap();
        assert_eq!(r.expose(), b"test");
    }

    #[test]
    fn rejects_1025_bytes_without_growing() {
        let big = vec![b'a'; 1025];
        assert!(read_bounded(&big[..]).is_err());
        let ok = vec![b'a'; 1024];
        let r = read_bounded(&ok[..]).unwrap();
        assert_eq!(r.len(), 1024);
        assert_eq!(r.capacity(), MAX_RAW_LEN + 1);
    }

    #[test]
    fn nfd_and_nfc_normalize_equal() {
        let nfd = "s\u{0327} g\u{0306} I\u{0307} e\u{0301}";
        let nfc = "ş ğ İ é";
        let a = normalize_nfc(&SecretBytes::from_slice(nfd.as_bytes()).unwrap()).unwrap();
        let b = normalize_nfc(&SecretBytes::from_slice(nfc.as_bytes()).unwrap()).unwrap();
        assert_eq!(a.expose(), b.expose());
        assert_eq!(a.expose(), nfc.as_bytes());
    }

    #[test]
    fn policy_counts_scalars_after_nfc() {
        let seven = normalize_nfc(&SecretBytes::from_slice("şğüöçıi".as_bytes()).unwrap()).unwrap();
        assert_eq!(scalar_count(&seven), 7);
        assert!(check_encrypt_policy(&seven).is_err());
        let eight =
            normalize_nfc(&SecretBytes::from_slice("şğüöçıiİ".as_bytes()).unwrap()).unwrap();
        assert!(check_encrypt_policy(&eight).is_ok());
    }

    #[test]
    fn keyfile_bounds() {
        let dir = std::env::temp_dir();
        let p = dir.join(format!("lphy-kf-{}", std::process::id()));
        std::fs::write(&p, [1u8; 31]).unwrap();
        assert!(keyfile_digest_from_path(&p).is_err());
        std::fs::write(&p, (0u8..64).collect::<Vec<_>>()).unwrap();
        let d = keyfile_digest_from_path(&p).unwrap();
        assert_eq!(
            *d,
            crate::kdf::keyfile_digest(&(0u8..64).collect::<Vec<_>>())
        );
        let _ = std::fs::remove_file(&p);
    }

    #[test]
    fn generated_keyfile_is_usable_and_never_overwritten() {
        let p = std::env::temp_dir().join(format!("lphy-kfgen-{}", std::process::id()));
        let _ = std::fs::remove_file(&p);
        generate_keyfile(&p, 64).unwrap();
        assert_eq!(std::fs::metadata(&p).unwrap().len(), 64);
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let m = std::fs::metadata(&p).unwrap().permissions().mode() & 0o777;
            assert_eq!(m, 0o600);
        }
        assert!(keyfile_digest_from_path(&p).is_ok());
        assert!(matches!(generate_keyfile(&p, 64), Err(Error::Exists(_))));
        assert!(generate_keyfile(&p.with_extension("x"), 8).is_err());
        let _ = std::fs::remove_file(&p);
    }
}
