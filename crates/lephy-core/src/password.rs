//! Parola ve keyfile okuma, politika.
//!
//! - Ham parola ≤ [`MAX_RAW_LEN`] B, kilitli `SecretBytes` (kapasite sabit, büyütme yok).
//! - Kaynaklar: terminal (`/dev/tty` / `CONIN$`, yankısız, kırpma yok), stdin, fd (yalnızca Unix),
//!   dosya/isimli pipe. Terminal dışı kaynaklarda sondaki tek `\n` ya da `\r\n` kırpılır.
//! - NFC: önceden ayrılmış `SecretBytes` (4 × ham); `unicode-normalization` yineleyicisinin iç
//!   tamponu arena dışındadır (THREAT-MODEL).
//! - Şifreleme politikası: NFC sonrası < 8 Unicode scalar → red (bayrakla aşılamaz).
//! - Keyfile: 32 B..=1 MiB, içerik BLAKE3 ile özetlenir; yol/ad türetmeye girmez.

use std::io::Read;
use std::path::Path;

use lephy_sys::mem::SecretBytes;
use unicode_normalization::UnicodeNormalization;

use crate::error::{Error, Result};

/// Ham parola üst sınırı (bayt).
pub const MAX_RAW_LEN: usize = 1024;
/// Şifrelemede en az Unicode scalar sayısı (NFC sonrası).
pub const MIN_SCALARS: usize = 8;
/// Keyfile alt sınırı.
pub const KEYFILE_MIN: u64 = 32;
/// Keyfile üst sınırı.
pub const KEYFILE_MAX: u64 = 1024 * 1024;

/// Parola kaynağı.
#[derive(Debug, Clone)]
pub enum Source {
    /// Etkileşimli terminal (yankısız).
    Tty,
    /// Standart girdi (EOF'a kadar; TTY ise hata).
    Stdin,
    /// Dosya tanıtıcısı (yalnızca Unix).
    #[cfg(unix)]
    Fd(i32),
    /// Dosya ya da isimli pipe.
    File(std::path::PathBuf),
}

fn arena_err(e: impl std::fmt::Display) -> Error {
    Error::Environment(format!("kilitli bellek: {e}"))
}

/// Terminalden yankısız bir satır okur; `prompt` tty'ye yazılır.
///
/// # Errors
/// Terminal açılamadı, kesinti (`Interrupted`), çok uzun, EOF.
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
                "parola {MAX_RAW_LEN} baytı aşıyor"
            )));
        }
        Err(lephy_sys::term::ReadError::Eof) => {
            return Err(Error::Environment("parola girilmedi (EOF)".into()));
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
        .map_err(|e| Error::Environment(format!("terminal açılamadı (/dev/tty): {e}")))
}

#[cfg(windows)]
fn open_tty() -> Result<std::fs::File> {
    std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open("CONIN$")
        .map_err(|e| Error::Environment(format!("konsol açılamadı (CONIN$): {e}")))
}

/// Bir `Read` kaynağından ≤ 1024 B okur (büyütme yok), sondaki tek `\n`/`\r\n` kırpılır.
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
            "parola {MAX_RAW_LEN} baytı aşıyor"
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

/// Kaynaktan ham parolayı okur. `input_is_stdin`: giriş verisi de stdin'den geliyorsa
/// `Source::Stdin` kod 1 ile reddedilir.
///
/// # Errors
/// Kaynağa göre kod 1 (TTY/çifte kullanım/G/Ç) ya da 130.
pub fn read_raw(source: &Source, prompt: &str, input_is_stdin: bool) -> Result<SecretBytes> {
    match source {
        Source::Tty => read_tty(prompt),
        Source::Stdin => {
            if input_is_stdin {
                return Err(Error::Environment(
                    "stdin hem giriş hem parola kaynağı olamaz".into(),
                ));
            }
            let stdin = std::io::stdin();
            if lephy_sys::term::is_tty(&stdin) {
                return Err(Error::Environment(
                    "--password-stdin ile stdin bir terminal olamaz".into(),
                ));
            }
            read_bounded(stdin.lock())
        }
        #[cfg(unix)]
        Source::Fd(fd) => {
            if *fd < 3 {
                return Err(Error::Environment("--password-fd 0, 1, 2 olamaz".into()));
            }
            // lephy-core unsafe içeremez; fd sahipliğini lephy-sys devralır ve doğrular.
            let f = lephy_sys::fdio::file_from_raw_fd(*fd)
                .ok_or_else(|| Error::Environment(format!("--password-fd {fd} geçersiz")))?;
            read_bounded(f)
        }
        Source::File(path) => {
            check_file_source(path);
            let f = std::fs::File::open(path)?;
            read_bounded(f)
        }
    }
}

/// `--password-file` uyarıları: Unix'te geniş izinler; disk kalıntısı (README).
fn check_file_source(path: &Path) {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if let Ok(md) = std::fs::metadata(path) {
            if md.file_type().is_file() && md.permissions().mode() & 0o077 != 0 {
                eprintln!(
                    "uyarı: parola dosyası başkaları tarafından okunabilir (mode {:o})",
                    md.permissions().mode() & 0o777
                );
            }
            if md.file_type().is_file() {
                eprintln!(
                    "uyarı: parola dosyası diskte düz metin kalır; tmpfs/RAM disk ya da pipe tercih edin"
                );
            }
        }
    }
    #[cfg(windows)]
    {
        if let Some(s) = path.to_str() {
            let lower = s.to_ascii_lowercase();
            if lower.starts_with(r"\\") && !lower.starts_with(r"\\.\pipe\") {
                eprintln!(
                    "uyarı: uzak pipe/paylaşım yolu; yalnızca yerel \\\\.\\pipe\\ kabul edilir"
                );
            } else if !lower.starts_with(r"\\.\pipe\") {
                eprintln!("uyarı: parola dosyası diskte düz metin kalır; isimli pipe tercih edin");
            }
        }
    }
}

/// Windows'ta uzak pipe reddi. Unix'te her yol kabul.
///
/// # Errors
/// `\\<host>\pipe\…` → kod 1.
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
                    "uzak pipe/UNC parola yolu reddedildi".into(),
                ));
            }
        }
    }
    let _ = path;
    Ok(())
}

/// UTF-8 ham parolayı NFC'ye çevirir; çıktı kapasitesi 4 × ham (realloc yok).
///
/// # Errors
/// Geçersiz UTF-8 → kod 1.
pub fn normalize_nfc(raw: &SecretBytes) -> Result<SecretBytes> {
    let s = std::str::from_utf8(raw.expose())
        .map_err(|_| Error::Environment("parola geçerli UTF-8 değil".into()))?;
    let mut out = SecretBytes::with_capacity(raw.len().max(1) * 4).map_err(arena_err)?;
    let mut tmp = [0u8; 4];
    for ch in s.nfc() {
        let enc = ch.encode_utf8(&mut tmp);
        out.push_slice(enc.as_bytes()).map_err(arena_err)?;
    }
    tmp.fill(0);
    Ok(out)
}

/// NFC parolada Unicode scalar sayısı.
#[must_use]
pub fn scalar_count(nfc: &SecretBytes) -> usize {
    std::str::from_utf8(nfc.expose()).map_or(0, |s| s.chars().count())
}

/// Şifreleme politikası: < 8 scalar → red (bayrakla aşılamaz).
///
/// # Errors
/// Kod 1.
pub fn check_encrypt_policy(nfc: &SecretBytes) -> Result<()> {
    if scalar_count(nfc) < MIN_SCALARS {
        return Err(Error::Environment(format!(
            "parola en az {MIN_SCALARS} karakter olmalı (NFC sonrası Unicode scalar)"
        )));
    }
    Ok(())
}

/// Keyfile içeriğini okur ve BLAKE3 özetini döner; boyut 32 B..=1 MiB.
///
/// # Errors
/// Boyut sınırı ya da G/Ç → kod 1.
pub fn keyfile_digest_from_path(path: &Path) -> Result<zeroize::Zeroizing<[u8; 32]>> {
    let md = std::fs::metadata(path)?;
    if !md.is_file() {
        return Err(Error::Environment(
            "anahtar dosyası normal dosya olmalı".into(),
        ));
    }
    if md.len() < KEYFILE_MIN {
        return Err(Error::Environment(format!(
            "anahtar dosyası en az {KEYFILE_MIN} bayt olmalı"
        )));
    }
    if md.len() > KEYFILE_MAX {
        return Err(Error::Environment("anahtar dosyası 1 MiB'ı aşamaz".into()));
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
            return Err(Error::Environment("anahtar dosyası 1 MiB'ı aşamaz".into()));
        }
        h.update(&buf[..n]);
    }
    if total < KEYFILE_MIN {
        return Err(Error::Environment(format!(
            "anahtar dosyası en az {KEYFILE_MIN} bayt olmalı"
        )));
    }
    let out = zeroize::Zeroizing::new(*h.finalize().as_bytes());
    zeroize::Zeroize::zeroize(&mut h);
    Ok(out)
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
}
