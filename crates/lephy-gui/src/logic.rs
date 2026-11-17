//! Arayüzden bağımsız mantık: mod tespiti, varsayılan çıktı yolu, arka plan işi.
//! Yollar argv'ye gitmez (THREAT-MODEL › açık meta veri): GUI argümansız başlar, kaynak
//! sürükle-bırak ya da dosya seçme penceresiyle gelir.

use std::path::{Path, PathBuf};

use lephy_core::cipher::AlgId;
use lephy_core::entropy::{Entropy, OsEntropy};
use lephy_core::error::{Error, ExitCode, Result};
use lephy_core::header::{HEADER_LEN, Header};
use lephy_core::kdf::KdfParams;
use lephy_core::ops::{self, DecryptOptions, EncryptOptions, Input, Output};
use lephy_core::password;
use lephy_sys::mem::SecretBytes;

/// İşlem modu.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Mode {
    /// Dosya/klasör → `.lphy`.
    Encrypt,
    /// `.lphy` → dosya/klasör.
    Decrypt,
}

/// Geçerli bir `.lphy` başlığı varsa çöz, yoksa şifrele.
#[must_use]
pub fn detect_mode(path: &Path) -> Mode {
    let Ok(md) = path.metadata() else {
        return Mode::Encrypt;
    };
    if !md.is_file() || md.len() < HEADER_LEN as u64 {
        return Mode::Encrypt;
    }
    let mut h = [0u8; HEADER_LEN];
    let ok = std::fs::File::open(path)
        .and_then(|mut f| std::io::Read::read_exact(&mut f, &mut h))
        .is_ok();
    if ok && Header::parse(&h).is_ok() {
        Mode::Decrypt
    } else {
        Mode::Encrypt
    }
}

/// Varsayılan çıktı: şifrelemede aynı dizinde `<8 rastgele hex>.lphy` (D1); çözmede `.lphy`
/// kaldırılmış ad ya da `<ad>.out`.
#[must_use]
pub fn default_output(input: &Path, mode: Mode) -> PathBuf {
    let dir = input.parent().unwrap_or(Path::new("."));
    match mode {
        Mode::Encrypt => {
            let mut b = [0u8; 4];
            let _ = OsEntropy.fill(&mut b);
            dir.join(format!(
                "{:02x}{:02x}{:02x}{:02x}.lphy",
                b[0], b[1], b[2], b[3]
            ))
        }
        Mode::Decrypt => {
            let name = input
                .file_name()
                .map(|f| f.to_string_lossy().into_owned())
                .unwrap_or_default();
            let base = name
                .strip_suffix(".lphy")
                .map_or_else(|| format!("{name}.out"), str::to_string);
            dir.join(base)
        }
    }
}

/// Arka plan işi. Parolalar kilitli `SecretBytes`'ta taşınır ve iş bitince düşer.
pub struct Job {
    /// Mod.
    pub mode: Mode,
    /// Kaynak.
    pub input: PathBuf,
    /// Hedef.
    pub output: PathBuf,
    /// Parola (ham UTF-8).
    pub password: SecretBytes,
    /// Şifrelemede tekrar.
    pub confirm: Option<SecretBytes>,
    /// Argon2id belleği (MiB).
    pub kdf_mib: u32,
    /// AES-256-GCM (varsayılan XChaCha20-Poly1305).
    pub aes: bool,
    /// Arşivde PADMÉ.
    pub pad: bool,
    /// Bulut senkron klasörüne çıkarmaya izin.
    pub allow_cloud: bool,
}

/// Başarılı işin sonucu.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Outcome {
    /// Yazılan dosya ya da klasör.
    pub output: PathBuf,
    /// Atlanan arşiv girişleri (özel dosyalar, kurulmayan symlink'ler).
    pub skipped: usize,
}

/// İşi yürütür.
///
/// # Errors
/// Çekirdek hataları (mesajı ve çıkış kodu kategorisi arayüzde gösterilir).
pub fn run(job: Job) -> Result<Outcome> {
    lephy_sys::signal::reset_interrupted();
    let nfc = password::normalize_nfc(&job.password)?;
    drop(job.password);
    let mut log = |_: &str| {};
    match job.mode {
        Mode::Encrypt => {
            let confirm = job
                .confirm
                .ok_or_else(|| Error::Environment("parolayı tekrar girin".into()))?;
            let c = password::normalize_nfc(&confirm)?;
            drop(confirm);
            if c.expose() != nfc.expose() {
                return Err(Error::Environment("parolalar eşleşmiyor".into()));
            }
            password::check_encrypt_policy(&nfc)?;
            let kdf = KdfParams {
                m_kib: job.kdf_mib.saturating_mul(1024),
                ..KdfParams::DEFAULT
            };
            let opts = EncryptOptions {
                alg: if job.aes {
                    AlgId::Aes256Gcm
                } else {
                    AlgId::XChaCha20Poly1305
                },
                chunk_code: 2,
                kdf,
                force: false,
                strict_memory: false,
                raw: false,
                pad: Some(job.pad),
                strict: false,
            };
            let rep = ops::encrypt(
                &Input::Path(&job.input),
                &job.output,
                &nfc,
                None,
                &opts,
                &mut OsEntropy,
                &mut log,
            )?;
            Ok(Outcome {
                output: job.output,
                skipped: rep.archive.as_ref().map_or(0, |a| a.skipped.len()),
            })
        }
        Mode::Decrypt => {
            if !job.allow_cloud && lephy_sys::fs::cloud_root_of(&job.output).is_some() {
                return Err(Error::Cancelled(
                    "hedef bir bulut senkron klasöründe; devam etmek için onay kutusunu işaretleyin".into(),
                ));
            }
            let rep = ops::decrypt(
                &job.input,
                &Output::Path(&job.output, false),
                &nfc,
                None,
                DecryptOptions::default(),
                &mut log,
            )?;
            Ok(Outcome {
                output: rep.target,
                skipped: rep.archive.as_ref().map_or(0, |a| a.skipped.len()),
            })
        }
    }
}

/// Kullanıcıya gösterilecek hata metni: ne oldu ve ne yapılabilir.
#[must_use]
pub fn describe_error(e: &Error) -> String {
    match (e, e.exit_code()) {
        (Error::KeyfileRequired, _) => {
            "Bu dosya bir anahtar dosyasıyla şifrelenmiş. Komut satırından `--keyfile` ile açın."
                .into()
        }
        (_, ExitCode::WrongPassword) => {
            "Parola yanlış. Büyük/küçük harf ve klavye düzenini kontrol edip yeniden deneyin."
                .into()
        }
        (_, ExitCode::Corrupt) => {
            "Dosya bozuk ya da değiştirilmiş; içeriği güvenle açılamıyor.".into()
        }
        (_, ExitCode::Exists) => {
            "Kayıt yerinde aynı adla bir dosya var. Başka bir kayıt yeri seçin.".into()
        }
        (_, ExitCode::DiskSpace) => "Diskte yeterli boş alan yok.".into(),
        (_, ExitCode::KdfBudget) => {
            "Bu ayar için bellek yetmiyor. Gelişmiş ayarlardan bellek miktarını düşürün.".into()
        }
        (_, ExitCode::Interrupted) => "İşlem durduruldu. Yarım kalan dosya silindi.".into(),
        _ => sentence(&e.to_string()),
    }
}

/// İlk harfi büyütür, sonuna nokta koyar.
fn sentence(s: &str) -> String {
    let mut c = s.trim().chars();
    let mut out: String = c
        .next()
        .map(|f| f.to_uppercase().collect())
        .unwrap_or_default();
    out.push_str(c.as_str());
    if !out.ends_with(['.', '!', '?']) {
        out.push('.');
    }
    out
}

/// Kaynak hakkında kısa bilgi: (görünen ad, açıklama).
#[must_use]
pub fn describe_source(path: &Path, mode: Mode) -> (String, String) {
    let name = path.file_name().map_or_else(
        || lephy_core::names::escape_display(&path.display().to_string()),
        |f| lephy_core::names::escape_display(&f.to_string_lossy()),
    );
    let md = path.metadata().ok();
    let detail = match (mode, md) {
        (_, Some(m)) if m.is_dir() => "Klasör".to_string(),
        (Mode::Decrypt, Some(m)) => format!("Şifreli dosya, {}", human_size(m.len())),
        (Mode::Encrypt, Some(m)) => human_size(m.len()),
        (_, None) => "Okunamıyor".to_string(),
    };
    (name, detail)
}

/// İnsan okunur boyut (Türkçe ondalık virgül).
#[must_use]
#[allow(clippy::cast_precision_loss)]
pub fn human_size(n: u64) -> String {
    const UNITS: [&str; 5] = ["bayt", "KB", "MB", "GB", "TB"];
    if n < 1000 {
        return format!("{n} bayt");
    }
    let mut v = n as f64;
    let mut u = 0;
    while v >= 1000.0 && u < UNITS.len() - 1 {
        v /= 1000.0;
        u += 1;
    }
    let s = if v < 10.0 {
        format!("{v:.1}")
    } else {
        format!("{v:.0}")
    };
    format!("{} {}", s.replace('.', ","), UNITS[u])
}

/// Klasör yolunu kısaltır: ev dizini `~` olur.
#[must_use]
pub fn short_dir(dir: &Path) -> String {
    let home = home_dir();
    match home.as_deref().and_then(|h| dir.strip_prefix(h).ok()) {
        Some(rest) if rest.as_os_str().is_empty() => "~".to_string(),
        Some(rest) => format!("~{}{}", std::path::MAIN_SEPARATOR, rest.display()),
        None => dir.display().to_string(),
    }
}

/// Ev dizini (ortam değişkeni okunmaz; `std::env::home_dir`).
fn home_dir() -> Option<PathBuf> {
    std::env::home_dir().filter(|h| h.is_absolute())
}

/// Dosya yöneticisinde gösterir (macOS Finder, Windows Gezgini). Araçlar mutlak yolla çağrılır.
///
/// # Errors
/// Araç başlatılamazsa.
pub fn reveal_in_folder(path: &Path) -> std::io::Result<()> {
    #[cfg(target_os = "macos")]
    {
        std::process::Command::new("/usr/bin/open")
            .arg("-R")
            .arg(path)
            .env_clear()
            .spawn()
            .map(drop)
    }
    #[cfg(windows)]
    {
        let sys = lephy_sys::vol::win::system_directory()?;
        let explorer = sys
            .parent()
            .map_or_else(|| sys.join("explorer.exe"), |w| w.join("explorer.exe"));
        let mut arg = std::ffi::OsString::from("/select,");
        arg.push(path);
        std::process::Command::new(explorer)
            .arg(arg)
            .spawn()
            .map(drop)
    }
    #[cfg(not(any(target_os = "macos", windows)))]
    {
        let _ = path;
        Err(std::io::Error::other("desteklenmiyor"))
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    fn secret(s: &str) -> SecretBytes {
        SecretBytes::from_slice(s.as_bytes()).unwrap()
    }

    #[test]
    fn mode_and_default_output() {
        let d = std::env::temp_dir().join(format!("lphy-gui-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(d.join("klasor")).unwrap();
        std::fs::write(d.join("a.txt"), b"hello").unwrap();
        assert_eq!(detect_mode(&d.join("a.txt")), Mode::Encrypt);
        assert_eq!(detect_mode(&d.join("klasor")), Mode::Encrypt);
        let out = default_output(&d.join("a.txt"), Mode::Encrypt);
        let name = out.file_name().unwrap().to_string_lossy().into_owned();
        assert_eq!(out.extension().and_then(|e| e.to_str()), Some("lphy"));
        assert_eq!(name.len(), 13, "{name}");
        assert!(
            !name.contains("a.txt"),
            "çıktı adı kaynak adını sızdırmamalı"
        );
        let job = Job {
            mode: Mode::Encrypt,
            input: d.join("a.txt"),
            output: d.join("x.lphy"),
            password: secret("gui parola 1234"),
            confirm: Some(secret("gui parola 1234")),
            kdf_mib: 64,
            aes: false,
            pad: true,
            allow_cloud: false,
        };
        run(job).unwrap();
        assert_eq!(detect_mode(&d.join("x.lphy")), Mode::Decrypt);
        assert_eq!(
            default_output(&d.join("x.lphy"), Mode::Decrypt),
            d.join("x")
        );
        let job = Job {
            mode: Mode::Decrypt,
            input: d.join("x.lphy"),
            output: d.join("geri.txt"),
            password: secret("gui parola 1234"),
            confirm: None,
            kdf_mib: 0,
            aes: false,
            pad: true,
            allow_cloud: false,
        };
        let out = run(job).unwrap();
        assert_eq!(out.output, d.join("geri.txt"));
        assert_eq!(out.skipped, 0);
        assert_eq!(std::fs::read(d.join("geri.txt")).unwrap(), b"hello");
        // Uyuşmayan tekrar ve kısa parola
        for (p, c) in [("gui parola 1234", "başka parola 99"), ("kisa", "kisa")] {
            let job = Job {
                mode: Mode::Encrypt,
                input: d.join("a.txt"),
                output: d.join("y.lphy"),
                password: secret(p),
                confirm: Some(secret(c)),
                kdf_mib: 64,
                aes: true,
                pad: false,
                allow_cloud: false,
            };
            let e = run(job).unwrap_err();
            assert_eq!(e.exit_code(), ExitCode::Io);
            assert!(describe_error(&e).ends_with('.'));
        }
        // Yanlış parola → kod 3
        let job = Job {
            mode: Mode::Decrypt,
            input: d.join("x.lphy"),
            output: d.join("z.txt"),
            password: secret("yanlış parola 1"),
            confirm: None,
            kdf_mib: 0,
            aes: false,
            pad: true,
            allow_cloud: false,
        };
        let e = run(job).unwrap_err();
        assert_eq!(e.exit_code(), ExitCode::WrongPassword);
        assert!(describe_error(&e).starts_with("Parola yanlış"));
        let _ = std::fs::remove_dir_all(&d);
    }

    #[test]
    fn sizes_and_sentences() {
        assert_eq!(human_size(0), "0 bayt");
        assert_eq!(human_size(999), "999 bayt");
        assert_eq!(human_size(2_400_000), "2,4 MB");
        assert_eq!(human_size(54_000_000_000), "54 GB");
        assert_eq!(sentence("hedef var"), "Hedef var.");
        assert_eq!(sentence("İşlem bitti."), "İşlem bitti.");
    }
}
