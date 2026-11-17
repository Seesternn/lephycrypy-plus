//! Arayüzden bağımsız mantık: mod tespiti, varsayılan çıktı yolu, arka plan işi.
//! Yollar argv'ye gitmez (THREAT-MODEL › açık meta veri): GUI argümansız başlar, kaynak
//! sürükle-bırak ya da metin alanıyla gelir.

use std::path::{Path, PathBuf};

use lephy_core::cipher::AlgId;
use lephy_core::entropy::{Entropy, OsEntropy};
use lephy_core::error::{Error, Result};
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

/// İşi yürütür; kullanıcıya gösterilecek başarı metni.
///
/// # Errors
/// Çekirdek hataları (mesajı ve çıkış kodu kategorisi arayüzde gösterilir).
pub fn run(job: Job) -> Result<String> {
    lephy_sys::signal::reset_interrupted();
    let nfc = password::normalize_nfc(&job.password)?;
    drop(job.password);
    let mut log = |_: &str| {};
    match job.mode {
        Mode::Encrypt => {
            let confirm = job
                .confirm
                .ok_or_else(|| Error::Environment("parola tekrarı gerekli".into()))?;
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
            let skipped = rep.archive.as_ref().map_or(0, |a| a.skipped.len());
            Ok(format!(
                "Şifrelendi → {}{}",
                lephy_core::names::escape_display(&job.output.display().to_string()),
                if skipped > 0 {
                    format!(" ({skipped} giriş atlandı)")
                } else {
                    String::new()
                }
            ))
        }
        Mode::Decrypt => {
            if !job.allow_cloud && lephy_sys::fs::cloud_root_of(&job.output).is_some() {
                return Err(Error::Cancelled(
                    "hedef bir bulut senkron klasöründe; onay kutusunu işaretleyin".into(),
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
            let skipped = rep.archive.as_ref().map_or(0, |a| a.skipped.len());
            Ok(format!(
                "Çözüldü → {}{}",
                lephy_core::names::escape_display(&rep.target.display().to_string()),
                if skipped > 0 {
                    format!(" ({skipped} giriş atlandı; symlink'ler kurulmaz)")
                } else {
                    String::new()
                }
            ))
        }
    }
}

/// Hata metni + çıkış kodu kategorisi (CLI ile aynı tablo).
#[must_use]
pub fn describe_error(e: &Error) -> String {
    format!("{e} (kod {})", e.exit_code().code())
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
        let msg = run(job).unwrap();
        assert!(msg.starts_with("Çözüldü"));
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
            assert!(describe_error(&e).contains("kod 1"));
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
        assert!(describe_error(&run(job).unwrap_err()).contains("kod 3"));
        let _ = std::fs::remove_dir_all(&d);
    }
}
