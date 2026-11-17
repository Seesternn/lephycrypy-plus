//! Hata türleri ↔ çıkış kodları (PLAN › Çıkış kodu tablosu; R4-O3, R5-10).

use std::fmt;

/// Süreç çıkış kodu. Tablo normatiftir; kod 2 yalnızca clap tarafından üretilir.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(i32)]
pub enum ExitCode {
    /// Başarı.
    Ok = 0,
    /// G/Ç, ortam veya genel hata.
    Io = 1,
    /// Kullanım hatası — yalnızca clap. Çekirdek bu kodu üretmez.
    Usage = 2,
    /// Parola veya anahtar dosyası yanlış; keyfile bayrak uyuşmazlığı.
    WrongPassword = 3,
    /// Dosya bozuk / biçim ihlali / `--strict` ile atlanan giriş.
    Corrupt = 4,
    /// Kullanıcı iptali: onay reddi, onay uyuşmazlığı, hedef aygıt değişti, bulut dizini onayı yok.
    Cancelled = 5,
    /// KDF bütçesi/RAM yetersiz (`--allow-large-kdf` gerekli).
    KdfBudget = 6,
    /// Hedef mevcut (`--force` gerekli).
    Exists = 7,
    /// Disk alanı / FAT32 4 GiB sınırı.
    DiskSpace = 8,
    /// SIGINT/SIGTERM/Ctrl+C — tüm platformlarda 130.
    Interrupted = 130,
}

impl ExitCode {
    /// Sayısal değer.
    #[must_use]
    pub const fn code(self) -> i32 {
        self as i32
    }
}

/// Çekirdek hata türü. Mesajlar kullanıcıya gösterilen metindir; ayrıntılı neden yalnızca
/// `--verbose` ile (`Error::detail`).
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// G/Ç hatası (kod 1).
    #[error("G/Ç hatası: {0}")]
    Io(#[from] std::io::Error),
    /// Ortam/politika hatası (kod 1): stdin TTY, stdin çifte kullanım, çıktı kaynak ağacında, vb.
    #[error("{0}")]
    Environment(String),
    /// Parola veya anahtar dosyası yanlış (kod 3). Tek sabit mesaj; `commit_tag` uyuşmazlığı.
    #[error("Parola veya anahtar dosyası yanlış")]
    WrongPassword,
    /// Dosya anahtar dosyası gerektiriyor ama verilmedi (kod 3, KDF çalışmadan).
    #[error("Bu dosya anahtar dosyası gerektiriyor")]
    KeyfileRequired,
    /// Dosya anahtar dosyası kullanmıyor ama verildi (kod 3, KDF çalışmadan).
    #[error("Bu dosya anahtar dosyası kullanmıyor")]
    KeyfileNotUsed,
    /// Dosya bozuk (kod 4). `at` = "başlık" ya da `chunk N`.
    #[error("Dosya bozuk ({at})")]
    Corrupt {
        /// Konum: `"başlık"` veya `"chunk N"`.
        at: String,
        /// Yalnızca `--verbose` ile gösterilen ayrıntı.
        detail: Option<String>,
    },
    /// Kullanıcı iptali (kod 5).
    #[error("İptal edildi: {0}")]
    Cancelled(String),
    /// KDF bütçesi/RAM (kod 6).
    #[error("KDF parametreleri bütçeyi aşıyor: {0} (--allow-large-kdf ile geçilebilir)")]
    KdfBudget(String),
    /// Hedef mevcut (kod 7).
    #[error("Hedef zaten var: {0} (--force ile üzerine yazılır)")]
    Exists(String),
    /// Disk alanı / FAT32 (kod 8).
    #[error("Disk alanı yetersiz veya FAT32 4 GiB sınırı: {0}")]
    DiskSpace(String),
    /// Kesinti (kod 130).
    #[error("Kesildi")]
    Interrupted,
}

impl Error {
    /// Hatanın çıkış kodu.
    #[must_use]
    pub const fn exit_code(&self) -> ExitCode {
        match self {
            Error::Io(_) | Error::Environment(_) => ExitCode::Io,
            Error::WrongPassword | Error::KeyfileRequired | Error::KeyfileNotUsed => {
                ExitCode::WrongPassword
            }
            Error::Corrupt { .. } => ExitCode::Corrupt,
            Error::Cancelled(_) => ExitCode::Cancelled,
            Error::KdfBudget(_) => ExitCode::KdfBudget,
            Error::Exists(_) => ExitCode::Exists,
            Error::DiskSpace(_) => ExitCode::DiskSpace,
            Error::Interrupted => ExitCode::Interrupted,
        }
    }

    /// `--verbose` ayrıntısı; sır içermez.
    #[must_use]
    pub fn detail(&self) -> Option<&str> {
        match self {
            Error::Corrupt { detail, .. } => detail.as_deref(),
            _ => None,
        }
    }
}

/// Çekirdek sonuç türü.
pub type Result<T> = std::result::Result<T, Error>;

/// `Write`/`Read` adaptörlerinden (PADMÉ, arşiv) `io::Error` içinde taşınan biçim ihlali;
/// [`Error::from_io`] bunu kod 4'e çevirir.
#[derive(Debug)]
pub struct FormatViolation {
    /// Konum (`"arşiv"`, `"PADMÉ"` …).
    pub at: String,
    /// Ayrıntı.
    pub detail: String,
}

impl fmt::Display for FormatViolation {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}: {}", self.at, self.detail)
    }
}

impl std::error::Error for FormatViolation {}

impl FormatViolation {
    /// `io::Error(InvalidData)` içine sarılmış ihlal.
    #[must_use]
    pub fn io(detail: &str) -> std::io::Error {
        std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            FormatViolation {
                at: "veri".into(),
                detail: detail.into(),
            },
        )
    }

    /// `at` ile.
    #[must_use]
    pub fn io_at(at: &str, detail: &str) -> std::io::Error {
        std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            FormatViolation {
                at: at.into(),
                detail: detail.into(),
            },
        )
    }

    /// Bu `io::Error` bir biçim ihlali mi.
    #[must_use]
    pub fn is(e: &std::io::Error) -> bool {
        matches!(e.get_ref(), Some(inner) if inner.is::<FormatViolation>())
    }
}

/// Politika ihlali (`--strict`: atlanan/değiştirilen giriş) — kod 4; ortam kaynaklı (ayrıcalık)
/// olanlar `Environment` ile kod 1.
#[derive(Debug)]
pub struct StrictViolation(pub String);

impl fmt::Display for StrictViolation {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "--strict: {}", self.0)
    }
}

impl std::error::Error for StrictViolation {}

impl Error {
    /// `io::Error` → `Corrupt` (biçim ihlali taşıyorsa), `Interrupted` ya da `Io`.
    #[must_use]
    pub fn from_io(e: std::io::Error) -> Self {
        if let Some(inner) = e.get_ref() {
            if let Some(fv) = inner.downcast_ref::<FormatViolation>() {
                return Error::Corrupt {
                    at: fv.at.clone(),
                    detail: Some(fv.detail.clone()),
                };
            }
            if let Some(sv) = inner.downcast_ref::<StrictViolation>() {
                return Error::Corrupt {
                    at: "arşiv".into(),
                    detail: Some(sv.to_string()),
                };
            }
        }
        if e.kind() == std::io::ErrorKind::Interrupted {
            return Error::Interrupted;
        }
        Error::Io(e)
    }
}

impl fmt::Display for ExitCode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.code())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn exit_codes_match_plan_table() {
        assert_eq!(ExitCode::Ok.code(), 0);
        assert_eq!(ExitCode::Io.code(), 1);
        assert_eq!(ExitCode::Usage.code(), 2);
        assert_eq!(ExitCode::WrongPassword.code(), 3);
        assert_eq!(ExitCode::Corrupt.code(), 4);
        assert_eq!(ExitCode::Cancelled.code(), 5);
        assert_eq!(ExitCode::KdfBudget.code(), 6);
        assert_eq!(ExitCode::Exists.code(), 7);
        assert_eq!(ExitCode::DiskSpace.code(), 8);
        assert_eq!(ExitCode::Interrupted.code(), 130);
    }

    #[test]
    fn keyfile_mismatch_is_code_3_with_distinct_message() {
        assert_eq!(Error::KeyfileRequired.exit_code(), ExitCode::WrongPassword);
        assert_eq!(Error::KeyfileNotUsed.exit_code(), ExitCode::WrongPassword);
        assert_ne!(
            Error::KeyfileRequired.to_string(),
            Error::WrongPassword.to_string()
        );
        assert_eq!(
            Error::WrongPassword.to_string(),
            "Parola veya anahtar dosyası yanlış"
        );
    }

    #[test]
    fn corrupt_message_hides_detail() {
        let e = Error::Corrupt {
            at: "chunk 7".into(),
            detail: Some("tag mismatch".into()),
        };
        assert_eq!(e.to_string(), "Dosya bozuk (chunk 7)");
        assert_eq!(e.detail(), Some("tag mismatch"));
        assert_eq!(e.exit_code(), ExitCode::Corrupt);
    }
}
