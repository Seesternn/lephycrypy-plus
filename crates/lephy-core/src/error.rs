//! Error types ↔ exit codes.

use std::fmt;

/// Process exit code. The table is normative; code 2 is produced only by clap.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(i32)]
pub enum ExitCode {
    /// Success.
    Ok = 0,
    /// I/O, environment or general error.
    Io = 1,
    /// Usage error — clap only. The core never produces this code.
    Usage = 2,
    /// Wrong password, key file or identity; key-file flag mismatch.
    WrongPassword = 3,
    /// Damaged file / format violation / entry skipped with `--strict`.
    Corrupt = 4,
    /// Cancelled by the user: confirmation refused or mismatched, target device changed, no cloud-folder consent.
    Cancelled = 5,
    /// KDF budget / RAM insufficient (`--allow-large-kdf` needed).
    KdfBudget = 6,
    /// Destination exists (`--force` needed).
    Exists = 7,
    /// Disk space / FAT32 4 GiB limit.
    DiskSpace = 8,
    /// SIGINT/SIGTERM/Ctrl+C — 130 on every platform.
    Interrupted = 130,
}

impl ExitCode {
    /// Numeric value.
    #[must_use]
    pub const fn code(self) -> i32 {
        self as i32
    }
}

/// Core error type. Messages are the text shown to the user; the detailed cause only with
/// `--verbose` (`Error::detail`).
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// I/O error (code 1).
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
    /// Environment/policy error (code 1): stdin is a TTY, stdin used twice, output inside the source tree, etc.
    #[error("{0}")]
    Environment(String),
    /// Wrong password or key file (code 3). One fixed message; a `commit_tag` mismatch.
    #[error("Wrong password or key file")]
    WrongPassword,
    /// The file needs a key file but none was given (code 3, before key derivation).
    #[error("This file needs a key file")]
    KeyfileRequired,
    /// The file does not use a key file but one was given (code 3, before key derivation).
    #[error("This file does not use a key file")]
    KeyfileNotUsed,
    /// The file is encrypted to public keys and no identity was given (code 3).
    #[error("This file is encrypted to a public key; an identity file is needed (--identity)")]
    IdentityRequired,
    /// The file uses a password; an identity was given (code 3).
    #[error("This file is encrypted with a password; no identity file is used")]
    IdentityNotUsed,
    /// No recipient stanza is for the given identity (code 3).
    #[error("This file is not encrypted for this identity")]
    NoMatchingIdentity,
    /// Damaged file (code 4). `at` = "header" or `chunk N`.
    #[error("The file is damaged ({at})")]
    Corrupt {
        /// Location: `"header"` or `"chunk N"`.
        at: String,
        /// Detail shown only with `--verbose`.
        detail: Option<String>,
    },
    /// Cancelled by the user (code 5).
    #[error("Cancelled: {0}")]
    Cancelled(String),
    /// KDF budget / RAM (code 6).
    #[error("The KDF parameters exceed the budget: {0} (override with --allow-large-kdf)")]
    KdfBudget(String),
    /// Destination exists (code 7).
    #[error("The destination already exists: {0} (--force overwrites it)")]
    Exists(String),
    /// Disk space / FAT32 (code 8).
    #[error("Not enough disk space or FAT32 4 GiB limit: {0}")]
    DiskSpace(String),
    /// Interruption (code 130).
    #[error("Interrupted")]
    Interrupted,
}

impl Error {
    /// The error's exit code.
    #[must_use]
    pub const fn exit_code(&self) -> ExitCode {
        match self {
            Error::Io(_) | Error::Environment(_) => ExitCode::Io,
            Error::WrongPassword
            | Error::KeyfileRequired
            | Error::KeyfileNotUsed
            | Error::IdentityRequired
            | Error::IdentityNotUsed
            | Error::NoMatchingIdentity => ExitCode::WrongPassword,
            Error::Corrupt { .. } => ExitCode::Corrupt,
            Error::Cancelled(_) => ExitCode::Cancelled,
            Error::KdfBudget(_) => ExitCode::KdfBudget,
            Error::Exists(_) => ExitCode::Exists,
            Error::DiskSpace(_) => ExitCode::DiskSpace,
            Error::Interrupted => ExitCode::Interrupted,
        }
    }

    /// `--verbose` detail; contains no secrets.
    #[must_use]
    pub fn detail(&self) -> Option<&str> {
        match self {
            Error::Corrupt { detail, .. } => detail.as_deref(),
            _ => None,
        }
    }
}

/// Core result type.
pub type Result<T> = std::result::Result<T, Error>;

/// A format violation carried inside an `io::Error` from `Write`/`Read` adapters (PADMÉ, archive);
/// [`Error::from_io`] turns it into code 4.
#[derive(Debug)]
pub struct FormatViolation {
    /// Location (`"archive"`, `"PADMÉ"` …).
    pub at: String,
    /// Detail.
    pub detail: String,
}

impl fmt::Display for FormatViolation {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}: {}", self.at, self.detail)
    }
}

impl std::error::Error for FormatViolation {}

impl FormatViolation {
    /// A violation wrapped in `io::Error(InvalidData)`.
    #[must_use]
    pub fn io(detail: &str) -> std::io::Error {
        std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            FormatViolation {
                at: "data".into(),
                detail: detail.into(),
            },
        )
    }

    /// With an `at`.
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

    /// Whether this `io::Error` is a format violation.
    #[must_use]
    pub fn is(e: &std::io::Error) -> bool {
        matches!(e.get_ref(), Some(inner) if inner.is::<FormatViolation>())
    }
}

/// Policy violation (`--strict`: skipped or changed entry) — code 4; environment-caused ones
/// (privileges) are `Environment`, code 1.
#[derive(Debug)]
pub struct StrictViolation(pub String);

impl fmt::Display for StrictViolation {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "--strict: {}", self.0)
    }
}

impl std::error::Error for StrictViolation {}

impl Error {
    /// `io::Error` → `Corrupt` (if it carries a format violation), `Interrupted` or `Io`.
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
                    at: "archive".into(),
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
            "Wrong password or key file"
        );
    }

    #[test]
    fn corrupt_message_hides_detail() {
        let e = Error::Corrupt {
            at: "chunk 7".into(),
            detail: Some("tag mismatch".into()),
        };
        assert_eq!(e.to_string(), "The file is damaged (chunk 7)");
        assert_eq!(e.detail(), Some("tag mismatch"));
        assert_eq!(e.exit_code(), ExitCode::Corrupt);
    }
}
