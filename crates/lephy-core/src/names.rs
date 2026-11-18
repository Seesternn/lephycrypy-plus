//! Name handling (FORMAT.md › Archive limits).
//!
//! - Archive path: UTF-8, NFC, `/` separator; `..`, empty components, a leading `/`, `\`, NUL and
//!   drive letters are forbidden; component ≤ 255 B, path ≤ 4096 B, depth ≤ 256.
//! - Case folding is an **early warning**; the file system is the authority (`create_new`).
//!   Folding uses `char::to_lowercase` (full Unicode lowercase mapping); the difference from
//!   CaseFolding.txt C+S is small special cases (ß, final sigma) and only affects the warning
//!   (UNVERIFIED: full equivalence). U+0130/U+0131 are left to the file system.
//! - Windows name rules: `: * ? " < > |`, control characters, trailing dot/space,
//!   reserved names (CON PRN AUX NUL COM1–9 LPT1–9 COM¹²³ CONIN$ CONOUT$), ADS → `_`.
//! - Display escaping: control, ANSI, bidi and format characters as `\u{…}`.
//! - Symlink target classification: **unsafe** if it starts with `/`, contains `\`, starts with
//!   `[A-Za-z]:` or has a `..` component.

use std::path::{Component, Path};

use unicode_normalization::UnicodeNormalization;

use crate::error::{Error, Result};

/// Component upper limit (bytes).
pub const MAX_COMPONENT: usize = 255;
/// Path upper limit (bytes).
pub const MAX_PATH: usize = 4096;
/// Depth upper limit.
pub const MAX_DEPTH: usize = 256;
/// Upper limit for the number of entries.
pub const MAX_ENTRIES: usize = 1_000_000;
/// Upper limit for total path bytes (including symlink targets).
pub const MAX_TOTAL_PATH_BYTES: u64 = 64 * 1024 * 1024;
/// Symlink target upper limit.
pub const MAX_SYMLINK_TARGET: usize = 4096;
/// Frame upper limit.
pub const MAX_FRAME: usize = 16 * 1024 * 1024;
/// mtime range.
pub const MAX_MTIME_ABS: i64 = 1 << 40;

fn bad(detail: &str) -> Error {
    Error::Corrupt {
        at: "archive".into(),
        detail: Some(detail.into()),
    }
}

/// Validates a path read from an archive (FORMAT.md limits). Returns the validated `&str`.
///
/// # Errors
/// Code 4.
pub fn validate_archive_path(path: &[u8]) -> Result<&str> {
    if path.is_empty() {
        return Err(bad("empty path"));
    }
    if path.len() > MAX_PATH {
        return Err(bad("path > 4096 B"));
    }
    if path.contains(&0) {
        return Err(bad("yolda NUL"));
    }
    if path.contains(&b'\\') {
        return Err(bad("backslash in path"));
    }
    let s = std::str::from_utf8(path).map_err(|_| bad("path is not UTF-8"))?;
    if s.starts_with('/') {
        return Err(bad("absolute path"));
    }
    let mut depth = 0;
    for comp in s.split('/') {
        depth += 1;
        if comp.is_empty() {
            return Err(bad("empty component"));
        }
        if comp == "." || comp == ".." {
            return Err(bad("`.`/`..` component"));
        }
        if comp.len() > MAX_COMPONENT {
            return Err(bad("component > 255 B"));
        }
    }
    if depth > MAX_DEPTH {
        return Err(bad("depth > 256"));
    }
    if is_drive_prefixed(s) {
        return Err(bad("drive letter"));
    }
    // NFC requirement: the writer writes NFC; the reader tolerates non-NFC, but the duplicate
    // check uses NFC + folding.
    Ok(s)
}

fn is_drive_prefixed(s: &str) -> bool {
    let b = s.as_bytes();
    b.len() >= 2 && b[0].is_ascii_alphabetic() && b[1] == b':'
}

/// Duplicate-path key: the first 16 B of `BLAKE3(NFC + lowercase)`.
#[must_use]
pub fn fold_key(path: &str) -> [u8; 16] {
    let folded: String = path.nfc().flat_map(char::to_lowercase).collect();
    let h = blake3::hash(folded.as_bytes());
    let mut k = [0u8; 16];
    k.copy_from_slice(&h.as_bytes()[..16]);
    k
}

/// Converts a relative path from the source file system to an archive path: NFC components, `/`
/// separator (Windows `\` → `/`).
///
/// # Errors
/// Invalid component (not UTF-8, `..`, absolute) → code 1.
pub fn to_archive_path(rel: &Path) -> Result<String> {
    let mut out = String::new();
    for c in rel.components() {
        match c {
            Component::Normal(os) => {
                let s = os.to_str().ok_or_else(|| {
                    Error::Environment(format!("name is not UTF-8: {}", rel.display()))
                })?;
                if !out.is_empty() {
                    out.push('/');
                }
                out.extend(s.nfc());
            }
            Component::CurDir => {}
            _ => {
                return Err(Error::Environment(format!(
                    "path component cannot be archived: {}",
                    rel.display()
                )));
            }
        }
    }
    if out.is_empty() {
        return Err(Error::Environment("empty archive path".into()));
    }
    validate_archive_path(out.as_bytes()).map_err(|e| Error::Environment(e.to_string()))?;
    Ok(out)
}

/// Replaces an invalid/reserved Windows name component with `_`; returns `(new, changed)`.
#[must_use]
pub fn windows_sanitize(component: &str) -> (String, bool) {
    let mut s: String = component
        .chars()
        .map(|c| {
            if matches!(c, ':' | '*' | '?' | '"' | '<' | '>' | '|') || c.is_control() {
                '_'
            } else {
                c
            }
        })
        .collect();
    let trimmed_len = s.trim_end_matches([' ', '.']).len();
    if trimmed_len != s.len() {
        let n = s.len() - trimmed_len;
        s.truncate(trimmed_len);
        s.extend(std::iter::repeat_n('_', n));
    }
    let stem = s.split('.').next().unwrap_or("").to_ascii_uppercase();
    let reserved = matches!(
        stem.as_str(),
        "CON" | "PRN" | "AUX" | "NUL" | "CONIN$" | "CONOUT$"
    ) || ((stem.starts_with("COM") || stem.starts_with("LPT"))
        && stem.len() == 4
        && (stem.as_bytes()[3].is_ascii_digit() && stem.as_bytes()[3] != b'0'))
        || (stem.starts_with("COM")
            && matches!(
                stem.chars().nth(3),
                Some('\u{00B9}' | '\u{00B2}' | '\u{00B3}')
            )
            && stem.chars().count() == 4);
    if reserved {
        s.insert(0, '_');
    }
    let changed = s != component;
    (s, changed)
}

/// Display escaping: control, ANSI (`\x1b`), bidi (U+202A–202E, U+2066–2069),
/// zero-width/format characters as `\u{…}`.
#[must_use]
pub fn escape_display(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        let cp = c as u32;
        let bidi = (0x202A..=0x202E).contains(&cp) || (0x2066..=0x2069).contains(&cp);
        let fmt = (0x200B..=0x200F).contains(&cp) || cp == 0xFEFF || cp == 0x00AD;
        if c.is_control() || bidi || fmt {
            use std::fmt::Write as _;
            let _ = write!(out, "\\u{{{cp:x}}}");
        } else {
            out.push(c);
        }
    }
    out
}

/// Symlink target class.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SymlinkClass {
    /// Relative, downward only.
    Safe,
    /// Absolute, or contains `..`, `\` or a drive letter.
    Unsafe,
}

/// Classifies the target.
#[must_use]
pub fn classify_symlink_target(target: &[u8]) -> SymlinkClass {
    if target.first() == Some(&b'/') || target.contains(&b'\\') {
        return SymlinkClass::Unsafe;
    }
    if target.len() >= 2 && target[0].is_ascii_alphabetic() && target[1] == b':' {
        return SymlinkClass::Unsafe;
    }
    if target.split(|&b| b == b'/').any(|c| c == b"..") {
        return SymlinkClass::Unsafe;
    }
    SymlinkClass::Safe
}

/// Format check of a symlink target (1..=4096 B, no NUL).
///
/// # Errors
/// Code 4.
pub fn validate_symlink_target(target: &[u8]) -> Result<()> {
    if target.is_empty() || target.len() > MAX_SYMLINK_TARGET {
        return Err(bad("symlink target must be 1..=4096 B"));
    }
    if target.contains(&0) {
        return Err(bad("NUL in symlink target"));
    }
    Ok(())
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::panic)]
mod tests {
    use super::*;

    #[test]
    fn path_rules() {
        assert!(validate_archive_path(b"a/b/c.txt").is_ok());
        for bad in [
            &b""[..],
            b"/abs",
            b"a//b",
            b"a/../b",
            b"..",
            b"a\\b",
            b"C:x",
            b"a\0b",
            b"a/",
        ] {
            assert!(validate_archive_path(bad).is_err(), "{bad:?}");
        }
        let long = vec![b'a'; 256];
        assert!(validate_archive_path(&long).is_err());
        let deep: Vec<u8> = std::iter::repeat_n(b"a/", 257)
            .flatten()
            .copied()
            .chain(*b"z")
            .collect();
        assert!(validate_archive_path(&deep).is_err());
        let ok_deep: Vec<u8> = std::iter::repeat_n(b"a/", 255)
            .flatten()
            .copied()
            .chain(*b"z")
            .collect();
        assert!(validate_archive_path(&ok_deep).is_ok());
    }

    #[test]
    fn fold_key_detects_case_and_nfc_duplicates() {
        assert_eq!(fold_key("a.txt"), fold_key("A.TXT"));
        assert_eq!(fold_key("ş"), fold_key("s\u{0327}"));
        assert_ne!(fold_key("a.txt"), fold_key("b.txt"));
        // U+0130: std lowercase is 'i̇' (i + U+0307); it does not collide with 'i' → left to the file system.
        assert_ne!(fold_key("İ.txt"), fold_key("i.txt"));
    }

    #[test]
    fn windows_names() {
        assert_eq!(windows_sanitize("a:b*c").0, "a_b_c");
        assert_eq!(windows_sanitize("con").0, "_con");
        assert_eq!(windows_sanitize("CON.txt").0, "_CON.txt");
        assert_eq!(windows_sanitize("COM1").0, "_COM1");
        assert_eq!(windows_sanitize("COM0").0, "COM0");
        assert_eq!(windows_sanitize("COM\u{00B9}").0, "_COM\u{00B9}");
        assert_eq!(windows_sanitize("LPT9.log").0, "_LPT9.log");
        assert_eq!(windows_sanitize("CONOUT$").0, "_CONOUT$");
        assert_eq!(windows_sanitize("trail. ").0, "trail__");
        assert_eq!(windows_sanitize("normal.txt"), ("normal.txt".into(), false));
        assert_eq!(windows_sanitize("ads.txt:stream").0, "ads.txt_stream");
    }

    #[test]
    fn escape() {
        assert_eq!(
            escape_display("a\x1b[31mb\u{202e}c\u{200b}"),
            "a\\u{1b}[31mb\\u{202e}c\\u{200b}"
        );
        assert_eq!(escape_display("ş ğ"), "ş ğ");
    }

    #[test]
    fn symlink_classes() {
        assert_eq!(classify_symlink_target(b"a/b"), SymlinkClass::Safe);
        for u in [&b"/etc/passwd"[..], b"../x", b"a/../../x", b"C:x", b"\\x"] {
            assert_eq!(classify_symlink_target(u), SymlinkClass::Unsafe, "{u:?}");
        }
        assert!(validate_symlink_target(&[b'a'; 4097]).is_err());
        assert!(validate_symlink_target(&[b'a'; 4096]).is_ok());
        assert!(validate_symlink_target(b"").is_err());
    }

    #[test]
    fn to_archive_path_nfc_and_rejects() {
        assert_eq!(to_archive_path(Path::new("s\u{0327}/x")).unwrap(), "ş/x");
        assert!(to_archive_path(Path::new("../x")).is_err());
        assert!(to_archive_path(Path::new("/abs")).is_err());
    }
}
