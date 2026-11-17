//! Ad işleme (FORMAT.md › Arşiv sınırları).
//!
//! - Arşiv yolu: UTF-8, NFC, `/` ayırıcı; `..`, boş bileşen, `/` ile başlama, `\`, NUL, sürücü
//!   harfi yasak; bileşen ≤ 255 B, yol ≤ 4096 B, derinlik ≤ 256.
//! - Harf katlama **erken uyarıdır**; otorite dosya sistemidir (`create_new`). Katlama burada
//!   `char::to_lowercase` (Unicode tam küçük harf eşlemesi) ile yapılır; CaseFolding.txt C+S ile
//!   farkı küçük özel durumlardır (ß, son sigma) ve yalnızca uyarı kalitesini etkiler
//!   (DOĞRULANMADI: tam eşdeğerlik). U+0130/U+0131 FS'ye bırakılır.
//! - Windows ad kuralları: `: * ? " < > |`, kontrol karakterleri, sonda nokta/boşluk,
//!   ayrılmış adlar (CON PRN AUX NUL COM1–9 LPT1–9 COM¹²³ CONIN$ CONOUT$), ADS → `_`.
//! - Görüntüleme kaçışlaması: kontrol, ANSI, bidi, format karakterleri `\u{…}`.
//! - Symlink hedefi sınıflandırması: `/` ile başlıyor, `\` içeriyor, `[A-Za-z]:` ile
//!   başlıyor ya da bir bileşeni `..` ise **güvensiz**.

use std::path::{Component, Path};

use unicode_normalization::UnicodeNormalization;

use crate::error::{Error, Result};

/// Bileşen üst sınırı (bayt).
pub const MAX_COMPONENT: usize = 255;
/// Yol üst sınırı (bayt).
pub const MAX_PATH: usize = 4096;
/// Derinlik üst sınırı.
pub const MAX_DEPTH: usize = 256;
/// Giriş sayısı üst sınırı.
pub const MAX_ENTRIES: usize = 1_000_000;
/// Toplam yol baytı (symlink hedefleri dahil) üst sınırı.
pub const MAX_TOTAL_PATH_BYTES: u64 = 64 * 1024 * 1024;
/// Symlink hedefi üst sınırı.
pub const MAX_SYMLINK_TARGET: usize = 4096;
/// Çerçeve üst sınırı.
pub const MAX_FRAME: usize = 16 * 1024 * 1024;
/// mtime aralığı.
pub const MAX_MTIME_ABS: i64 = 1 << 40;

fn bad(detail: &str) -> Error {
    Error::Corrupt {
        at: "arşiv".into(),
        detail: Some(detail.into()),
    }
}

/// Arşivden okunan yolu doğrular (FORMAT.md sınırları). Döner: doğrulanmış `&str`.
///
/// # Errors
/// Kod 4.
pub fn validate_archive_path(path: &[u8]) -> Result<&str> {
    if path.is_empty() {
        return Err(bad("boş yol"));
    }
    if path.len() > MAX_PATH {
        return Err(bad("yol > 4096 B"));
    }
    if path.contains(&0) {
        return Err(bad("yolda NUL"));
    }
    if path.contains(&b'\\') {
        return Err(bad("yolda ters bölü"));
    }
    let s = std::str::from_utf8(path).map_err(|_| bad("yol UTF-8 değil"))?;
    if s.starts_with('/') {
        return Err(bad("mutlak yol"));
    }
    let mut depth = 0;
    for comp in s.split('/') {
        depth += 1;
        if comp.is_empty() {
            return Err(bad("boş bileşen"));
        }
        if comp == "." || comp == ".." {
            return Err(bad("`.`/`..` bileşeni"));
        }
        if comp.len() > MAX_COMPONENT {
            return Err(bad("bileşen > 255 B"));
        }
    }
    if depth > MAX_DEPTH {
        return Err(bad("derinlik > 256"));
    }
    if is_drive_prefixed(s) {
        return Err(bad("sürücü harfi"));
    }
    // NFC şartı: yazıcı NFC yazar; okuyucu NFC olmayanı reddetmez (tolerans), ancak yinelenen
    // denetimi NFC + katlama ile yapılır.
    Ok(s)
}

fn is_drive_prefixed(s: &str) -> bool {
    let b = s.as_bytes();
    b.len() >= 2 && b[0].is_ascii_alphabetic() && b[1] == b':'
}

/// Yinelenen-yol anahtarı: `BLAKE3(NFC + küçük harf)` ilk 16 B.
#[must_use]
pub fn fold_key(path: &str) -> [u8; 16] {
    let folded: String = path.nfc().flat_map(char::to_lowercase).collect();
    let h = blake3::hash(folded.as_bytes());
    let mut k = [0u8; 16];
    k.copy_from_slice(&h.as_bytes()[..16]);
    k
}

/// Kaynak dosya sisteminden alınan göreli yolu arşiv yoluna çevirir: bileşenler NFC, `/`
/// ayırıcı (Windows `\` → `/`).
///
/// # Errors
/// Geçersiz bileşen (UTF-8 değil, `..`, mutlak) → kod 1.
pub fn to_archive_path(rel: &Path) -> Result<String> {
    let mut out = String::new();
    for c in rel.components() {
        match c {
            Component::Normal(os) => {
                let s = os.to_str().ok_or_else(|| {
                    Error::Environment(format!("ad UTF-8 değil: {}", rel.display()))
                })?;
                if !out.is_empty() {
                    out.push('/');
                }
                out.extend(s.nfc());
            }
            Component::CurDir => {}
            _ => {
                return Err(Error::Environment(format!(
                    "arşivlenemeyen yol bileşeni: {}",
                    rel.display()
                )));
            }
        }
    }
    if out.is_empty() {
        return Err(Error::Environment("boş arşiv yolu".into()));
    }
    validate_archive_path(out.as_bytes()).map_err(|e| Error::Environment(e.to_string()))?;
    Ok(out)
}

/// Windows'ta geçersiz/ayrılmış ad bileşenini `_` ile düzeltir; `(yeni, değişti)`.
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

/// Görüntüleme kaçışlaması: kontrol, ANSI (`\x1b`), bidi (U+202A–202E, U+2066–2069),
/// zero-width/format karakterleri `\u{…}`.
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

/// Symlink hedefi sınıfı.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SymlinkClass {
    /// Göreli, yalnızca aşağı.
    Safe,
    /// Mutlak, `..`, `\` ya da sürücü harfi içeriyor.
    Unsafe,
}

/// Hedefi sınıflandırır.
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

/// Symlink hedefinin biçim denetimi (1..=4096 B, NUL yok).
///
/// # Errors
/// Kod 4.
pub fn validate_symlink_target(target: &[u8]) -> Result<()> {
    if target.is_empty() || target.len() > MAX_SYMLINK_TARGET {
        return Err(bad("symlink hedefi 1..=4096 B olmalı"));
    }
    if target.contains(&0) {
        return Err(bad("symlink hedefinde NUL"));
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
        // U+0130: std küçük harf 'i̇' (i + U+0307); 'i' ile çakışmaz → FS'ye bırakılır.
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
