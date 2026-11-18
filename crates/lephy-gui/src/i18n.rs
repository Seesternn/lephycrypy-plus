//! UI language (Turkish / English). Every text is written in both languages with `tr("…", "…")`;
//! both arguments are required, so a missing translation does not compile. The language is detected
//! from the system and can be changed in the UI (not persisted: the app stores no settings).

use std::sync::atomic::{AtomicU8, Ordering};

/// UI language.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Lang {
    /// Turkish.
    Tr,
    /// English.
    En,
}

static LANG: AtomicU8 = AtomicU8::new(0);

/// Active language.
#[must_use]
pub fn lang() -> Lang {
    if LANG.load(Ordering::Relaxed) == 1 {
        Lang::En
    } else {
        Lang::Tr
    }
}

/// Changes the language.
pub fn set_lang(l: Lang) {
    LANG.store(u8::from(l == Lang::En), Ordering::Relaxed);
}

/// From the system language: Turkish if Turkish or unknown, English for every other language.
#[must_use]
pub fn detect() -> Lang {
    match lephy_sys::locale::preferred_language().as_deref() {
        Some("tr") | None => Lang::Tr,
        Some(_) => Lang::En,
    }
}

/// Text for the given language.
#[must_use]
pub const fn pick(l: Lang, tr: &'static str, en: &'static str) -> &'static str {
    match l {
        Lang::Tr => tr,
        Lang::En => en,
    }
}

/// Text for the active language.
#[must_use]
pub fn tr(tr: &'static str, en: &'static str) -> &'static str {
    pick(lang(), tr, en)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn picks_by_language() {
        // The global language is not changed: parallel tests expect Turkish text.
        assert_eq!(pick(Lang::En, "Şifrele", "Encrypt"), "Encrypt");
        assert_eq!(pick(Lang::Tr, "Şifrele", "Encrypt"), "Şifrele");
    }
}
