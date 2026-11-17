//! Arayüz dili (Türkçe / İngilizce). Her metin `tr("…", "…")` ile iki dilde yazılır; iki
//! argüman da zorunlu olduğundan eksik çeviri derlenmez. Dil sistemden algılanır, arayüzden
//! değiştirilebilir (kalıcı değildir: uygulama ayar saklamaz).

use std::sync::atomic::{AtomicU8, Ordering};

/// Arayüz dili.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Lang {
    /// Türkçe.
    Tr,
    /// İngilizce.
    En,
}

static LANG: AtomicU8 = AtomicU8::new(0);

/// Etkin dil.
#[must_use]
pub fn lang() -> Lang {
    if LANG.load(Ordering::Relaxed) == 1 {
        Lang::En
    } else {
        Lang::Tr
    }
}

/// Dili değiştirir.
pub fn set_lang(l: Lang) {
    LANG.store(u8::from(l == Lang::En), Ordering::Relaxed);
}

/// Sistem dilinden: Türkçe ya da bilinmiyorsa Türkçe, diğer her dilde İngilizce.
#[must_use]
pub fn detect() -> Lang {
    match lephy_sys::locale::preferred_language().as_deref() {
        Some("tr") | None => Lang::Tr,
        Some(_) => Lang::En,
    }
}

/// Verilen dile göre metin.
#[must_use]
pub const fn pick(l: Lang, tr: &'static str, en: &'static str) -> &'static str {
    match l {
        Lang::Tr => tr,
        Lang::En => en,
    }
}

/// Etkin dile göre metin.
#[must_use]
pub fn tr(tr: &'static str, en: &'static str) -> &'static str {
    pick(lang(), tr, en)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn picks_by_language() {
        // Global dil değiştirilmez: paralel testler Türkçe metin bekler.
        assert_eq!(pick(Lang::En, "Şifrele", "Encrypt"), "Encrypt");
        assert_eq!(pick(Lang::Tr, "Şifrele", "Encrypt"), "Şifrele");
    }
}
