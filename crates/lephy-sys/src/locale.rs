//! Kullanıcının tercih ettiği arayüz dili (yalnızca dil kodu, ör. "tr", "en").
//!
//! macOS: `CFLocaleCopyPreferredLanguages` listesinin ilk öğesi. Windows:
//! `GetUserDefaultUILanguage` birincil dil kimliği. Diğer platformlar: `None`. Ortam değişkeni
//! okunmaz.

/// Tercih edilen dilin küçük harfli ISO 639-1 kodu; bilinmiyorsa `None`.
#[must_use]
pub fn preferred_language() -> Option<String> {
    imp::preferred_language()
}

#[cfg(target_os = "macos")]
mod imp {
    use core::ffi::{c_char, c_void};

    type CFIndex = isize;

    #[link(name = "CoreFoundation", kind = "framework")]
    unsafe extern "C" {
        fn CFLocaleCopyPreferredLanguages() -> *const c_void;
        fn CFArrayGetCount(array: *const c_void) -> CFIndex;
        fn CFArrayGetValueAtIndex(array: *const c_void, idx: CFIndex) -> *const c_void;
        fn CFStringGetCString(
            s: *const c_void,
            buf: *mut c_char,
            len: CFIndex,
            encoding: u32,
        ) -> u8;
        fn CFRelease(cf: *const c_void);
    }

    const K_CF_STRING_ENCODING_UTF8: u32 = 0x0800_0100;

    pub(super) fn preferred_language() -> Option<String> {
        // SAFETY: argümansız; sahiplik bizdedir (Copy kuralı), aşağıda CFRelease ile bırakılır.
        let arr = unsafe { CFLocaleCopyPreferredLanguages() };
        if arr.is_null() {
            return None;
        }
        let out = first_code(arr);
        // SAFETY: `arr` yukarıdaki Copy çağrısından gelen, henüz bırakılmamış geçerli nesne.
        unsafe { CFRelease(arr) };
        out
    }

    fn first_code(arr: *const c_void) -> Option<String> {
        // SAFETY: `arr` geçerli bir CFArray.
        if unsafe { CFArrayGetCount(arr) } < 1 {
            return None;
        }
        // SAFETY: indeks 0 < sayı; dönen değer dizinin sahipliğindedir (Get kuralı), bırakılmaz.
        let s = unsafe { CFArrayGetValueAtIndex(arr, 0) };
        if s.is_null() {
            return None;
        }
        let mut buf = [0 as c_char; 64];
        let len = CFIndex::try_from(buf.len()).ok()?;
        // SAFETY: `s` geçerli bir CFString; `buf` `len` baytlık yazılabilir tampon.
        let ok = unsafe { CFStringGetCString(s, buf.as_mut_ptr(), len, K_CF_STRING_ENCODING_UTF8) };
        if ok == 0 {
            return None;
        }
        let bytes: Vec<u8> = buf
            .iter()
            .take_while(|&&c| c != 0)
            .map(|&c| c.to_ne_bytes()[0])
            .collect();
        let tag = String::from_utf8(bytes).ok()?;
        let code: String = tag
            .split(['-', '_'])
            .next()?
            .chars()
            .filter(char::is_ascii_alphabetic)
            .collect::<String>()
            .to_ascii_lowercase();
        (!code.is_empty()).then_some(code)
    }
}

#[cfg(windows)]
mod imp {
    use windows_sys::Win32::Globalization::GetUserDefaultUILanguage;

    pub(super) fn preferred_language() -> Option<String> {
        // SAFETY: argümansız Win32 çağrısı; LANGID döner.
        let id = unsafe { GetUserDefaultUILanguage() };
        let code = match id & 0x3ff {
            0x1f => "tr",
            0x09 => "en",
            0x07 => "de",
            0x0c => "fr",
            0x0a => "es",
            _ => return None,
        };
        Some(code.to_string())
    }
}

#[cfg(not(any(target_os = "macos", windows)))]
mod imp {
    pub(super) const fn preferred_language() -> Option<String> {
        None
    }
}

#[cfg(test)]
mod tests {
    #[cfg_attr(miri, ignore = "FFI; Miri'de çalışmaz")]
    #[test]
    fn language_code_is_lowercase_letters() {
        if let Some(c) = super::preferred_language() {
            assert!(
                !c.is_empty() && c.chars().all(|ch| ch.is_ascii_lowercase()),
                "{c}"
            );
        }
    }
}
