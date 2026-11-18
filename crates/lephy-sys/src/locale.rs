//! The user's preferred UI language (language code only, e.g. "tr", "en").
//!
//! macOS: the first item of `CFLocaleCopyPreferredLanguages`. Windows: the primary language of
//! `GetUserDefaultUILanguage`. Other platforms: `None`. Environment variables are not read.

/// Lowercase ISO 639-1 code of the preferred language; `None` if unknown.
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
        // SAFETY: no arguments; we own the result (Copy rule) and release it with CFRelease below.
        let arr = unsafe { CFLocaleCopyPreferredLanguages() };
        if arr.is_null() {
            return None;
        }
        let out = first_code(arr);
        // SAFETY: `arr` is the valid object from the Copy call above, not yet released.
        unsafe { CFRelease(arr) };
        out
    }

    fn first_code(arr: *const c_void) -> Option<String> {
        // SAFETY: `arr` is a valid CFArray.
        if unsafe { CFArrayGetCount(arr) } < 1 {
            return None;
        }
        // SAFETY: index 0 < count; the returned value is owned by the array (Get rule), not released.
        let s = unsafe { CFArrayGetValueAtIndex(arr, 0) };
        if s.is_null() {
            return None;
        }
        let mut buf = [0 as c_char; 64];
        let len = CFIndex::try_from(buf.len()).ok()?;
        // SAFETY: `s` is a valid CFString; `buf` is a writable buffer of `len` bytes.
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
        // SAFETY: Win32 call without arguments; returns a LANGID.
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
    #[cfg_attr(miri, ignore = "FFI; does not run under Miri")]
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
