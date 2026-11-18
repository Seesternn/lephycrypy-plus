//! How long the user has been away, and whether the screen is locked: used to lock an open
//! vault automatically.
//!
//! macOS: `CGEventSourceSecondsSinceLastEventType` and the session dictionary's
//! `CGSSessionScreenIsLocked`. Windows: `GetLastInputInfo`, and the input desktop cannot be
//! opened while the workstation is locked.

/// Seconds since the last keyboard or mouse input anywhere in the session (`None`: unknown).
#[must_use]
pub fn idle_seconds() -> Option<u64> {
    imp::idle_seconds()
}

/// The screen is locked (login window shown). `false` where unknown.
#[must_use]
pub fn screen_locked() -> bool {
    imp::screen_locked()
}

#[cfg(all(target_os = "macos", not(miri)))]
mod imp {
    use std::ffi::{c_char, c_void};

    type CFTypeRef = *const c_void;

    /// `kCGEventSourceStateCombinedSessionState`.
    const COMBINED_SESSION: i32 = 0;
    /// `kCGAnyInputEventType`.
    const ANY_INPUT: u32 = u32::MAX;
    /// `kCFStringEncodingUTF8`.
    const UTF8: u32 = 0x0800_0100;

    #[link(name = "CoreGraphics", kind = "framework")]
    unsafe extern "C" {
        fn CGEventSourceSecondsSinceLastEventType(state: i32, event_type: u32) -> f64;
        fn CGSessionCopyCurrentDictionary() -> CFTypeRef;
    }

    #[link(name = "CoreFoundation", kind = "framework")]
    unsafe extern "C" {
        fn CFStringCreateWithCString(alloc: CFTypeRef, s: *const c_char, enc: u32) -> CFTypeRef;
        fn CFDictionaryGetValue(dict: CFTypeRef, key: CFTypeRef) -> CFTypeRef;
        fn CFBooleanGetValue(b: CFTypeRef) -> u8;
        fn CFGetTypeID(cf: CFTypeRef) -> usize;
        fn CFBooleanGetTypeID() -> usize;
        fn CFRelease(cf: CFTypeRef);
    }

    pub(super) fn idle_seconds() -> Option<u64> {
        // SAFETY: plain C call with constant arguments; returns a double.
        let s = unsafe { CGEventSourceSecondsSinceLastEventType(COMBINED_SESSION, ANY_INPUT) };
        #[allow(
            clippy::cast_possible_truncation,
            clippy::cast_sign_loss,
            reason = "checked"
        )]
        (s.is_finite() && s >= 0.0).then_some(s as u64)
    }

    pub(super) fn screen_locked() -> bool {
        // SAFETY: returns a +1 dictionary or NULL (no window server session).
        let dict = unsafe { CGSessionCopyCurrentDictionary() };
        if dict.is_null() {
            return false;
        }
        // SAFETY: NUL-terminated ASCII key; returns a +1 string or NULL.
        let key = unsafe {
            CFStringCreateWithCString(std::ptr::null(), c"CGSSessionScreenIsLocked".as_ptr(), UTF8)
        };
        let mut locked = false;
        if !key.is_null() {
            // SAFETY: `dict` and `key` are live CF objects; the value is borrowed (not owned).
            let v = unsafe { CFDictionaryGetValue(dict, key) };
            // SAFETY: plain type-id calls on a live object / no arguments.
            let is_bool =
                !v.is_null() && unsafe { CFGetTypeID(v) } == unsafe { CFBooleanGetTypeID() };
            if is_bool {
                // SAFETY: `v` is a CFBoolean (checked above).
                locked = unsafe { CFBooleanGetValue(v) } != 0;
            }
            // SAFETY: `key` was created above and is released once.
            unsafe { CFRelease(key) };
        }
        // SAFETY: `dict` was copied above and is released once.
        unsafe { CFRelease(dict) };
        locked
    }
}

#[cfg(all(windows, not(miri)))]
mod imp {
    use windows_sys::Win32::System::StationsAndDesktops::{
        CloseDesktop, DESKTOP_SWITCHDESKTOP, OpenInputDesktop,
    };
    use windows_sys::Win32::System::SystemInformation::GetTickCount;
    use windows_sys::Win32::UI::Input::KeyboardAndMouse::{GetLastInputInfo, LASTINPUTINFO};

    pub(super) fn idle_seconds() -> Option<u64> {
        let mut li = LASTINPUTINFO {
            cbSize: u32::try_from(std::mem::size_of::<LASTINPUTINFO>()).ok()?,
            dwTime: 0,
        };
        // SAFETY: `li` is a valid LASTINPUTINFO with cbSize set.
        if unsafe { GetLastInputInfo(&raw mut li) } == 0 {
            return None;
        }
        // SAFETY: no arguments.
        let now = unsafe { GetTickCount() };
        Some(u64::from(now.wrapping_sub(li.dwTime)) / 1000)
    }

    pub(super) fn screen_locked() -> bool {
        // SAFETY: plain call; returns a desktop handle or null.
        let d = unsafe { OpenInputDesktop(0, 0, DESKTOP_SWITCHDESKTOP) };
        if d.is_null() {
            return true;
        }
        // SAFETY: `d` was opened above and is closed once.
        unsafe { CloseDesktop(d) };
        false
    }
}

#[cfg(any(miri, not(any(target_os = "macos", windows))))]
mod imp {
    pub(super) fn idle_seconds() -> Option<u64> {
        None
    }

    pub(super) fn screen_locked() -> bool {
        false
    }
}

#[cfg(test)]
mod tests {
    #[test]
    #[cfg_attr(
        any(miri, not(any(target_os = "macos", windows))),
        ignore = "idle time is known on macOS and Windows only"
    )]
    fn idle_time_is_reported() {
        // In CI there may be no input session; the call must still not fail.
        let _ = super::idle_seconds();
        let _ = super::screen_locked();
    }
}
