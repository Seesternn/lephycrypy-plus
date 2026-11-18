//! Keeps the app's windows out of screenshots, screen recordings and screen sharing while secrets
//! are on screen (paper-backup words, a generated password).
//!
//! macOS: `NSWindow.sharingType = NSWindowSharingNone`. Windows:
//! `SetWindowDisplayAffinity(WDA_EXCLUDEFROMCAPTURE)` (Windows 10 2004 and later). Neither stops
//! a camera, or malware running with administrator rights.

/// Turns protection on or off for every window of this app (call from the UI thread). Returns
/// `false` where this is not supported.
#[must_use]
pub fn set_protected(on: bool) -> bool {
    imp::set(on)
}

#[cfg(all(target_os = "macos", not(miri)))]
mod imp {
    use crate::objc::{send_id, send_id_usize, send_usize, send_void_usize, shared_app};

    /// `NSWindowSharingNone` / `NSWindowSharingReadOnly` (the default).
    const NONE: usize = 0;
    const READ_ONLY: usize = 1;

    pub(super) fn set(on: bool) -> bool {
        let windows = send_id(shared_app(), c"windows");
        if windows.is_null() {
            return false;
        }
        let n = send_usize(windows, c"count");
        for i in 0..n {
            let w = send_id_usize(windows, c"objectAtIndex:", i);
            send_void_usize(w, c"setSharingType:", if on { NONE } else { READ_ONLY });
        }
        true
    }
}

#[cfg(all(windows, not(miri)))]
mod imp {
    use windows_sys::Win32::Foundation::{HWND, LPARAM};
    use windows_sys::Win32::System::Threading::GetCurrentThreadId;
    use windows_sys::Win32::UI::WindowsAndMessaging::{
        EnumThreadWindows, SetWindowDisplayAffinity, WDA_EXCLUDEFROMCAPTURE, WDA_NONE,
    };

    /// `on` is 1 to exclude the window from capture, 0 to allow it again.
    unsafe extern "system" fn each(hwnd: HWND, on: LPARAM) -> windows_sys::core::BOOL {
        let a = if on != 0 {
            WDA_EXCLUDEFROMCAPTURE
        } else {
            WDA_NONE
        };
        // SAFETY: `hwnd` is a window of this thread handed over by EnumThreadWindows.
        unsafe { SetWindowDisplayAffinity(hwnd, a) };
        1
    }

    pub(super) fn set(on: bool) -> bool {
        let affinity = if on { WDA_EXCLUDEFROMCAPTURE } else { WDA_NONE };
        // SAFETY: no arguments; returns the calling thread's id.
        let tid = unsafe { GetCurrentThreadId() };
        // SAFETY: `each` matches WNDENUMPROC and only uses the window handle it is given; the
        // LPARAM carries a plain integer.
        unsafe { EnumThreadWindows(tid, Some(each), LPARAM::from(affinity != WDA_NONE)) };
        true
    }
}

#[cfg(any(miri, not(any(target_os = "macos", windows))))]
mod imp {
    pub(super) fn set(_on: bool) -> bool {
        false
    }
}
