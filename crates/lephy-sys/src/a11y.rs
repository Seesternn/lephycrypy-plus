//! Accessibility settings of the operating system.

/// The user asked the system to reduce motion (macOS "Reduce motion"; Windows "Show animations
/// in Windows" turned off). `false` where unknown.
#[must_use]
pub fn reduce_motion() -> bool {
    imp::reduce_motion()
}

#[cfg(all(target_os = "macos", not(miri)))]
mod imp {
    use crate::objc::{class, send_bool, send_id};

    pub(super) fn reduce_motion() -> bool {
        let ws = send_id(class(c"NSWorkspace"), c"sharedWorkspace");
        send_bool(ws, c"accessibilityDisplayShouldReduceMotion")
    }
}

#[cfg(all(windows, not(miri)))]
mod imp {
    use windows_sys::Win32::UI::WindowsAndMessaging::{
        SPI_GETCLIENTAREAANIMATION, SystemParametersInfoW,
    };

    pub(super) fn reduce_motion() -> bool {
        let mut on: windows_sys::core::BOOL = 1;
        // SAFETY: SPI_GETCLIENTAREAANIMATION writes one BOOL to the pointer given.
        let ok = unsafe {
            SystemParametersInfoW(SPI_GETCLIENTAREAANIMATION, 0, (&raw mut on).cast(), 0)
        };
        ok != 0 && on == 0
    }
}

#[cfg(any(miri, not(any(target_os = "macos", windows))))]
mod imp {
    pub(super) fn reduce_motion() -> bool {
        false
    }
}
