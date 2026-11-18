//! macOS Secure Event Input.
//!
//! While it is enabled, other processes with input-monitoring permission (e.g. `CGEventTap`)
//! cannot read keystrokes; `NSSecureTextField` does this itself, egui's custom password field
//! enables it by hand. Calls are counted by the system: every `Enable` must be balanced by a
//! `Disable`, which [`SecureInputGuard`] guarantees. A no-op elsewhere (Windows has no equivalent).

/// Keeps Secure Event Input enabled while it exists.
#[derive(Debug)]
pub struct SecureInputGuard {
    _private: (),
}

#[cfg(target_os = "macos")]
#[link(name = "Carbon", kind = "framework")]
unsafe extern "C" {
    fn EnableSecureEventInput() -> i32;
    fn DisableSecureEventInput() -> i32;
}

impl SecureInputGuard {
    /// Enables secure input.
    #[must_use]
    pub fn new() -> Self {
        #[cfg(target_os = "macos")]
        {
            // SAFETY: Carbon call without arguments; increments the system counter, Drop balances it.
            let _ = unsafe { EnableSecureEventInput() };
        }
        Self { _private: () }
    }
}

impl Default for SecureInputGuard {
    fn default() -> Self {
        Self::new()
    }
}

impl Drop for SecureInputGuard {
    fn drop(&mut self) {
        #[cfg(target_os = "macos")]
        {
            // SAFETY: Carbon call without arguments; balanced with the Enable in `new`.
            let _ = unsafe { DisableSecureEventInput() };
        }
    }
}

#[cfg(all(test, target_os = "macos"))]
mod tests {
    #[cfg_attr(miri, ignore = "FFI; does not run under Miri")]
    #[test]
    fn guard_is_balanced() {
        let a = super::SecureInputGuard::new();
        let b = super::SecureInputGuard::new();
        drop(a);
        drop(b);
    }
}
