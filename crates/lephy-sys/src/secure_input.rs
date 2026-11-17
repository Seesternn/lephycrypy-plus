//! macOS güvenli klavye girişi (Secure Event Input).
//!
//! Etkinken, girdi izleme izni almış başka süreçler (ör. `CGEventTap`) tuş vuruşlarını okuyamaz;
//! `NSSecureTextField` bunu kendiliğinden yapar, egui'nin özel parola alanı için elle açılır.
//! Çağrılar sistem tarafında sayılır: her `Enable` bir `Disable` ile dengelenmelidir; bunu
//! [`SecureInputGuard`] garanti eder. Diğer platformlarda no-op'tur (Windows'ta eşdeğeri yok).

/// Var olduğu sürece güvenli klavye girişini açık tutar.
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
    /// Güvenli girişi açar.
    #[must_use]
    pub fn new() -> Self {
        #[cfg(target_os = "macos")]
        {
            // SAFETY: argümansız Carbon çağrısı; sistem sayacını artırır, Drop dengeler.
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
            // SAFETY: argümansız Carbon çağrısı; `new` içindeki Enable ile dengelenir.
            let _ = unsafe { DisableSecureEventInput() };
        }
    }
}

#[cfg(all(test, target_os = "macos"))]
mod tests {
    #[cfg_attr(miri, ignore = "FFI; Miri'de çalışmaz")]
    #[test]
    fn guard_is_balanced() {
        let a = super::SecureInputGuard::new();
        let b = super::SecureInputGuard::new();
        drop(a);
        drop(b);
    }
}
