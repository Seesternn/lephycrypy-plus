//! App lifetime on macOS: closing the window hides the app (work continues; the Dock icon
//! brings it back), and quitting (Cmd+Q, Dock → Quit) while work runs asks first.
//!
//! The window library's application delegate does not implement `applicationShouldTerminate:`,
//! so [`install_macos_quit_guard`] adds it through the Objective-C runtime. While the app reports
//! itself busy ([`set_busy`]) and quitting was not confirmed ([`allow_quit`]), the method cancels
//! the termination, shows the app and records a request that the UI takes with
//! [`take_quit_request`].

use std::sync::atomic::{AtomicBool, Ordering};

static BUSY: AtomicBool = AtomicBool::new(false);
static QUIT_ASKED: AtomicBool = AtomicBool::new(false);
static QUIT_OK: AtomicBool = AtomicBool::new(false);

/// Whether work is running (a quit request is then held back for confirmation).
pub fn set_busy(busy: bool) {
    BUSY.store(busy, Ordering::SeqCst);
}

/// A quit request arrived while busy (taken once).
#[must_use]
pub fn take_quit_request() -> bool {
    QUIT_ASKED.swap(false, Ordering::SeqCst)
}

/// The user confirmed quitting: the next termination request goes through.
pub fn allow_quit() {
    QUIT_OK.store(true, Ordering::SeqCst);
}

/// Decision for a termination request: `true` = terminate now.
#[cfg_attr(not(any(target_os = "macos", test)), allow(dead_code))]
fn should_terminate() -> bool {
    if BUSY.load(Ordering::SeqCst) && !QUIT_OK.load(Ordering::SeqCst) {
        QUIT_ASKED.store(true, Ordering::SeqCst);
        crate::open_docs::wake();
        return false;
    }
    true
}

/// Hides the whole app (macOS `[NSApp hide:]`); clicking the Dock icon shows it again. Returns
/// `false` where this is not supported.
#[must_use]
pub fn hide_app() -> bool {
    #[cfg(target_os = "macos")]
    {
        macos::app_action(c"hide:");
        true
    }
    #[cfg(not(target_os = "macos"))]
    {
        false
    }
}

/// Installs `applicationShouldTerminate:` on the window library's application delegate. Returns
/// `false` if the class is missing or already has the method.
#[cfg(target_os = "macos")]
#[must_use]
pub fn install_macos_quit_guard(delegate_class: &str) -> bool {
    macos::install(delegate_class)
}

/// No-op outside macOS.
#[cfg(not(target_os = "macos"))]
#[must_use]
pub fn install_macos_quit_guard(_delegate_class: &str) -> bool {
    false
}

#[cfg(target_os = "macos")]
mod macos {
    use crate::objc::{Id, Sel, class, class_addMethod, sel, send_void_id, shared_app};
    use std::ffi::{CStr, CString, c_void};

    /// `[NSApp <action>:nil]` for `hide:` / `unhide:`.
    pub(super) fn app_action(action: &CStr) {
        send_void_id(shared_app(), action, std::ptr::null_mut());
    }

    /// `- (NSApplicationTerminateReply)applicationShouldTerminate:(NSApplication *)sender`
    /// (`NSTerminateCancel` = 0, `NSTerminateNow` = 1).
    extern "C" fn should_terminate(_this: Id, _cmd: Sel, _sender: Id) -> usize {
        if super::should_terminate() {
            1
        } else {
            app_action(c"unhide:");
            0
        }
    }

    pub(super) fn install(delegate_class: &str) -> bool {
        let Ok(name) = CString::new(delegate_class) else {
            return false;
        };
        let cls = class(&name);
        if cls.is_null() {
            return false;
        }
        let imp = should_terminate as extern "C" fn(Id, Sel, Id) -> usize;
        // SAFETY: `cls` is a registered class; `imp` matches the type encoding "Q@:@"
        // (NSUInteger return; self, _cmd, one object argument). The runtime refuses (returns NO)
        // if the class already implements the selector.
        unsafe {
            class_addMethod(
                cls,
                sel(c"applicationShouldTerminate:"),
                imp as *const c_void,
                c"Q@:@".as_ptr(),
            )
        }
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn quit_is_held_while_busy_until_allowed() {
        super::set_busy(false);
        assert!(super::should_terminate());
        assert!(!super::take_quit_request());
        super::set_busy(true);
        assert!(!super::should_terminate());
        assert!(super::take_quit_request());
        assert!(!super::take_quit_request());
        super::allow_quit();
        assert!(super::should_terminate());
        super::set_busy(false);
    }
}
