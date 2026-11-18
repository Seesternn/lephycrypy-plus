//! Files the operating system asks the app to open (double-click, "Open With", drop on the
//! Dock icon).
//!
//! macOS delivers them as an Apple Event that `NSApplication` forwards to its delegate's
//! `application:openURLs:`. The window library's delegate does not implement it, so
//! [`install_macos_handler`] adds the method to the delegate class through the Objective-C
//! runtime. It must run after the event loop is created (the class exists) and before it runs
//! (files given at launch are delivered while the app finishes launching). Received paths wait in
//! a queue until the app takes them with [`take_pending`].
//!
//! On other platforms the queue is filled by the app itself (command-line `--open`).

use std::path::PathBuf;
use std::sync::{Mutex, OnceLock};

static QUEUE: Mutex<Vec<PathBuf>> = Mutex::new(Vec::new());
type Waker = Box<dyn Fn() + Send + Sync>;
static WAKER: OnceLock<Waker> = OnceLock::new();

/// Called after new paths arrive (e.g. to repaint the window). Set once.
pub fn set_waker(f: impl Fn() + Send + Sync + 'static) {
    let _ = WAKER.set(Box::new(f));
}

/// Wakes the app (repaints the window) if a waker is set.
#[cfg_attr(not(any(target_os = "macos", test)), allow(dead_code))]
pub(crate) fn wake() {
    if let Some(w) = WAKER.get() {
        w();
    }
}

/// Adds paths to the queue and wakes the app.
pub fn push(paths: Vec<PathBuf>) {
    if paths.is_empty() {
        return;
    }
    if let Ok(mut q) = QUEUE.lock() {
        q.extend(paths);
    }
    if let Some(w) = WAKER.get() {
        w();
    }
}

/// Takes every queued path (oldest first).
#[must_use]
pub fn take_pending() -> Vec<PathBuf> {
    QUEUE
        .lock()
        .map(|mut q| std::mem::take(&mut *q))
        .unwrap_or_default()
}

/// Installs `application:openURLs:` on the window library's application delegate. Returns
/// `false` if the class is missing or already has the method (nothing is changed then).
#[cfg(target_os = "macos")]
#[must_use]
pub fn install_macos_handler(delegate_class: &str) -> bool {
    macos::install(delegate_class)
}

/// No-op outside macOS.
#[cfg(not(target_os = "macos"))]
#[must_use]
pub fn install_macos_handler(_delegate_class: &str) -> bool {
    false
}

#[cfg(target_os = "macos")]
mod macos {
    use std::ffi::{CStr, CString, c_char, c_void};
    use std::os::unix::ffi::OsStrExt;
    use std::path::PathBuf;

    type Id = *mut c_void;
    type Sel = *const c_void;

    #[link(name = "objc")]
    unsafe extern "C" {
        fn objc_getClass(name: *const c_char) -> Id;
        fn sel_registerName(name: *const c_char) -> Sel;
        fn class_addMethod(cls: Id, name: Sel, imp: *const c_void, types: *const c_char) -> bool;
        fn objc_msgSend();
    }

    // AppKit/Foundation must be loaded for NSURL/NSArray; the window library links them too.
    #[link(name = "Foundation", kind = "framework")]
    unsafe extern "C" {}

    fn sel(name: &CStr) -> Sel {
        // SAFETY: `name` is a NUL-terminated selector name; the runtime interns it.
        unsafe { sel_registerName(name.as_ptr()) }
    }

    /// `[obj sel]` returning an `NSUInteger`.
    fn send_usize(obj: Id, s: Sel) -> usize {
        // SAFETY: objc_msgSend must be called through a pointer of the method's exact type;
        // `count` takes no arguments and returns NSUInteger (usize on 64-bit macOS).
        let f: unsafe extern "C" fn(Id, Sel) -> usize = unsafe {
            std::mem::transmute::<unsafe extern "C" fn(), unsafe extern "C" fn(Id, Sel) -> usize>(
                objc_msgSend,
            )
        };
        // SAFETY: `obj` is a live NSArray from AppKit for the duration of the callback.
        unsafe { f(obj, s) }
    }

    /// `[obj sel:index]` returning an object.
    fn send_index(obj: Id, s: Sel, index: usize) -> Id {
        // SAFETY: as in `send_usize`; `objectAtIndex:` takes NSUInteger and returns id.
        let f: unsafe extern "C" fn(Id, Sel, usize) -> Id = unsafe {
            std::mem::transmute::<unsafe extern "C" fn(), unsafe extern "C" fn(Id, Sel, usize) -> Id>(
                objc_msgSend,
            )
        };
        // SAFETY: `index < count` is checked by the caller; the array is live.
        unsafe { f(obj, s, index) }
    }

    /// `[obj sel]` returning a C string or BOOL-sized value as a pointer-sized integer.
    fn send_ptr(obj: Id, s: Sel) -> *const c_char {
        // SAFETY: as in `send_usize`; `fileSystemRepresentation` returns `const char *`.
        let f: unsafe extern "C" fn(Id, Sel) -> *const c_char = unsafe {
            std::mem::transmute::<
                unsafe extern "C" fn(),
                unsafe extern "C" fn(Id, Sel) -> *const c_char,
            >(objc_msgSend)
        };
        // SAFETY: `obj` is a live NSURL.
        unsafe { f(obj, s) }
    }

    fn send_bool(obj: Id, s: Sel) -> bool {
        // SAFETY: as in `send_usize`; `isFileURL` returns BOOL (a C `bool` on arm64 and x86_64
        // macOS ABIs as used by the runtime: signed char/bool, non-zero = YES).
        let f: unsafe extern "C" fn(Id, Sel) -> i8 = unsafe {
            std::mem::transmute::<unsafe extern "C" fn(), unsafe extern "C" fn(Id, Sel) -> i8>(
                objc_msgSend,
            )
        };
        // SAFETY: `obj` is a live NSURL.
        unsafe { f(obj, s) != 0 }
    }

    /// `- (void)application:(NSApplication *)app openURLs:(NSArray<NSURL *> *)urls`
    extern "C" fn open_urls(_this: Id, _cmd: Sel, _app: Id, urls: Id) {
        if urls.is_null() {
            return;
        }
        let count = sel(c"count");
        let at = sel(c"objectAtIndex:");
        let is_file = sel(c"isFileURL");
        let fs_rep = sel(c"fileSystemRepresentation");
        let n = send_usize(urls, count).min(10_000);
        let mut paths = Vec::with_capacity(n);
        for i in 0..n {
            let url = send_index(urls, at, i);
            if url.is_null() || !send_bool(url, is_file) {
                continue;
            }
            let p = send_ptr(url, fs_rep);
            if p.is_null() {
                continue;
            }
            // SAFETY: `fileSystemRepresentation` returns a NUL-terminated string that lives at
            // least as long as the autorelease pool of this callback; it is copied at once.
            let bytes = unsafe { CStr::from_ptr(p) }.to_bytes();
            paths.push(PathBuf::from(std::ffi::OsStr::from_bytes(bytes)));
        }
        super::push(paths);
    }

    pub(super) fn install(delegate_class: &str) -> bool {
        let Ok(name) = CString::new(delegate_class) else {
            return false;
        };
        // SAFETY: NUL-terminated class name; returns nil if no such class is registered.
        let cls = unsafe { objc_getClass(name.as_ptr()) };
        if cls.is_null() {
            return false;
        }
        let imp = open_urls as extern "C" fn(Id, Sel, Id, Id);
        // SAFETY: `cls` is a registered class; `imp` matches the type encoding "v@:@@"
        // (void return; self, _cmd, two object arguments). The runtime refuses (returns NO) if
        // the class already implements the selector.
        unsafe {
            class_addMethod(
                cls,
                sel(c"application:openURLs:"),
                imp as *const c_void,
                c"v@:@@".as_ptr(),
            )
        }
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn queue_takes_in_order_and_empties() {
        super::push(vec!["a".into(), "b".into()]);
        super::push(vec![]);
        assert_eq!(
            super::take_pending(),
            vec![std::path::PathBuf::from("a"), "b".into()]
        );
        assert!(super::take_pending().is_empty());
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn unknown_class_is_refused() {
        assert!(!super::install_macos_handler("NoSuchLephyClass"));
    }
}
