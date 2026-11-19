//! Minimal Objective-C runtime calls (macOS): the shared application, selectors and typed
//! `objc_msgSend` wrappers. Every wrapper casts `objc_msgSend` to the exact C type of the method
//! it calls, as the runtime requires on arm64.

use std::ffi::{CStr, c_char, c_void};

/// Objective-C object pointer.
pub(crate) type Id = *mut c_void;
/// Selector.
pub(crate) type Sel = *const c_void;

#[link(name = "objc")]
unsafe extern "C" {
    fn objc_getClass(name: *const c_char) -> Id;
    fn sel_registerName(name: *const c_char) -> Sel;
    pub(crate) fn class_addMethod(
        cls: Id,
        name: Sel,
        imp: *const c_void,
        types: *const c_char,
    ) -> bool;
    fn objc_msgSend();
}

#[link(name = "AppKit", kind = "framework")]
unsafe extern "C" {}

/// Registered selector for `name`.
pub(crate) fn sel(name: &CStr) -> Sel {
    // SAFETY: `name` is a NUL-terminated selector name; the runtime interns it.
    unsafe { sel_registerName(name.as_ptr()) }
}

/// Class object by name (nil if not registered).
pub(crate) fn class(name: &CStr) -> Id {
    // SAFETY: NUL-terminated class name; returns nil if no such class is registered.
    unsafe { objc_getClass(name.as_ptr()) }
}

/// `[obj sel]` returning an object.
pub(crate) fn send_id(obj: Id, s: &CStr) -> Id {
    if obj.is_null() {
        return std::ptr::null_mut();
    }
    // SAFETY: objc_msgSend is called through a pointer of the method's exact type: no arguments,
    // returns an object.
    let f: unsafe extern "C" fn(Id, Sel) -> Id = unsafe {
        std::mem::transmute::<unsafe extern "C" fn(), unsafe extern "C" fn(Id, Sel) -> Id>(
            objc_msgSend,
        )
    };
    // SAFETY: `obj` is a live object; the caller names a method of this type.
    unsafe { f(obj, sel(s)) }
}

/// `[obj sel]` returning `NSUInteger` / `BOOL` (as usize; BOOL is widened by the cast type).
pub(crate) fn send_usize(obj: Id, s: &CStr) -> usize {
    if obj.is_null() {
        return 0;
    }
    // SAFETY: as in `send_id`; the method takes no arguments and returns NSUInteger.
    let f: unsafe extern "C" fn(Id, Sel) -> usize = unsafe {
        std::mem::transmute::<unsafe extern "C" fn(), unsafe extern "C" fn(Id, Sel) -> usize>(
            objc_msgSend,
        )
    };
    // SAFETY: `obj` is a live object; the caller names a method of this type.
    unsafe { f(obj, sel(s)) }
}

/// `[obj sel:n]` returning `BOOL` (a signed char on x86-64, `bool` on arm64).
pub(crate) fn send_bool(obj: Id, s: &CStr) -> bool {
    if obj.is_null() {
        return false;
    }
    // SAFETY: as in `send_id`; the method takes no arguments and returns BOOL (one byte).
    let f: unsafe extern "C" fn(Id, Sel) -> i8 = unsafe {
        std::mem::transmute::<unsafe extern "C" fn(), unsafe extern "C" fn(Id, Sel) -> i8>(
            objc_msgSend,
        )
    };
    // SAFETY: `obj` is a live object; the caller names a method of this type.
    unsafe { f(obj, sel(s)) != 0 }
}

/// `[obj sel:n]` with one `NSUInteger` argument, returning an object.
pub(crate) fn send_id_usize(obj: Id, s: &CStr, n: usize) -> Id {
    if obj.is_null() {
        return std::ptr::null_mut();
    }
    // SAFETY: as in `send_id`; one NSUInteger argument, returns an object.
    let f: unsafe extern "C" fn(Id, Sel, usize) -> Id = unsafe {
        std::mem::transmute::<unsafe extern "C" fn(), unsafe extern "C" fn(Id, Sel, usize) -> Id>(
            objc_msgSend,
        )
    };
    // SAFETY: `obj` is a live object; the caller names a method of this type.
    unsafe { f(obj, sel(s), n) }
}

/// `[obj sel:n]` with one `NSUInteger` argument, returning void.
pub(crate) fn send_void_usize(obj: Id, s: &CStr, n: usize) {
    if obj.is_null() {
        return;
    }
    // SAFETY: as in `send_id`; one NSUInteger argument, returns void.
    let f: unsafe extern "C" fn(Id, Sel, usize) = unsafe {
        std::mem::transmute::<unsafe extern "C" fn(), unsafe extern "C" fn(Id, Sel, usize)>(
            objc_msgSend,
        )
    };
    // SAFETY: `obj` is a live object; the caller names a method of this type.
    unsafe { f(obj, sel(s), n) }
}

/// `[obj sel:arg]` with one object argument, returning void.
pub(crate) fn send_void_id(obj: Id, s: &CStr, arg: Id) {
    if obj.is_null() {
        return;
    }
    // SAFETY: as in `send_id`; one object argument, returns void.
    let f: unsafe extern "C" fn(Id, Sel, Id) = unsafe {
        std::mem::transmute::<unsafe extern "C" fn(), unsafe extern "C" fn(Id, Sel, Id)>(
            objc_msgSend,
        )
    };
    // SAFETY: `obj` is a live object; the caller names a method of this type.
    unsafe { f(obj, sel(s), arg) }
}

/// `[obj sel:ptr]` with one C-string argument, returning an object.
pub(crate) fn send_id_cstr(obj: Id, s: &CStr, arg: &CStr) -> Id {
    if obj.is_null() {
        return std::ptr::null_mut();
    }
    // SAFETY: as in `send_id`; one `const char *` argument, returns an object.
    let f: unsafe extern "C" fn(Id, Sel, *const c_char) -> Id = unsafe {
        std::mem::transmute::<
            unsafe extern "C" fn(),
            unsafe extern "C" fn(Id, Sel, *const c_char) -> Id,
        >(objc_msgSend)
    };
    // SAFETY: `obj` is a live object; `arg` is NUL-terminated and outlives the call.
    unsafe { f(obj, sel(s), arg.as_ptr()) }
}

/// `[obj sel:n arg:o]` with an `NSUInteger`/`uint64_t` and an object, returning an object.
pub(crate) fn send_id_u64_id(obj: Id, s: &CStr, n: u64, o: Id) -> Id {
    if obj.is_null() {
        return std::ptr::null_mut();
    }
    // SAFETY: as in `send_id`; a 64-bit integer and an object argument, returns an object.
    let f: unsafe extern "C" fn(Id, Sel, u64, Id) -> Id = unsafe {
        std::mem::transmute::<unsafe extern "C" fn(), unsafe extern "C" fn(Id, Sel, u64, Id) -> Id>(
            objc_msgSend,
        )
    };
    // SAFETY: `obj` is a live object; the caller names a method of this type.
    unsafe { f(obj, sel(s), n, o) }
}

/// `[NSApplication sharedApplication]` (nil if `AppKit` is not loaded).
pub(crate) fn shared_app() -> Id {
    send_id(class(c"NSApplication"), c"sharedApplication")
}
