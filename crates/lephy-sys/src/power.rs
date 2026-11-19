//! "The computer is about to sleep": a hook that runs before the system sleeps, used to save and
//! lock open vaults first.
//!
//! macOS: `IORegisterForSystemPower` on a thread of its own with a run loop. On
//! `kIOMessageSystemWillSleep` the hook runs and sleep is allowed (`IOAllowPowerChange`) when it
//! returns; the system waits for that up to about 30 seconds. Idle-sleep queries
//! (`kIOMessageCanSystemSleep`) are allowed at once.
//!
//! Windows: `PowerRegisterSuspendResumeNotification` with a callback (no window needed). The
//! hook runs on `PBT_APMSUSPEND`; Windows waits only about two seconds for it.

use std::sync::OnceLock;

/// What runs before the system sleeps. It should return within a few seconds.
pub type SleepHook = Box<dyn Fn() + Send + Sync>;

static HOOK: OnceLock<SleepHook> = OnceLock::new();

/// Registers `hook` (once per process). Returns `false` if this system offers no notice or a
/// hook is already registered.
pub fn on_will_sleep(hook: SleepHook) -> bool {
    if HOOK.set(hook).is_err() {
        return false;
    }
    imp::register()
}

#[cfg_attr(
    not(any(all(target_os = "macos", not(miri)), windows)),
    allow(dead_code, reason = "no sleep notice on this system")
)]
fn run_hook() {
    if let Some(h) = HOOK.get() {
        h();
    }
}

#[cfg(all(target_os = "macos", not(miri)))]
mod imp {
    use std::ffi::c_void;
    use std::sync::atomic::{AtomicU32, Ordering};

    type IoConnect = u32;
    type IoObject = u32;
    type CFTypeRef = *const c_void;

    /// `kIOMessageCanSystemSleep`.
    const CAN_SLEEP: u32 = 0xe000_0270;
    /// `kIOMessageSystemWillSleep`.
    const WILL_SLEEP: u32 = 0xe000_0280;

    /// The root power-domain connection (for `IOAllowPowerChange`).
    static ROOT: AtomicU32 = AtomicU32::new(0);

    type Callback = unsafe extern "C" fn(*mut c_void, IoObject, u32, *mut c_void);

    #[link(name = "IOKit", kind = "framework")]
    unsafe extern "C" {
        fn IORegisterForSystemPower(
            refcon: *mut c_void,
            port: *mut *mut c_void,
            callback: Callback,
            notifier: *mut IoObject,
        ) -> IoConnect;
        fn IONotificationPortGetRunLoopSource(port: *mut c_void) -> CFTypeRef;
        fn IOAllowPowerChange(kernel_port: IoConnect, notification_id: isize) -> i32;
    }

    #[link(name = "CoreFoundation", kind = "framework")]
    unsafe extern "C" {
        static kCFRunLoopDefaultMode: CFTypeRef;
        fn CFRunLoopGetCurrent() -> CFTypeRef;
        fn CFRunLoopAddSource(rl: CFTypeRef, source: CFTypeRef, mode: CFTypeRef);
        fn CFRunLoopRun();
    }

    unsafe extern "C" fn on_power(_: *mut c_void, _: IoObject, kind: u32, arg: *mut c_void) {
        let root = ROOT.load(Ordering::SeqCst);
        match kind {
            WILL_SLEEP => {
                super::run_hook();
                // SAFETY: `root` is the connection from IORegisterForSystemPower; `arg` is the
                // notification id handed to this callback.
                let _ = unsafe { IOAllowPowerChange(root, arg as isize) };
            }
            CAN_SLEEP => {
                // SAFETY: as above.
                let _ = unsafe { IOAllowPowerChange(root, arg as isize) };
            }
            _ => {}
        }
    }

    pub(super) fn register() -> bool {
        let (tx, rx) = std::sync::mpsc::channel();
        let spawned = std::thread::Builder::new()
            .name("lephy-power".into())
            .spawn(move || {
                let mut port: *mut c_void = std::ptr::null_mut();
                let mut notifier: IoObject = 0;
                // SAFETY: out-pointers to locals; the callback is a plain extern fn that lives
                // for the whole process.
                let root = unsafe {
                    IORegisterForSystemPower(
                        std::ptr::null_mut(),
                        &raw mut port,
                        on_power,
                        &raw mut notifier,
                    )
                };
                if root == 0 || port.is_null() {
                    let _ = tx.send(false);
                    return;
                }
                ROOT.store(root, Ordering::SeqCst);
                // SAFETY: `port` is the live notification port returned above; the source is
                // borrowed (not owned).
                let src = unsafe { IONotificationPortGetRunLoopSource(port) };
                // SAFETY: no arguments; the current run loop is borrowed.
                let rl = unsafe { CFRunLoopGetCurrent() };
                // SAFETY: framework constant, read once.
                let mode = unsafe { kCFRunLoopDefaultMode };
                // SAFETY: live run loop and source; the mode is a framework constant.
                unsafe { CFRunLoopAddSource(rl, src, mode) };
                let _ = tx.send(true);
                // SAFETY: runs this thread's run loop for the rest of the process.
                unsafe { CFRunLoopRun() };
            });
        spawned.is_ok() && rx.recv().unwrap_or(false)
    }
}

#[cfg(windows)]
mod imp {
    use std::ffi::c_void;
    use windows_sys::Win32::System::Power::{
        DEVICE_NOTIFY_SUBSCRIBE_PARAMETERS, PowerRegisterSuspendResumeNotification,
    };
    use windows_sys::Win32::UI::WindowsAndMessaging::DEVICE_NOTIFY_CALLBACK;

    /// `PBT_APMSUSPEND`.
    const SUSPEND: u32 = 4;

    unsafe extern "system" fn on_power(_: *const c_void, kind: u32, _: *const c_void) -> u32 {
        if kind == SUSPEND {
            super::run_hook();
        }
        0
    }

    pub(super) fn register() -> bool {
        // Lives for the whole process (Windows keeps a pointer to it).
        let params: &'static mut DEVICE_NOTIFY_SUBSCRIBE_PARAMETERS =
            Box::leak(Box::new(DEVICE_NOTIFY_SUBSCRIBE_PARAMETERS {
                Callback: Some(on_power),
                Context: std::ptr::null_mut(),
            }));
        let mut handle: *mut c_void = std::ptr::null_mut();
        // SAFETY: `params` is a valid, never-freed structure; `handle` is an out-pointer.
        let r = unsafe {
            PowerRegisterSuspendResumeNotification(
                DEVICE_NOTIFY_CALLBACK,
                std::ptr::from_mut(params).cast(),
                &raw mut handle,
            )
        };
        r == 0
    }
}

#[cfg(any(not(any(target_os = "macos", windows)), all(target_os = "macos", miri)))]
mod imp {
    pub(super) const fn register() -> bool {
        false
    }
}

#[cfg(test)]
mod tests {
    /// Registers for real (manual: put the computer to sleep and watch the output).
    #[test]
    #[ignore = "manual: needs a real sleep"]
    fn registers() {
        assert!(super::on_will_sleep(Box::new(|| eprintln!("will sleep"))));
        std::thread::sleep(std::time::Duration::from_mins(2));
    }

    #[test]
    fn second_hook_is_refused() {
        let _ = super::on_will_sleep(Box::new(|| {}));
        assert!(!super::on_will_sleep(Box::new(|| {})));
    }
}
