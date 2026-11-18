//! Signal handling.
//!
//! Unix: direct `sigaction` for SIGINT/SIGTERM/SIGHUP, **without `SA_RESTART`**; the handler only
//! sets the [`INTERRUPTED`] flag and writes 1 byte to the self-pipe (async-signal-safe). A second
//! signal calls `_exit(130)` (temp files may remain; `cleanup` finds them). Threads other than the
//! main thread are masked with [`mask_signals_on_this_thread`].
//!
//! Windows: `SetConsoleCtrlHandler`; the system runs the handler on a new thread. Ctrl+C /
//! Ctrl+Break: flag + `CancelSynchronousIo(main thread)` (breaks the console read,
//! UNVERIFIED) + `TRUE`. Close/Logoff/Shutdown: flag, then waits ≤ ~4.5 s for
//! [`mark_cleanup_done`] (system limit 5000 ms).
//!
//! `signal-hook`/`ctrlc` are not used.

use std::io;
use std::sync::atomic::{AtomicBool, Ordering};

/// Signal flag (SIGINT/SIGTERM/SIGHUP, Windows console events). A second real signal exits with
/// `_exit(130)`.
static INTERRUPTED: AtomicBool = AtomicBool::new(false);
/// In-app cancellation (the app's "Cancel" button). Separate from the signal flag: the first
/// signal after a cancellation does not trigger the `_exit` path that skips cleanup.
static CANCELLED: AtomicBool = AtomicBool::new(false);
static INSTALLED: AtomicBool = AtomicBool::new(false);

/// Whether to stop: a signal arrived or cancellation was requested. The pipeline polls it at every chunk boundary.
#[must_use]
pub fn interrupted() -> bool {
    INTERRUPTED.load(Ordering::SeqCst) || CANCELLED.load(Ordering::SeqCst)
}

/// Whether a real signal arrived (excluding in-app cancellation).
#[must_use]
pub fn signalled() -> bool {
    INTERRUPTED.load(Ordering::SeqCst)
}

/// Requests in-app cancellation (the app's "Cancel" button, closing the window): the pipeline
/// stops with `Interrupted` at the next chunk boundary and temp files are removed normally.
pub fn request_cancel() {
    CANCELLED.store(true, Ordering::SeqCst);
}

/// Clears in-app cancellation (does not touch the signal flag).
pub fn reset_cancel() {
    CANCELLED.store(false, Ordering::SeqCst);
}

/// Old name: [`request_cancel`].
pub fn request_interrupt() {
    request_cancel();
}

/// Resets both flags (tests and consecutive commands only).
pub fn reset_interrupted() {
    INTERRUPTED.store(false, Ordering::SeqCst);
    CANCELLED.store(false, Ordering::SeqCst);
}

/// Installs the handler; calling it again is harmless.
///
/// # Errors
/// `pipe`/`sigaction` (Unix) or `SetConsoleCtrlHandler`/`DuplicateHandle` (Windows) error.
pub fn install() -> io::Result<()> {
    if INSTALLED.swap(true, Ordering::SeqCst) {
        return Ok(());
    }
    imp::install()
}

/// Whether `fd` is one of the signal handler's own self-pipe ends (Unix; `false` elsewhere).
#[must_use]
pub fn is_internal_fd(fd: i32) -> bool {
    imp::is_internal_fd(fd)
}

/// Unix: the self-pipe read end (for poll). Windows: `None`.
#[must_use]
pub fn self_pipe_read_fd() -> Option<i32> {
    imp::self_pipe_read_fd()
}

/// Masks SIGINT/SIGTERM/SIGHUP on this thread (for threads other than the main thread).
/// A no-op on Windows.
///
/// # Errors
/// `pthread_sigmask` error.
pub fn mask_signals_on_this_thread() -> io::Result<()> {
    imp::mask_signals_on_this_thread()
}

/// Tells the Windows console close handler that cleanup is done; a no-op elsewhere.
pub fn mark_cleanup_done() {
    imp::mark_cleanup_done();
}

#[cfg(unix)]
mod imp {
    use super::INTERRUPTED;
    use std::io;
    use std::sync::atomic::{AtomicI32, Ordering};

    static PIPE_RD: AtomicI32 = AtomicI32::new(-1);
    static PIPE_WR: AtomicI32 = AtomicI32::new(-1);

    const SIGNALS: [libc::c_int; 3] = [libc::SIGINT, libc::SIGTERM, libc::SIGHUP];

    /// This thread's `errno` location.
    fn errno_ptr() -> *mut libc::c_int {
        #[cfg(any(target_os = "macos", target_os = "ios", target_os = "freebsd"))]
        // SAFETY: `__error` takes no argument, returns a valid thread-specific pointer and is
        // async-signal-safe.
        let p = unsafe { libc::__error() };
        #[cfg(not(any(target_os = "macos", target_os = "ios", target_os = "freebsd")))]
        // SAFETY: `__errno_location` takes no argument, returns a valid thread-specific pointer
        // and is async-signal-safe.
        let p = unsafe { libc::__errno_location() };
        p
    }

    extern "C" fn handler(_sig: libc::c_int) {
        // The interrupted code's errno is preserved (the handler's `write` may change it).
        let ep = errno_ptr();
        // SAFETY: `ep` is this thread's valid, aligned errno location.
        let saved = unsafe { ep.read() };
        if INTERRUPTED.swap(true, Ordering::SeqCst) {
            // Second signal: exit at once (async-signal-safe).
            // SAFETY: `_exit` is async-signal-safe and takes no argument.
            unsafe { libc::_exit(130) };
        }
        let wr = PIPE_WR.load(Ordering::SeqCst);
        if wr >= 0 {
            let b = [b'x'];
            // SAFETY: `wr` is a valid non-blocking pipe end opened during setup; `b` is a valid
            // 1-byte buffer; `write` is async-signal-safe. The return value is ignored (the pipe may
            // be full; the flag is already set).
            let _ = unsafe { libc::write(wr, b.as_ptr().cast::<libc::c_void>(), 1) };
        }
        // SAFETY: `ep` is this thread's valid, aligned errno location.
        unsafe { ep.write(saved) };
    }

    fn set_flags(fd: libc::c_int) -> io::Result<()> {
        // SAFETY: F_GETFL takes no memory pointer; `fd` is valid.
        let fl = unsafe { libc::fcntl(fd, libc::F_GETFL) };
        if fl < 0 {
            return Err(io::Error::last_os_error());
        }
        // SAFETY: F_SETFL takes only an integer flag.
        if unsafe { libc::fcntl(fd, libc::F_SETFL, fl | libc::O_NONBLOCK) } < 0 {
            return Err(io::Error::last_os_error());
        }
        // SAFETY: F_SETFD takes only an integer flag.
        if unsafe { libc::fcntl(fd, libc::F_SETFD, libc::FD_CLOEXEC) } < 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(())
    }

    pub(super) fn install() -> io::Result<()> {
        let mut fds: [libc::c_int; 2] = [-1, -1];
        // SAFETY: `fds` is a valid 2-element array; `pipe` writes two fds.
        if unsafe { libc::pipe(fds.as_mut_ptr()) } != 0 {
            return Err(io::Error::last_os_error());
        }
        set_flags(fds[0])?;
        set_flags(fds[1])?;
        PIPE_RD.store(fds[0], Ordering::SeqCst);
        PIPE_WR.store(fds[1], Ordering::SeqCst);

        for sig in SIGNALS {
            // SAFETY: `sigaction` is a plain C struct; zero initialisation is valid (SIG_DFL, empty
            // mask, no flags).
            let mut sa: libc::sigaction = unsafe { core::mem::zeroed() };
            // SAFETY: `sa_mask` is a valid, writable sigset_t.
            unsafe { libc::sigemptyset(&raw mut sa.sa_mask) };
            sa.sa_sigaction = handler as extern "C" fn(libc::c_int) as libc::sighandler_t;
            sa.sa_flags = 0; // deliberately NO SA_RESTART
            // SAFETY: `sa` is fully initialised; `oldact` is NULL; `sig` is a valid signal number.
            if unsafe { libc::sigaction(sig, &raw const sa, core::ptr::null_mut()) } != 0 {
                return Err(io::Error::last_os_error());
            }
        }
        Ok(())
    }

    pub(super) fn self_pipe_read_fd() -> Option<i32> {
        let fd = PIPE_RD.load(Ordering::SeqCst);
        (fd >= 0).then_some(fd)
    }

    pub(super) fn is_internal_fd(fd: i32) -> bool {
        fd >= 0 && (fd == PIPE_RD.load(Ordering::SeqCst) || fd == PIPE_WR.load(Ordering::SeqCst))
    }

    pub(super) fn mask_signals_on_this_thread() -> io::Result<()> {
        // SAFETY: sigset_t is a plain C type; the zero initialisation is normalised by `sigemptyset`.
        let mut set: libc::sigset_t = unsafe { core::mem::zeroed() };
        // SAFETY: `set` is valid and writable.
        unsafe { libc::sigemptyset(&raw mut set) };
        for sig in SIGNALS {
            // SAFETY: `set` is valid; `sig` is a valid signal.
            unsafe { libc::sigaddset(&raw mut set, sig) };
        }
        // SAFETY: `set` is valid; `oldset` is NULL.
        let rc = unsafe {
            libc::pthread_sigmask(libc::SIG_BLOCK, &raw const set, core::ptr::null_mut())
        };
        if rc == 0 {
            Ok(())
        } else {
            Err(io::Error::from_raw_os_error(rc))
        }
    }

    pub(super) fn mark_cleanup_done() {}
}

#[cfg(windows)]
mod imp {
    use super::INTERRUPTED;
    use std::io;
    use std::sync::atomic::{AtomicBool, AtomicPtr, Ordering};
    use windows_sys::Win32::Foundation::{
        DUPLICATE_SAME_ACCESS, DuplicateHandle, FALSE, HANDLE, TRUE,
    };
    use windows_sys::Win32::System::Console::{
        CTRL_BREAK_EVENT, CTRL_C_EVENT, CTRL_CLOSE_EVENT, CTRL_LOGOFF_EVENT, CTRL_SHUTDOWN_EVENT,
        SetConsoleCtrlHandler,
    };
    use windows_sys::Win32::System::IO::CancelSynchronousIo;
    use windows_sys::Win32::System::Threading::{
        ExitProcess, GetCurrentProcess, GetCurrentThread, Sleep,
    };

    static MAIN_THREAD: AtomicPtr<core::ffi::c_void> = AtomicPtr::new(core::ptr::null_mut());
    static CLEANUP_DONE: AtomicBool = AtomicBool::new(false);

    fn cancel_main_io() {
        let h = MAIN_THREAD.load(Ordering::SeqCst);
        if !h.is_null() {
            // SAFETY: `h` is the thread handle obtained with DuplicateHandle during setup, not closed.
            let _ = unsafe { CancelSynchronousIo(h) };
        }
    }

    unsafe extern "system" fn ctrl_handler(ty: u32) -> i32 {
        match ty {
            CTRL_C_EVENT | CTRL_BREAK_EVENT => {
                if INTERRUPTED.swap(true, Ordering::SeqCst) {
                    // SAFETY: ExitProcess takes only an exit code.
                    unsafe { ExitProcess(130) };
                }
                cancel_main_io();
                TRUE
            }
            CTRL_CLOSE_EVENT | CTRL_LOGOFF_EVENT | CTRL_SHUTDOWN_EVENT => {
                INTERRUPTED.store(true, Ordering::SeqCst);
                cancel_main_io();
                // System limit 5000 ms; wait ≤ ~4.5 s for cleanup.
                for _ in 0..90 {
                    if CLEANUP_DONE.load(Ordering::SeqCst) {
                        break;
                    }
                    // SAFETY: Sleep takes only milliseconds.
                    unsafe { Sleep(50) };
                }
                TRUE
            }
            _ => FALSE,
        }
    }

    pub(super) fn install() -> io::Result<()> {
        let mut dup: HANDLE = core::ptr::null_mut();
        // SAFETY: pseudo handle; takes no argument, not closed.
        let proc_h = unsafe { GetCurrentProcess() };
        // SAFETY: pseudo handle; takes no argument, not closed.
        let thread_h = unsafe { GetCurrentThread() };
        // SAFETY: all handles are valid; `dup` is a valid output pointer; DUPLICATE_SAME_ACCESS.
        let ok = unsafe {
            DuplicateHandle(
                proc_h,
                thread_h,
                proc_h,
                &raw mut dup,
                0,
                FALSE,
                DUPLICATE_SAME_ACCESS,
            )
        };
        if ok == 0 {
            return Err(io::Error::last_os_error());
        }
        MAIN_THREAD.store(dup, Ordering::SeqCst);
        // SAFETY: `ctrl_handler` is an `extern "system"` function with the right signature, alive for the process lifetime.
        let ok = unsafe { SetConsoleCtrlHandler(Some(ctrl_handler), TRUE) };
        if ok == 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(())
    }

    pub(super) fn self_pipe_read_fd() -> Option<i32> {
        None
    }

    pub(super) const fn is_internal_fd(_fd: i32) -> bool {
        false
    }

    #[allow(clippy::unnecessary_wraps)]
    pub(super) fn mask_signals_on_this_thread() -> io::Result<()> {
        Ok(())
    }

    pub(super) fn mark_cleanup_done() {
        CLEANUP_DONE.store(true, Ordering::SeqCst);
    }
}

#[cfg(all(test, unix))]
#[allow(clippy::expect_used, clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    #[cfg_attr(miri, ignore = "FFI")]
    fn raise_sets_flag_and_writes_self_pipe() {
        install().unwrap();
        reset_interrupted();
        // SAFETY: we send SIGINT to our own process; the handler is installed.
        unsafe { libc::raise(libc::SIGINT) };
        assert!(interrupted());
        let rd = self_pipe_read_fd().unwrap();
        let mut b = [0u8; 8];
        // SAFETY: `rd` is a valid non-blocking fd; `b` is a valid buffer.
        let n = unsafe { libc::read(rd, b.as_mut_ptr().cast(), b.len()) };
        assert!(n >= 1, "expected a byte in the self-pipe");
        reset_interrupted();
    }
}
