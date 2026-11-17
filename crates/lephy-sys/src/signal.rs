//! Sinyal işleme.
//!
//! Unix: SIGINT/SIGTERM/SIGHUP için doğrudan `sigaction`, **`SA_RESTART` olmadan**; işleyici
//! yalnızca [`INTERRUPTED`] bayrağını kaldırır ve self-pipe'a 1 bayt yazar (async-signal-safe).
//! İkinci sinyalde `_exit(130)` (tmp kalabilir, `cleanup` bulur). Ana iş parçacığı dışındaki iş
//! parçacıkları [`mask_signals_on_this_thread`] ile maskelenir.
//!
//! Windows: `SetConsoleCtrlHandler`; sistem işleyiciyi yeni iş parçacığında çalıştırır. Ctrl+C /
//! Ctrl+Break: bayrak + `CancelSynchronousIo(ana iş parçacığı)` (konsol okumasını kırar,
//! DOĞRULANMADI) + `TRUE`. Close/Logoff/Shutdown: bayrak, sonra [`mark_cleanup_done`] için
//! ≤ ~4,5 s bekler (sistem sınırı 5000 ms).
//!
//! `signal-hook`/`ctrlc` kullanılmaz.

use std::io;
use std::sync::atomic::{AtomicBool, Ordering};

/// Sinyal bayrağı (SIGINT/SIGTERM/SIGHUP, Windows konsol olayları). İkinci gerçek sinyal
/// `_exit(130)` ile çıkar.
static INTERRUPTED: AtomicBool = AtomicBool::new(false);
/// Uygulama içi iptal (GUI "İptal" düğmesi). Sinyal bayrağından ayrıdır: iptalden sonra gelen
/// ilk sinyal temizliği atlayan `_exit` yolunu tetiklemez.
static CANCELLED: AtomicBool = AtomicBool::new(false);
static INSTALLED: AtomicBool = AtomicBool::new(false);

/// Durulmalı mı: sinyal alındı ya da iptal istendi. Hat her chunk sınırında yoklar.
#[must_use]
pub fn interrupted() -> bool {
    INTERRUPTED.load(Ordering::SeqCst) || CANCELLED.load(Ordering::SeqCst)
}

/// Yalnızca gerçek bir sinyal alındı mı (uygulama içi iptal hariç).
#[must_use]
pub fn signalled() -> bool {
    INTERRUPTED.load(Ordering::SeqCst)
}

/// Uygulama içi iptal ister (GUI "İptal" düğmesi, pencere kapatma): hat bir sonraki chunk
/// sınırında `Interrupted` ile durur, tmp dosyaları normal yoldan silinir.
pub fn request_cancel() {
    CANCELLED.store(true, Ordering::SeqCst);
}

/// Uygulama içi iptali temizler (sinyal bayrağına dokunmaz).
pub fn reset_cancel() {
    CANCELLED.store(false, Ordering::SeqCst);
}

/// Eski ad: [`request_cancel`].
pub fn request_interrupt() {
    request_cancel();
}

/// İki bayrağı da sıfırlar (yalnızca testler ve ardışık komutlar için).
pub fn reset_interrupted() {
    INTERRUPTED.store(false, Ordering::SeqCst);
    CANCELLED.store(false, Ordering::SeqCst);
}

/// İşleyiciyi kurar; tekrar çağrılması zararsızdır.
///
/// # Errors
/// `pipe`/`sigaction` (Unix) ya da `SetConsoleCtrlHandler`/`DuplicateHandle` (Windows) hatası.
pub fn install() -> io::Result<()> {
    if INSTALLED.swap(true, Ordering::SeqCst) {
        return Ok(());
    }
    imp::install()
}

/// `fd` sinyal işleyicinin kendi self-pipe uçlarından biri mi (Unix; diğerlerinde `false`).
#[must_use]
pub fn is_internal_fd(fd: i32) -> bool {
    imp::is_internal_fd(fd)
}

/// Unix: self-pipe okuma ucu (poll için). Windows: `None`.
#[must_use]
pub fn self_pipe_read_fd() -> Option<i32> {
    imp::self_pipe_read_fd()
}

/// Bu iş parçacığında SIGINT/SIGTERM/SIGHUP maskeler (ana iş parçacığı dışındakiler için).
/// Windows'ta no-op.
///
/// # Errors
/// `pthread_sigmask` hatası.
pub fn mask_signals_on_this_thread() -> io::Result<()> {
    imp::mask_signals_on_this_thread()
}

/// Windows konsol kapatma işleyicisine "temizlik bitti" der; diğer platformlarda no-op.
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

    /// Bu iş parçacığının `errno` konumu.
    fn errno_ptr() -> *mut libc::c_int {
        #[cfg(any(target_os = "macos", target_os = "ios", target_os = "freebsd"))]
        // SAFETY: `__error` argüman almaz, iş parçacığına özgü geçerli bir işaretçi döndürür ve
        // async-signal-safe'dir.
        let p = unsafe { libc::__error() };
        #[cfg(not(any(target_os = "macos", target_os = "ios", target_os = "freebsd")))]
        // SAFETY: `__errno_location` argüman almaz, iş parçacığına özgü geçerli bir işaretçi
        // döndürür ve async-signal-safe'dir.
        let p = unsafe { libc::__errno_location() };
        p
    }

    extern "C" fn handler(_sig: libc::c_int) {
        // Kesilen kodun errno'su korunur (işleyicideki `write` onu değiştirebilir).
        let ep = errno_ptr();
        // SAFETY: `ep` bu iş parçacığının geçerli, hizalı errno konumu.
        let saved = unsafe { ep.read() };
        if INTERRUPTED.swap(true, Ordering::SeqCst) {
            // İkinci sinyal: hemen çık (async-signal-safe).
            // SAFETY: `_exit` async-signal-safe'dir ve argüman almaz.
            unsafe { libc::_exit(130) };
        }
        let wr = PIPE_WR.load(Ordering::SeqCst);
        if wr >= 0 {
            let b = [b'x'];
            // SAFETY: `wr` kurulumda açılmış geçerli, non-blocking bir pipe ucu; `b` 1 baytlık
            // geçerli tampon; `write` async-signal-safe'dir. Dönüş değeri yok sayılır (pipe dolu
            // olabilir, bayrak zaten kalktı).
            let _ = unsafe { libc::write(wr, b.as_ptr().cast::<libc::c_void>(), 1) };
        }
        // SAFETY: `ep` bu iş parçacığının geçerli, hizalı errno konumu.
        unsafe { ep.write(saved) };
    }

    fn set_flags(fd: libc::c_int) -> io::Result<()> {
        // SAFETY: F_GETFL bellek işaretçisi almaz; `fd` geçerli.
        let fl = unsafe { libc::fcntl(fd, libc::F_GETFL) };
        if fl < 0 {
            return Err(io::Error::last_os_error());
        }
        // SAFETY: F_SETFL yalnızca tamsayı bayrak alır.
        if unsafe { libc::fcntl(fd, libc::F_SETFL, fl | libc::O_NONBLOCK) } < 0 {
            return Err(io::Error::last_os_error());
        }
        // SAFETY: F_SETFD yalnızca tamsayı bayrak alır.
        if unsafe { libc::fcntl(fd, libc::F_SETFD, libc::FD_CLOEXEC) } < 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(())
    }

    pub(super) fn install() -> io::Result<()> {
        let mut fds: [libc::c_int; 2] = [-1, -1];
        // SAFETY: `fds` 2 elemanlı geçerli dizi; `pipe` iki fd yazar.
        if unsafe { libc::pipe(fds.as_mut_ptr()) } != 0 {
            return Err(io::Error::last_os_error());
        }
        set_flags(fds[0])?;
        set_flags(fds[1])?;
        PIPE_RD.store(fds[0], Ordering::SeqCst);
        PIPE_WR.store(fds[1], Ordering::SeqCst);

        for sig in SIGNALS {
            // SAFETY: `sigaction` düz C struct'ıdır; sıfır başlangıç geçerli (SIG_DFL, boş maske,
            // bayrak yok).
            let mut sa: libc::sigaction = unsafe { core::mem::zeroed() };
            // SAFETY: `sa_mask` geçerli, yazılabilir sigset_t.
            unsafe { libc::sigemptyset(&raw mut sa.sa_mask) };
            sa.sa_sigaction = handler as extern "C" fn(libc::c_int) as libc::sighandler_t;
            sa.sa_flags = 0; // SA_RESTART bilinçli olarak YOK
            // SAFETY: `sa` tam başlatılmış; `oldact` NULL; `sig` geçerli sinyal numarası.
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
        // SAFETY: sigset_t düz C türü; sıfır başlangıç `sigemptyset` ile normalize edilir.
        let mut set: libc::sigset_t = unsafe { core::mem::zeroed() };
        // SAFETY: `set` geçerli, yazılabilir.
        unsafe { libc::sigemptyset(&raw mut set) };
        for sig in SIGNALS {
            // SAFETY: `set` geçerli; `sig` geçerli sinyal.
            unsafe { libc::sigaddset(&raw mut set, sig) };
        }
        // SAFETY: `set` geçerli; `oldset` NULL.
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
            // SAFETY: `h` kurulumda DuplicateHandle ile alınmış, kapatılmamış iş parçacığı handle'ı.
            let _ = unsafe { CancelSynchronousIo(h) };
        }
    }

    unsafe extern "system" fn ctrl_handler(ty: u32) -> i32 {
        match ty {
            CTRL_C_EVENT | CTRL_BREAK_EVENT => {
                if INTERRUPTED.swap(true, Ordering::SeqCst) {
                    // SAFETY: ExitProcess yalnızca çıkış kodu alır.
                    unsafe { ExitProcess(130) };
                }
                cancel_main_io();
                TRUE
            }
            CTRL_CLOSE_EVENT | CTRL_LOGOFF_EVENT | CTRL_SHUTDOWN_EVENT => {
                INTERRUPTED.store(true, Ordering::SeqCst);
                cancel_main_io();
                // Sistem sınırı 5000 ms; ≤ ~4,5 s temizlik bekle.
                for _ in 0..90 {
                    if CLEANUP_DONE.load(Ordering::SeqCst) {
                        break;
                    }
                    // SAFETY: Sleep yalnızca milisaniye alır.
                    unsafe { Sleep(50) };
                }
                TRUE
            }
            _ => FALSE,
        }
    }

    pub(super) fn install() -> io::Result<()> {
        let mut dup: HANDLE = core::ptr::null_mut();
        // SAFETY: sahte handle; argüman almaz, kapatılmaz.
        let proc_h = unsafe { GetCurrentProcess() };
        // SAFETY: sahte handle; argüman almaz, kapatılmaz.
        let thread_h = unsafe { GetCurrentThread() };
        // SAFETY: tüm handle'lar geçerli; `dup` geçerli çıktı işaretçisi; DUPLICATE_SAME_ACCESS.
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
        // SAFETY: `ctrl_handler` doğru imzalı `extern "system"` fonksiyon; süreç ömrü boyunca canlı.
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
        // SAFETY: SIGINT'i kendi sürecimize göndeririz; işleyici kurulu.
        unsafe { libc::raise(libc::SIGINT) };
        assert!(interrupted());
        let rd = self_pipe_read_fd().unwrap();
        let mut b = [0u8; 8];
        // SAFETY: `rd` geçerli non-blocking fd; `b` geçerli tampon.
        let n = unsafe { libc::read(rd, b.as_mut_ptr().cast(), b.len()) };
        assert!(n >= 1, "self-pipe'ta bayt bekleniyordu");
        reset_interrupted();
    }
}
