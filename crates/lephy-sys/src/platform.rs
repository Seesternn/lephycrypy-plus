//! Süreç sertleştirme (PLAN › Bellek › Süreç başı; R5-04, R5-06).
//!
//! [`harden`] sırası:
//! 0. Windows: `SetDefaultDllDirectories(LOAD_LIBRARY_SEARCH_SYSTEM32)` — clap'ten ve her
//!    `LoadLibrary`'den önce.
//! 1. Windows: `SetErrorMode(SEM_NOGPFAULTERRORBOX)` (`WerAddExcludedApplication` DOĞRULANMADI,
//!    aşama 3).
//! 2. Unix: `setrlimit(RLIMIT_CORE, 0)`.
//! 3. Linux (best-effort): `prctl(PR_SET_DUMPABLE, 0)`.
//!
//! Ardından çağıran [`install_panic_hook`] (4), clap (5) ve macOS'ta [`deny_debugger`] (6).

use std::io;
use std::sync::atomic::{AtomicBool, Ordering};

/// Adım 0–3'ü sırayla uygular. Her adım best-effort'tur; ilk hata döndürülür ama kalan adımlar
/// yine de denenir (sertleştirme birbirinden bağımsızdır).
///
/// # Errors
/// Bir OS çağrısı başarısız olursa o çağrının `io::Error`'ı (ilk hata) döner.
pub fn harden() -> io::Result<()> {
    let mut first_err: Option<io::Error> = None;
    let mut note = |r: io::Result<()>| {
        if let Err(e) = r {
            first_err.get_or_insert(e);
        }
    };

    #[cfg(windows)]
    {
        note(windows::restrict_dll_search());
        windows::disable_error_dialogs();
    }
    #[cfg(unix)]
    {
        note(unix::disable_core_dumps());
    }
    #[cfg(target_os = "linux")]
    {
        note(unix::set_not_dumpable());
    }

    match first_err {
        Some(e) => Err(e),
        None => Ok(()),
    }
}

/// Toplam fiziksel RAM (bayt). KDF `m > %75 × RAM` denetimi için (PLAN › KDF politikası).
///
/// # Errors
/// OS sorgusu başarısız olursa `io::Error`.
pub fn physical_memory_bytes() -> io::Result<u64> {
    #[cfg(target_os = "macos")]
    {
        unix::sysctl_hw_memsize()
    }
    #[cfg(target_os = "linux")]
    {
        unix::sysconf_phys_pages()
    }
    #[cfg(windows)]
    {
        windows::global_memory_status()
    }
    #[cfg(not(any(target_os = "macos", target_os = "linux", windows)))]
    {
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "fiziksel RAM sorgusu bu platformda desteklenmiyor",
        ))
    }
}

/// macOS: `ptrace(PT_DENY_ATTACH)`. Yalnızca caydırıcıdır, güvenlik sınırı değildir. Diğer
/// platformlarda no-op.
///
/// # Errors
/// `ptrace` hatası.
pub fn deny_debugger() -> io::Result<()> {
    #[cfg(target_os = "macos")]
    {
        // SAFETY: PT_DENY_ATTACH için pid = 0, addr = NULL, data = 0 belgelenmiş kullanım.
        let rc = unsafe { libc::ptrace(libc::PT_DENY_ATTACH, 0, core::ptr::null_mut(), 0) };
        if rc != 0 {
            return Err(io::Error::last_os_error());
        }
    }
    Ok(())
}

// ---------------------------------------------------------------------------------------------
// Panik hook'u (R5-04, açık karar 13: arena → tmp → terminal)
// ---------------------------------------------------------------------------------------------

static IN_HOOK: AtomicBool = AtomicBool::new(false);

/// Ayırma yapmadan ondalık yazar.
fn write_num(out: &mut [u8; 20], mut n: usize) -> &[u8] {
    let mut i = out.len();
    if n == 0 {
        i -= 1;
        out[i] = b'0';
    }
    while n > 0 && i > 0 {
        i -= 1;
        #[allow(clippy::cast_possible_truncation)]
        let d = (n % 10) as u8;
        out[i] = b'0' + d;
        n /= 10;
    }
    &out[i..]
}

fn hook_body(info: &std::panic::PanicHookInfo<'_>) {
    if IN_HOOK.swap(true, Ordering::SeqCst) {
        std::process::abort();
    }
    // (1) arena + kayıtlı büyük bölgeler
    let (arena, regions) = crate::mem::zeroize_all_registered();
    // (2) tmp kaydı
    let tmp = crate::fs::tmp_unlink_all_in_hook();
    // (3) terminal
    crate::term::restore_if_raw();
    // Ham stderr satırı (ayırma yok).
    let err = std::io::stderr();
    let mut buf = [0u8; 20];
    let _ = crate::term::write_all_raw(&err, b"\nlephycrypy: i\xc3\xa7 hata (panik); arena=");
    let _ = crate::term::write_all_raw(&err, if arena > 0 { b"0" } else { b"-" });
    let _ = crate::term::write_all_raw(&err, b" b\xc3\xb6lge=");
    let _ = crate::term::write_all_raw(&err, write_num(&mut buf, regions));
    let _ = crate::term::write_all_raw(&err, b" tmp=");
    let _ = crate::term::write_all_raw(&err, write_num(&mut buf, tmp));
    if let Some(loc) = info.location() {
        let _ = crate::term::write_all_raw(&err, b" konum=");
        let _ = crate::term::write_all_raw(&err, loc.file().as_bytes());
        let _ = crate::term::write_all_raw(&err, b":");
        let _ = crate::term::write_all_raw(&err, write_num(&mut buf, loc.line() as usize));
    }
    let _ = crate::term::write_all_raw(&err, b"\n");
    IN_HOOK.store(false, Ordering::SeqCst);
}

/// Panik hook'unu kurar. `main`'in ilk satırında, hiçbir sır oluşmadan çağrılır. `panic=abort`
/// altında hook döndükten sonra çalışma zamanı abort eder; Drop'lar çalışmaz.
pub fn install_panic_hook() {
    std::panic::set_hook(Box::new(hook_body));
}

#[cfg(unix)]
mod unix {
    use std::io;

    /// Adım 2: `RLIMIT_CORE = 0`.
    pub(super) fn disable_core_dumps() -> io::Result<()> {
        let lim = libc::rlimit {
            rlim_cur: 0,
            rlim_max: 0,
        };
        // SAFETY: `lim` geçerli, tam başlatılmış bir `rlimit`; işaretçi çağrı süresince geçerli;
        // setrlimit yalnızca okur.
        let rc = unsafe { libc::setrlimit(libc::RLIMIT_CORE, &raw const lim) };
        if rc == 0 {
            Ok(())
        } else {
            Err(io::Error::last_os_error())
        }
    }

    /// Adım 3 (yalnızca Linux, best-effort): `PR_SET_DUMPABLE = 0`.
    #[cfg(target_os = "linux")]
    pub(super) fn set_not_dumpable() -> io::Result<()> {
        // SAFETY: prctl(PR_SET_DUMPABLE, 0) bellek işaretçisi almaz; kalan argümanlar yok sayılır.
        let rc = unsafe { libc::prctl(libc::PR_SET_DUMPABLE, 0_i32, 0_i32, 0_i32, 0_i32) };
        if rc == 0 {
            Ok(())
        } else {
            Err(io::Error::last_os_error())
        }
    }

    /// `sysctl hw.memsize` (macOS).
    #[cfg(target_os = "macos")]
    pub(super) fn sysctl_hw_memsize() -> io::Result<u64> {
        let mut value: u64 = 0;
        let mut len: libc::size_t = size_of::<u64>();
        let name = c"hw.memsize";
        // SAFETY: `name` NUL sonlu; `value` için `len` bayt yazılabilir alan var ve `len` doğru
        // başlatılmış; newp = NULL, newlen = 0 (yalnızca okuma).
        let rc = unsafe {
            libc::sysctlbyname(
                name.as_ptr(),
                (&raw mut value).cast::<libc::c_void>(),
                &raw mut len,
                std::ptr::null_mut(),
                0,
            )
        };
        if rc == 0 && len == size_of::<u64>() {
            Ok(value)
        } else if rc == 0 {
            Err(io::Error::other("hw.memsize beklenmeyen uzunlukta"))
        } else {
            Err(io::Error::last_os_error())
        }
    }

    /// `sysconf(_SC_PHYS_PAGES) × sysconf(_SC_PAGESIZE)` (Linux).
    #[cfg(target_os = "linux")]
    pub(super) fn sysconf_phys_pages() -> io::Result<u64> {
        // SAFETY: sysconf bellek işaretçisi almaz; herhangi bir ad ile çağrılabilir.
        let pages = unsafe { libc::sysconf(libc::_SC_PHYS_PAGES) };
        // SAFETY: yukarıdaki ile aynı.
        let page = unsafe { libc::sysconf(libc::_SC_PAGESIZE) };
        if pages < 0 || page < 0 {
            return Err(io::Error::last_os_error());
        }
        let pages = u64::try_from(pages).map_err(io::Error::other)?;
        let page = u64::try_from(page).map_err(io::Error::other)?;
        pages
            .checked_mul(page)
            .ok_or_else(|| io::Error::other("RAM boyutu taştı"))
    }
}

#[cfg(windows)]
mod windows {
    use std::io;
    use windows_sys::Win32::System::Diagnostics::Debug::{SEM_NOGPFAULTERRORBOX, SetErrorMode};
    use windows_sys::Win32::System::LibraryLoader::{
        LOAD_LIBRARY_SEARCH_SYSTEM32, SetDefaultDllDirectories,
    };
    use windows_sys::Win32::System::SystemInformation::{GlobalMemoryStatusEx, MEMORYSTATUSEX};

    /// Adım 0: DLL arama yolunu System32 ile sınırla (geri alınamaz; yalnızca bu sürece uygulanır).
    pub(super) fn restrict_dll_search() -> io::Result<()> {
        // SAFETY: bayrak sabiti geçerli; fonksiyon bellek işaretçisi almaz.
        let ok = unsafe { SetDefaultDllDirectories(LOAD_LIBRARY_SEARCH_SYSTEM32) };
        if ok == 0 {
            Err(io::Error::last_os_error())
        } else {
            Ok(())
        }
    }

    /// Adım 1: çökme iletişim kutusunu kapat.
    pub(super) fn disable_error_dialogs() {
        // SAFETY: SetErrorMode yalnızca bir bayrak alır; önceki modu döndürür, hata üretmez.
        let _prev = unsafe { SetErrorMode(SEM_NOGPFAULTERRORBOX) };
    }

    /// `GlobalMemoryStatusEx().ullTotalPhys`.
    pub(super) fn global_memory_status() -> io::Result<u64> {
        let mut st = MEMORYSTATUSEX {
            dwLength: u32::try_from(size_of::<MEMORYSTATUSEX>()).map_err(io::Error::other)?,
            dwMemoryLoad: 0,
            ullTotalPhys: 0,
            ullAvailPhys: 0,
            ullTotalPageFile: 0,
            ullAvailPageFile: 0,
            ullTotalVirtual: 0,
            ullAvailVirtual: 0,
            ullAvailExtendedVirtual: 0,
        };
        // SAFETY: `st` geçerli ve `dwLength` doğru doldurulmuş; işaretçi çağrı süresince geçerli.
        let ok = unsafe { GlobalMemoryStatusEx(&raw mut st) };
        if ok == 0 {
            Err(io::Error::last_os_error())
        } else {
            Ok(st.ullTotalPhys)
        }
    }
}

#[cfg(test)]
#[allow(clippy::expect_used)]
mod tests {
    use super::*;

    #[test]
    #[cfg_attr(miri, ignore = "FFI; Miri'de çalışmaz (PLAN I3)")]
    fn physical_memory_is_plausible() {
        let bytes = physical_memory_bytes().expect("RAM sorgusu");
        // 256 MiB'tan küçük bir makine beklenmez; taşma/sıfır hatasını yakalar.
        assert!(bytes >= 256 * 1024 * 1024, "RAM = {bytes}");
    }

    #[test]
    #[cfg_attr(miri, ignore = "FFI; Miri'de çalışmaz (PLAN I3)")]
    fn harden_succeeds() {
        harden().expect("harden");
    }

    #[test]
    fn write_num_formats() {
        let mut b = [0u8; 20];
        assert_eq!(write_num(&mut b, 0), b"0");
        assert_eq!(write_num(&mut b, 1234), b"1234");
    }
}
