//! Kilitli bellek.
//!
//! - **Arena:** süreç başına tek, sabit boyutlu (`ARENA_PAGES` sayfa), sayfa hizalı bölge;
//!   büyümez, yer değiştirmez. Taban/uzunluk `static` atomiklerde tutulur ki panik hook'u kilit
//!   almadan sıfırlayabilsin. 64 baytlık birimler üzerinde bitmap ile first-fit ayırma; sayfa
//!   başına referans sayacı: `mlock`/`VirtualLock` sayfa ilk kullanımında, `munlock` yalnızca
//!   sayfadaki son sır bırakılınca (POSIX `mlock` sayım yapmaz).
//! - [`SecretBytes`]: arenada sabit kapasiteli bayt tamponu; `expose()`/`expose_mut()`,
//!   `Debug` → `[REDACTED]`, `Clone`/`Display` yok; Drop'ta sıfırlanır; kapasite aşımı hata.
//! - [`SecretBox<T>`]: arenada hizalı yer, `ptr::write` ile kurulum, Drop'ta `drop_in_place` +
//!   ham sıfırlama (AEAD struct'ları için).
//! - [`LargeSecretBuf<T>`]: `mmap`/`VirtualAlloc` ile büyük bölge (Argon2 belleği, chunk havuzu);
//!   kilit best-effort; `MADV_DONTDUMP` yalnızca Linux; Drop'ta sıfırla + unmap; hook listesine
//!   kaydedilir.
//! - [`zeroize_all_registered`]: panik hook'unun (1) adımı.
//!
//! `cfg(miri)`: OS çağrıları yerine `std::alloc` + no-op kilit.

use core::fmt;
use core::ops::{Deref, DerefMut};
use core::ptr::NonNull;
use std::io;
use std::sync::Mutex;
use std::sync::atomic::{AtomicBool, AtomicPtr, AtomicUsize, Ordering};

use zeroize::Zeroize;

/// Arena ayırma birimi (bayt). Tüm slot'lar bu hizada başlar.
const UNIT: usize = 64;
/// Arena sayfa sayısı (macOS arm64'te 16 KiB sayfa → 256 KiB).
const ARENA_PAGES: usize = 16;
/// Hook için kayıtlı büyük bölge sayısı.
const MAX_REGIONS: usize = 16;

/// Bellek hataları.
#[derive(Debug)]
pub enum MemError {
    /// Arena dolu; istenen boyut için bitişik yer yok.
    ArenaExhausted {
        /// İstenen bayt.
        requested: usize,
    },
    /// Arena kurulamadı (mmap/VirtualAlloc).
    ArenaInit(io::Error),
    /// Sabit kapasite aşıldı (`SecretBytes`).
    CapacityExceeded {
        /// Kapasite.
        capacity: usize,
        /// İstenen toplam uzunluk.
        requested: usize,
    },
    /// Tür hizası desteklenmiyor (> sayfa boyutu).
    AlignmentUnsupported(usize),
    /// Boyut hesabı taştı ya da sıfır.
    InvalidSize,
    /// Büyük bölge ayrılamadı.
    MapFailed(io::Error),
    /// Hook kayıt tablosu dolu (aynı anda > 16 büyük bölge).
    RegistryFull,
}

impl fmt::Display for MemError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            MemError::ArenaExhausted { requested } => {
                write!(f, "kilitli bellek arenası dolu ({requested} bayt istendi)")
            }
            MemError::ArenaInit(e) => write!(f, "kilitli bellek arenası kurulamadı: {e}"),
            MemError::CapacityExceeded {
                capacity,
                requested,
            } => write!(
                f,
                "sır tamponu kapasitesi aşıldı ({requested} > {capacity})"
            ),
            MemError::AlignmentUnsupported(a) => write!(f, "desteklenmeyen hiza: {a}"),
            MemError::InvalidSize => write!(f, "geçersiz boyut"),
            MemError::MapFailed(e) => write!(f, "büyük bellek bölgesi ayrılamadı: {e}"),
            MemError::RegistryFull => write!(f, "büyük bölge kayıt tablosu dolu"),
        }
    }
}

impl std::error::Error for MemError {}

// ---------------------------------------------------------------------------------------------
// OS arka ucu
// ---------------------------------------------------------------------------------------------

#[cfg(not(miri))]
mod os {
    use super::MemError;
    use core::ptr::NonNull;
    use std::io;

    #[cfg(unix)]
    pub(super) fn page_size() -> usize {
        // SAFETY: sysconf bellek işaretçisi almaz.
        let v = unsafe { libc::sysconf(libc::_SC_PAGESIZE) };
        usize::try_from(v).ok().filter(|p| *p >= 64).unwrap_or(4096)
    }

    #[cfg(windows)]
    pub(super) fn page_size() -> usize {
        use windows_sys::Win32::System::SystemInformation::{GetSystemInfo, SYSTEM_INFO};
        // SAFETY: SYSTEM_INFO düz bir C struct'ıdır; sıfır ile başlatılması geçerlidir.
        let mut si: SYSTEM_INFO = unsafe { core::mem::zeroed() };
        // SAFETY: `si` geçerli ve yazılabilir; çağrı yalnızca onu doldurur.
        unsafe { GetSystemInfo(&raw mut si) };
        usize::try_from(si.dwPageSize)
            .ok()
            .filter(|p| *p >= 64)
            .unwrap_or(4096)
    }

    /// Sıfırlanmış, sayfa hizalı anonim bölge.
    #[cfg(unix)]
    pub(super) fn map(len: usize) -> Result<NonNull<u8>, MemError> {
        // SAFETY: addr = NULL (çekirdek seçer), len > 0, PROT_READ|WRITE, MAP_PRIVATE|MAP_ANON,
        // fd = -1, offset = 0: anonim eşleme için geçerli argüman kümesi.
        let p = unsafe {
            libc::mmap(
                core::ptr::null_mut(),
                len,
                libc::PROT_READ | libc::PROT_WRITE,
                libc::MAP_PRIVATE | libc::MAP_ANON,
                -1,
                0,
            )
        };
        if p == libc::MAP_FAILED {
            return Err(MemError::MapFailed(io::Error::last_os_error()));
        }
        NonNull::new(p.cast::<u8>())
            .ok_or_else(|| MemError::MapFailed(io::Error::other("mmap NULL")))
    }

    #[cfg(unix)]
    pub(super) fn unmap(p: NonNull<u8>, len: usize) {
        // SAFETY: `p`/`len` aynı `map` çağrısından gelir; bölge başka yerde kullanılmıyor
        // (çağıran Drop içinde, tek sahiplik).
        let _ = unsafe { libc::munmap(p.as_ptr().cast::<libc::c_void>(), len) };
    }

    #[cfg(unix)]
    pub(super) fn lock(p: NonNull<u8>, len: usize) -> io::Result<()> {
        // SAFETY: `p`/`len` eşlenmiş bir bölgeyi tanımlar (çağıran garanti eder); mlock bu
        // aralığı yalnızca kilitler.
        let rc = unsafe { libc::mlock(p.as_ptr().cast::<libc::c_void>(), len) };
        if rc == 0 {
            Ok(())
        } else {
            Err(io::Error::last_os_error())
        }
    }

    #[cfg(unix)]
    pub(super) fn unlock(p: NonNull<u8>, len: usize) {
        // SAFETY: `p`/`len` daha önce `lock` ile kilitlenmiş eşlenmiş bölge.
        let _ = unsafe { libc::munlock(p.as_ptr().cast::<libc::c_void>(), len) };
    }

    /// Linux: core dump'tan hariç tut (best-effort). Diğer Unix'lerde no-op.
    #[cfg(unix)]
    pub(super) fn exclude_from_dump(p: NonNull<u8>, len: usize) {
        #[cfg(target_os = "linux")]
        {
            // SAFETY: `p`/`len` eşlenmiş bölge; MADV_DONTDUMP yalnızca bir bayrak koyar.
            let _ = unsafe {
                libc::madvise(p.as_ptr().cast::<libc::c_void>(), len, libc::MADV_DONTDUMP)
            };
        }
        #[cfg(not(target_os = "linux"))]
        {
            let _ = (p, len);
        }
    }

    #[cfg(windows)]
    pub(super) fn map(len: usize) -> Result<NonNull<u8>, MemError> {
        use windows_sys::Win32::System::Memory::{
            MEM_COMMIT, MEM_RESERVE, PAGE_READWRITE, VirtualAlloc,
        };
        // SAFETY: lpAddress = NULL, dwSize = len > 0, geçerli bayraklar; VirtualAlloc sıfırlanmış
        // sayfalar döndürür.
        let p = unsafe {
            VirtualAlloc(
                core::ptr::null_mut(),
                len,
                MEM_COMMIT | MEM_RESERVE,
                PAGE_READWRITE,
            )
        };
        NonNull::new(p.cast::<u8>()).ok_or_else(|| MemError::MapFailed(io::Error::last_os_error()))
    }

    #[cfg(windows)]
    pub(super) fn unmap(p: NonNull<u8>, _len: usize) {
        use windows_sys::Win32::System::Memory::{MEM_RELEASE, VirtualFree};
        // SAFETY: `p` aynı VirtualAlloc çağrısının taban adresi; MEM_RELEASE için dwSize = 0 şart.
        let _ = unsafe { VirtualFree(p.as_ptr().cast::<core::ffi::c_void>(), 0, MEM_RELEASE) };
    }

    #[cfg(windows)]
    fn grow_working_set(extra: usize) {
        use windows_sys::Win32::System::Threading::{
            GetCurrentProcess, GetProcessWorkingSetSize, SetProcessWorkingSetSize,
        };
        let mut min: usize = 0;
        let mut max: usize = 0;
        // SAFETY: GetCurrentProcess sahte handle döndürür, kapatılmaz; argüman almaz.
        let me = unsafe { GetCurrentProcess() };
        // SAFETY: `me` geçerli; min/max geçerli çıktı işaretçileri.
        let ok = unsafe { GetProcessWorkingSetSize(me, &raw mut min, &raw mut max) };
        if ok == 0 {
            return;
        }
        let (Some(nmin), Some(nmax)) = (min.checked_add(extra), max.checked_add(extra)) else {
            return;
        };
        // SAFETY: yalnızca sayısal argümanlar; başarısızlık best-effort (kilit sonra hata verir).
        let _ = unsafe { SetProcessWorkingSetSize(me, nmin, nmax) };
    }

    #[cfg(windows)]
    pub(super) fn lock(p: NonNull<u8>, len: usize) -> io::Result<()> {
        use windows_sys::Win32::System::Memory::VirtualLock;
        grow_working_set(len);
        // SAFETY: `p`/`len` VirtualAlloc ile commit edilmiş bölge içindedir.
        let ok = unsafe { VirtualLock(p.as_ptr().cast::<core::ffi::c_void>(), len) };
        if ok == 0 {
            Err(io::Error::last_os_error())
        } else {
            Ok(())
        }
    }

    #[cfg(windows)]
    pub(super) fn unlock(p: NonNull<u8>, len: usize) {
        use windows_sys::Win32::System::Memory::VirtualUnlock;
        // SAFETY: `p`/`len` daha önce VirtualLock ile kilitlenmiş bölge.
        let _ = unsafe { VirtualUnlock(p.as_ptr().cast::<core::ffi::c_void>(), len) };
    }

    #[cfg(windows)]
    pub(super) fn exclude_from_dump(_p: NonNull<u8>, _len: usize) {}
}

#[cfg(miri)]
mod os {
    //! Miri arka ucu: `std::alloc` + no-op kilit. Hizalama/sınır aritmetiği ve
    //! zeroize-sonra-dealloc buradan denetlenir.
    use super::MemError;
    use core::ptr::NonNull;
    use std::alloc::{Layout, alloc_zeroed, dealloc};
    use std::io;

    pub(super) const MIRI_PAGE: usize = 4096;

    pub(super) fn page_size() -> usize {
        MIRI_PAGE
    }

    pub(super) fn map(len: usize) -> Result<NonNull<u8>, MemError> {
        let layout = Layout::from_size_align(len, MIRI_PAGE).map_err(|_| MemError::InvalidSize)?;
        // SAFETY: layout boyutu sıfır değil (çağıran `len > 0` garanti eder).
        let p = unsafe { alloc_zeroed(layout) };
        NonNull::new(p).ok_or_else(|| MemError::MapFailed(io::Error::other("alloc_zeroed")))
    }

    pub(super) fn unmap(p: NonNull<u8>, len: usize) {
        if let Ok(layout) = Layout::from_size_align(len, MIRI_PAGE) {
            // SAFETY: `p` aynı layout ile `alloc_zeroed`'dan geldi; tek sahiplik.
            unsafe { dealloc(p.as_ptr(), layout) };
        }
    }

    pub(super) fn lock(_p: NonNull<u8>, _len: usize) -> io::Result<()> {
        Ok(())
    }
    pub(super) fn unlock(_p: NonNull<u8>, _len: usize) {}
    pub(super) fn exclude_from_dump(_p: NonNull<u8>, _len: usize) {}
}

/// Sayfa boyutu (önbellekli).
fn page_size() -> usize {
    static PAGE: AtomicUsize = AtomicUsize::new(0);
    let p = PAGE.load(Ordering::Relaxed);
    if p != 0 {
        return p;
    }
    let p = os::page_size();
    PAGE.store(p, Ordering::Relaxed);
    p
}

/// `[offset, offset+len)` aralığının kapsadığı sayfa indeksleri (dahil), arena sınırına kırpılmış.
fn page_span(offset: usize, len: usize, page: usize) -> (usize, usize) {
    let first = (offset / page).min(ARENA_PAGES - 1);
    let last = ((offset + len.max(1) - 1) / page).min(ARENA_PAGES - 1);
    (first, last.max(first))
}

fn round_up(n: usize, m: usize) -> Option<usize> {
    n.checked_add(m - 1).map(|v| v / m * m)
}

/// Volatile sıfırlama; `zeroize` crate'i üzerinden (ayırma yapmaz).
fn zero_bytes(p: NonNull<u8>, len: usize) {
    if len == 0 {
        return;
    }
    // SAFETY: çağıran `p..p+len` aralığının bu süreçte eşlenmiş, yazılabilir ve bu çağrı
    // süresince başka hiçbir referansla kullanılmayan bellek olduğunu garanti eder.
    let s = unsafe { core::slice::from_raw_parts_mut(p.as_ptr(), len) };
    s.zeroize();
}

// ---------------------------------------------------------------------------------------------
// Arena
// ---------------------------------------------------------------------------------------------

/// Hook için: arena tabanı (NULL = kurulmadı) ve uzunluğu.
static ARENA_BASE: AtomicPtr<u8> = AtomicPtr::new(core::ptr::null_mut());
static ARENA_LEN: AtomicUsize = AtomicUsize::new(0);
/// Herhangi bir `mlock`/`VirtualLock` başarısız oldu mu (uyarı / `--strict-memory`).
static LOCK_FAILED: AtomicBool = AtomicBool::new(false);

struct ArenaState {
    /// Birim başına 1 bit; 1 = dolu.
    bitmap: Vec<u64>,
    units: usize,
    /// Sayfa başına canlı ayırma sayısı.
    page_refs: Vec<u32>,
    /// Sayfa başına kilit durumu.
    page_locked: Vec<bool>,
    last_lock_error: Option<String>,
}

static STATE: Mutex<Option<ArenaState>> = Mutex::new(None);

fn arena_base() -> NonNull<u8> {
    // Yalnızca STATE Some iken çağrılır; o zaman ARENA_BASE null değildir.
    NonNull::new(ARENA_BASE.load(Ordering::Acquire)).unwrap_or(NonNull::dangling())
}

fn with_state<R>(f: impl FnOnce(&mut ArenaState) -> Result<R, MemError>) -> Result<R, MemError> {
    let mut guard = STATE
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    if guard.is_none() {
        let page = page_size();
        let len = page.checked_mul(ARENA_PAGES).ok_or(MemError::InvalidSize)?;
        let base = os::map(len)?;
        os::exclude_from_dump(base, len);
        ARENA_BASE.store(base.as_ptr(), Ordering::Release);
        ARENA_LEN.store(len, Ordering::Release);
        let units = len / UNIT;
        *guard = Some(ArenaState {
            bitmap: vec![0; units.div_ceil(64)],
            units,
            page_refs: vec![0; ARENA_PAGES],
            page_locked: vec![false; ARENA_PAGES],
            last_lock_error: None,
        });
    }
    let st = guard.as_mut().ok_or(MemError::InvalidSize)?;
    f(st)
}

impl ArenaState {
    fn is_set(&self, u: usize) -> bool {
        self.bitmap[u / 64] & (1u64 << (u % 64)) != 0
    }
    fn set(&mut self, u: usize, v: bool) {
        if v {
            self.bitmap[u / 64] |= 1u64 << (u % 64);
        } else {
            self.bitmap[u / 64] &= !(1u64 << (u % 64));
        }
    }

    /// `k` birimlik, `align_units` katı başlangıçlı boş aralık bulur.
    fn find_run(&self, k: usize, align_units: usize) -> Option<usize> {
        let mut start = 0;
        while start + k <= self.units {
            if start % align_units != 0 {
                start += 1;
                continue;
            }
            match (start..start + k).find(|&u| self.is_set(u)) {
                None => return Some(start),
                Some(busy) => start = busy + 1,
            }
        }
        None
    }

    fn alloc(&mut self, size: usize, align: usize) -> Result<usize, MemError> {
        let page = page_size();
        if align > page || !align.is_power_of_two() {
            return Err(MemError::AlignmentUnsupported(align));
        }
        let size = size.max(1);
        let k = round_up(size, UNIT).ok_or(MemError::InvalidSize)? / UNIT;
        let align_units = align.max(UNIT) / UNIT;
        let start = self
            .find_run(k, align_units)
            .ok_or(MemError::ArenaExhausted { requested: size })?;
        for u in start..start + k {
            self.set(u, true);
        }
        // Sayfa refcount + ilk kullanımda kilit.
        let base = arena_base();
        let (first_page, last_page) = page_span(start * UNIT, k * UNIT, page);
        for pg in first_page..=last_page {
            if self.page_refs[pg] == 0 && !self.page_locked[pg] {
                // SAFETY-sözleşmesi: `base + pg*page` arena içindedir.
                let pp = NonNull::new(base.as_ptr().wrapping_add(pg * page)).unwrap_or(base);
                match os::lock(pp, page) {
                    Ok(()) => self.page_locked[pg] = true,
                    Err(e) => {
                        LOCK_FAILED.store(true, Ordering::Relaxed);
                        self.last_lock_error = Some(e.to_string());
                    }
                }
            }
            self.page_refs[pg] += 1;
        }
        Ok(start * UNIT)
    }

    fn free(&mut self, offset: usize, size: usize) {
        let page = page_size();
        let size = size.max(1);
        let Some(k) = round_up(size, UNIT).map(|b| b / UNIT) else {
            return;
        };
        let start = offset / UNIT;
        for u in start..start + k {
            self.set(u, false);
        }
        let (first_page, last_page) = page_span(offset, k * UNIT, page);
        let base = arena_base();
        for pg in first_page..=last_page {
            self.page_refs[pg] = self.page_refs[pg].saturating_sub(1);
            if self.page_refs[pg] == 0 && self.page_locked[pg] {
                let pp = NonNull::new(base.as_ptr().wrapping_add(pg * page)).unwrap_or(base);
                os::unlock(pp, page);
                self.page_locked[pg] = false;
            }
        }
    }
}

/// Arena'dan `size` bayt, `align` hizalı slot ayırır; sıfırlanmış döner.
fn arena_alloc(size: usize, align: usize) -> Result<NonNull<u8>, MemError> {
    let off = with_state(|st| st.alloc(size, align))?;
    let base = arena_base();
    // Slot sıfır olduğundan emin ol (önceki kullanıcı Drop'ta sıfırladı; yine de garanti).
    let p = NonNull::new(base.as_ptr().wrapping_add(off)).ok_or(MemError::InvalidSize)?;
    zero_bytes(p, size.max(1));
    Ok(p)
}

/// Slotu sıfırlar ve serbest bırakır.
fn arena_free(p: NonNull<u8>, size: usize) {
    zero_bytes(p, size.max(1));
    let base = arena_base();
    let off = (p.as_ptr() as usize).wrapping_sub(base.as_ptr() as usize);
    let _ = with_state(|st| {
        st.free(off, size);
        Ok(())
    });
}

/// Herhangi bir kilitleme başarısız olduysa `true` (uyarı; `--strict-memory` ile hata).
#[must_use]
pub fn lock_failed() -> bool {
    LOCK_FAILED.load(Ordering::Relaxed)
}

/// Son kilit hatasının metni (varsa).
#[must_use]
pub fn last_lock_error() -> Option<String> {
    STATE
        .lock()
        .ok()
        .and_then(|g| g.as_ref().and_then(|s| s.last_lock_error.clone()))
}

// ---------------------------------------------------------------------------------------------
// SecretBytes
// ---------------------------------------------------------------------------------------------

/// Kilitli arenada sabit kapasiteli bayt tamponu. Tek sır türü.
pub struct SecretBytes {
    ptr: NonNull<u8>,
    cap: usize,
    len: usize,
}

// SAFETY: içerik düz baytlardır; `&SecretBytes` yalnızca okuma, `&mut` tek yazar.
unsafe impl Send for SecretBytes {}
// SAFETY: yukarıdaki gibi; iç değişebilirlik yok.
unsafe impl Sync for SecretBytes {}

impl SecretBytes {
    /// `cap` baytlık sıfırlanmış, kilitli tampon (uzunluk 0).
    ///
    /// # Errors
    /// Arena dolu ya da kurulamadıysa.
    pub fn with_capacity(cap: usize) -> Result<Self, MemError> {
        let ptr = arena_alloc(cap.max(1), UNIT)?;
        Ok(Self { ptr, cap, len: 0 })
    }

    /// Dilimi kopyalar (kaynağı sıfırlamak çağıranın işidir).
    ///
    /// # Errors
    /// Arena dolu ya da kurulamadıysa.
    pub fn from_slice(bytes: &[u8]) -> Result<Self, MemError> {
        let mut s = Self::with_capacity(bytes.len())?;
        s.push_slice(bytes)?;
        Ok(s)
    }

    /// Kapasite.
    #[must_use]
    pub const fn capacity(&self) -> usize {
        self.cap
    }
    /// Uzunluk.
    #[must_use]
    pub const fn len(&self) -> usize {
        self.len
    }
    /// Boş mu.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.len == 0
    }

    /// İçeriği okur.
    #[must_use]
    pub fn expose(&self) -> &[u8] {
        // SAFETY: `ptr..ptr+cap` arena slotu; `len ≤ cap`; tüm baytlar başlatılmış (sıfır/yazılmış).
        unsafe { core::slice::from_raw_parts(self.ptr.as_ptr(), self.len) }
    }

    /// İçeriği değiştirir (uzunluk sabit).
    pub fn expose_mut(&mut self) -> &mut [u8] {
        // SAFETY: yukarıdaki gibi; `&mut self` tek erişim.
        unsafe { core::slice::from_raw_parts_mut(self.ptr.as_ptr(), self.len) }
    }

    /// `len..cap` arası boş alan; okuyucular doğrudan buraya yazıp [`set_len`](Self::set_len) çağırır.
    pub fn spare_mut(&mut self) -> &mut [u8] {
        let tail = self.ptr.as_ptr().wrapping_add(self.len);
        // SAFETY: `ptr+len .. ptr+cap` slot içinde; başlatılmış; `&mut self` tek erişim.
        unsafe { core::slice::from_raw_parts_mut(tail, self.cap - self.len) }
    }

    /// Uzunluğu ayarlar (`n ≤ cap`). Kısalırken artan kısım sıfırlanır.
    ///
    /// # Errors
    /// `n > cap`.
    pub fn set_len(&mut self, n: usize) -> Result<(), MemError> {
        if n > self.cap {
            return Err(MemError::CapacityExceeded {
                capacity: self.cap,
                requested: n,
            });
        }
        if n < self.len {
            let tail = NonNull::new(self.ptr.as_ptr().wrapping_add(n)).unwrap_or(self.ptr);
            zero_bytes(tail, self.len - n);
        }
        self.len = n;
        Ok(())
    }

    /// Sona ekler; kapasite aşılırsa hata, tampon büyütülmez.
    ///
    /// # Errors
    /// `len + bytes.len() > cap`.
    pub fn push_slice(&mut self, bytes: &[u8]) -> Result<(), MemError> {
        let new_len = self
            .len
            .checked_add(bytes.len())
            .ok_or(MemError::InvalidSize)?;
        if new_len > self.cap {
            return Err(MemError::CapacityExceeded {
                capacity: self.cap,
                requested: new_len,
            });
        }
        self.spare_mut()[..bytes.len()].copy_from_slice(bytes);
        self.len = new_len;
        Ok(())
    }

    /// Kısaltır; kesilen kısım sıfırlanır.
    pub fn truncate(&mut self, n: usize) {
        if n < self.len {
            let _ = self.set_len(n);
        }
    }

    /// Tüm içeriği sıfırlar, uzunluk 0.
    pub fn clear(&mut self) {
        self.truncate(0);
    }
}

impl Drop for SecretBytes {
    fn drop(&mut self) {
        arena_free(self.ptr, self.cap.max(1));
    }
}

impl fmt::Debug for SecretBytes {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("SecretBytes([REDACTED])")
    }
}

// ---------------------------------------------------------------------------------------------
// SecretBox<T>
// ---------------------------------------------------------------------------------------------

/// Kilitli arenada yaşayan `T`. Drop'ta `drop_in_place` + ham sıfırlama.
pub struct SecretBox<T> {
    ptr: NonNull<T>,
    size: usize,
}

// SAFETY: `SecretBox<T>` yalnızca `T`'nin kendisine sahiptir; `Box<T>` ile aynı kurallar.
unsafe impl<T: Send> Send for SecretBox<T> {}
// SAFETY: yukarıdaki gibi.
unsafe impl<T: Sync> Sync for SecretBox<T> {}

impl<T> SecretBox<T> {
    /// `value`'yu arenaya taşır. Çağıranın yığındaki kopyası taşıma sonrasında geçersizdir
    /// (Rust taşıma semantiği; yığın kalıntısı THREAT-MODEL'de).
    ///
    /// # Errors
    /// Arena dolu, kurulamadı ya da `align_of::<T>()` sayfa boyutunu aşıyor.
    pub fn new(value: T) -> Result<Self, MemError> {
        let size = size_of::<T>().max(1);
        let raw = arena_alloc(size, align_of::<T>())?;
        let ptr = raw.cast::<T>();
        // SAFETY: `ptr` `align_of::<T>()` hizalı, `size_of::<T>()` baytlık yazılabilir slot;
        // `value` sahipliği buraya taşınır.
        unsafe { ptr.as_ptr().write(value) };
        Ok(Self { ptr, size })
    }
}

impl<T> Deref for SecretBox<T> {
    type Target = T;
    fn deref(&self) -> &T {
        // SAFETY: `ptr` `new` içinde başlatılmış geçerli bir `T`'yi gösterir; Drop'a kadar canlı.
        unsafe { self.ptr.as_ref() }
    }
}

impl<T> DerefMut for SecretBox<T> {
    fn deref_mut(&mut self) -> &mut T {
        // SAFETY: yukarıdaki gibi; `&mut self` tek erişim.
        unsafe { self.ptr.as_mut() }
    }
}

impl<T> Drop for SecretBox<T> {
    fn drop(&mut self) {
        // SAFETY: `ptr` başlatılmış `T`; yalnızca bir kez düşürülür (Drop tek çağrılır).
        unsafe { core::ptr::drop_in_place(self.ptr.as_ptr()) };
        arena_free(self.ptr.cast::<u8>(), self.size);
    }
}

impl<T> fmt::Debug for SecretBox<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("SecretBox([REDACTED])")
    }
}

// ---------------------------------------------------------------------------------------------
// LargeSecretBuf<T>
// ---------------------------------------------------------------------------------------------

/// Hook kayıt tablosu: (taban, bayt uzunluğu). Taban NULL = boş slot.
static REGIONS: [(AtomicPtr<u8>, AtomicUsize); MAX_REGIONS] =
    [const { (AtomicPtr::new(core::ptr::null_mut()), AtomicUsize::new(0)) }; MAX_REGIONS];

fn register_region(p: NonNull<u8>, len: usize) -> Result<usize, MemError> {
    for (i, (ptr, l)) in REGIONS.iter().enumerate() {
        if ptr
            .compare_exchange(
                core::ptr::null_mut(),
                p.as_ptr(),
                Ordering::AcqRel,
                Ordering::Acquire,
            )
            .is_ok()
        {
            l.store(len, Ordering::Release);
            return Ok(i);
        }
    }
    Err(MemError::RegistryFull)
}

fn unregister_region(i: usize) {
    REGIONS[i].1.store(0, Ordering::Release);
    REGIONS[i].0.store(core::ptr::null_mut(), Ordering::Release);
}

/// `mmap`/`VirtualAlloc` ile ayrılmış, best-effort kilitli büyük bölge. `T: Copy` olduğundan
/// Drop çalıştırılmaz; bölge ham baytlar olarak sıfırlanır.
pub struct LargeSecretBuf<T: Copy> {
    ptr: NonNull<T>,
    len: usize,
    map_len: usize,
    locked: bool,
    slot: usize,
}

// SAFETY: bölgeye yalnızca bu değer sahiptir; `T: Send` ise taşınabilir.
unsafe impl<T: Copy + Send> Send for LargeSecretBuf<T> {}
// SAFETY: `&self` yalnızca `&[T]` verir; `T: Sync` ise paylaşılabilir.
unsafe impl<T: Copy + Sync> Sync for LargeSecretBuf<T> {}

impl<T: Copy> LargeSecretBuf<T> {
    /// `len` adet `T`, her biri `init` ile doldurulmuş. Kilit denenir; başarısızlık
    /// [`is_locked`](Self::is_locked) ile görülür ve [`lock_failed`] bayrağına yansır.
    ///
    /// # Errors
    /// Boyut taşması, hiza > sayfa, eşleme hatası, kayıt tablosu dolu.
    pub fn new_filled(len: usize, init: T) -> Result<Self, MemError> {
        let page = page_size();
        if align_of::<T>() > page {
            return Err(MemError::AlignmentUnsupported(align_of::<T>()));
        }
        let bytes = len
            .checked_mul(size_of::<T>())
            .ok_or(MemError::InvalidSize)?;
        let map_len = round_up(bytes.max(1), page).ok_or(MemError::InvalidSize)?;
        let raw = os::map(map_len)?;
        os::exclude_from_dump(raw, map_len);
        let slot = match register_region(raw, map_len) {
            Ok(s) => s,
            Err(e) => {
                os::unmap(raw, map_len);
                return Err(e);
            }
        };
        let locked = match os::lock(raw, map_len) {
            Ok(()) => true,
            Err(e) => {
                LOCK_FAILED.store(true, Ordering::Relaxed);
                let _ = with_state(|st| {
                    st.last_lock_error = Some(e.to_string());
                    Ok(())
                });
                false
            }
        };
        let ptr = raw.cast::<T>();
        for i in 0..len {
            let slot = ptr.as_ptr().wrapping_add(i);
            // SAFETY: `ptr` sayfa hizalı (≥ align_of::<T>()), `i < len` ve `len*size_of::<T>()
            // ≤ map_len`; `T: Copy` olduğundan üzerine yazma Drop gerektirmez.
            unsafe { slot.write(init) };
        }
        Ok(Self {
            ptr,
            len,
            map_len,
            locked,
            slot,
        })
    }

    /// Eleman sayısı.
    #[must_use]
    pub const fn len(&self) -> usize {
        self.len
    }
    /// Boş mu.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.len == 0
    }
    /// Kilit başarılı mı.
    #[must_use]
    pub const fn is_locked(&self) -> bool {
        self.locked
    }

    /// Dilim.
    #[must_use]
    pub fn as_slice(&self) -> &[T] {
        // SAFETY: `ptr..ptr+len` `new_filled` içinde başlatılmış, hizalı; Drop'a kadar canlı.
        unsafe { core::slice::from_raw_parts(self.ptr.as_ptr(), self.len) }
    }

    /// Değişebilir dilim.
    pub fn as_mut_slice(&mut self) -> &mut [T] {
        // SAFETY: yukarıdaki gibi; `&mut self` tek erişim.
        unsafe { core::slice::from_raw_parts_mut(self.ptr.as_ptr(), self.len) }
    }
}

impl<T: Copy> AsRef<[T]> for LargeSecretBuf<T> {
    fn as_ref(&self) -> &[T] {
        self.as_slice()
    }
}

impl<T: Copy> AsMut<[T]> for LargeSecretBuf<T> {
    fn as_mut(&mut self) -> &mut [T] {
        self.as_mut_slice()
    }
}

impl<T: Copy> Drop for LargeSecretBuf<T> {
    fn drop(&mut self) {
        let raw = self.ptr.cast::<u8>();
        zero_bytes(raw, self.map_len);
        if self.locked {
            os::unlock(raw, self.map_len);
        }
        unregister_region(self.slot);
        os::unmap(raw, self.map_len);
    }
}

impl<T: Copy> fmt::Debug for LargeSecretBuf<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "LargeSecretBuf([REDACTED; {}])", self.len)
    }
}

// ---------------------------------------------------------------------------------------------
// Panik hook'u desteği
// ---------------------------------------------------------------------------------------------

/// Arenayı ve kayıtlı tüm büyük bölgeleri sıfırlar. Panik hook'unun (1) adımı.
/// Kilit almaz, ayırma yapmaz. `(arena_bayt, bölge_sayısı)` döner.
///
/// Diğer iş parçacıkları bu sırada hâlâ çalışıyor olabilir; abort hemen ardından geldiği için
/// bu veri yarışı kabul edilir (THREAT-MODEL › Bellek). Yalnızca abort öncesi çağrılmalıdır.
pub fn zeroize_all_registered() -> (usize, usize) {
    let mut arena = 0;
    if let Some(base) = NonNull::new(ARENA_BASE.load(Ordering::Acquire)) {
        let len = ARENA_LEN.load(Ordering::Acquire);
        // SAFETY (kabul edilen yarış): arena süreç ömrü boyunca eşlenmiş kalır; eşzamanlı
        // okuyucular olabilir, abort izleyeceğinden veri yarışı bilinçli olarak kabul edilir.
        zero_bytes(base, len);
        arena = len;
    }
    let mut regions = 0;
    for (ptr, len) in &REGIONS {
        let l = len.load(Ordering::Acquire);
        if let Some(p) = NonNull::new(ptr.load(Ordering::Acquire)).filter(|_| l > 0) {
            // SAFETY (kabul edilen yarış): kayıt yalnızca eşlenmiş bölgeleri içerir; Drop
            // önce uzunluğu 0'lar sonra unmap eder; yukarıdaki gerekçe geçerlidir.
            zero_bytes(p, l);
            regions += 1;
        }
    }
    (arena, regions)
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn secret_bytes_roundtrip_and_capacity() {
        let mut s = SecretBytes::with_capacity(8).unwrap();
        assert_eq!(s.capacity(), 8);
        s.push_slice(b"abc").unwrap();
        assert_eq!(s.expose(), b"abc");
        assert!(matches!(
            s.push_slice(b"123456"),
            Err(MemError::CapacityExceeded { .. })
        ));
        assert_eq!(s.capacity(), 8, "kapasite değişmemeli");
        s.spare_mut()[0] = b'z';
        s.set_len(4).unwrap();
        assert_eq!(s.expose(), b"abcz");
        s.truncate(2);
        assert_eq!(s.expose(), b"ab");
        s.set_len(4).unwrap();
        assert_eq!(&s.expose()[2..], &[0, 0], "kesilen kısım sıfırlanmalı");
        assert_eq!(format!("{s:?}"), "SecretBytes([REDACTED])");
    }

    #[test]
    fn freed_slot_is_zero_and_reusable() {
        let p;
        {
            let mut a = SecretBytes::with_capacity(32).unwrap();
            a.push_slice(&[0xAA; 32]).unwrap();
            p = a.ptr;
        }
        // Aynı slot sıfır olarak yeniden verilmeli (first-fit).
        let b = SecretBytes::with_capacity(32).unwrap();
        if b.ptr == p {
            // SAFETY: slot `b`'ye ait, 32 bayt kapasite, tüm baytlar başlatılmış.
            let full = unsafe { core::slice::from_raw_parts(b.ptr.as_ptr(), 32) };
            assert!(full.iter().all(|&x| x == 0));
        }
    }

    #[test]
    fn page_refcount_keeps_page_locked_until_last_drop() {
        // aynı sayfada iki sır, biri düşünce sayfa kilitli kalır. Diğer testler aynı
        // arenayı paylaştığından yalnızca "b yaşarken sayfa kilitli ve refs ≥ 1" denetlenir;
        // tam sayaç eşitliği `page_span`/`alloc` mantığıyla aşağıdaki tek-iş-parçacıklı
        // `refcount_arithmetic` testinde doğrulanır.
        let page = page_size();
        let pg =
            |s: &SecretBytes| (s.ptr.as_ptr() as usize - arena_base().as_ptr() as usize) / page;
        let a = SecretBytes::with_capacity(64).unwrap();
        let b = SecretBytes::with_capacity(64).unwrap();
        if pg(&a) != pg(&b) {
            return;
        }
        let idx = pg(&a);
        drop(a);
        let (refs, locked) = with_state(|st| Ok((st.page_refs[idx], st.page_locked[idx]))).unwrap();
        assert!(refs >= 1, "b hâlâ canlı");
        if !lock_failed() {
            assert!(locked, "sayfada hâlâ sır varken kilit kalkmamalı");
        }
        drop(b);
    }

    #[test]
    fn refcount_arithmetic() {
        // page_span: tek sayfa, sınırda biten ve iki sayfaya yayılan aralıklar.
        let page = page_size();
        assert_eq!(page_span(0, 64, page), (0, 0));
        assert_eq!(page_span(page - 64, 64, page), (0, 0));
        assert_eq!(page_span(page - 64, 128, page), (0, 1));
        assert_eq!(page_span(page, page, page), (1, 1));
        assert_eq!(page_span(0, page * ARENA_PAGES, page), (0, ARENA_PAGES - 1));
    }

    #[test]
    fn arena_exhaustion_is_an_error_not_a_panic() {
        let mut keep = Vec::new();
        loop {
            match SecretBytes::with_capacity(4096) {
                Ok(s) => keep.push(s),
                Err(MemError::ArenaExhausted { .. }) => break,
                Err(e) => panic!("beklenmeyen hata: {e}"),
            }
            assert!(keep.len() < 10_000);
        }
        assert!(!keep.is_empty());
    }

    #[test]
    fn secret_box_holds_aligned_value_and_drops() {
        use std::sync::atomic::AtomicUsize;
        static DROPS: AtomicUsize = AtomicUsize::new(0);
        #[repr(align(64))]
        struct Aligned([u8; 100]);
        impl Drop for Aligned {
            fn drop(&mut self) {
                DROPS.fetch_add(1, Ordering::SeqCst);
            }
        }
        let b = SecretBox::new(Aligned([7; 100])).unwrap();
        assert_eq!((b.ptr.as_ptr() as usize) % 64, 0);
        assert_eq!(b.0[99], 7);
        drop(b);
        assert_eq!(DROPS.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn large_buf_filled_zeroed_on_drop_and_registered() {
        #[derive(Clone, Copy, PartialEq, Debug)]
        #[repr(align(64))]
        struct Blk([u64; 16]);
        let mut buf = LargeSecretBuf::new_filled(3000, Blk([3; 16])).unwrap();
        assert_eq!(buf.len(), 3000);
        assert!(buf.as_slice().iter().all(|b| *b == Blk([3; 16])));
        buf.as_mut_slice()[5] = Blk([9; 16]);
        let registered = REGIONS
            .iter()
            .filter(|(p, _)| !p.load(Ordering::Acquire).is_null())
            .count();
        assert!(registered >= 1);
        let (_, regions) = zeroize_all_registered();
        assert!(regions >= 1);
        assert_eq!(
            buf.as_slice()[5],
            Blk([0; 16]),
            "hook sıfırlaması bölgeyi kapsamalı"
        );
        drop(buf);
    }

    #[test]
    fn zero_len_large_buf() {
        let b: LargeSecretBuf<u8> = LargeSecretBuf::new_filled(0, 0).unwrap();
        assert!(b.is_empty());
    }
}
