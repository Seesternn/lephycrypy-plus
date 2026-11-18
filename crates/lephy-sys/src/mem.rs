//! Locked memory.
//!
//! - **Arena:** one fixed-size (`ARENA_PAGES` pages), page-aligned region per process; it never
//!   grows or moves. Base/length are kept in `static` atomics so that the panic hook can zeroize
//!   it without taking a lock. First-fit allocation with a bitmap over 64-byte units; per-page
//!   reference counts: `mlock`/`VirtualLock` on a page's first use, `munlock` only when the last
//!   secret on the page is released (POSIX `mlock` does not count).
//! - [`SecretBytes`]: fixed-capacity byte buffer in the arena; `expose()`/`expose_mut()`,
//!   `Debug` → `[REDACTED]`, no `Clone`/`Display`; zeroized on Drop; exceeding the capacity is an error.
//! - [`SecretBox<T>`]: aligned space in the arena, built with `ptr::write`, `drop_in_place` + raw
//!   zeroization on Drop (for AEAD structs).
//! - [`LargeSecretBuf<T>`]: large region via `mmap`/`VirtualAlloc` (Argon2 memory, chunk pool);
//!   best-effort lock; `MADV_DONTDUMP` on Linux only; zeroize + unmap on Drop; registered with the
//!   hook.
//! - [`zeroize_all_registered`]: step (1) of the panic hook.
//!
//! `cfg(miri)`: `std::alloc` + a no-op lock instead of OS calls.

use core::fmt;
use core::ops::{Deref, DerefMut};
use core::ptr::NonNull;
use std::io;
use std::sync::Mutex;
use std::sync::atomic::{AtomicBool, AtomicPtr, AtomicU8, AtomicUsize, Ordering};

use zeroize::Zeroize;

/// Arena allocation unit (bytes). Every slot starts at this alignment.
const UNIT: usize = 64;
/// Number of arena pages (16 KiB pages on macOS arm64 → 256 KiB).
const ARENA_PAGES: usize = 16;
/// Number of large regions registered for the hook.
const MAX_REGIONS: usize = 16;

/// Memory errors.
#[derive(Debug)]
pub enum MemError {
    /// Arena full; no contiguous space for the requested size.
    ArenaExhausted {
        /// Requested bytes.
        requested: usize,
    },
    /// The arena could not be set up (mmap/VirtualAlloc).
    ArenaInit(io::Error),
    /// Fixed capacity exceeded (`SecretBytes`).
    CapacityExceeded {
        /// Capacity.
        capacity: usize,
        /// Requested total length.
        requested: usize,
    },
    /// Type alignment not supported (> page size).
    AlignmentUnsupported(usize),
    /// Size computation overflowed or is zero.
    InvalidSize,
    /// Large region could not be allocated.
    MapFailed(io::Error),
    /// Hook registry full (> 16 large regions at once).
    RegistryFull,
}

impl fmt::Display for MemError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            MemError::ArenaExhausted { requested } => {
                write!(f, "locked-memory arena full ({requested} bytes requested)")
            }
            MemError::ArenaInit(e) => write!(f, "locked-memory arena could not be set up: {e}"),
            MemError::CapacityExceeded {
                capacity,
                requested,
            } => write!(
                f,
                "secret buffer capacity exceeded ({requested} > {capacity})"
            ),
            MemError::AlignmentUnsupported(a) => write!(f, "unsupported alignment: {a}"),
            MemError::InvalidSize => write!(f, "invalid size"),
            MemError::MapFailed(e) => write!(f, "large memory region could not be allocated: {e}"),
            MemError::RegistryFull => write!(f, "large-region registry full"),
        }
    }
}

impl std::error::Error for MemError {}

// ---------------------------------------------------------------------------------------------
// OS back end
// ---------------------------------------------------------------------------------------------

#[cfg(not(miri))]
mod os {
    use super::MemError;
    use core::ptr::NonNull;
    use std::io;

    #[cfg(unix)]
    pub(super) fn page_size() -> usize {
        // SAFETY: sysconf takes no memory pointer.
        let v = unsafe { libc::sysconf(libc::_SC_PAGESIZE) };
        usize::try_from(v).ok().filter(|p| *p >= 64).unwrap_or(4096)
    }

    #[cfg(windows)]
    pub(super) fn page_size() -> usize {
        use windows_sys::Win32::System::SystemInformation::{GetSystemInfo, SYSTEM_INFO};
        // SAFETY: SYSTEM_INFO is a plain C struct; zero initialisation is valid.
        let mut si: SYSTEM_INFO = unsafe { core::mem::zeroed() };
        // SAFETY: `si` is valid and writable; the call only fills it.
        unsafe { GetSystemInfo(&raw mut si) };
        usize::try_from(si.dwPageSize)
            .ok()
            .filter(|p| *p >= 64)
            .unwrap_or(4096)
    }

    /// Zeroed, page-aligned anonymous region.
    #[cfg(unix)]
    pub(super) fn map(len: usize) -> Result<NonNull<u8>, MemError> {
        // SAFETY: addr = NULL (the kernel chooses), len > 0, PROT_READ|WRITE, MAP_PRIVATE|MAP_ANON,
        // fd = -1, offset = 0: a valid argument set for an anonymous mapping.
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
        // SAFETY: `p`/`len` come from the same `map` call; the region is not used elsewhere
        // (the caller is in Drop, sole ownership).
        let _ = unsafe { libc::munmap(p.as_ptr().cast::<libc::c_void>(), len) };
    }

    #[cfg(unix)]
    pub(super) fn lock(p: NonNull<u8>, len: usize) -> io::Result<()> {
        // SAFETY: `p`/`len` describe a mapped region (guaranteed by the caller); mlock only locks
        // this range.
        let rc = unsafe { libc::mlock(p.as_ptr().cast::<libc::c_void>(), len) };
        if rc == 0 {
            Ok(())
        } else {
            Err(io::Error::last_os_error())
        }
    }

    #[cfg(unix)]
    pub(super) fn unlock(p: NonNull<u8>, len: usize) {
        // SAFETY: `p`/`len` is a mapped region previously locked with `lock`.
        let _ = unsafe { libc::munlock(p.as_ptr().cast::<libc::c_void>(), len) };
    }

    /// Linux: exclude from core dumps (best effort). A no-op on other Unix systems.
    #[cfg(unix)]
    pub(super) fn exclude_from_dump(p: NonNull<u8>, len: usize) {
        #[cfg(target_os = "linux")]
        {
            // SAFETY: `p`/`len` is a mapped region; MADV_DONTDUMP only sets a flag.
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
        // SAFETY: lpAddress = NULL, dwSize = len > 0, valid flags; VirtualAlloc returns zeroed
        // pages.
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
        // SAFETY: `p` is the base address from the same VirtualAlloc call; MEM_RELEASE requires dwSize = 0.
        let _ = unsafe { VirtualFree(p.as_ptr().cast::<core::ffi::c_void>(), 0, MEM_RELEASE) };
    }

    #[cfg(windows)]
    fn grow_working_set(extra: usize) {
        use windows_sys::Win32::System::Threading::{
            GetCurrentProcess, GetProcessWorkingSetSize, SetProcessWorkingSetSize,
        };
        let mut min: usize = 0;
        let mut max: usize = 0;
        // SAFETY: GetCurrentProcess returns a pseudo handle, not closed; takes no argument.
        let me = unsafe { GetCurrentProcess() };
        // SAFETY: `me` is valid; min/max are valid output pointers.
        let ok = unsafe { GetProcessWorkingSetSize(me, &raw mut min, &raw mut max) };
        if ok == 0 {
            return;
        }
        let (Some(nmin), Some(nmax)) = (min.checked_add(extra), max.checked_add(extra)) else {
            return;
        };
        // SAFETY: numeric arguments only; failure is best effort (locking reports the error later).
        let _ = unsafe { SetProcessWorkingSetSize(me, nmin, nmax) };
    }

    #[cfg(windows)]
    pub(super) fn lock(p: NonNull<u8>, len: usize) -> io::Result<()> {
        use windows_sys::Win32::System::Memory::VirtualLock;
        grow_working_set(len);
        // SAFETY: `p`/`len` lie inside a region committed with VirtualAlloc.
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
        // SAFETY: `p`/`len` is a region previously locked with VirtualLock.
        let _ = unsafe { VirtualUnlock(p.as_ptr().cast::<core::ffi::c_void>(), len) };
    }

    #[cfg(windows)]
    pub(super) fn exclude_from_dump(_p: NonNull<u8>, _len: usize) {}
}

#[cfg(miri)]
mod os {
    //! Miri back end: `std::alloc` + a no-op lock. Alignment/bounds arithmetic and
    //! zeroize-then-dealloc are checked here.
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
        // SAFETY: the layout size is non-zero (the caller guarantees `len > 0`).
        let p = unsafe { alloc_zeroed(layout) };
        NonNull::new(p).ok_or_else(|| MemError::MapFailed(io::Error::other("alloc_zeroed")))
    }

    pub(super) fn unmap(p: NonNull<u8>, len: usize) {
        if let Ok(layout) = Layout::from_size_align(len, MIRI_PAGE) {
            // SAFETY: `p` came from `alloc_zeroed` with the same layout; sole ownership.
            unsafe { dealloc(p.as_ptr(), layout) };
        }
    }

    pub(super) fn lock(_p: NonNull<u8>, _len: usize) -> io::Result<()> {
        Ok(())
    }
    pub(super) fn unlock(_p: NonNull<u8>, _len: usize) {}
    pub(super) fn exclude_from_dump(_p: NonNull<u8>, _len: usize) {}
}

/// Page size (cached).
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

/// Page indices (inclusive) covered by `[offset, offset+len)`, clipped to the arena.
fn page_span(offset: usize, len: usize, page: usize) -> (usize, usize) {
    let first = (offset / page).min(ARENA_PAGES - 1);
    let last = ((offset + len.max(1) - 1) / page).min(ARENA_PAGES - 1);
    (first, last.max(first))
}

fn round_up(n: usize, m: usize) -> Option<usize> {
    n.checked_add(m - 1).map(|v| v / m * m)
}

/// Volatile zeroization through the `zeroize` crate (no allocation).
fn zero_bytes(p: NonNull<u8>, len: usize) {
    if len == 0 {
        return;
    }
    // SAFETY: the caller guarantees that `p..p+len` is memory mapped in this process, writable,
    // and not used through any other reference during this call.
    let s = unsafe { core::slice::from_raw_parts_mut(p.as_ptr(), len) };
    s.zeroize();
}

// ---------------------------------------------------------------------------------------------
// Arena
// ---------------------------------------------------------------------------------------------

/// For the hook: arena base (NULL = not set up) and length.
static ARENA_BASE: AtomicPtr<u8> = AtomicPtr::new(core::ptr::null_mut());
static ARENA_LEN: AtomicUsize = AtomicUsize::new(0);
/// Whether any `mlock`/`VirtualLock` failed (warning / `--strict-memory`).
static LOCK_FAILED: AtomicBool = AtomicBool::new(false);

struct ArenaState {
    /// 1 bit per unit; 1 = used.
    bitmap: Vec<u64>,
    units: usize,
    /// Live allocations per page.
    page_refs: Vec<u32>,
    /// Lock state per page.
    page_locked: Vec<bool>,
    last_lock_error: Option<String>,
}

static STATE: Mutex<Option<ArenaState>> = Mutex::new(None);

fn arena_base() -> NonNull<u8> {
    // Called only while STATE is Some; ARENA_BASE is then not null.
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

    /// Finds a free range of `k` units starting at a multiple of `align_units`.
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
        // Page refcount + lock on first use.
        let base = arena_base();
        let (first_page, last_page) = page_span(start * UNIT, k * UNIT, page);
        for pg in first_page..=last_page {
            if self.page_refs[pg] == 0 && !self.page_locked[pg] {
                // SAFETY contract: `base + pg*page` is inside the arena.
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

/// Allocates a slot of `size` bytes with alignment `align` from the arena; returned zeroed.
fn arena_alloc(size: usize, align: usize) -> Result<NonNull<u8>, MemError> {
    let off = with_state(|st| st.alloc(size, align))?;
    let base = arena_base();
    // Make sure the slot is zero (the previous user zeroized it on Drop; guaranteed anyway).
    let p = NonNull::new(base.as_ptr().wrapping_add(off)).ok_or(MemError::InvalidSize)?;
    zero_bytes(p, size.max(1));
    Ok(p)
}

/// Zeroizes and frees the slot.
fn arena_free(p: NonNull<u8>, size: usize) {
    zero_bytes(p, size.max(1));
    let base = arena_base();
    let off = (p.as_ptr() as usize).wrapping_sub(base.as_ptr() as usize);
    let _ = with_state(|st| {
        st.free(off, size);
        Ok(())
    });
}

/// `true` if any locking failed (warning; an error with `--strict-memory`).
#[must_use]
pub fn lock_failed() -> bool {
    LOCK_FAILED.load(Ordering::Relaxed)
}

/// Text of the last locking error (if any).
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

/// Fixed-capacity byte buffer in the locked arena. The single secret type.
pub struct SecretBytes {
    ptr: NonNull<u8>,
    cap: usize,
    len: usize,
}

// SAFETY: the content is plain bytes; `&SecretBytes` only reads, `&mut` is the single writer.
unsafe impl Send for SecretBytes {}
// SAFETY: as above; no interior mutability.
unsafe impl Sync for SecretBytes {}

impl SecretBytes {
    /// Zeroed, locked buffer of `cap` bytes (length 0).
    ///
    /// # Errors
    /// If the arena is full or could not be set up.
    pub fn with_capacity(cap: usize) -> Result<Self, MemError> {
        let ptr = arena_alloc(cap.max(1), UNIT)?;
        Ok(Self { ptr, cap, len: 0 })
    }

    /// Copies the slice (zeroizing the source is the caller's job).
    ///
    /// # Errors
    /// If the arena is full or could not be set up.
    pub fn from_slice(bytes: &[u8]) -> Result<Self, MemError> {
        let mut s = Self::with_capacity(bytes.len())?;
        s.push_slice(bytes)?;
        Ok(s)
    }

    /// Capacity.
    #[must_use]
    pub const fn capacity(&self) -> usize {
        self.cap
    }
    /// Length.
    #[must_use]
    pub const fn len(&self) -> usize {
        self.len
    }
    /// Whether it is empty.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.len == 0
    }

    /// Reads the content.
    #[must_use]
    pub fn expose(&self) -> &[u8] {
        // SAFETY: `ptr..ptr+cap` is an arena slot; `len ≤ cap`; every byte is initialised (zero/written).
        unsafe { core::slice::from_raw_parts(self.ptr.as_ptr(), self.len) }
    }

    /// Changes the content (fixed length).
    pub fn expose_mut(&mut self) -> &mut [u8] {
        // SAFETY: as above; `&mut self` is the only access.
        unsafe { core::slice::from_raw_parts_mut(self.ptr.as_ptr(), self.len) }
    }

    /// Free space `len..cap`; readers write here directly and call [`set_len`](Self::set_len).
    pub fn spare_mut(&mut self) -> &mut [u8] {
        let tail = self.ptr.as_ptr().wrapping_add(self.len);
        // SAFETY: `ptr+len .. ptr+cap` is inside the slot and initialised; `&mut self` is the only access.
        unsafe { core::slice::from_raw_parts_mut(tail, self.cap - self.len) }
    }

    /// Sets the length (`n ≤ cap`). When shrinking, the removed part is zeroized.
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

    /// Appends; an error if the capacity is exceeded, the buffer is never grown.
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

    /// Truncates; the removed part is zeroized.
    pub fn truncate(&mut self, n: usize) {
        if n < self.len {
            let _ = self.set_len(n);
        }
    }

    /// Zeroizes the whole content, length 0.
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

/// A `T` living in the locked arena. `drop_in_place` + raw zeroization on Drop.
pub struct SecretBox<T> {
    ptr: NonNull<T>,
    size: usize,
}

// SAFETY: `SecretBox<T>` owns only the `T` itself; same rules as `Box<T>`.
unsafe impl<T: Send> Send for SecretBox<T> {}
// SAFETY: as above.
unsafe impl<T: Sync> Sync for SecretBox<T> {}

impl<T> SecretBox<T> {
    /// Moves `value` into the arena. The caller's stack copy is invalid after the move
    /// (Rust move semantics; stack residue: see THREAT-MODEL).
    ///
    /// # Errors
    /// Arena full, could not be set up, or `align_of::<T>()` exceeds the page size.
    pub fn new(value: T) -> Result<Self, MemError> {
        let size = size_of::<T>().max(1);
        let raw = arena_alloc(size, align_of::<T>())?;
        let ptr = raw.cast::<T>();
        // SAFETY: `ptr` is a writable slot aligned to `align_of::<T>()` with `size_of::<T>()` bytes;
        // ownership of `value` moves here.
        unsafe { ptr.as_ptr().write(value) };
        Ok(Self { ptr, size })
    }
}

impl<T> Deref for SecretBox<T> {
    type Target = T;
    fn deref(&self) -> &T {
        // SAFETY: `ptr` points to a valid `T` initialised in `new`; alive until Drop.
        unsafe { self.ptr.as_ref() }
    }
}

impl<T> DerefMut for SecretBox<T> {
    fn deref_mut(&mut self) -> &mut T {
        // SAFETY: as above; `&mut self` is the only access.
        unsafe { self.ptr.as_mut() }
    }
}

impl<T> Drop for SecretBox<T> {
    fn drop(&mut self) {
        // SAFETY: `ptr` is an initialised `T`; it is dropped only once (Drop runs once).
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

/// Hook registry slot. `state` prevents a race between the hook and `Drop`: the hook only moves an
/// ACTIVE slot to HOOK and zeroizes it; if Drop cannot move the slot ACTIVE→RETIRING (the hook is
/// zeroizing), it waits for the hook. So the hook never writes to unmapped memory.
struct Slot {
    state: AtomicU8,
    ptr: AtomicPtr<u8>,
    len: AtomicUsize,
}

const S_FREE: u8 = 0;
const S_SETUP: u8 = 1;
const S_ACTIVE: u8 = 2;
const S_HOOK: u8 = 3;
const S_RETIRING: u8 = 4;

static REGIONS: [Slot; MAX_REGIONS] = [const {
    Slot {
        state: AtomicU8::new(S_FREE),
        ptr: AtomicPtr::new(core::ptr::null_mut()),
        len: AtomicUsize::new(0),
    }
}; MAX_REGIONS];

fn register_region(p: NonNull<u8>, len: usize) -> Result<usize, MemError> {
    for (i, slot) in REGIONS.iter().enumerate() {
        if slot
            .state
            .compare_exchange(S_FREE, S_SETUP, Ordering::AcqRel, Ordering::Acquire)
            .is_ok()
        {
            slot.ptr.store(p.as_ptr(), Ordering::Release);
            slot.len.store(len, Ordering::Release);
            slot.state.store(S_ACTIVE, Ordering::Release);
            return Ok(i);
        }
    }
    Err(MemError::RegistryFull)
}

/// Retires the slot; only then may the region be unmapped.
fn retire_region(i: usize) {
    let slot = &REGIONS[i];
    while slot
        .state
        .compare_exchange(S_ACTIVE, S_RETIRING, Ordering::AcqRel, Ordering::Acquire)
        .is_err()
    {
        // The hook is zeroizing this region (an abort follows): wait for it to finish.
        std::thread::yield_now();
    }
}

/// Clears the slot after unmapping.
fn free_region(i: usize) {
    let slot = &REGIONS[i];
    slot.len.store(0, Ordering::Release);
    slot.ptr.store(core::ptr::null_mut(), Ordering::Release);
    slot.state.store(S_FREE, Ordering::Release);
}

/// Large region allocated with `mmap`/`VirtualAlloc`, locked best effort. Since `T: Copy`, no
/// Drop runs; the region is zeroized as raw bytes.
pub struct LargeSecretBuf<T: Copy> {
    ptr: NonNull<T>,
    len: usize,
    map_len: usize,
    locked: bool,
    slot: usize,
}

// SAFETY: only this value owns the region; it can be moved if `T: Send`.
unsafe impl<T: Copy + Send> Send for LargeSecretBuf<T> {}
// SAFETY: `&self` only gives `&[T]`; it can be shared if `T: Sync`.
unsafe impl<T: Copy + Sync> Sync for LargeSecretBuf<T> {}

impl<T: Copy> LargeSecretBuf<T> {
    /// `len` items of `T`, each filled with `init`. Locking is attempted; a failure is visible
    /// through [`is_locked`](Self::is_locked) and the [`lock_failed`] flag.
    ///
    /// # Errors
    /// Size overflow, alignment > page, mapping error, registry full.
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
            // SAFETY: `ptr` is page aligned (≥ align_of::<T>()), `i < len` and `len*size_of::<T>()
            // ≤ map_len`; since `T: Copy`, overwriting needs no Drop.
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

    /// Number of items.
    #[must_use]
    pub const fn len(&self) -> usize {
        self.len
    }
    /// Whether it is empty.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.len == 0
    }
    /// Whether locking succeeded.
    #[must_use]
    pub const fn is_locked(&self) -> bool {
        self.locked
    }

    /// Slice.
    #[must_use]
    pub fn as_slice(&self) -> &[T] {
        // SAFETY: `ptr..ptr+len` was initialised in `new_filled` and is aligned; alive until Drop.
        unsafe { core::slice::from_raw_parts(self.ptr.as_ptr(), self.len) }
    }

    /// Mutable slice.
    pub fn as_mut_slice(&mut self) -> &mut [T] {
        // SAFETY: as above; `&mut self` is the only access.
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
        retire_region(self.slot);
        os::unmap(raw, self.map_len);
        free_region(self.slot);
    }
}

impl<T: Copy> fmt::Debug for LargeSecretBuf<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "LargeSecretBuf([REDACTED; {}])", self.len)
    }
}

// ---------------------------------------------------------------------------------------------
// Panic-hook support
// ---------------------------------------------------------------------------------------------

/// Zeroizes the arena and every registered large region. Step (1) of the panic hook.
/// Takes no lock and does not allocate. Returns `(arena_bytes, region_count)`.
///
/// Other threads may still be running meanwhile; since an abort follows immediately, this data
/// race is accepted (THREAT-MODEL › Memory). Call it only right before aborting.
pub fn zeroize_all_registered() -> (usize, usize) {
    let mut arena = 0;
    if let Some(base) = NonNull::new(ARENA_BASE.load(Ordering::Acquire)) {
        let len = ARENA_LEN.load(Ordering::Acquire);
        // SAFETY (accepted race): the arena stays mapped for the process lifetime; concurrent
        // readers may exist, and since an abort follows, the data race is deliberately accepted.
        zero_bytes(base, len);
        arena = len;
    }
    let mut regions = 0;
    for slot in &REGIONS {
        // Only an ACTIVE slot is taken; in the HOOK state Drop cannot unmap (retire_region waits).
        if slot
            .state
            .compare_exchange(S_ACTIVE, S_HOOK, Ordering::AcqRel, Ordering::Acquire)
            .is_err()
        {
            continue;
        }
        let l = slot.len.load(Ordering::Acquire);
        if let Some(p) = NonNull::new(slot.ptr.load(Ordering::Acquire)).filter(|_| l > 0) {
            // The HOOK state guarantees the region stays mapped; concurrent readers may exist
            // (an abort follows; the data race is accepted).
            zero_bytes(p, l);
            regions += 1;
        }
        slot.state.store(S_ACTIVE, Ordering::Release);
    }
    (arena, regions)
}

#[cfg(test)]
#[allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::items_after_statements
)]
mod tests {
    use super::*;

    /// Tests share the same process arena; memory tests run one at a time so that the test that
    /// deliberately fills the arena does not starve the others.
    fn serial() -> std::sync::MutexGuard<'static, ()> {
        static LOCK: Mutex<()> = Mutex::new(());
        LOCK.lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    #[test]
    fn secret_bytes_roundtrip_and_capacity() {
        let _serial = serial();
        let mut s = SecretBytes::with_capacity(8).unwrap();
        assert_eq!(s.capacity(), 8);
        s.push_slice(b"abc").unwrap();
        assert_eq!(s.expose(), b"abc");
        assert!(matches!(
            s.push_slice(b"123456"),
            Err(MemError::CapacityExceeded { .. })
        ));
        assert_eq!(s.capacity(), 8, "capacity must not change");
        s.spare_mut()[0] = b'z';
        s.set_len(4).unwrap();
        assert_eq!(s.expose(), b"abcz");
        s.truncate(2);
        assert_eq!(s.expose(), b"ab");
        s.set_len(4).unwrap();
        assert_eq!(
            &s.expose()[2..],
            &[0, 0],
            "the removed part must be zeroized"
        );
        assert_eq!(format!("{s:?}"), "SecretBytes([REDACTED])");
    }

    #[test]
    fn freed_slot_is_zero_and_reusable() {
        let _serial = serial();
        let p;
        {
            let mut a = SecretBytes::with_capacity(32).unwrap();
            a.push_slice(&[0xAA; 32]).unwrap();
            p = a.ptr;
        }
        // The same slot must be handed out again, zeroed (first-fit).
        let b = SecretBytes::with_capacity(32).unwrap();
        if b.ptr == p {
            // SAFETY: the slot belongs to `b`, 32 bytes of capacity, every byte initialised.
            let full = unsafe { core::slice::from_raw_parts(b.ptr.as_ptr(), 32) };
            assert!(full.iter().all(|&x| x == 0));
        }
    }

    #[test]
    fn page_refcount_keeps_page_locked_until_last_drop() {
        let _serial = serial();
        // two secrets on the same page; when one is dropped the page stays locked. Since other
        // tests share the arena, only "while b lives the page is locked and refs ≥ 1" is checked;
        // exact counter equality is verified with the `page_span`/`alloc` logic in the
        // single-threaded `refcount_arithmetic` test below.
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
        assert!(refs >= 1, "b is still alive");
        if !lock_failed() {
            assert!(
                locked,
                "the lock must stay while the page still holds a secret"
            );
        }
        drop(b);
    }

    #[test]
    fn refcount_arithmetic() {
        let _serial = serial();
        // page_span: a single page, a range ending at a boundary and one spanning two pages.
        let page = page_size();
        assert_eq!(page_span(0, 64, page), (0, 0));
        assert_eq!(page_span(page - 64, 64, page), (0, 0));
        assert_eq!(page_span(page - 64, 128, page), (0, 1));
        assert_eq!(page_span(page, page, page), (1, 1));
        assert_eq!(page_span(0, page * ARENA_PAGES, page), (0, ARENA_PAGES - 1));
    }

    #[test]
    fn arena_exhaustion_is_an_error_not_a_panic() {
        let _serial = serial();
        let mut keep = Vec::new();
        loop {
            match SecretBytes::with_capacity(4096) {
                Ok(s) => keep.push(s),
                Err(MemError::ArenaExhausted { .. }) => break,
                Err(e) => panic!("unexpected error: {e}"),
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
        let _serial = serial();
        let b = SecretBox::new(Aligned([7; 100])).unwrap();
        assert_eq!((b.ptr.as_ptr() as usize) % 64, 0);
        assert_eq!(b.0[99], 7);
        drop(b);
        assert_eq!(DROPS.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn large_buf_filled_zeroed_on_drop_and_registered() {
        let _serial = serial();
        #[derive(Clone, Copy, PartialEq, Debug)]
        #[repr(align(64))]
        struct Blk([u64; 16]);
        let mut buf = LargeSecretBuf::new_filled(3000, Blk([3; 16])).unwrap();
        assert_eq!(buf.len(), 3000);
        assert!(buf.as_slice().iter().all(|b| *b == Blk([3; 16])));
        buf.as_mut_slice()[5] = Blk([9; 16]);
        let registered = REGIONS
            .iter()
            .filter(|s| s.state.load(Ordering::Acquire) == S_ACTIVE)
            .count();
        assert!(registered >= 1);
        let (_, regions) = zeroize_all_registered();
        assert!(regions >= 1);
        assert_eq!(
            buf.as_slice()[5],
            Blk([0; 16]),
            "the hook's zeroization must cover the region"
        );
        drop(buf);
    }

    #[test]
    fn zero_len_large_buf() {
        let _serial = serial();
        let b: LargeSecretBuf<u8> = LargeSecretBuf::new_filled(0, 0).unwrap();
        assert!(b.is_empty());
    }
}
