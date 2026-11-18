//! File-system FFI.
//!
//! No-clobber/replace rename, directory fsync, free space / file-system type,
//! `FILE_ATTRIBUTE_NOT_CONTENT_INDEXED`, the temp-file registry for the panic hook. Symlinks
//! (`CreateSymbolicLinkW`), cloud roots, `FILE_SHARE_DELETE`/`FileDispositionInfo`.

use std::io;
use std::path::Path;
use std::sync::Mutex;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

/// No-clobber rename result.
#[derive(Debug)]
pub enum NoclobberError {
    /// The destination already exists (code 7).
    Exists,
    /// The file system does not support atomic no-clobber; the caller falls back and warns.
    Unsupported,
    /// Other I/O error.
    Io(io::Error),
}

impl std::fmt::Display for NoclobberError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            NoclobberError::Exists => f.write_str("the destination already exists"),
            NoclobberError::Unsupported => {
                f.write_str("the file system does not support no-clobber rename")
            }
            NoclobberError::Io(e) => write!(f, "{e}"),
        }
    }
}

impl std::error::Error for NoclobberError {}

/// Atomic rename that fails if the destination exists (macOS `renamex_np(RENAME_EXCL)`, Linux
/// `renameat2(RENAME_NOREPLACE)`, Windows `MoveFileExW` + `MOVEFILE_WRITE_THROUGH`).
/// On Windows, exponential back-off from 10 ms for `ACCESS_DENIED`/`SHARING_VIOLATION`,
/// ≤ 2 s.
///
/// # Errors
/// [`NoclobberError`].
pub fn rename_noclobber(from: &Path, to: &Path) -> Result<(), NoclobberError> {
    imp::rename_noclobber(from, to)
}

/// Rename that overwrites the destination (`--force`). Unix `rename`, Windows
/// `MoveFileExW(REPLACE_EXISTING | WRITE_THROUGH)` (with retries).
///
/// # Errors
/// I/O error.
pub fn rename_replace(from: &Path, to: &Path) -> io::Result<()> {
    imp::rename_replace(from, to)
}

/// Makes a directory entry durable: Unix directory fd + Apple `F_FULLFSYNC`; a no-op on Windows.
///
/// # Errors
/// I/O error.
pub fn fsync_dir(dir: &Path) -> io::Result<()> {
    imp::fsync_dir(dir)
}

/// Tries to flush file content to the physical medium: `F_FULLFSYNC` on macOS (including the
/// drive cache), `sync_all` where that is not supported and on other platforms.
///
/// # Errors
/// I/O error.
pub fn full_sync(f: &std::fs::File) -> io::Result<()> {
    #[cfg(any(target_os = "macos", target_os = "ios"))]
    {
        use std::os::fd::AsRawFd;
        // SAFETY: F_FULLFSYNC takes no argument; `f` is an open file.
        if unsafe { libc::fcntl(f.as_raw_fd(), libc::F_FULLFSYNC) } == 0 {
            return Ok(());
        }
    }
    f.sync_all()
}

/// Windows: sets `FILE_ATTRIBUTE_NOT_CONTENT_INDEXED` (0x2000); a no-op elsewhere.
///
/// # Errors
/// I/O error.
pub fn mark_not_content_indexed(path: &Path) -> io::Result<()> {
    imp::mark_not_content_indexed(path)
}

/// Free space available on the volume of the path (bytes).
///
/// # Errors
/// I/O error.
pub fn free_space(path: &Path) -> io::Result<u64> {
    imp::free_space(path)
}

/// File-system type name (lowercase): `apfs`, `exfat`, `msdos`/`fat32`, `ntfs`, `ext4`…
///
/// # Errors
/// I/O error.
pub fn fs_type_name(path: &Path) -> io::Result<String> {
    imp::fs_type_name(path).map(|s| s.to_ascii_lowercase())
}

/// Whether it is FAT12/16/32 (4 GiB file limit, code 8 pre-check).
///
/// # Errors
/// I/O error.
pub fn is_fat(path: &Path) -> io::Result<bool> {
    let t = fs_type_name(path)?;
    Ok(t == "msdos" || t == "fat" || t == "fat32" || t == "fat16" || t == "vfat")
}

/// Retry with back-off for `MoveFileExW` on Windows. A single attempt on Unix.
#[allow(dead_code)]
fn retry_sharing<T>(mut f: impl FnMut() -> io::Result<T>) -> io::Result<T> {
    let start = Instant::now();
    let mut delay = Duration::from_millis(10);
    loop {
        match f() {
            Ok(v) => return Ok(v),
            Err(e) => {
                let retryable = matches!(e.raw_os_error(), Some(5 | 32)); // ACCESS_DENIED, SHARING_VIOLATION
                if !cfg!(windows) || !retryable || start.elapsed() >= Duration::from_secs(2) {
                    return Err(e);
                }
                std::thread::sleep(delay);
                delay = (delay * 2).min(Duration::from_millis(400));
            }
        }
    }
}

// ---------------------------------------------------------------------------------------------
// Temp-file registry (panic hook step 2)
// ---------------------------------------------------------------------------------------------

/// Registration id.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TmpId(u64);

static TMP_NEXT: AtomicU64 = AtomicU64::new(1);
static TMP: Mutex<Vec<(u64, imp::EncodedPath)>> = Mutex::new(Vec::new());

/// Registers the path pre-encoded (`CString` / UTF-16); the hook deletes it without allocating.
///
/// # Errors
/// The path cannot be encoded (interior NUL).
pub fn tmp_register(path: &Path) -> io::Result<TmpId> {
    let enc = imp::encode(path)?;
    let id = TMP_NEXT.fetch_add(1, Ordering::Relaxed);
    TMP.lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .push((id, enc));
    Ok(TmpId(id))
}

/// Drops the registration (the file is not deleted).
pub fn tmp_unregister(id: TmpId) {
    let mut g = TMP
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    g.retain(|(i, _)| *i != id.0);
}

/// Hook: deletes every registered temp path. Uses `try_lock`; does nothing if the lock is taken.
/// Returns the number deleted.
pub fn tmp_unlink_all_in_hook() -> usize {
    let Ok(g) = TMP.try_lock() else {
        return 0;
    };
    let mut n = 0;
    for (_, enc) in g.iter() {
        if imp::unlink_encoded(enc) {
            n += 1;
        }
    }
    n
}

#[cfg(unix)]
mod imp {
    use super::NoclobberError;
    use std::ffi::CString;
    use std::io;
    use std::os::unix::ffi::OsStrExt;
    use std::path::Path;

    pub(super) type EncodedPath = CString;

    pub(super) fn encode(path: &Path) -> io::Result<CString> {
        CString::new(path.as_os_str().as_bytes())
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "NUL in path"))
    }

    pub(super) fn unlink_encoded(p: &CString) -> bool {
        // SAFETY: `p` is a valid NUL-terminated C string; unlink only reads it.
        unsafe { libc::unlink(p.as_ptr()) == 0 }
    }

    #[cfg(target_os = "macos")]
    fn rename_excl(from: &CString, to: &CString) -> io::Result<()> {
        // SAFETY: two valid NUL-terminated C strings; RENAME_EXCL is only a flag.
        let rc = unsafe { libc::renamex_np(from.as_ptr(), to.as_ptr(), libc::RENAME_EXCL) };
        if rc == 0 {
            Ok(())
        } else {
            Err(io::Error::last_os_error())
        }
    }

    #[cfg(target_os = "linux")]
    fn rename_excl(from: &CString, to: &CString) -> io::Result<()> {
        // SAFETY: two valid NUL-terminated C strings; AT_FDCWD relative; RENAME_NOREPLACE is a flag.
        let rc = unsafe {
            libc::renameat2(
                libc::AT_FDCWD,
                from.as_ptr(),
                libc::AT_FDCWD,
                to.as_ptr(),
                libc::RENAME_NOREPLACE,
            )
        };
        if rc == 0 {
            Ok(())
        } else {
            Err(io::Error::last_os_error())
        }
    }

    #[cfg(not(any(target_os = "macos", target_os = "linux")))]
    fn rename_excl(_from: &CString, _to: &CString) -> io::Result<()> {
        Err(io::Error::from_raw_os_error(libc::ENOTSUP))
    }

    pub(super) fn rename_noclobber(from: &Path, to: &Path) -> Result<(), NoclobberError> {
        let f = encode(from).map_err(NoclobberError::Io)?;
        let t = encode(to).map_err(NoclobberError::Io)?;
        match rename_excl(&f, &t) {
            Ok(()) => Ok(()),
            Err(e) => match e.raw_os_error() {
                Some(libc::EEXIST) => Err(NoclobberError::Exists),
                Some(libc::ENOTSUP | libc::EINVAL | libc::ENOSYS) => {
                    Err(NoclobberError::Unsupported)
                }
                _ => Err(NoclobberError::Io(e)),
            },
        }
    }

    pub(super) fn rename_replace(from: &Path, to: &Path) -> io::Result<()> {
        std::fs::rename(from, to)
    }

    pub(super) fn fsync_dir(dir: &Path) -> io::Result<()> {
        use std::os::fd::AsRawFd;
        let f = std::fs::File::open(dir)?;
        #[cfg(any(target_os = "macos", target_os = "ios"))]
        {
            // SAFETY: F_FULLFSYNC takes no argument; `fd` is an open file.
            if unsafe { libc::fcntl(f.as_raw_fd(), libc::F_FULLFSYNC) } == 0 {
                return Ok(());
            }
            // Fall back to fsync on volumes without F_FULLFSYNC.
        }
        // SAFETY: fsync takes only an fd.
        if unsafe { libc::fsync(f.as_raw_fd()) } != 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(())
    }

    #[allow(clippy::unnecessary_wraps)]
    pub(super) fn mark_not_content_indexed(_path: &Path) -> io::Result<()> {
        Ok(())
    }

    pub(super) fn free_space(path: &Path) -> io::Result<u64> {
        let p = encode(path)?;
        // SAFETY: statvfs is a plain C struct; zero initialisation is valid.
        let mut st: libc::statvfs = unsafe { core::mem::zeroed() };
        // SAFETY: `p` is NUL terminated; `st` is valid and writable.
        if unsafe { libc::statvfs(p.as_ptr(), &raw mut st) } != 0 {
            return Err(io::Error::last_os_error());
        }
        #[allow(clippy::useless_conversion, clippy::unnecessary_fallible_conversions)]
        let bavail = u64::try_from(st.f_bavail).unwrap_or(0);
        #[allow(clippy::useless_conversion, clippy::unnecessary_fallible_conversions)]
        let frsize = u64::try_from(st.f_frsize).unwrap_or(0);
        Ok(bavail.saturating_mul(frsize))
    }

    #[cfg(any(target_os = "macos", target_os = "ios"))]
    pub(super) fn fs_type_name(path: &Path) -> io::Result<String> {
        let p = encode(path)?;
        // SAFETY: statfs is a plain C struct; zero initialisation is valid.
        let mut st: libc::statfs = unsafe { core::mem::zeroed() };
        // SAFETY: `p` is NUL terminated; `st` is valid and writable.
        if unsafe { libc::statfs(p.as_ptr(), &raw mut st) } != 0 {
            return Err(io::Error::last_os_error());
        }
        let bytes: Vec<u8> = st
            .f_fstypename
            .iter()
            .take_while(|&&c| c != 0)
            .map(|&c| u8::try_from(c).unwrap_or(b'?'))
            .collect();
        Ok(String::from_utf8_lossy(&bytes).into_owned())
    }

    #[cfg(target_os = "linux")]
    pub(super) fn fs_type_name(path: &Path) -> io::Result<String> {
        let p = encode(path)?;
        // SAFETY: statfs is a plain C struct; zero initialisation is valid.
        let mut st: libc::statfs = unsafe { core::mem::zeroed() };
        // SAFETY: `p` is NUL terminated; `st` is valid and writable.
        if unsafe { libc::statfs(p.as_ptr(), &raw mut st) } != 0 {
            return Err(io::Error::last_os_error());
        }
        #[allow(clippy::cast_sign_loss)]
        let magic = st.f_type as u64;
        Ok(match magic {
            0x4d44 => "vfat",
            0x2011_BAB0 => "exfat",
            0xEF53 => "ext4",
            0x9123_683E => "btrfs",
            0x5846_5342 => "xfs",
            0x0102_1994 => "tmpfs",
            0x5346_544e => "ntfs",
            _ => "unknown",
        }
        .to_string())
    }

    #[cfg(not(any(target_os = "macos", target_os = "ios", target_os = "linux")))]
    pub(super) fn fs_type_name(_path: &Path) -> io::Result<String> {
        Ok("unknown".to_string())
    }
}

#[cfg(windows)]
mod imp {
    use super::{NoclobberError, retry_sharing};
    use std::io;
    use std::os::windows::ffi::OsStrExt;
    use std::path::Path;
    use windows_sys::Win32::Foundation::{ERROR_ALREADY_EXISTS, ERROR_FILE_EXISTS};
    use windows_sys::Win32::Storage::FileSystem::{
        DeleteFileW, FILE_ATTRIBUTE_NOT_CONTENT_INDEXED, GetDiskFreeSpaceExW, GetFileAttributesW,
        GetVolumeInformationW, GetVolumePathNameW, INVALID_FILE_ATTRIBUTES,
        MOVEFILE_REPLACE_EXISTING, MOVEFILE_WRITE_THROUGH, MoveFileExW, SetFileAttributesW,
    };

    pub(super) type EncodedPath = Vec<u16>;

    pub(super) fn encode(path: &Path) -> io::Result<Vec<u16>> {
        let mut v: Vec<u16> = path.as_os_str().encode_wide().collect();
        if v.contains(&0) {
            return Err(io::Error::new(io::ErrorKind::InvalidInput, "NUL in path"));
        }
        v.push(0);
        Ok(v)
    }

    pub(super) fn unlink_encoded(p: &[u16]) -> bool {
        // SAFETY: `p` is NUL-terminated UTF-16; DeleteFileW only reads it.
        unsafe { DeleteFileW(p.as_ptr()) != 0 }
    }

    fn move_file(from: &[u16], to: &[u16], flags: u32) -> io::Result<()> {
        // SAFETY: two NUL-terminated UTF-16 strings; valid flags.
        if unsafe { MoveFileExW(from.as_ptr(), to.as_ptr(), flags) } == 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(())
    }

    pub(super) fn rename_noclobber(from: &Path, to: &Path) -> Result<(), NoclobberError> {
        let f = encode(from).map_err(NoclobberError::Io)?;
        let t = encode(to).map_err(NoclobberError::Io)?;
        match retry_sharing(|| move_file(&f, &t, MOVEFILE_WRITE_THROUGH)) {
            Ok(()) => Ok(()),
            Err(e) => {
                let code = e.raw_os_error().and_then(|c| u32::try_from(c).ok());
                if code == Some(ERROR_ALREADY_EXISTS) || code == Some(ERROR_FILE_EXISTS) {
                    Err(NoclobberError::Exists)
                } else {
                    Err(NoclobberError::Io(e))
                }
            }
        }
    }

    pub(super) fn rename_replace(from: &Path, to: &Path) -> io::Result<()> {
        let f = encode(from)?;
        let t = encode(to)?;
        retry_sharing(|| move_file(&f, &t, MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH))
    }

    #[allow(clippy::unnecessary_wraps)]
    pub(super) fn fsync_dir(_dir: &Path) -> io::Result<()> {
        Ok(())
    }

    pub(super) fn mark_not_content_indexed(path: &Path) -> io::Result<()> {
        let p = encode(path)?;
        // SAFETY: `p` is NUL-terminated UTF-16.
        let attrs = unsafe { GetFileAttributesW(p.as_ptr()) };
        if attrs == INVALID_FILE_ATTRIBUTES {
            return Err(io::Error::last_os_error());
        }
        // SAFETY: `p` is NUL-terminated UTF-16; valid flag.
        if unsafe { SetFileAttributesW(p.as_ptr(), attrs | FILE_ATTRIBUTE_NOT_CONTENT_INDEXED) }
            == 0
        {
            return Err(io::Error::last_os_error());
        }
        Ok(())
    }

    fn volume_root(path: &Path) -> io::Result<Vec<u16>> {
        let p = encode(path)?;
        let mut root = vec![0u16; 261];
        let len = u32::try_from(root.len()).unwrap_or(260);
        // SAFETY: `p` is NUL terminated; `root` is a valid buffer of `len` wchars.
        if unsafe { GetVolumePathNameW(p.as_ptr(), root.as_mut_ptr(), len) } == 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(root)
    }

    pub(super) fn free_space(path: &Path) -> io::Result<u64> {
        let root = volume_root(path)?;
        let mut avail: u64 = 0;
        let mut total: u64 = 0;
        let mut free: u64 = 0;
        // SAFETY: `root` is NUL terminated; the three output pointers are valid.
        let ok = unsafe {
            GetDiskFreeSpaceExW(root.as_ptr(), &raw mut avail, &raw mut total, &raw mut free)
        };
        if ok == 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(avail)
    }

    pub(super) fn fs_type_name(path: &Path) -> io::Result<String> {
        let root = volume_root(path)?;
        let mut name = vec![0u16; 64];
        let len = u32::try_from(name.len()).unwrap_or(64);
        // SAFETY: `root` is NUL terminated; `name` is a valid buffer of `len` wchars; other outputs NULL.
        let ok = unsafe {
            GetVolumeInformationW(
                root.as_ptr(),
                core::ptr::null_mut(),
                0,
                core::ptr::null_mut(),
                core::ptr::null_mut(),
                core::ptr::null_mut(),
                name.as_mut_ptr(),
                len,
            )
        };
        if ok == 0 {
            return Err(io::Error::last_os_error());
        }
        let end = name.iter().position(|&c| c == 0).unwrap_or(name.len());
        Ok(String::from_utf16_lossy(&name[..end]))
    }
}

// ---------------------------------------------------------------------------------------------
// Cloud-sync roots — heuristic list, in one place
// ---------------------------------------------------------------------------------------------

/// Known cloud-sync roots (those that exist): macOS `~/Library/Mobile Documents`,
/// `~/Library/CloudStorage/*`; Windows `%OneDrive%`, `%USERPROFILE%\OneDrive*`, `Dropbox`,
/// `Google Drive`, `My Drive`. The list is heuristic and may be incomplete.
#[must_use]
#[allow(clippy::disallowed_methods)] // only HOME/USERPROFILE/OneDrive are read; not secrets
pub fn cloud_sync_roots() -> Vec<std::path::PathBuf> {
    #[allow(unused_mut)] // Linux: no root block is compiled (best-effort platform)
    let mut out: Vec<std::path::PathBuf> = Vec::new();
    #[cfg(target_os = "macos")]
    {
        if let Some(home) = std::env::var_os("HOME") {
            let home = std::path::PathBuf::from(home);
            out.push(home.join("Library/Mobile Documents"));
            if let Ok(rd) = std::fs::read_dir(home.join("Library/CloudStorage")) {
                for e in rd.flatten() {
                    out.push(e.path());
                }
            }
        }
    }
    #[cfg(windows)]
    {
        if let Some(od) = std::env::var_os("OneDrive") {
            out.push(std::path::PathBuf::from(od));
        }
        if let Some(up) = std::env::var_os("USERPROFILE") {
            let up = std::path::PathBuf::from(up);
            if let Ok(rd) = std::fs::read_dir(&up) {
                for e in rd.flatten() {
                    let n = e.file_name().to_string_lossy().into_owned();
                    if n.starts_with("OneDrive")
                        || n == "Dropbox"
                        || n == "Google Drive"
                        || n == "My Drive"
                    {
                        out.push(e.path());
                    }
                }
            }
        }
    }
    out.retain(|p| p.exists());
    out
}

/// If `path` (canonicalised) is under a known cloud root, returns that root.
#[must_use]
pub fn cloud_root_of(path: &Path) -> Option<std::path::PathBuf> {
    let canon = path
        .canonicalize()
        .or_else(|_| {
            path.parent()
                .map_or(Ok(path.to_path_buf()), Path::canonicalize)
        })
        .ok()?;
    cloud_sync_roots()
        .into_iter()
        .filter_map(|r| r.canonicalize().ok())
        .find(|r| canon.starts_with(r))
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    #[cfg_attr(miri, ignore = "FFI")]
    fn noclobber_refuses_existing_target() {
        let dir = std::env::temp_dir().join(format!("lphy-fs-test-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let a = dir.join("a");
        let b = dir.join("b");
        std::fs::write(&a, b"1").unwrap();
        std::fs::write(&b, b"2").unwrap();
        match rename_noclobber(&a, &b) {
            Err(NoclobberError::Exists) => {}
            Err(NoclobberError::Unsupported) => eprintln!("no-clobber not supported (file system)"),
            other => panic!("unexpected: {other:?}"),
        }
        assert_eq!(std::fs::read(&b).unwrap(), b"2");
        let c = dir.join("c");
        match rename_noclobber(&a, &c) {
            Ok(()) => assert_eq!(std::fs::read(&c).unwrap(), b"1"),
            Err(NoclobberError::Unsupported) => {}
            Err(e) => panic!("{e}"),
        }
        fsync_dir(&dir).unwrap();
        assert!(free_space(&dir).unwrap() > 0);
        let t = fs_type_name(&dir).unwrap();
        assert!(!t.is_empty());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    #[cfg_attr(miri, ignore = "FFI")]
    fn tmp_registry_unlinks_in_hook() {
        let dir = std::env::temp_dir();
        let p = dir.join(format!(".lphy-tmp-test-{}", std::process::id()));
        std::fs::write(&p, b"x").unwrap();
        let id = tmp_register(&p).unwrap();
        let n = tmp_unlink_all_in_hook();
        assert!(n >= 1);
        assert!(!p.exists());
        tmp_unregister(id);
        assert_eq!(tmp_unlink_all_in_hook(), 0);
    }
}
