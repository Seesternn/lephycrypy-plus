//! Download marks: macOS `com.apple.quarantine`, Windows `Zone.Identifier` (Mark of the Web).
//!
//! A file downloaded from the internet carries such a mark, and the operating system checks
//! marked programs before running them (Gatekeeper, `SmartScreen`). Whatever is decrypted from a
//! marked `.lphy` file gets the same mark, so a program inside it is checked too.

use std::io;
use std::path::Path;

/// The mark of `path` (`None`: unmarked, or not supported here).
#[must_use]
pub fn read(path: &Path) -> Option<Vec<u8>> {
    imp::read(path)
}

/// Puts `mark` on `path` (a file or a directory; symlinks are not followed on macOS).
///
/// # Errors
/// The mark could not be written.
pub fn apply(path: &Path, mark: &[u8]) -> io::Result<()> {
    imp::apply(path, mark)
}

/// Puts `mark` on `root` and everything below it; symlinks are neither followed nor marked.
/// Returns the number of items that could not be marked.
#[must_use]
pub fn apply_tree(root: &Path, mark: &[u8]) -> usize {
    let mut failed = 0;
    let mut stack = vec![root.to_path_buf()];
    while let Some(p) = stack.pop() {
        let Ok(md) = p.symlink_metadata() else {
            failed += 1;
            continue;
        };
        if md.file_type().is_symlink() {
            continue;
        }
        if md.is_dir()
            && let Ok(rd) = std::fs::read_dir(&p)
        {
            stack.extend(rd.flatten().map(|e| e.path()));
        }
        // Windows marks files only (an ADS on a directory is not checked by SmartScreen).
        if (cfg!(windows) && md.is_dir()) || apply(&p, mark).is_ok() {
            continue;
        }
        failed += 1;
    }
    failed
}

#[cfg(all(target_os = "macos", not(miri)))]
mod imp {
    use std::ffi::CString;
    use std::io;
    use std::os::unix::ffi::OsStrExt;
    use std::path::Path;

    const NAME: &std::ffi::CStr = c"com.apple.quarantine";
    /// Large enough for any quarantine value (`flags;time;agent;uuid`).
    const MAX: usize = 1024;

    fn cpath(path: &Path) -> io::Result<CString> {
        CString::new(path.as_os_str().as_bytes())
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "path contains NUL"))
    }

    pub(super) fn read(path: &Path) -> Option<Vec<u8>> {
        let p = cpath(path).ok()?;
        let mut buf = vec![0u8; MAX];
        // SAFETY: `p` and `NAME` are NUL-terminated; `buf` is writable for `buf.len()` bytes;
        // XATTR_NOFOLLOW keeps a symlink from being followed.
        let n = unsafe {
            libc::getxattr(
                p.as_ptr(),
                NAME.as_ptr(),
                buf.as_mut_ptr().cast(),
                buf.len(),
                0,
                libc::XATTR_NOFOLLOW,
            )
        };
        let n = usize::try_from(n).ok().filter(|n| *n > 0)?;
        buf.truncate(n);
        Some(buf)
    }

    pub(super) fn apply(path: &Path, mark: &[u8]) -> io::Result<()> {
        let p = cpath(path)?;
        // SAFETY: `p` and `NAME` are NUL-terminated; `mark` is readable for `mark.len()` bytes.
        let r = unsafe {
            libc::setxattr(
                p.as_ptr(),
                NAME.as_ptr(),
                mark.as_ptr().cast(),
                mark.len(),
                0,
                libc::XATTR_NOFOLLOW,
            )
        };
        if r == 0 {
            Ok(())
        } else {
            Err(io::Error::last_os_error())
        }
    }
}

#[cfg(all(windows, not(miri)))]
mod imp {
    use std::io::{self, Read, Write};
    use std::path::{Path, PathBuf};

    /// Largest Zone.Identifier stream read (it is a few lines of text).
    const MAX: u64 = 4096;

    fn stream(path: &Path) -> PathBuf {
        let mut s = path.as_os_str().to_os_string();
        s.push(":Zone.Identifier");
        PathBuf::from(s)
    }

    pub(super) fn read(path: &Path) -> Option<Vec<u8>> {
        let f = std::fs::File::open(stream(path)).ok()?;
        let mut out = Vec::new();
        f.take(MAX).read_to_end(&mut out).ok()?;
        (!out.is_empty()).then_some(out)
    }

    pub(super) fn apply(path: &Path, mark: &[u8]) -> io::Result<()> {
        let mut f = std::fs::File::create(stream(path))?;
        f.write_all(mark)
    }
}

#[cfg(any(miri, not(any(target_os = "macos", windows))))]
mod imp {
    use std::io;
    use std::path::Path;

    pub(super) fn read(_path: &Path) -> Option<Vec<u8>> {
        None
    }

    #[allow(
        clippy::unnecessary_wraps,
        reason = "same signature as the real platforms"
    )]
    pub(super) fn apply(_path: &Path, _mark: &[u8]) -> io::Result<()> {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    #[test]
    #[cfg_attr(
        any(miri, not(any(target_os = "macos", windows))),
        ignore = "download marks exist on macOS and Windows only"
    )]
    fn marks_a_tree() {
        let d = std::env::temp_dir().join(format!("lphy-qtn-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(d.join("sub")).unwrap_or(());
        std::fs::write(d.join("a.txt"), b"a").unwrap_or(());
        std::fs::write(d.join("sub/b.txt"), b"b").unwrap_or(());
        assert_eq!(super::read(&d.join("a.txt")), None);
        let mark: &[u8] = if cfg!(windows) {
            b"[ZoneTransfer]\r\nZoneId=3\r\n"
        } else {
            b"0081;6738a1c0;Safari;"
        };
        assert_eq!(super::apply_tree(&d, mark), 0);
        assert_eq!(super::read(&d.join("a.txt")).as_deref(), Some(mark));
        assert_eq!(super::read(&d.join("sub/b.txt")).as_deref(), Some(mark));
        let _ = std::fs::remove_dir_all(&d);
    }
}
