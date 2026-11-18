//! Splitting into parts: `name.lphy` → `name.lphy.001`, `name.lphy.002`, …
//!
//! Splitting sits below the format (no format flag): concatenating the parts in order gives the
//! original file. Integrity comes from STREAM; a missing, truncated or reordered part is caught
//! as damage (code 4) when decrypting.
//!
//! Splitting uses at most one part of extra disk space: after encryption the parts are copied
//! into separate files starting from the **end** of the file, and the original is truncated after
//! each step; the remaining head becomes `.001`. If interrupted, the (truncated) original and the
//! last parts written so far remain; since `.001` is created only at the very end, a half-written
//! set is never decrypted.

use std::fs::File;
use std::io::{self, Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};

use crate::error::{Error, Result};

/// Smallest part size.
pub const MIN_PART: u64 = 1024 * 1024;
/// Largest number of parts.
pub const MAX_PARTS: usize = 999;

/// Path of part `n` (`n` starts at 1).
#[must_use]
pub fn part_path(base: &Path, n: usize) -> PathBuf {
    let mut s = base.as_os_str().to_os_string();
    s.push(format!(".{n:03}"));
    PathBuf::from(s)
}

/// Whether the path is the first part of a set (`….001`).
#[must_use]
pub fn is_first_part(path: &Path) -> bool {
    path.extension().is_some_and(|e| e == "001")
}

/// Base name of the set from its first part (`name.lphy.001` → `name.lphy`).
#[must_use]
pub fn base_of(first: &Path) -> PathBuf {
    first.with_extension("")
}

/// The parts of the set, in order. Stops at the first missing one; every part except the last
/// must have the same size.
///
/// # Errors
/// First part missing, inconsistent sizes (code 4) or I/O.
pub fn parts(first: &Path) -> Result<Vec<PathBuf>> {
    let base = base_of(first);
    let mut out = Vec::new();
    for n in 1..=MAX_PARTS {
        let p = part_path(&base, n);
        if p.symlink_metadata().is_err() {
            break;
        }
        out.push(p);
    }
    if out.is_empty() {
        return Err(Error::Io(io::Error::new(
            io::ErrorKind::NotFound,
            "first part missing",
        )));
    }
    let sizes: Vec<u64> = out
        .iter()
        .map(|p| std::fs::metadata(p).map(|m| m.len()))
        .collect::<io::Result<_>>()?;
    if let Some((last, rest)) = sizes.split_last()
        && (rest.iter().any(|&s| s != sizes[0]) || *last > sizes[0] || *last == 0)
    {
        return Err(Error::Corrupt {
            at: "parts".into(),
            detail: Some("inconsistent part sizes (missing or modified part)".into()),
        });
    }
    Ok(out)
}

/// Reads the parts in order as one stream.
pub struct JoinReader {
    files: Vec<PathBuf>,
    next: usize,
    cur: Option<File>,
}

impl JoinReader {
    /// Reader over a list of parts.
    #[must_use]
    pub const fn new(files: Vec<PathBuf>) -> Self {
        Self {
            files,
            next: 0,
            cur: None,
        }
    }
}

impl Read for JoinReader {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        loop {
            if self.cur.is_none() {
                let Some(p) = self.files.get(self.next) else {
                    return Ok(0);
                };
                self.cur = Some(File::open(p)?);
                self.next += 1;
            }
            if let Some(f) = self.cur.as_mut() {
                let n = f.read(buf)?;
                if n > 0 || buf.is_empty() {
                    return Ok(n);
                }
                self.cur = None;
            }
        }
    }
}

/// Total length.
///
/// # Errors
/// I/O.
pub fn total_len(parts: &[PathBuf]) -> Result<u64> {
    let mut t = 0u64;
    for p in parts {
        t = t.saturating_add(std::fs::metadata(p)?.len());
    }
    Ok(t)
}

/// Splits `path` into parts of `part_size` bytes (the last may be shorter); the original file
/// is gone afterwards and the list of parts is returned. A file that fits one part is just renamed to `.001`.
///
/// # Errors
/// Part size < 1 MiB, more than 999 parts, an existing part name (code 7) or I/O.
pub fn split_file(path: &Path, part_size: u64) -> Result<Vec<PathBuf>> {
    if part_size < MIN_PART {
        return Err(Error::Environment(
            "the part size must be at least 1 MiB".into(),
        ));
    }
    let len = std::fs::metadata(path)?.len();
    let count = usize::try_from(len.div_ceil(part_size).max(1)).unwrap_or(usize::MAX);
    if count > MAX_PARTS {
        return Err(Error::Environment(format!(
            "at most {MAX_PARTS} parts; choose a larger part size"
        )));
    }
    let names: Vec<PathBuf> = (1..=count).map(|n| part_path(path, n)).collect();
    if let Some(p) = names.iter().find(|p| p.symlink_metadata().is_ok()) {
        return Err(Error::Exists(p.display().to_string()));
    }
    let mut src = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open(path)?;
    let mut buf = vec![0u8; 1 << 20]; // encrypted data; not secret
    for n in (2..=count).rev() {
        let start = part_size * (n as u64 - 1);
        let mut w = crate::io::AtomicWriter::create(&names[n - 1], false)?;
        src.seek(SeekFrom::Start(start))?;
        // Earlier steps truncated the file: the remaining length is the current size.
        let mut left = src.metadata()?.len() - start;
        while left > 0 {
            let k = usize::try_from(left.min(buf.len() as u64)).unwrap_or(buf.len());
            src.read_exact(&mut buf[..k])?;
            w.file().write_all(&buf[..k])?;
            left -= k as u64;
        }
        w.commit(false)?;
        // The original is truncated only after the part is durable.
        src.set_len(start)?;
        src.sync_all()?;
    }
    drop(src);
    lephy_sys::fs::rename_noclobber(path, &names[0]).map_err(|e| match e {
        lephy_sys::fs::NoclobberError::Exists => Error::Exists(names[0].display().to_string()),
        lephy_sys::fs::NoclobberError::Unsupported => {
            Error::Environment("the file system does not support atomic rename".into())
        }
        lephy_sys::fs::NoclobberError::Io(e) => Error::Io(e),
    })?;
    if let Some(d) = path.parent().filter(|d| !d.as_os_str().is_empty()) {
        let _ = lephy_sys::fs::fsync_dir(d);
    }
    Ok(names)
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::cast_possible_truncation)]
mod tests {
    use super::*;

    fn tmp(tag: &str) -> PathBuf {
        let d = std::env::temp_dir().join(format!("lphy-split-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        d
    }

    #[test]
    fn split_and_join_roundtrip() {
        let d = tmp("rt");
        let f = d.join("x.lphy");
        let data: Vec<u8> = (0..(3 * MIN_PART + 12345))
            .map(|i| (i % 251) as u8)
            .collect();
        std::fs::write(&f, &data).unwrap();
        let ps = split_file(&f, MIN_PART).unwrap();
        assert_eq!(ps.len(), 4);
        assert!(!f.exists());
        assert!(is_first_part(&ps[0]));
        let found = parts(&ps[0]).unwrap();
        assert_eq!(found, ps);
        let mut joined = Vec::new();
        JoinReader::new(found).read_to_end(&mut joined).unwrap();
        assert_eq!(joined, data);
        // A missing middle part: the rest is found and the sizes are not inconsistent; decryption
        // catches the truncated stream. A truncated middle part is caught here.
        std::fs::OpenOptions::new()
            .write(true)
            .open(&ps[1])
            .unwrap()
            .set_len(100)
            .unwrap();
        assert!(matches!(parts(&ps[0]), Err(Error::Corrupt { .. })));
        let _ = std::fs::remove_dir_all(&d);
    }

    #[test]
    fn small_file_becomes_single_part_and_names_are_never_overwritten() {
        let d = tmp("small");
        let f = d.join("y.lphy");
        std::fs::write(&f, b"small").unwrap();
        std::fs::write(part_path(&f, 1), b"exists").unwrap();
        assert!(matches!(split_file(&f, MIN_PART), Err(Error::Exists(_))));
        std::fs::remove_file(part_path(&f, 1)).unwrap();
        let ps = split_file(&f, MIN_PART).unwrap();
        assert_eq!(ps.len(), 1);
        assert_eq!(std::fs::read(&ps[0]).unwrap(), b"small");
        assert!(split_file(&d.join("z"), 10).is_err());
        let _ = std::fs::remove_dir_all(&d);
    }
}
