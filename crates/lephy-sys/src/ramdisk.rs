//! macOS RAM disk for an open vault: decrypted files live only in memory and are gone when the
//! disk is detached (or the computer restarts). Driven with the system tools `hdiutil` and
//! `diskutil`, called by absolute path with an empty environment.

use std::io;
use std::path::PathBuf;

/// Volume names start with this; leftovers from a crash are found by it.
pub const NAME_PREFIX: &str = "lephy-vault-";

/// An attached RAM disk.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RamDisk {
    /// Device node (`/dev/diskN`).
    pub dev: String,
    /// Mount point (`/Volumes/lephy-vault-…`).
    pub mount: PathBuf,
}

/// 512-byte sectors for `bytes`, rounded up.
#[must_use]
pub fn sectors(bytes: u64) -> u64 {
    bytes.div_ceil(512)
}

/// Size for a vault holding `content` bytes: 25 % headroom + 64 MiB, in whole MiB.
#[must_use]
pub fn size_for(content: u64) -> u64 {
    let want = content.saturating_add(content / 4).saturating_add(64 << 20);
    want.div_ceil(1 << 20) << 20
}

/// Leftover lephy RAM disks in `hdiutil info` output: blocks whose image is `ram://` and that
/// are mounted under a `lephy-vault-` name.
#[must_use]
pub fn parse_leftovers(info: &str) -> Vec<RamDisk> {
    let mut out = Vec::new();
    for block in info.split("================================================") {
        let ram = block
            .lines()
            .any(|l| l.starts_with("image-path") && l.contains("ram://"));
        if !ram {
            continue;
        }
        for line in block.lines() {
            let mut cols = line.split('\t');
            let dev = cols.next().unwrap_or("").trim();
            let mount = cols.next_back().unwrap_or("").trim();
            let named = std::path::Path::new(mount)
                .file_name()
                .is_some_and(|n| n.to_string_lossy().starts_with(NAME_PREFIX));
            if dev.starts_with("/dev/disk") && named {
                // Detach the whole disk (`/dev/diskN`), not its slice.
                let whole = dev
                    .trim_start_matches("/dev/disk")
                    .split('s')
                    .next()
                    .unwrap_or("");
                out.push(RamDisk {
                    dev: format!("/dev/disk{whole}"),
                    mount: PathBuf::from(mount),
                });
            }
        }
    }
    out
}

#[cfg(all(target_os = "macos", not(miri)))]
mod imp {
    use super::{NAME_PREFIX, RamDisk};
    use std::io;
    use std::path::PathBuf;
    use std::process::Command;

    const HDIUTIL: &str = "/usr/bin/hdiutil";
    const DISKUTIL: &str = "/usr/sbin/diskutil";
    const MDUTIL: &str = "/usr/bin/mdutil";
    const SYSCTL: &str = "/usr/sbin/sysctl";

    fn run(tool: &str, args: &[&str]) -> io::Result<String> {
        let out = Command::new(tool).args(args).env_clear().output()?;
        if out.status.success() {
            Ok(String::from_utf8_lossy(&out.stdout).into_owned())
        } else {
            Err(io::Error::other(format!(
                "{tool} failed: {}",
                String::from_utf8_lossy(&out.stderr).trim()
            )))
        }
    }

    pub(super) fn memory_bytes() -> Option<u64> {
        run(SYSCTL, &["-n", "hw.memsize"]).ok()?.trim().parse().ok()
    }

    pub(super) fn create(tag: &str, bytes: u64) -> io::Result<RamDisk> {
        if !tag.chars().all(|c| c.is_ascii_alphanumeric()) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "bad volume tag",
            ));
        }
        let url = format!("ram://{}", super::sectors(bytes));
        let dev = run(HDIUTIL, &["attach", "-nomount", &url])?
            .split_whitespace()
            .next()
            .map(str::to_owned)
            .filter(|d| d.starts_with("/dev/disk"))
            .ok_or_else(|| io::Error::other("hdiutil gave no device"))?;
        let name = format!("{NAME_PREFIX}{tag}");
        if let Err(e) = run(DISKUTIL, &["erasevolume", "HFS+", &name, &dev]) {
            let _ = run(HDIUTIL, &["detach", &dev, "-force"]);
            return Err(e);
        }
        let mount = PathBuf::from("/Volumes").join(&name);
        // Keep Spotlight away from the decrypted files.
        let _ = std::fs::write(mount.join(".metadata_never_index"), b"");
        let _ = run(MDUTIL, &["-i", "off", &mount.to_string_lossy()]);
        Ok(RamDisk { dev, mount })
    }

    pub(super) fn destroy(disk: &RamDisk, force: bool) -> io::Result<()> {
        let mut args = vec!["detach", disk.dev.as_str()];
        if force {
            args.push("-force");
        }
        run(HDIUTIL, &args).map(drop)
    }

    pub(super) fn leftovers() -> Vec<RamDisk> {
        run(HDIUTIL, &["info"])
            .map(|t| super::parse_leftovers(&t))
            .unwrap_or_default()
    }
}

#[cfg(any(miri, not(target_os = "macos")))]
mod imp {
    use super::RamDisk;
    use std::io;

    fn unsupported() -> io::Error {
        io::Error::new(io::ErrorKind::Unsupported, "RAM disks are macOS only")
    }

    pub(super) fn memory_bytes() -> Option<u64> {
        None
    }

    pub(super) fn create(_tag: &str, _bytes: u64) -> io::Result<RamDisk> {
        Err(unsupported())
    }

    pub(super) fn destroy(_disk: &RamDisk, _force: bool) -> io::Result<()> {
        Err(unsupported())
    }

    pub(super) fn leftovers() -> Vec<RamDisk> {
        Vec::new()
    }
}

/// Physical memory (bytes), where known.
#[must_use]
pub fn memory_bytes() -> Option<u64> {
    imp::memory_bytes()
}

/// Creates and mounts a RAM disk of `bytes` named `lephy-vault-<tag>` (`tag`: ASCII letters and
/// digits).
///
/// # Errors
/// Not macOS, bad tag, or a system tool failed (the half-made disk is detached).
pub fn create(tag: &str, bytes: u64) -> io::Result<RamDisk> {
    imp::create(tag, bytes)
}

/// Detaches the disk; everything on it is gone. Without `force` it fails while a program still
/// has a file on it open.
///
/// # Errors
/// The disk is busy or the tool failed.
pub fn destroy(disk: &RamDisk, force: bool) -> io::Result<()> {
    imp::destroy(disk, force)
}

/// lephy RAM disks still attached (e.g. after a crash).
#[must_use]
pub fn leftovers() -> Vec<RamDisk> {
    imp::leftovers()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sizes_and_sectors() {
        assert_eq!(sectors(1), 1);
        assert_eq!(sectors(1024), 2);
        assert_eq!(size_for(0), 64 << 20);
        assert_eq!(size_for(100 << 20), (125 + 64) << 20);
    }

    #[test]
    fn leftovers_from_hdiutil_info() {
        let info = "framework : 1\n================================================\n\
image-path      : /x.dmg\n/dev/disk4\tGUID\t\n/dev/disk4s1\tAPFS\t/Volumes/lephy-vault-fake\n\
================================================\n\
image-path      : ram://131072\nimage-type      : RAM disk\n/dev/disk9\t\t/Volumes/lephy-vault-ab12\n\
================================================\n\
image-path      : ram://2048\n/dev/disk10\t\t/Volumes/Other\n";
        let got = parse_leftovers(info);
        assert_eq!(
            got,
            vec![RamDisk {
                dev: "/dev/disk9".into(),
                mount: PathBuf::from("/Volumes/lephy-vault-ab12"),
            }]
        );
    }

    /// Attaches a real RAM disk: run by hand with `--ignored` on macOS.
    #[test]
    #[ignore = "attaches a real RAM disk"]
    fn create_write_destroy() {
        let d = create("test1", 8 << 20).unwrap_or_else(|e| panic!("{e}"));
        std::fs::write(d.mount.join("a.txt"), b"x").unwrap_or(());
        assert!(leftovers().contains(&d));
        destroy(&d, false).unwrap_or_else(|e| panic!("{e}"));
        assert!(!d.mount.exists());
    }
}
