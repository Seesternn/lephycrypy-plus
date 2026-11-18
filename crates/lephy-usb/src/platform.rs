//! Platform back ends: listing/describing devices, remounting, formatting.
//!
//! External tools are called only with an **absolute path** and an **argument array**; no shell,
//! PATH or environment expansion is used. macOS: `/usr/sbin/diskutil`. Windows:
//! `<GetSystemDirectoryW>\WindowsPowerShell\v1.0\powershell.exe`; variable values go into the
//! child process's environment, not into the command string (no injection). The tool signature is
//! not checked with `WinVerifyTrust` (UNVERIFIED / not done).

use std::path::{Path, PathBuf};

use lephy_core::error::{Error, Result};

use crate::device::Device;

/// Platform abstraction (a fake implementation in tests).
pub trait Platform {
    /// Candidate volumes (system volumes are not listed).
    ///
    /// # Errors
    /// Tool/OS error; unsupported platform.
    fn list(&self) -> Result<Vec<Device>>;

    /// A **fresh** description of the volume at the mount point (for the identity before each step).
    ///
    /// # Errors
    /// Tool/OS error.
    fn describe(&self, mount: &Path) -> Result<Device>;

    /// Eject and remount; returns the new mount point. `Ok(None)` if not supported
    /// (the read-back is labelled "verified from cache").
    ///
    /// # Errors
    /// Tool error.
    fn remount(&self, dev: &Device) -> Result<Option<PathBuf>>;

    /// Format as exFAT (the label is kept).
    ///
    /// # Errors
    /// Tool error, no permission.
    fn format(&self, dev: &Device, label: &str) -> Result<()>;

    /// Whether a serial number is required (Windows: yes; macOS: `diskutil` gives no serial).
    fn require_serial(&self) -> bool;
}

#[cfg_attr(not(any(target_os = "macos", windows)), allow(dead_code))]
fn tool_err(what: &str, out: &std::process::Output) -> Error {
    Error::Environment(format!(
        "{what} failed (code {:?}): {}",
        out.status.code(),
        String::from_utf8_lossy(&out.stderr).trim()
    ))
}

/// exFAT label: 1..=11 characters, ASCII letters/digits, space, `-`, `_`.
#[must_use]
pub fn valid_exfat_label(label: &str) -> bool {
    !label.is_empty()
        && label.chars().count() <= 11
        && label
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == ' ' || c == '-' || c == '_')
}

/// Active platform.
#[must_use]
pub fn native() -> Box<dyn Platform> {
    #[cfg(target_os = "macos")]
    {
        Box::new(mac::MacPlatform::new())
    }
    #[cfg(windows)]
    {
        Box::new(win::WinPlatform)
    }
    #[cfg(not(any(target_os = "macos", windows)))]
    {
        Box::new(Unsupported)
    }
}

/// Unsupported platform (Linux is best effort: `usb` is not supported).
pub struct Unsupported;

fn unsupported() -> Error {
    Error::Environment("USB commands are supported only on macOS and Windows".into())
}

impl Platform for Unsupported {
    fn list(&self) -> Result<Vec<Device>> {
        Err(unsupported())
    }
    fn describe(&self, _mount: &Path) -> Result<Device> {
        Err(unsupported())
    }
    fn remount(&self, _dev: &Device) -> Result<Option<PathBuf>> {
        Ok(None)
    }
    fn format(&self, _dev: &Device, _label: &str) -> Result<()> {
        Err(unsupported())
    }
    fn require_serial(&self) -> bool {
        true
    }
}

/// macOS: parsing `diskutil -plist` (the pure functions compile and are tested on every platform).
pub mod diskutil {
    use std::path::{Path, PathBuf};

    use crate::device::{Bus, Device, Identity};
    use crate::plist_lite::{self, Value};

    /// Parsed plist dictionary.
    pub type Dictionary = Value;

    /// Turns plist bytes into a dictionary.
    #[must_use]
    pub fn parse(bytes: &[u8]) -> Option<Dictionary> {
        plist_lite::parse(bytes).filter(Value::is_dict)
    }

    fn s(d: &Dictionary, k: &str) -> String {
        d.get(k).and_then(Value::as_str).unwrap_or("").to_string()
    }
    fn b(d: &Dictionary, k: &str) -> bool {
        d.get(k).and_then(Value::as_bool).unwrap_or(false)
    }
    fn u(d: &Dictionary, k: &str) -> u64 {
        d.get(k).and_then(Value::as_u64).unwrap_or(0)
    }

    /// `diskutil list -plist external physical` → `DeviceIdentifier`s of mounted volumes.
    #[must_use]
    pub fn mounted_identifiers(list: &Dictionary) -> Vec<String> {
        let mut out = Vec::new();
        let Some(all) = list.get("AllDisksAndPartitions").and_then(Value::as_array) else {
            return out;
        };
        for disk in all.iter().filter(|v| v.is_dict()) {
            if !s(disk, "MountPoint").is_empty() {
                out.push(s(disk, "DeviceIdentifier"));
            }
            for key in ["Partitions", "APFSVolumes"] {
                if let Some(parts) = disk.get(key).and_then(Value::as_array) {
                    for p in parts.iter().filter(|v| v.is_dict()) {
                        if !s(p, "MountPoint").is_empty() {
                            out.push(s(p, "DeviceIdentifier"));
                        }
                    }
                }
            }
        }
        out
    }

    /// `diskutil info -plist <volume>` (+ optional whole-disk info) → [`Device`].
    /// Key names were verified from this machine's internal-disk output; their values on a USB
    /// stick are UNVERIFIED (no real hardware).
    #[must_use]
    pub fn to_device(vol: &Dictionary, whole: Option<&Dictionary>, dev_id: u64) -> Device {
        let mount = PathBuf::from(s(vol, "MountPoint"));
        let size = match u(vol, "TotalSize") {
            0 => u(vol, "Size"),
            n => n,
        };
        let bus = match s(vol, "BusProtocol").as_str() {
            "USB" => Bus::Usb,
            other => Bus::Other(other.to_string()),
        };
        let media = whole
            .map(|w| s(w, "MediaName"))
            .filter(|m| !m.is_empty())
            .unwrap_or_else(|| s(vol, "MediaName"));
        let system = mount == Path::new("/")
            || mount.starts_with("/System")
            || b(vol, "SystemImage")
            || mount.join("Backups.backupdb").exists()
            || mount.join(".timemachine").exists();
        Device {
            label: s(vol, "VolumeName"),
            size_bytes: size,
            fs_type: s(vol, "FilesystemType").to_ascii_lowercase(),
            removable: b(vol, "RemovableMedia") || b(vol, "Removable"),
            internal: b(vol, "Internal"),
            virtual_device: s(vol, "VirtualOrPhysical") == "Virtual"
                || s(vol, "BusProtocol") == "Disk Image",
            system,
            serial: None,
            product: media.clone(),
            tool_ref: s(vol, "DeviceIdentifier"),
            identity: Identity {
                disk: format!(
                    "{media}|{}|{}",
                    s(vol, "DiskUUID"),
                    s(vol, "ParentWholeDisk")
                ),
                volume: s(vol, "VolumeUUID"),
                size_bytes: size,
                dev_id,
            },
            mount,
            bus,
        }
    }
}

#[cfg(target_os = "macos")]
mod mac {
    use std::path::{Path, PathBuf};
    use std::process::Command;

    use lephy_core::error::{Error, Result};

    use super::{Platform, diskutil, tool_err, valid_exfat_label};
    use crate::device::Device;

    const DISKUTIL: &str = "/usr/sbin/diskutil";

    pub(super) struct MacPlatform;

    impl MacPlatform {
        pub(super) const fn new() -> Self {
            Self
        }

        fn run(args: &[&str]) -> Result<Vec<u8>> {
            let out = Command::new(DISKUTIL)
                .args(args)
                .env_clear()
                .output()
                .map_err(|e| Error::Environment(format!("{DISKUTIL} could not be run: {e}")))?;
            if !out.status.success() {
                return Err(tool_err(
                    &format!("diskutil {}", args.first().unwrap_or(&"")),
                    &out,
                ));
            }
            Ok(out.stdout)
        }

        fn info(target: &str) -> Result<diskutil::Dictionary> {
            let bytes = Self::run(&["info", "-plist", target])?;
            diskutil::parse(&bytes).ok_or_else(|| {
                Error::Environment("diskutil info output could not be parsed".into())
            })
        }

        fn device_for(target: &str) -> Result<Device> {
            let vol = Self::info(target)?;
            let whole_id = vol
                .get("ParentWholeDisk")
                .and_then(crate::plist_lite::Value::as_str)
                .unwrap_or("")
                .to_string();
            let whole = if whole_id.is_empty() {
                None
            } else {
                Self::info(&whole_id).ok()
            };
            let mount = vol
                .get("MountPoint")
                .and_then(crate::plist_lite::Value::as_str)
                .unwrap_or("")
                .to_string();
            let dev_id = if mount.is_empty() {
                0
            } else {
                lephy_sys::vol::device_id(Path::new(&mount))?
            };
            Ok(diskutil::to_device(&vol, whole.as_ref(), dev_id))
        }
    }

    /// Whether it has the form `XXXXXXXX-XXXX-XXXX-XXXX-XXXXXXXXXXXX` (hexadecimal).
    pub(crate) fn is_uuid(s: &str) -> bool {
        let b = s.as_bytes();
        b.len() == 36
            && b.iter().enumerate().all(|(i, c)| {
                if matches!(i, 8 | 13 | 18 | 23) {
                    *c == b'-'
                } else {
                    c.is_ascii_hexdigit()
                }
            })
    }

    impl Platform for MacPlatform {
        fn list(&self) -> Result<Vec<Device>> {
            let bytes = Self::run(&["list", "-plist", "external", "physical"])?;
            let list = diskutil::parse(&bytes).ok_or_else(|| {
                Error::Environment("diskutil list output could not be parsed".into())
            })?;
            let mut out = Vec::new();
            for id in diskutil::mounted_identifiers(&list) {
                let d = Self::device_for(&id)?;
                if !d.system {
                    out.push(d);
                }
            }
            Ok(out)
        }

        fn describe(&self, mount: &Path) -> Result<Device> {
            let m = mount
                .to_str()
                .ok_or_else(|| Error::Environment("mount point is not UTF-8".into()))?;
            Self::device_for(m)
        }

        fn remount(&self, dev: &Device) -> Result<Option<PathBuf>> {
            if Self::run(&["unmount", &dev.tool_ref]).is_err() {
                return Ok(None);
            }
            Self::run(&["mount", &dev.tool_ref])?;
            let d = Self::device_for(&dev.tool_ref)?;
            if d.mount.as_os_str().is_empty() {
                return Err(Error::Environment("no mount point after remounting".into()));
            }
            Ok(Some(d.mount))
        }

        fn format(&self, dev: &Device, label: &str) -> Result<()> {
            if !valid_exfat_label(label) {
                return Err(Error::Environment(format!(
                    "invalid exFAT label (1–11 ASCII letters/digits, space, -, _): {label:?}"
                )));
            }
            // Only this volume (diskXsY), never the whole disk — whole disks are refused.
            let r = &dev.tool_ref;
            let ok = r.starts_with("disk") && r[4..].contains('s');
            if !ok {
                return Err(Error::Environment(format!(
                    "a whole disk is never formatted: {r}"
                )));
            }
            // Targeted by volume UUID: the `diskXsY` name can be reassigned when devices change, the
            // UUID cannot. Without a UUID (some MBR volumes) the device name is used.
            let target = if is_uuid(&dev.identity.volume) {
                dev.identity.volume.as_str()
            } else {
                r.as_str()
            };
            Self::run(&["eraseVolume", "ExFAT", label, target])?;
            Ok(())
        }

        fn require_serial(&self) -> bool {
            false
        }
    }
}

#[cfg(windows)]
mod win {
    use std::path::{Path, PathBuf};
    use std::process::Command;

    use lephy_core::error::{Error, Result};
    use lephy_sys::vol::win::{self as wv, BUS_TYPE_USB, DRIVE_REMOVABLE};

    use super::{Platform, tool_err, valid_exfat_label};
    use crate::device::{Bus, Device, Identity};

    pub(super) struct WinPlatform;

    fn to_device(v: &wv::VolumeInfo, system_drive: Option<char>) -> Device {
        let letter = v.root.to_string_lossy().chars().next();
        Device {
            mount: v.root.clone(),
            label: v.label.clone(),
            size_bytes: v.total_bytes,
            fs_type: v.fs_name.to_ascii_lowercase(),
            bus: if v.bus_type == BUS_TYPE_USB {
                Bus::Usb
            } else {
                Bus::Other(format!("BusType {}", v.bus_type))
            },
            removable: v.drive_type == DRIVE_REMOVABLE && v.removable_media,
            internal: false,
            virtual_device: false,
            system: letter.is_some() && letter == system_drive,
            serial: Some(v.serial.clone()),
            product: v.product.clone(),
            tool_ref: v.guid_path.clone(),
            identity: Identity {
                disk: format!("{}|{}", v.device_number, v.serial),
                volume: format!("{}|{:08x}", v.guid_path, v.volume_serial),
                size_bytes: v.total_bytes,
                dev_id: u64::from(v.volume_serial),
            },
        }
    }

    fn system_drive() -> Option<char> {
        wv::system_directory()
            .ok()
            .and_then(|p| p.to_string_lossy().chars().next())
    }

    /// `\\?\Volume{xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx}\`
    pub(super) fn valid_guid_path(p: &str) -> bool {
        let Some(inner) = p
            .strip_prefix("\\\\?\\Volume{")
            .and_then(|r| r.strip_suffix("}\\"))
        else {
            return false;
        };
        inner.len() == 36
            && inner.chars().enumerate().all(|(i, c)| {
                if matches!(i, 8 | 13 | 18 | 23) {
                    c == '-'
                } else {
                    c.is_ascii_hexdigit()
                }
            })
    }

    /// Only `X:`, `X:\\` or `X:/` are accepted (X a letter). Relative paths are not turned into
    /// a drive from their first letter.
    fn drive_root(s: &str) -> Option<PathBuf> {
        let b = s.as_bytes();
        let ok = matches!(b.len(), 2 | 3)
            && b[0].is_ascii_alphabetic()
            && b[1] == b':'
            && (b.len() == 2 || b[2] == b'\\' || b[2] == b'/');
        ok.then(|| PathBuf::from(format!("{}:\\", char::from(b[0].to_ascii_uppercase()))))
    }

    #[cfg(test)]
    mod drive_tests {
        #[test]
        fn only_drive_roots_are_accepted() {
            for good in ["E:", "e:\\", "E:/"] {
                assert!(super::drive_root(good).is_some(), "{good}");
            }
            for bad in ["data", "fixed", "E:\\dir", "\\\\server\\share", "", "1:"] {
                assert!(super::drive_root(bad).is_none(), "{bad}");
            }
        }
    }

    impl Platform for WinPlatform {
        fn list(&self) -> Result<Vec<Device>> {
            let sys = system_drive();
            let mut out = Vec::new();
            for root in wv::logical_drives() {
                if let Ok(v) = wv::volume_info(&root) {
                    let d = to_device(&v, sys);
                    if !d.system {
                        out.push(d);
                    }
                }
            }
            Ok(out)
        }

        fn describe(&self, mount: &Path) -> Result<Device> {
            let root = drive_root(&mount.to_string_lossy()).ok_or_else(|| {
                Error::Environment(
                    "the target must be a drive root (e.g. E:\\); relative or subfolder paths are not accepted"
                        .into(),
                )
            })?;
            let v = wv::volume_info(&root)?;
            Ok(to_device(&v, system_drive()))
        }

        fn remount(&self, _dev: &Device) -> Result<Option<PathBuf>> {
            // FSCTL_LOCK/DISMOUNT_VOLUME not implemented: the read-back is "verified from cache".
            Ok(None)
        }

        fn format(&self, dev: &Device, label: &str) -> Result<()> {
            if !lephy_sys::vol::is_elevated() {
                return Err(Error::Environment(
                    "--format needs an administrator (elevated) session: \
                     open PowerShell with \"Run as administrator\" and try again"
                        .into(),
                ));
            }
            if !valid_exfat_label(label) {
                return Err(Error::Environment(format!(
                    "invalid exFAT label: {label:?}"
                )));
            }
            if !valid_guid_path(&dev.tool_ref) {
                return Err(Error::Environment(format!(
                    "invalid volume GUID path: {}",
                    dev.tool_ref
                )));
            }
            let ps = wv::system_directory()?.join("WindowsPowerShell\\v1.0\\powershell.exe");
            // Values are not embedded in the command string; they are read from the environment (no injection).
            let script = "Format-Volume -Path $env:LPHY_VOL -FileSystem exFAT \
                          -NewFileSystemLabel $env:LPHY_LABEL -Confirm:$false -Force | Out-Null";
            let out = Command::new(&ps)
                .args([
                    "-NoProfile",
                    "-NonInteractive",
                    "-ExecutionPolicy",
                    "Bypass",
                    "-Command",
                    script,
                ])
                .env_clear()
                .env("LPHY_VOL", &dev.tool_ref)
                .env("LPHY_LABEL", label)
                .env(
                    "SystemRoot",
                    wv::system_directory()?
                        .parent()
                        .unwrap_or(Path::new("C:\\Windows")),
                )
                .output()
                .map_err(|e| Error::Environment(format!("powershell could not be run: {e}")))?;
            if !out.status.success() {
                return Err(tool_err("Format-Volume", &out));
            }
            Ok(())
        }

        fn require_serial(&self) -> bool {
            true
        }
    }

    #[cfg(test)]
    mod tests {
        #[test]
        fn guid_path_validation() {
            assert!(super::valid_guid_path(
                "\\\\?\\Volume{01234567-89ab-cdef-0123-456789abcdef}\\"
            ));
            assert!(!super::valid_guid_path("\\\\?\\Volume{0123}\\"));
            assert!(!super::valid_guid_path("C:\\"));
            assert!(!super::valid_guid_path(
                "\\\\?\\Volume{01234567-89ab-cdef-0123-456789abcdef}\\; rm"
            ));
        }
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn exfat_labels() {
        assert!(valid_exfat_label("LEPHY"));
        assert!(valid_exfat_label("MY USB_1-2"));
        assert!(!valid_exfat_label(""));
        assert!(!valid_exfat_label("TWELVECHARSX"));
        assert!(!valid_exfat_label("a;rm -rf"));
        assert!(!valid_exfat_label("ŞŞ"));
    }

    const VOL: &str = r#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
<key>BusProtocol</key><string>USB</string>
<key>DeviceIdentifier</key><string>disk4s1</string>
<key>DiskUUID</key><string>AAAA-1111</string>
<key>FilesystemType</key><string>exfat</string>
<key>Internal</key><false/>
<key>MediaName</key><string></string>
<key>MountPoint</key><string>/Volumes/STICK</string>
<key>ParentWholeDisk</key><string>disk4</string>
<key>RemovableMedia</key><true/>
<key>SystemImage</key><false/>
<key>TotalSize</key><integer>32017047552</integer>
<key>VirtualOrPhysical</key><string>Physical</string>
<key>VolumeName</key><string>STICK</string>
<key>VolumeUUID</key><string>BBBB-2222</string>
</dict></plist>"#;

    const WHOLE: &str = r#"<?xml version="1.0" encoding="UTF-8"?>
<plist version="1.0"><dict><key>MediaName</key><string>SanDisk Ultra</string></dict></plist>"#;

    const LIST: &str = r#"<?xml version="1.0" encoding="UTF-8"?>
<plist version="1.0"><dict><key>AllDisksAndPartitions</key><array>
<dict><key>DeviceIdentifier</key><string>disk4</string><key>Partitions</key><array>
<dict><key>DeviceIdentifier</key><string>disk4s1</string><key>MountPoint</key><string>/Volumes/STICK</string></dict>
<dict><key>DeviceIdentifier</key><string>disk4s2</string></dict>
</array></dict>
<dict><key>DeviceIdentifier</key><string>disk6</string><key>MountPoint</key><string>/Volumes/RAW</string></dict>
</array></dict></plist>"#;

    #[test]
    fn diskutil_plist_parsing() {
        let vol = diskutil::parse(VOL.as_bytes()).unwrap();
        let whole = diskutil::parse(WHOLE.as_bytes()).unwrap();
        let d = diskutil::to_device(&vol, Some(&whole), 7);
        assert_eq!(d.bus, crate::device::Bus::Usb);
        assert!(d.removable && !d.internal && !d.virtual_device && !d.system);
        assert_eq!(d.label, "STICK");
        assert_eq!(d.size_gib(), 29);
        assert_eq!(d.tool_ref, "disk4s1");
        assert_eq!(d.product, "SanDisk Ultra");
        assert_eq!(d.identity.volume, "BBBB-2222");
        assert!(d.identity.disk.contains("AAAA-1111") && d.identity.disk.contains("disk4"));
        assert!(d.eligibility(false).is_ok());
        // Fixed USB SSD: RemovableMedia false → refused
        let fixed = VOL.replace(
            "<key>RemovableMedia</key><true/>",
            "<key>RemovableMedia</key><false/>",
        );
        let d = diskutil::to_device(&diskutil::parse(fixed.as_bytes()).unwrap(), None, 7);
        assert!(d.eligibility(false).is_err());
        // Thunderbolt → refused
        let tb = VOL.replace(">USB<", ">Thunderbolt<");
        let d = diskutil::to_device(&diskutil::parse(tb.as_bytes()).unwrap(), None, 7);
        assert!(d.eligibility(false).is_err());
        let list = diskutil::parse(LIST.as_bytes()).unwrap();
        assert_eq!(
            diskutil::mounted_identifiers(&list),
            vec!["disk4s1".to_string(), "disk6".to_string()]
        );
    }
}
