//! Platform arka uçları: aygıt listeleme/tanımlama, yeniden bağlama, biçimlendirme.
//!
//! Harici araçlar yalnızca **mutlak yol** ve **argüman dizisi** ile çağrılır; kabuk,
//! PATH ve ortam genişletmesi kullanılmaz. macOS: `/usr/sbin/diskutil`. Windows:
//! `<GetSystemDirectoryW>\WindowsPowerShell\v1.0\powershell.exe`; değişken değerler komut dizgisine
//! değil, alt sürecin ortamına konur (enjeksiyon yok). `WinVerifyTrust` ile araç imza denetimi
//! DOĞRULANMADI / yapılmıyor.

use std::path::{Path, PathBuf};

use lephy_core::error::{Error, Result};

use crate::device::Device;

/// Platform soyutlaması (testlerde sahte uygulama).
pub trait Platform {
    /// Aday birimler (sistem birimleri listelenmez).
    ///
    /// # Errors
    /// Araç/OS hatası; desteklenmeyen platform.
    fn list(&self) -> Result<Vec<Device>>;

    /// Bağlama noktasındaki birimin **taze** tanımı (her adım öncesi kimlik için).
    ///
    /// # Errors
    /// Araç/OS hatası.
    fn describe(&self, mount: &Path) -> Result<Device>;

    /// Ayır ve yeniden bağla; yeni bağlama noktasını döner. Desteklenmiyorsa `Ok(None)`
    /// (geri okuma "önbellekten doğrulandı" etiketi alır).
    ///
    /// # Errors
    /// Araç hatası.
    fn remount(&self, dev: &Device) -> Result<Option<PathBuf>>;

    /// exFAT olarak biçimlendir (etiket korunur).
    ///
    /// # Errors
    /// Araç hatası, yetki yok.
    fn format(&self, dev: &Device, label: &str) -> Result<()>;

    /// Seri numarası zorunlu mu (Windows: evet; macOS: `diskutil` seri vermez).
    fn require_serial(&self) -> bool;
}

#[cfg_attr(not(any(target_os = "macos", windows)), allow(dead_code))]
fn tool_err(what: &str, out: &std::process::Output) -> Error {
    Error::Environment(format!(
        "{what} başarısız (kod {:?}): {}",
        out.status.code(),
        String::from_utf8_lossy(&out.stderr).trim()
    ))
}

/// exFAT etiketi: 1..=11 karakter, ASCII harf/rakam, boşluk, `-`, `_`.
#[must_use]
pub fn valid_exfat_label(label: &str) -> bool {
    !label.is_empty()
        && label.chars().count() <= 11
        && label
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == ' ' || c == '-' || c == '_')
}

/// Etkin platform.
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

/// Desteklenmeyen platform (Linux best-effort: `usb` desteklenmez).
pub struct Unsupported;

fn unsupported() -> Error {
    Error::Environment("USB komutları yalnızca macOS ve Windows'ta desteklenir".into())
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

/// macOS: `diskutil -plist` ayrıştırma (saf fonksiyonlar her platformda derlenir ve test edilir).
pub mod diskutil {
    use std::path::{Path, PathBuf};

    use crate::device::{Bus, Device, Identity};
    use crate::plist_lite::{self, Value};

    /// Ayrıştırılmış plist sözlüğü.
    pub type Dictionary = Value;

    /// Plist baytlarını sözlüğe çevirir.
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

    /// `diskutil list -plist external physical` → bağlı birimlerin `DeviceIdentifier`'ları.
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

    /// `diskutil info -plist <birim>` (+ isteğe bağlı bütün disk bilgisi) → [`Device`].
    /// Anahtar adları bu makinedeki dahili disk çıktısından doğrulandı; bir USB bellekte
    /// aldıkları değerler DOĞRULANMADI (gerçek donanım yok).
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
                .map_err(|e| Error::Environment(format!("{DISKUTIL} çalıştırılamadı: {e}")))?;
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
            diskutil::parse(&bytes)
                .ok_or_else(|| Error::Environment("diskutil info çıktısı ayrıştırılamadı".into()))
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

    /// `XXXXXXXX-XXXX-XXXX-XXXX-XXXXXXXXXXXX` (onaltılık) biçiminde mi.
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
                Error::Environment("diskutil list çıktısı ayrıştırılamadı".into())
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
                .ok_or_else(|| Error::Environment("bağlama noktası UTF-8 değil".into()))?;
            Self::device_for(m)
        }

        fn remount(&self, dev: &Device) -> Result<Option<PathBuf>> {
            if Self::run(&["unmount", &dev.tool_ref]).is_err() {
                return Ok(None);
            }
            Self::run(&["mount", &dev.tool_ref])?;
            let d = Self::device_for(&dev.tool_ref)?;
            if d.mount.as_os_str().is_empty() {
                return Err(Error::Environment(
                    "yeniden bağlama sonrası bağlama noktası yok".into(),
                ));
            }
            Ok(Some(d.mount))
        }

        fn format(&self, dev: &Device, label: &str) -> Result<()> {
            if !valid_exfat_label(label) {
                return Err(Error::Environment(format!(
                    "exFAT etiketi geçersiz (1–11 ASCII harf/rakam, boşluk, -, _): {label:?}"
                )));
            }
            // Bütün disk değil, yalnızca bu birim (diskXsY) — whole-disk reddi.
            let r = &dev.tool_ref;
            let ok = r.starts_with("disk") && r[4..].contains('s');
            if !ok {
                return Err(Error::Environment(format!(
                    "bütün disk biçimlendirilmez: {r}"
                )));
            }
            // Birim UUID ile hedeflenir: `diskXsY` adı aygıt değişince yeniden atanabilir, UUID
            // atanmaz. UUID yoksa (bazı MBR birimleri) aygıt adına düşülür.
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

    /// Yalnızca `X:`, `X:\\` ya da `X:/` kabul edilir (X harf). Göreli yollar ilk harflerinden
    /// sürücüye çevrilmez.
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
                    "hedef bir sürücü kökü olmalı (ör. E:\\); göreli ya da alt klasör yolu kabul edilmez"
                        .into(),
                )
            })?;
            let v = wv::volume_info(&root)?;
            Ok(to_device(&v, system_drive()))
        }

        fn remount(&self, _dev: &Device) -> Result<Option<PathBuf>> {
            // FSCTL_LOCK/DISMOUNT_VOLUME uygulanmadı: geri okuma "önbellekten doğrulandı".
            Ok(None)
        }

        fn format(&self, dev: &Device, label: &str) -> Result<()> {
            if !lephy_sys::vol::is_elevated() {
                return Err(Error::Environment(
                    "--format yönetici (yükseltilmiş) oturum gerektirir: \
                     PowerShell'i \"Yönetici olarak çalıştır\" ile açıp komutu yeniden deneyin"
                        .into(),
                ));
            }
            if !valid_exfat_label(label) {
                return Err(Error::Environment(format!(
                    "exFAT etiketi geçersiz: {label:?}"
                )));
            }
            if !valid_guid_path(&dev.tool_ref) {
                return Err(Error::Environment(format!(
                    "birim GUID yolu geçersiz: {}",
                    dev.tool_ref
                )));
            }
            let ps = wv::system_directory()?.join("WindowsPowerShell\\v1.0\\powershell.exe");
            // Değerler komut dizgisine gömülmez; ortamdan okunur (enjeksiyon yok).
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
                .map_err(|e| Error::Environment(format!("powershell çalıştırılamadı: {e}")))?;
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
        // Fixed USB SSD: RemovableMedia false → red
        let fixed = VOL.replace(
            "<key>RemovableMedia</key><true/>",
            "<key>RemovableMedia</key><false/>",
        );
        let d = diskutil::to_device(&diskutil::parse(fixed.as_bytes()).unwrap(), None, 7);
        assert!(d.eligibility(false).is_err());
        // Thunderbolt → red
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
