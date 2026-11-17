//! Aygıt modeli, uygunluk (PLAN USB 0a) ve kimlik (0c).

use std::path::PathBuf;

/// Veriyolu.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Bus {
    /// USB.
    Usb,
    /// Diğer (Thunderbolt, `PCIe`, SATA, `NVMe`, "Apple Fabric", sanal …).
    Other(String),
}

impl std::fmt::Display for Bus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Bus::Usb => f.write_str("USB"),
            Bus::Other(s) => f.write_str(s),
        }
    }
}

/// Bir adımdan önce yeniden okunan kimlik (0c).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Identity {
    /// Fiziksel disk: macOS `MediaName|DiskUUID|ParentWholeDisk`; Windows `DeviceNumber|Seri`.
    pub disk: String,
    /// Birim: macOS `VolumeUUID`; Windows `\\?\Volume{GUID}\` + birim seri no.
    pub volume: String,
    /// Bayt cinsinden boyut.
    pub size_bytes: u64,
    /// Bağlama noktasının birim kimliği (`st_dev` / birim seri no).
    pub dev_id: u64,
}

/// Bir birim (bağlı bölüm) ve onu taşıyan fiziksel aygıt. Bayraklar OS sorgusunun ham
/// yansımasıdır; uygunluk kararı [`Device::eligibility`] içinde tek yerde verilir.
#[derive(Debug, Clone)]
#[allow(clippy::struct_excessive_bools)]
pub struct Device {
    /// Bağlama noktası / sürücü kökü.
    pub mount: PathBuf,
    /// Birim etiketi.
    pub label: String,
    /// Toplam bayt.
    pub size_bytes: u64,
    /// Dosya sistemi (küçük harf).
    pub fs_type: String,
    /// Veriyolu.
    pub bus: Bus,
    /// Çıkarılabilir ortam (macOS `RemovableMedia`; Windows `DRIVE_REMOVABLE` **ve**
    /// `RemovableMedia`).
    pub removable: bool,
    /// Dahili aygıt.
    pub internal: bool,
    /// Sanal/imaj aygıt.
    pub virtual_device: bool,
    /// Sistem/boot/Time Machine birimi.
    pub system: bool,
    /// Aygıt seri numarası (macOS'ta `diskutil` vermez: `None`).
    pub serial: Option<String>,
    /// Üretici/ürün adı.
    pub product: String,
    /// Harici araçlara verilen tanıtıcı: macOS `diskXsY`; Windows `\\?\Volume{GUID}\`.
    pub tool_ref: String,
    /// Kimlik.
    pub identity: Identity,
}

impl Device {
    /// Boyut, GiB tam sayı (`floor(bayt / 2^30)`) — onayda kullanıcının yazdığı değer.
    #[must_use]
    pub const fn size_gib(&self) -> u64 {
        self.size_bytes >> 30
    }

    /// Uygunluk (0a). Bypass yoktur. `require_serial`: Windows'ta açık karar 16.
    ///
    /// # Errors
    /// Reddetme nedeni (çağıran kod 1'e çevirir).
    pub fn eligibility(&self, require_serial: bool) -> Result<(), String> {
        if self.bus != Bus::Usb {
            return Err(format!("veriyolu USB değil ({})", self.bus));
        }
        if !self.removable {
            return Err("çıkarılabilir ortam değil (\"Fixed\" USB SSD/HDD desteklenmez)".into());
        }
        if self.internal {
            return Err("dahili aygıt".into());
        }
        if self.virtual_device {
            return Err("sanal/imaj aygıtı".into());
        }
        if self.system {
            return Err("sistem/boot/Time Machine birimi".into());
        }
        if require_serial && self.serial.as_deref().is_none_or(|s| s.trim().is_empty()) {
            return Err("seri numarası boş (açık karar 16)".into());
        }
        if self.size_bytes == 0 {
            return Err("boyut okunamadı".into());
        }
        Ok(())
    }
}

#[cfg(test)]
pub(crate) fn sample(mount: PathBuf) -> Device {
    Device {
        mount,
        label: "LEPHYTEST".into(),
        size_bytes: 16 * (1 << 30) + 123,
        fs_type: "exfat".into(),
        bus: Bus::Usb,
        removable: true,
        internal: false,
        virtual_device: false,
        system: false,
        serial: Some("SN123".into()),
        product: "Test Stick".into(),
        tool_ref: "disk9s1".into(),
        identity: Identity {
            disk: "Test Stick|DISK-UUID|disk9".into(),
            volume: "VOL-UUID".into(),
            size_bytes: 16 * (1 << 30) + 123,
            dev_id: 42,
        },
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn eligibility_rules() {
        let ok = sample(PathBuf::from("/Volumes/X"));
        assert!(ok.eligibility(true).is_ok());
        assert_eq!(ok.size_gib(), 16);
        let mut d = ok.clone();
        d.bus = Bus::Other("SATA".into());
        assert!(d.eligibility(false).unwrap_err().contains("USB değil"));
        let mut d = ok.clone();
        d.bus = Bus::Other("Thunderbolt".into());
        assert!(d.eligibility(false).is_err());
        let mut d = ok.clone();
        d.removable = false;
        assert!(d.eligibility(false).unwrap_err().contains("Fixed"));
        let mut d = ok.clone();
        d.internal = true;
        assert!(d.eligibility(false).is_err());
        let mut d = ok.clone();
        d.virtual_device = true;
        assert!(d.eligibility(false).is_err());
        let mut d = ok.clone();
        d.system = true;
        assert!(d.eligibility(false).is_err());
        let mut d = ok.clone();
        d.serial = Some("  ".into());
        assert!(d.eligibility(true).unwrap_err().contains("seri"));
        assert!(d.eligibility(false).is_ok());
    }
}
