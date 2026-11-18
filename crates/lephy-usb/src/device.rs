//! Device model, eligibility and identity.

use std::path::PathBuf;

/// Bus.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Bus {
    /// USB.
    Usb,
    /// Other (Thunderbolt, `PCIe`, SATA, `NVMe`, "Apple Fabric", virtual …).
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

/// Identity re-read before each step.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Identity {
    /// Physical disk: macOS `MediaName|DiskUUID|ParentWholeDisk`; Windows `DeviceNumber|Serial`.
    pub disk: String,
    /// Volume: macOS `VolumeUUID`; Windows `\\?\Volume{GUID}\` + volume serial number.
    pub volume: String,
    /// Size in bytes.
    pub size_bytes: u64,
    /// Volume identity of the mount point (`st_dev` / volume serial number).
    pub dev_id: u64,
}

/// A volume (mounted partition) and the physical device that holds it. The flags mirror the OS
/// query as is; the eligibility decision is made in one place, [`Device::eligibility`].
#[derive(Debug, Clone)]
#[allow(clippy::struct_excessive_bools)]
pub struct Device {
    /// Mount point / drive root.
    pub mount: PathBuf,
    /// Volume label.
    pub label: String,
    /// Total bytes.
    pub size_bytes: u64,
    /// File system (lowercase).
    pub fs_type: String,
    /// Bus.
    pub bus: Bus,
    /// Removable media (macOS `RemovableMedia`; Windows `DRIVE_REMOVABLE` **and**
    /// `RemovableMedia`).
    pub removable: bool,
    /// Internal device.
    pub internal: bool,
    /// Virtual/image device.
    pub virtual_device: bool,
    /// System/boot/Time Machine volume.
    pub system: bool,
    /// Device serial number (`diskutil` does not provide it on macOS: `None`).
    pub serial: Option<String>,
    /// Vendor/product name.
    pub product: String,
    /// Identifier passed to external tools: macOS `diskXsY`; Windows `\\?\Volume{GUID}\`.
    pub tool_ref: String,
    /// Identity.
    pub identity: Identity,
}

impl Device {
    /// Size as a whole number of GiB (`floor(bytes / 2^30)`) — the value the user types to confirm.
    #[must_use]
    pub const fn size_gib(&self) -> u64 {
        self.size_bytes >> 30
    }

    /// Eligibility. There is no bypass. `require_serial`: required on Windows.
    ///
    /// # Errors
    /// Reason for refusal (the caller turns it into code 1).
    pub fn eligibility(&self, require_serial: bool) -> Result<(), String> {
        if self.bus != Bus::Usb {
            return Err(format!("the bus is not USB ({})", self.bus));
        }
        if !self.removable {
            return Err("not removable media (\"fixed\" USB SSDs/HDDs are not supported)".into());
        }
        if self.internal {
            return Err("internal device".into());
        }
        if self.virtual_device {
            return Err("virtual/image device".into());
        }
        if self.system {
            return Err("system/boot/Time Machine volume".into());
        }
        if require_serial && self.serial.as_deref().is_none_or(|s| s.trim().is_empty()) {
            return Err("empty serial number".into());
        }
        if self.size_bytes == 0 {
            return Err("size could not be read".into());
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
        assert!(d.eligibility(false).unwrap_err().contains("not USB"));
        let mut d = ok.clone();
        d.bus = Bus::Other("Thunderbolt".into());
        assert!(d.eligibility(false).is_err());
        let mut d = ok.clone();
        d.removable = false;
        assert!(d.eligibility(false).unwrap_err().contains("fixed"));
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
        assert!(d.eligibility(true).unwrap_err().contains("serial"));
        assert!(d.eligibility(false).is_ok());
    }
}
