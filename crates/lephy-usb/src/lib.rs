//! lephycrypy+ USB: wipe **removable USB media** only and write only the encrypted `.lphy`
//! file. `#![forbid(unsafe_code)]`; all FFI is in `lephy-sys`.
//!
//! Rules (no flag overrides any of them): USB bus **and** removable media; internal/virtual/
//! system volumes are refused; a serial number is required on Windows; confirmation needs the
//! label **and** the size in GiB; the device identity is re-read before every step (a difference → code 5).
//!
//! Not verified on real hardware: the values of the `diskutil` plist keys on a USB stick, the
//! values of the Windows `STORAGE_DEVICE_DESCRIPTOR` fields on a USB stick, and the end-to-end
//! behaviour of `diskutil eraseVolume` and `Format-Volume -Path` (THREAT-MODEL › USB).

#![forbid(unsafe_code)]

pub mod device;
pub mod engine;
pub mod platform;
pub mod plist_lite;

pub use device::{Bus, Device, Identity};
pub use engine::{Confirm, DryRun, FillOptions, Verification, WriteReport, WriteRequest};
pub use platform::{Platform, native};
