//! Birim ve fiziksel disk kimliği (PLAN › USB 1.1; R5-15). Aşama 4'te doldurulur.
//!
//! - `volume_id(handle)`: `fstatfs`/`st_dev` + UUID; Windows `GetVolumeInformationByHandleW`.
//! - `physical_disk_id(handle)`: Windows `IOCTL_STORAGE_GET_DEVICE_NUMBER` + `IOCTL_STORAGE_QUERY_PROPERTY`
//!   (`BusTypeUsb`, `RemovableMedia`); macOS `diskutil info -plist` (lephy-usb tarafında).
//! - `list_drives()`: `GetLogicalDrives` + `GetDriveTypeW` + `GetVolumeNameForVolumeMountPointW`.
//! - `lock_and_dismount(handle)`: `FSCTL_LOCK_VOLUME` + `FSCTL_DISMOUNT_VOLUME`.
//! - `open_nocache(path)`: `F_NOCACHE` / `FILE_FLAG_NO_BUFFERING`.
//!
//! `Win32_System_Ioctl` feature'ı yalnızca bu modül için ve 1.1'de eklenir.
