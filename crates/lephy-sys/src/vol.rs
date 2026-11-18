//! Volume and physical-disk identity. Used by `lephy-usb`.
//!
//! - [`device_id`]: identity of the volume holding a path (Unix `st_dev`; Windows volume serial).
//!   Re-read at every step after the root handle is opened; if it changes, the target changed.
//! - [`open_nocache`]: open with macOS `F_NOCACHE` (read-back; does not drop existing pages —
//!   UNVERIFIED); a plain open on other platforms.
//! - [`is_elevated`]: Unix `geteuid() == 0`; Windows `TokenElevation` (`--format`
//!   only in an elevated session).
//! - macOS: [`mount_source`] (`statfs.f_mntfromname`, e.g. `/dev/disk4s1`).
//! - Windows: [`win::volume_info`] (`GetDriveTypeW`, `GetVolumeInformationW`,
//!   `GetVolumeNameForVolumeMountPointW`, `IOCTL_STORAGE_QUERY_PROPERTY` →
//!   `STORAGE_DEVICE_DESCRIPTOR`, `IOCTL_STORAGE_GET_DEVICE_NUMBER`), [`win::logical_drives`],
//!   [`win::system_directory`].

use std::fs::File;
use std::io;
use std::path::Path;

/// Identity of the volume holding the path.
///
/// # Errors
/// I/O error.
pub fn device_id(path: &Path) -> io::Result<u64> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        Ok(std::fs::symlink_metadata(path)?.dev())
    }
    #[cfg(windows)]
    {
        win::volume_serial(path).map(u64::from)
    }
}

/// Opens for reading while trying to bypass the cache (macOS `F_NOCACHE`).
///
/// # Errors
/// I/O error.
pub fn open_nocache(path: &Path) -> io::Result<File> {
    let f = File::open(path)?;
    #[cfg(target_os = "macos")]
    {
        use std::os::fd::AsRawFd;
        // SAFETY: `f` is an open file; F_NOCACHE takes an integer argument, no memory pointer.
        let rc = unsafe { libc::fcntl(f.as_raw_fd(), libc::F_NOCACHE, 1) };
        if rc == -1 {
            return Err(io::Error::last_os_error());
        }
    }
    Ok(f)
}

/// Whether the process runs with administrator/root rights.
#[must_use]
pub fn is_elevated() -> bool {
    #[cfg(unix)]
    {
        // SAFETY: geteuid takes no argument and always succeeds.
        unsafe { libc::geteuid() == 0 }
    }
    #[cfg(windows)]
    {
        win::is_elevated()
    }
}

/// macOS: the volume's mount source (`/dev/diskXsY`).
///
/// # Errors
/// I/O error.
#[cfg(target_os = "macos")]
pub fn mount_source(path: &Path) -> io::Result<String> {
    use std::os::unix::ffi::OsStrExt;
    let c = std::ffi::CString::new(path.as_os_str().as_bytes())
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "NUL in path"))?;
    // SAFETY: statfs is a plain C struct; zero initialisation is valid.
    let mut st: libc::statfs = unsafe { core::mem::zeroed() };
    // SAFETY: `c` is NUL terminated; `st` is valid and writable.
    if unsafe { libc::statfs(c.as_ptr(), &raw mut st) } != 0 {
        return Err(io::Error::last_os_error());
    }
    let bytes: Vec<u8> = st
        .f_mntfromname
        .iter()
        .take_while(|&&ch| ch != 0)
        .map(|&ch| u8::try_from(ch).unwrap_or(b'?'))
        .collect();
    Ok(String::from_utf8_lossy(&bytes).into_owned())
}

/// Windows volume/disk queries.
#[cfg(windows)]
pub mod win {
    use std::io;
    use std::os::windows::ffi::{OsStrExt, OsStringExt};
    use std::os::windows::io::{AsRawHandle, FromRawHandle, OwnedHandle};
    use std::path::{Path, PathBuf};

    use windows_sys::Win32::Foundation::{GENERIC_READ, HANDLE, INVALID_HANDLE_VALUE};
    use windows_sys::Win32::Security::{
        GetTokenInformation, TOKEN_ELEVATION, TOKEN_QUERY, TokenElevation,
    };
    use windows_sys::Win32::Storage::FileSystem::{
        CreateFileW, FILE_SHARE_READ, FILE_SHARE_WRITE, GetDiskFreeSpaceExW, GetDriveTypeW,
        GetLogicalDrives, GetVolumeInformationW, GetVolumeNameForVolumeMountPointW, OPEN_EXISTING,
    };
    use windows_sys::Win32::System::IO::DeviceIoControl;
    use windows_sys::Win32::System::Ioctl::{
        IOCTL_STORAGE_GET_DEVICE_NUMBER, IOCTL_STORAGE_QUERY_PROPERTY, PropertyStandardQuery,
        STORAGE_DEVICE_DESCRIPTOR, STORAGE_DEVICE_NUMBER, STORAGE_PROPERTY_QUERY,
        StorageDeviceProperty,
    };
    use windows_sys::Win32::System::SystemInformation::GetSystemDirectoryW;
    use windows_sys::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};

    /// `GetDriveTypeW` value: removable drive.
    pub const DRIVE_REMOVABLE: u32 = 2;
    /// `STORAGE_BUS_TYPE`: USB.
    pub const BUS_TYPE_USB: i32 = 7;

    fn wide(p: &Path) -> Vec<u16> {
        let mut v: Vec<u16> = p.as_os_str().encode_wide().collect();
        v.push(0);
        v
    }

    fn from_wide(buf: &[u16]) -> String {
        let end = buf.iter().position(|&c| c == 0).unwrap_or(buf.len());
        std::ffi::OsString::from_wide(&buf[..end])
            .to_string_lossy()
            .into_owned()
    }

    /// Volume and physical-disk information of a drive root (`E:\`).
    #[derive(Debug, Clone, PartialEq, Eq)]
    pub struct VolumeInfo {
        /// Root (`E:\`).
        pub root: PathBuf,
        /// `GetDriveTypeW`.
        pub drive_type: u32,
        /// Volume label.
        pub label: String,
        /// File-system name (`FAT32`, `exFAT`, `NTFS`).
        pub fs_name: String,
        /// Volume serial number (changes on format).
        pub volume_serial: u32,
        /// Total bytes.
        pub total_bytes: u64,
        /// `\\?\Volume{GUID}\`.
        pub guid_path: String,
        /// `STORAGE_BUS_TYPE`.
        pub bus_type: i32,
        /// `STORAGE_DEVICE_DESCRIPTOR.RemovableMedia`.
        pub removable_media: bool,
        /// Device serial number (may be empty — refused on Windows).
        pub serial: String,
        /// Vendor + product.
        pub product: String,
        /// `STORAGE_DEVICE_NUMBER.DeviceNumber` (physical disk number).
        pub device_number: u32,
        /// Partition number.
        pub partition_number: u32,
    }

    /// Existing drive roots (`A:\` … `Z:\`).
    #[must_use]
    pub fn logical_drives() -> Vec<PathBuf> {
        // SAFETY: takes no argument.
        let mask = unsafe { GetLogicalDrives() };
        (0u8..26)
            .filter(|i| mask & (1 << i) != 0)
            .map(|i| PathBuf::from(format!("{}:\\", char::from(b'A' + i))))
            .collect()
    }

    /// `GetSystemDirectoryW` (e.g. `C:\Windows\System32`). External tools are called from this
    /// absolute path; PATH is not used.
    ///
    /// # Errors
    /// I/O error.
    pub fn system_directory() -> io::Result<PathBuf> {
        let mut buf = vec![0u16; 260];
        let len = u32::try_from(buf.len()).unwrap_or(260);
        // SAFETY: `buf` is a valid buffer of `len` wchars.
        let n = unsafe { GetSystemDirectoryW(buf.as_mut_ptr(), len) };
        if n == 0 || n >= len {
            return Err(io::Error::last_os_error());
        }
        Ok(PathBuf::from(from_wide(&buf)))
    }

    /// Whether the process token is elevated.
    #[must_use]
    pub fn is_elevated() -> bool {
        let mut token: HANDLE = core::ptr::null_mut();
        // SAFETY: pseudo process handle; takes no argument.
        let me = unsafe { GetCurrentProcess() };
        // SAFETY: `me` is valid; `token` is a valid output pointer.
        if unsafe { OpenProcessToken(me, TOKEN_QUERY, &raw mut token) } == 0 {
            return false;
        }
        // SAFETY: `token` is a valid handle from OpenProcessToken that we own.
        let token = unsafe { OwnedHandle::from_raw_handle(token) };
        let mut elev = TOKEN_ELEVATION { TokenIsElevated: 0 };
        let mut ret: u32 = 0;
        let size = u32::try_from(size_of::<TOKEN_ELEVATION>()).unwrap_or(4);
        // SAFETY: `token` is valid; `elev` has `size` writable bytes; `ret` is a valid output.
        let ok = unsafe {
            GetTokenInformation(
                token.as_raw_handle(),
                TokenElevation,
                (&raw mut elev).cast(),
                size,
                &raw mut ret,
            )
        };
        ok != 0 && elev.TokenIsElevated != 0
    }

    /// Volume serial number.
    ///
    /// # Errors
    /// I/O error.
    pub fn volume_serial(path: &Path) -> io::Result<u32> {
        let root = volume_root_of(path)?;
        let w = wide(&root);
        let mut serial: u32 = 0;
        // SAFETY: `w` is NUL terminated; only the serial output is requested, the others NULL/0.
        let ok = unsafe {
            GetVolumeInformationW(
                w.as_ptr(),
                core::ptr::null_mut(),
                0,
                &raw mut serial,
                core::ptr::null_mut(),
                core::ptr::null_mut(),
                core::ptr::null_mut(),
                0,
            )
        };
        if ok == 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(serial)
    }

    fn volume_root_of(path: &Path) -> io::Result<PathBuf> {
        use windows_sys::Win32::Storage::FileSystem::GetVolumePathNameW;
        let w = wide(path);
        let mut root = vec![0u16; 261];
        let len = u32::try_from(root.len()).unwrap_or(260);
        // SAFETY: `w` is NUL terminated; `root` is a valid buffer of `len` wchars.
        if unsafe { GetVolumePathNameW(w.as_ptr(), root.as_mut_ptr(), len) } == 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(PathBuf::from(from_wide(&root)))
    }

    /// `\\.\E:` device handle (access 0: IOCTL queries only).
    fn open_device(root: &Path) -> io::Result<OwnedHandle> {
        let s = root.to_string_lossy();
        let letter = s
            .chars()
            .next()
            .filter(char::is_ascii_alphabetic)
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "no drive letter"))?;
        let dev: Vec<u16> = format!("\\\\.\\{letter}:")
            .encode_utf16()
            .chain(std::iter::once(0))
            .collect();
        let _ = GENERIC_READ; // deliberately unused: access 0 is enough
        // SAFETY: `dev` is NUL terminated; access 0, read/write sharing, OPEN_EXISTING; template NULL.
        let h = unsafe {
            CreateFileW(
                dev.as_ptr(),
                0,
                FILE_SHARE_READ | FILE_SHARE_WRITE,
                core::ptr::null(),
                OPEN_EXISTING,
                0,
                core::ptr::null_mut(),
            )
        };
        if h == INVALID_HANDLE_VALUE || h.is_null() {
            return Err(io::Error::last_os_error());
        }
        // SAFETY: `h` is a valid handle from CreateFileW that we own.
        Ok(unsafe { OwnedHandle::from_raw_handle(h) })
    }

    fn c_string_at(buf: &[u8], off: u32) -> String {
        let off = off as usize;
        if off == 0 || off >= buf.len() {
            return String::new();
        }
        let end = buf[off..]
            .iter()
            .position(|&b| b == 0)
            .map_or(buf.len(), |p| off + p);
        String::from_utf8_lossy(&buf[off..end]).trim().to_string()
    }

    struct Descriptor {
        bus_type: i32,
        removable_media: bool,
        serial: String,
        product: String,
    }

    /// `IOCTL_STORAGE_QUERY_PROPERTY` → `STORAGE_DEVICE_DESCRIPTOR` + strings.
    fn storage_descriptor(dev: &OwnedHandle) -> io::Result<Descriptor> {
        let query = STORAGE_PROPERTY_QUERY {
            PropertyId: StorageDeviceProperty,
            QueryType: PropertyStandardQuery,
            AdditionalParameters: [0],
        };
        let mut buf = vec![0u8; 1024];
        let mut ret: u32 = 0;
        let qlen = u32::try_from(size_of::<STORAGE_PROPERTY_QUERY>()).unwrap_or(12);
        let blen = u32::try_from(buf.len()).unwrap_or(1024);
        // SAFETY: `dev` is a valid handle; `query` is `qlen` bytes of input; `buf` is `blen` bytes
        // of writable output; `ret` is a valid output; overlapped NULL (synchronous).
        let ok = unsafe {
            DeviceIoControl(
                dev.as_raw_handle(),
                IOCTL_STORAGE_QUERY_PROPERTY,
                (&raw const query).cast(),
                qlen,
                buf.as_mut_ptr().cast(),
                blen,
                &raw mut ret,
                core::ptr::null_mut(),
            )
        };
        if ok == 0 {
            return Err(io::Error::last_os_error());
        }
        if (ret as usize) < size_of::<STORAGE_DEVICE_DESCRIPTOR>() {
            return Err(io::Error::other("STORAGE_DEVICE_DESCRIPTOR too short"));
        }
        buf.truncate(ret as usize);
        // SAFETY: `buf` holds at least `size_of::<STORAGE_DEVICE_DESCRIPTOR>()` bytes; unaligned read.
        let desc: STORAGE_DEVICE_DESCRIPTOR =
            unsafe { core::ptr::read_unaligned(buf.as_ptr().cast()) };
        let vendor = c_string_at(&buf, desc.VendorIdOffset);
        let product = c_string_at(&buf, desc.ProductIdOffset);
        Ok(Descriptor {
            bus_type: desc.BusType,
            removable_media: desc.RemovableMedia,
            serial: c_string_at(&buf, desc.SerialNumberOffset),
            product: format!("{vendor} {product}").trim().to_string(),
        })
    }

    /// `IOCTL_STORAGE_GET_DEVICE_NUMBER`.
    fn device_number(dev: &OwnedHandle) -> io::Result<STORAGE_DEVICE_NUMBER> {
        let mut num = STORAGE_DEVICE_NUMBER {
            DeviceType: 0,
            DeviceNumber: u32::MAX,
            PartitionNumber: u32::MAX,
        };
        let mut ret: u32 = 0;
        let nlen = u32::try_from(size_of::<STORAGE_DEVICE_NUMBER>()).unwrap_or(12);
        // SAFETY: `dev` is valid; no input; `num` is `nlen` bytes of writable output.
        let ok = unsafe {
            DeviceIoControl(
                dev.as_raw_handle(),
                IOCTL_STORAGE_GET_DEVICE_NUMBER,
                core::ptr::null(),
                0,
                (&raw mut num).cast(),
                nlen,
                &raw mut ret,
                core::ptr::null_mut(),
            )
        };
        if ok == 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(num)
    }

    /// Full information about a drive root.
    ///
    /// # Errors
    /// I/O error (no drive, access denied, IOCTL not supported).
    pub fn volume_info(root: &Path) -> io::Result<VolumeInfo> {
        let w = wide(root);
        // SAFETY: `w` is NUL terminated.
        let drive_type = unsafe { GetDriveTypeW(w.as_ptr()) };
        let mut label = vec![0u16; 262];
        let mut fs = vec![0u16; 64];
        let mut serial: u32 = 0;
        let label_len = u32::try_from(label.len()).unwrap_or(261);
        let fs_len = u32::try_from(fs.len()).unwrap_or(63);
        // SAFETY: `w` is NUL terminated; `label`/`fs` are valid buffers of the given length.
        let ok = unsafe {
            GetVolumeInformationW(
                w.as_ptr(),
                label.as_mut_ptr(),
                label_len,
                &raw mut serial,
                core::ptr::null_mut(),
                core::ptr::null_mut(),
                fs.as_mut_ptr(),
                fs_len,
            )
        };
        if ok == 0 {
            return Err(io::Error::last_os_error());
        }
        let mut guid = vec![0u16; 64];
        let guid_len = u32::try_from(guid.len()).unwrap_or(63);
        // SAFETY: `w` is NUL terminated and a root ending in `\`; `guid` is a valid buffer.
        if unsafe { GetVolumeNameForVolumeMountPointW(w.as_ptr(), guid.as_mut_ptr(), guid_len) }
            == 0
        {
            return Err(io::Error::last_os_error());
        }
        let mut avail: u64 = 0;
        let mut total: u64 = 0;
        let mut free: u64 = 0;
        // SAFETY: `w` is NUL terminated; the three outputs are valid.
        if unsafe { GetDiskFreeSpaceExW(w.as_ptr(), &raw mut avail, &raw mut total, &raw mut free) }
            == 0
        {
            return Err(io::Error::last_os_error());
        }
        let dev = open_device(root)?;
        let d = storage_descriptor(&dev)?;
        let num = device_number(&dev)?;
        Ok(VolumeInfo {
            root: root.to_path_buf(),
            drive_type,
            label: from_wide(&label),
            fs_name: from_wide(&fs),
            volume_serial: serial,
            total_bytes: total,
            guid_path: from_wide(&guid),
            bus_type: d.bus_type,
            removable_media: d.removable_media,
            serial: d.serial,
            product: d.product,
            device_number: num.DeviceNumber,
            partition_number: num.PartitionNumber,
        })
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    #[cfg_attr(miri, ignore = "FFI")]
    fn device_id_stable_and_nocache_reads() {
        let d = std::env::temp_dir();
        let a = device_id(&d).unwrap();
        assert_eq!(a, device_id(&d).unwrap());
        let p = d.join(format!("lphy-vol-{}", std::process::id()));
        std::fs::write(&p, b"abc").unwrap();
        let mut s = String::new();
        std::io::Read::read_to_string(&mut open_nocache(&p).unwrap(), &mut s).unwrap();
        assert_eq!(s, "abc");
        let _ = std::fs::remove_file(&p);
        let _ = is_elevated();
    }

    #[cfg(target_os = "macos")]
    #[test]
    #[cfg_attr(miri, ignore = "FFI")]
    fn mount_source_of_root_is_a_device() {
        assert!(mount_source(Path::new("/")).unwrap().starts_with("/dev/"));
    }
}
