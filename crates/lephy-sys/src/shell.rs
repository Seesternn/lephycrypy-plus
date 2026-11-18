//! Windows Explorer integration for the current user only (`HKCU\Software\Classes`; no
//! administrator rights, nothing outside the user's own registry hive).
//!
//! Registers:
//! - `.lphy` → `lephycrypy.file` (double-click opens the app, icon from the executable);
//! - a context-menu entry for every file (`*`) and folder (`Directory`).
//!
//! Every command is `"<exe>" --open "%1"`: the app accepts only that form and only an absolute
//! path. [`unregister`] removes exactly the keys [`register`] creates, and `.lphy` only while it
//! still points at our class.

use std::io;
use std::path::Path;

/// File class name used for `.lphy`.
pub const PROG_ID: &str = "lephycrypy.file";
/// Context-menu verb key.
pub const VERB: &str = "lephycrypy";

/// Texts shown in Explorer.
#[derive(Debug, Clone, Copy)]
pub struct Labels<'a> {
    /// File type name (e.g. "lephycrypy+ encrypted file").
    pub file_type: &'a str,
    /// Context-menu entry (e.g. "Encrypt or decrypt with lephycrypy+").
    pub menu: &'a str,
}

/// Default registry root.
pub const CLASSES: &str = r"Software\Classes";

/// Registers the integration under `HKCU\<root>` (normally [`CLASSES`]).
///
/// # Errors
/// Registry errors; unsupported outside Windows.
pub fn register(root: &str, exe: &Path, labels: Labels<'_>) -> io::Result<()> {
    imp::register(root, exe, labels)
}

/// Removes what [`register`] created.
///
/// # Errors
/// Registry errors; unsupported outside Windows.
pub fn unregister(root: &str) -> io::Result<()> {
    imp::unregister(root)
}

/// Whether the integration is registered (the context-menu verb exists).
#[must_use]
pub fn is_registered(root: &str) -> bool {
    imp::is_registered(root)
}

#[cfg(not(windows))]
mod imp {
    use super::Labels;
    use std::io;
    use std::path::Path;

    fn unsupported() -> io::Error {
        io::Error::new(
            io::ErrorKind::Unsupported,
            "Explorer integration is Windows-only",
        )
    }
    pub(super) fn register(_: &str, _: &Path, _: Labels<'_>) -> io::Result<()> {
        Err(unsupported())
    }
    pub(super) fn unregister(_: &str) -> io::Result<()> {
        Err(unsupported())
    }
    pub(super) fn is_registered(_: &str) -> bool {
        false
    }
}

#[cfg(windows)]
mod imp {
    use super::{Labels, PROG_ID, VERB};
    use std::io;
    use std::os::windows::ffi::OsStrExt;
    use std::path::Path;
    use windows_sys::Win32::Foundation::{ERROR_FILE_NOT_FOUND, ERROR_SUCCESS};
    use windows_sys::Win32::System::Registry::{
        HKEY, HKEY_CURRENT_USER, KEY_READ, KEY_WRITE, REG_OPTION_NON_VOLATILE, REG_SZ, RegCloseKey,
        RegCreateKeyExW, RegDeleteTreeW, RegOpenKeyExW, RegQueryValueExW, RegSetValueExW,
    };
    use windows_sys::Win32::UI::Shell::{SHCNE_ASSOCCHANGED, SHCNF_IDLIST, SHChangeNotify};

    fn wide(s: &str) -> Vec<u16> {
        s.encode_utf16().chain(std::iter::once(0)).collect()
    }

    fn check(code: u32) -> io::Result<()> {
        if code == ERROR_SUCCESS {
            Ok(())
        } else {
            #[allow(clippy::cast_possible_wrap)]
            Err(io::Error::from_raw_os_error(code as i32))
        }
    }

    struct Key(HKEY);

    impl Drop for Key {
        fn drop(&mut self) {
            // SAFETY: `self.0` is a key opened by RegCreateKeyExW/RegOpenKeyExW and closed once.
            let _ = unsafe { RegCloseKey(self.0) };
        }
    }

    fn create(path: &str) -> io::Result<Key> {
        let p = wide(path);
        let mut h: HKEY = std::ptr::null_mut();
        // SAFETY: `p` is NUL-terminated UTF-16 and outlives the call; `h` receives the handle.
        let r = unsafe {
            RegCreateKeyExW(
                HKEY_CURRENT_USER,
                p.as_ptr(),
                0,
                std::ptr::null(),
                REG_OPTION_NON_VOLATILE,
                KEY_WRITE,
                std::ptr::null(),
                &raw mut h,
                std::ptr::null_mut(),
            )
        };
        check(r)?;
        Ok(Key(h))
    }

    fn set(key: &Key, name: Option<&str>, value: &str) -> io::Result<()> {
        let n = name.map(wide);
        let v = wide(value);
        let bytes = u32::try_from(v.len() * 2)
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "value too long"))?;
        // SAFETY: `key` is open for writing; the name (or null for the default value) and the
        // NUL-terminated data buffer of `bytes` bytes outlive the call.
        let r = unsafe {
            RegSetValueExW(
                key.0,
                n.as_ref().map_or(std::ptr::null(), Vec::as_ptr),
                0,
                REG_SZ,
                v.as_ptr().cast(),
                bytes,
            )
        };
        check(r)
    }

    fn write(path: &str, name: Option<&str>, value: &str) -> io::Result<()> {
        let k = create(path)?;
        set(&k, name, value)
    }

    fn delete_tree(path: &str) -> io::Result<()> {
        let p = wide(path);
        // SAFETY: NUL-terminated UTF-16 subkey path under HKCU.
        let r = unsafe { RegDeleteTreeW(HKEY_CURRENT_USER, p.as_ptr()) };
        if r == ERROR_FILE_NOT_FOUND {
            return Ok(());
        }
        check(r)
    }

    fn open_read(path: &str) -> Option<Key> {
        let p = wide(path);
        let mut h: HKEY = std::ptr::null_mut();
        // SAFETY: NUL-terminated path; `h` receives the handle on success.
        let r = unsafe { RegOpenKeyExW(HKEY_CURRENT_USER, p.as_ptr(), 0, KEY_READ, &raw mut h) };
        (r == ERROR_SUCCESS).then_some(Key(h))
    }

    fn read_default(path: &str) -> Option<String> {
        let k = open_read(path)?;
        let mut buf = [0u16; 260];
        let mut len = u32::try_from(std::mem::size_of_val(&buf)).ok()?;
        // SAFETY: `k` is open for reading; `buf` has `len` bytes of space; null name = default
        // value; type pointer not needed.
        let r = unsafe {
            RegQueryValueExW(
                k.0,
                std::ptr::null(),
                std::ptr::null(),
                std::ptr::null_mut(),
                buf.as_mut_ptr().cast(),
                &raw mut len,
            )
        };
        if r != ERROR_SUCCESS {
            return None;
        }
        let n = (len as usize / 2).min(buf.len());
        let s = String::from_utf16_lossy(&buf[..n]);
        Some(s.trim_end_matches('\0').to_string())
    }

    fn notify() {
        // SAFETY: documented call with no item pointers for SHCNE_ASSOCCHANGED.
        unsafe {
            SHChangeNotify(
                SHCNE_ASSOCCHANGED.cast_signed(),
                SHCNF_IDLIST,
                std::ptr::null(),
                std::ptr::null(),
            );
        };
    }

    fn command(exe: &Path) -> io::Result<String> {
        if !exe.is_absolute() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "executable path is not absolute",
            ));
        }
        let s: Vec<u16> = exe.as_os_str().encode_wide().collect();
        let s = String::from_utf16(&s).map_err(|_| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                "executable path is not Unicode",
            )
        })?;
        if s.contains('"') {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "executable path contains a quote",
            ));
        }
        Ok(format!("\"{s}\" --open \"%1\""))
    }

    pub(super) fn register(root: &str, exe: &Path, labels: Labels<'_>) -> io::Result<()> {
        let cmd = command(exe)?;
        let icon = format!("\"{}\",0", exe.display());
        write(&format!(r"{root}\.lphy"), None, PROG_ID)?;
        write(&format!(r"{root}\{PROG_ID}"), None, labels.file_type)?;
        write(&format!(r"{root}\{PROG_ID}\DefaultIcon"), None, &icon)?;
        write(&format!(r"{root}\{PROG_ID}\shell\open\command"), None, &cmd)?;
        for base in ["*", "Directory"] {
            let verb = format!(r"{root}\{base}\shell\{VERB}");
            write(&verb, Some("MUIVerb"), labels.menu)?;
            write(&verb, Some("Icon"), &icon)?;
            write(&format!(r"{verb}\command"), None, &cmd)?;
        }
        notify();
        Ok(())
    }

    pub(super) fn unregister(root: &str) -> io::Result<()> {
        for base in ["*", "Directory"] {
            delete_tree(&format!(r"{root}\{base}\shell\{VERB}"))?;
        }
        delete_tree(&format!(r"{root}\{PROG_ID}"))?;
        // `.lphy` only while it is still ours (another program may have taken it over).
        if read_default(&format!(r"{root}\.lphy")).as_deref() == Some(PROG_ID) {
            delete_tree(&format!(r"{root}\.lphy"))?;
        }
        notify();
        Ok(())
    }

    pub(super) fn is_registered(root: &str) -> bool {
        open_read(&format!(r"{root}\*\shell\{VERB}\command")).is_some()
    }

    #[cfg(test)]
    #[allow(clippy::unwrap_used)]
    mod tests {
        use super::super::{Labels, is_registered, register, unregister};

        #[test]
        fn register_and_unregister_in_a_scratch_root() {
            let root = format!(r"Software\lephycrypy-test-{}", std::process::id());
            let exe = std::env::current_exe().unwrap();
            let labels = Labels {
                file_type: "test file",
                menu: "test menu",
            };
            assert!(!is_registered(&root));
            register(&root, &exe, labels).unwrap();
            assert!(is_registered(&root));
            let cmd = super::read_default(&format!(r"{root}\*\shell\lephycrypy\command")).unwrap();
            assert!(cmd.ends_with("\" --open \"%1\""), "{cmd}");
            assert_eq!(
                super::read_default(&format!(r"{root}\.lphy")).unwrap(),
                "lephycrypy.file"
            );
            unregister(&root).unwrap();
            assert!(!is_registered(&root));
            assert!(super::read_default(&format!(r"{root}\.lphy")).is_none());
            super::delete_tree(&root).unwrap();
        }
    }
}
