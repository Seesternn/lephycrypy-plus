//! A small value in the operating system's credential store: macOS login keychain (generic
//! password), Windows Credential Manager (generic credential). Used for the app-lock verifier, so
//! deleting the settings file does not remove the lock.
//!
//! The stores are per user: any program of the same user can still delete the item (on macOS
//! possibly after a keychain prompt). This raises the bar; it is not a security boundary.

use std::io;

/// Outcome of a read.
#[derive(Debug, PartialEq, Eq)]
pub enum Read {
    /// The stored bytes.
    Found(Vec<u8>),
    /// Nothing is stored under the name.
    Missing,
}

/// Stores `value` under `name` (replacing an earlier value).
///
/// # Errors
/// The store is unavailable or refused the write.
pub fn put(name: &str, value: &[u8]) -> io::Result<()> {
    imp::put(name, value)
}

/// Reads the value stored under `name`.
///
/// # Errors
/// The store is unavailable or refused the read (e.g. the user denied a keychain prompt).
pub fn get(name: &str) -> io::Result<Read> {
    imp::get(name)
}

/// Deletes the value stored under `name` (missing is not an error).
///
/// # Errors
/// The store is unavailable or refused the deletion.
pub fn delete(name: &str) -> io::Result<()> {
    imp::delete(name)
}

#[cfg(all(target_os = "macos", not(miri)))]
mod imp {
    use super::Read;
    use std::ffi::c_void;
    use std::io;

    type OSStatus = i32;
    type ItemRef = *mut c_void;
    const ERR_ITEM_NOT_FOUND: OSStatus = -25300;
    const ACCOUNT: &str = "lephycrypy+";

    #[link(name = "Security", kind = "framework")]
    unsafe extern "C" {
        fn SecKeychainAddGenericPassword(
            keychain: *mut c_void,
            service_len: u32,
            service: *const u8,
            account_len: u32,
            account: *const u8,
            password_len: u32,
            password: *const c_void,
            item: *mut ItemRef,
        ) -> OSStatus;
        fn SecKeychainFindGenericPassword(
            keychain: *const c_void,
            service_len: u32,
            service: *const u8,
            account_len: u32,
            account: *const u8,
            password_len: *mut u32,
            password: *mut *mut c_void,
            item: *mut ItemRef,
        ) -> OSStatus;
        fn SecKeychainItemFreeContent(attrs: *mut c_void, data: *mut c_void) -> OSStatus;
        fn SecKeychainItemDelete(item: ItemRef) -> OSStatus;
    }

    #[link(name = "CoreFoundation", kind = "framework")]
    unsafe extern "C" {
        fn CFRelease(cf: *const c_void);
    }

    fn len(s: &[u8]) -> io::Result<u32> {
        u32::try_from(s.len()).map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "too long"))
    }

    fn err(st: OSStatus) -> io::Error {
        io::Error::other(format!("keychain error {st}"))
    }

    /// Finds the item; returns its data (copied) and the item reference (caller releases).
    fn find(name: &str, want_data: bool) -> io::Result<Option<(Vec<u8>, ItemRef)>> {
        let (s, a) = (name.as_bytes(), ACCOUNT.as_bytes());
        let mut n: u32 = 0;
        let mut data: *mut c_void = std::ptr::null_mut();
        let mut item: ItemRef = std::ptr::null_mut();
        let (pn, pd) = if want_data {
            (&raw mut n, &raw mut data)
        } else {
            (std::ptr::null_mut(), std::ptr::null_mut())
        };
        // SAFETY: the name buffers are valid for the lengths given; the out-pointers are valid
        // or null (allowed by the API: null means "not wanted").
        let st = unsafe {
            SecKeychainFindGenericPassword(
                std::ptr::null(),
                len(s)?,
                s.as_ptr(),
                len(a)?,
                a.as_ptr(),
                pn,
                pd,
                &raw mut item,
            )
        };
        if st == ERR_ITEM_NOT_FOUND {
            return Ok(None);
        }
        if st != 0 {
            return Err(err(st));
        }
        let mut out = Vec::new();
        if want_data && !data.is_null() {
            // SAFETY: on success `data` points to `n` bytes owned by the keychain until freed.
            let bytes = unsafe { std::slice::from_raw_parts(data.cast::<u8>(), n as usize) };
            out.extend_from_slice(bytes);
            // SAFETY: `data` was returned by SecKeychainFindGenericPassword and is freed once.
            unsafe { SecKeychainItemFreeContent(std::ptr::null_mut(), data) };
        }
        Ok(Some((out, item)))
    }

    fn release(item: ItemRef) {
        if !item.is_null() {
            // SAFETY: `item` is a +1 reference returned by the keychain; released once.
            unsafe { CFRelease(item) };
        }
    }

    pub(super) fn put(name: &str, value: &[u8]) -> io::Result<()> {
        delete(name)?;
        let (s, a) = (name.as_bytes(), ACCOUNT.as_bytes());
        let mut item: ItemRef = std::ptr::null_mut();
        // SAFETY: all buffers are valid for the lengths given; `item` receives a +1 reference.
        let st = unsafe {
            SecKeychainAddGenericPassword(
                std::ptr::null_mut(),
                len(s)?,
                s.as_ptr(),
                len(a)?,
                a.as_ptr(),
                len(value)?,
                value.as_ptr().cast(),
                &raw mut item,
            )
        };
        release(item);
        if st == 0 { Ok(()) } else { Err(err(st)) }
    }

    pub(super) fn get(name: &str) -> io::Result<Read> {
        Ok(match find(name, true)? {
            Some((data, item)) => {
                release(item);
                Read::Found(data)
            }
            None => Read::Missing,
        })
    }

    pub(super) fn delete(name: &str) -> io::Result<()> {
        let Some((_, item)) = find(name, false)? else {
            return Ok(());
        };
        // SAFETY: `item` is a live keychain item reference from `find`.
        let st = unsafe { SecKeychainItemDelete(item) };
        release(item);
        if st == 0 { Ok(()) } else { Err(err(st)) }
    }
}

#[cfg(all(windows, not(miri)))]
mod imp {
    use super::Read;
    use std::io;
    use windows_sys::Win32::Foundation::{ERROR_NOT_FOUND, GetLastError};
    use windows_sys::Win32::Security::Credentials::{
        CRED_PERSIST_LOCAL_MACHINE, CRED_TYPE_GENERIC, CREDENTIALW, CredDeleteW, CredFree,
        CredReadW, CredWriteW,
    };

    fn wide(name: &str) -> Vec<u16> {
        format!("lephycrypy+/{name}")
            .encode_utf16()
            .chain(std::iter::once(0))
            .collect()
    }

    fn last_err() -> (u32, io::Error) {
        // SAFETY: no arguments; reads the calling thread's last error.
        let e = unsafe { GetLastError() };
        #[allow(clippy::cast_possible_wrap, reason = "Win32 error codes fit in i32")]
        (e, io::Error::from_raw_os_error(e as i32))
    }

    pub(super) fn put(name: &str, value: &[u8]) -> io::Result<()> {
        let mut target = wide(name);
        let mut blob = value.to_vec();
        let cred = CREDENTIALW {
            Type: CRED_TYPE_GENERIC,
            TargetName: target.as_mut_ptr(),
            CredentialBlobSize: u32::try_from(blob.len())
                .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "too long"))?,
            CredentialBlob: blob.as_mut_ptr(),
            Persist: CRED_PERSIST_LOCAL_MACHINE,
            ..CREDENTIALW::default()
        };
        // SAFETY: `cred` points to live buffers (`target` NUL-terminated, `blob` of the size
        // given) for the duration of the call.
        let ok = unsafe { CredWriteW(&raw const cred, 0) };
        if ok != 0 { Ok(()) } else { Err(last_err().1) }
    }

    pub(super) fn get(name: &str) -> io::Result<Read> {
        let target = wide(name);
        let mut out: *mut CREDENTIALW = std::ptr::null_mut();
        // SAFETY: `target` is NUL-terminated; `out` receives a buffer freed with CredFree.
        let ok = unsafe { CredReadW(target.as_ptr(), CRED_TYPE_GENERIC, 0, &raw mut out) };
        if ok == 0 {
            let (code, e) = last_err();
            return if code == ERROR_NOT_FOUND {
                Ok(Read::Missing)
            } else {
                Err(e)
            };
        }
        // SAFETY: on success `out` points to a CREDENTIALW owned by the system until CredFree.
        let c = unsafe { &*out };
        let data = if c.CredentialBlob.is_null() {
            Vec::new()
        } else {
            // SAFETY: the blob holds `CredentialBlobSize` bytes while `out` is alive.
            unsafe { std::slice::from_raw_parts(c.CredentialBlob, c.CredentialBlobSize as usize) }
                .to_vec()
        };
        // SAFETY: `out` came from CredReadW and is freed once.
        unsafe { CredFree(out.cast()) };
        Ok(Read::Found(data))
    }

    pub(super) fn delete(name: &str) -> io::Result<()> {
        let target = wide(name);
        // SAFETY: `target` is NUL-terminated.
        let ok = unsafe { CredDeleteW(target.as_ptr(), CRED_TYPE_GENERIC, 0) };
        if ok != 0 {
            return Ok(());
        }
        let (code, e) = last_err();
        if code == ERROR_NOT_FOUND {
            Ok(())
        } else {
            Err(e)
        }
    }
}

#[cfg(any(miri, not(any(target_os = "macos", windows))))]
mod imp {
    use super::Read;
    use std::io;

    fn unsupported() -> io::Error {
        io::Error::new(io::ErrorKind::Unsupported, "no credential store")
    }

    pub(super) fn put(_name: &str, _value: &[u8]) -> io::Result<()> {
        Err(unsupported())
    }

    pub(super) fn get(_name: &str) -> io::Result<Read> {
        Err(unsupported())
    }

    pub(super) fn delete(_name: &str) -> io::Result<()> {
        Err(unsupported())
    }
}

#[cfg(test)]
mod tests {
    /// Touches the real keychain / Credential Manager: run by hand with `--ignored`.
    #[test]
    #[ignore = "uses the real credential store of the current user"]
    fn roundtrip() {
        let name = "test-roundtrip";
        super::put(name, b"one").unwrap_or(());
        assert_eq!(
            super::get(name).ok(),
            Some(super::Read::Found(b"one".to_vec()))
        );
        super::put(name, b"two").unwrap_or(());
        assert_eq!(
            super::get(name).ok(),
            Some(super::Read::Found(b"two".to_vec()))
        );
        super::delete(name).unwrap_or(());
        assert_eq!(super::get(name).ok(), Some(super::Read::Missing));
    }
}
