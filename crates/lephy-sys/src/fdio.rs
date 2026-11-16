//! Devralınan fd sahipliği (`--password-fd`, yalnızca Unix; PLAN D3).

/// `fd`'yi doğrular (`fcntl(F_GETFD)`) ve sahipliğini `File` olarak devralır; `File` düşünce fd
/// kapanır. Geçersiz fd → `None`. Windows'ta yoktur (devralınan handle reddedildi, R5-13).
#[cfg(unix)]
#[must_use]
pub fn file_from_raw_fd(fd: i32) -> Option<std::fs::File> {
    use std::os::fd::FromRawFd;
    // SAFETY: F_GETFD bellek işaretçisi almaz.
    if unsafe { libc::fcntl(fd, libc::F_GETFD) } < 0 {
        return None;
    }
    // SAFETY: `fd` açık ve geçerli; sahiplik bu noktadan sonra yalnızca dönen `File`'dadır
    // (çağıran aynı fd'yi başka yerde kapatmamalıdır — CLI sözleşmesi).
    Some(unsafe { std::fs::File::from_raw_fd(fd) })
}
