//! Ownership of inherited file descriptors (`--password-fd`; Unix only).

/// Returns a duplicate (`F_DUPFD_CLOEXEC`) of the inherited `fd` as a `File`. The original fd is
/// neither taken over nor closed, so this safe function cannot close an fd owned by another
/// object (I/O safety). The standard streams (0–2) and the signal handler's self-pipe ends are
/// refused. An invalid fd → `None`. Not available on Windows (inherited handles are refused).
#[cfg(unix)]
#[must_use]
pub fn dup_inherited_fd(fd: i32) -> Option<std::fs::File> {
    use std::os::fd::FromRawFd;
    if fd <= 2 || crate::signal::is_internal_fd(fd) {
        return None;
    }
    // SAFETY: F_DUPFD_CLOEXEC takes no memory pointer; returns -1 for an invalid fd.
    let dup = unsafe { libc::fcntl(fd, libc::F_DUPFD_CLOEXEC, 3) };
    if dup < 0 {
        return None;
    }
    // SAFETY: `dup` is an open fd just created and not owned anywhere else.
    Some(unsafe { std::fs::File::from_raw_fd(dup) })
}
