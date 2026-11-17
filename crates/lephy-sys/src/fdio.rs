//! Devralınan fd sahipliği (`--password-fd`; yalnızca Unix).

/// Devralınan `fd`'nin bir kopyasını (`F_DUPFD_CLOEXEC`) `File` olarak döndürür. Özgün fd'nin
/// sahipliği alınmaz ve kapatılmaz; böylece bu güvenli fonksiyon başka bir nesneye ait fd'yi
/// kapatamaz (I/O güvenliği). Standart akışlar (0–2) ve sinyal işleyicinin self-pipe uçları
/// reddedilir. Geçersiz fd → `None`. Windows'ta yoktur (devralınan handle reddedildi).
#[cfg(unix)]
#[must_use]
pub fn dup_inherited_fd(fd: i32) -> Option<std::fs::File> {
    use std::os::fd::FromRawFd;
    if fd <= 2 || crate::signal::is_internal_fd(fd) {
        return None;
    }
    // SAFETY: F_DUPFD_CLOEXEC bellek işaretçisi almaz; geçersiz fd'de -1 döner.
    let dup = unsafe { libc::fcntl(fd, libc::F_DUPFD_CLOEXEC, 3) };
    if dup < 0 {
        return None;
    }
    // SAFETY: `dup` az önce oluşturulan, başka hiçbir yerde sahiplenilmemiş açık bir fd.
    Some(unsafe { std::fs::File::from_raw_fd(dup) })
}
