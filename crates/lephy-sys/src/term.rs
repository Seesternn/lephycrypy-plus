//! Terminal: reading passwords without echo and raw fd writes.
//!
//! - [`RawModeGuard`]: turns off echo and line buffering (`ECHO`/`ICANON`; `ISIG` stays on so
//!   that Ctrl+C arrives as a signal), records the original mode in a `static`; Drop and the
//!   panic hook ([`restore_if_raw`]) restore it.
//! - [`read_line_noecho`]: writes bytes straight into the caller's (arena) buffer; on Unix
//!   `poll([tty, self_pipe])` + `read` (returns with EINTR since there is no `SA_RESTART`); on Windows
//!   `ReadConsoleW` (Ctrl+C breaks it with `CancelSynchronousIo`, UNVERIFIED). A full buffer is
//!   [`ReadError::TooLong`]; the buffer is never grown.
//! - [`write_all_raw`]: raw writes instead of `std::io::Stdout` (`LineWriter`) (`--stdout`, prompts).

use std::io;
use std::sync::Mutex;
use std::sync::atomic::{AtomicBool, Ordering};

use crate::{AsRawIo, RawIo};

/// Password reading errors.
#[derive(Debug)]
pub enum ReadError {
    /// SIGINT/SIGTERM/Ctrl+C.
    Interrupted,
    /// EOF before any byte was read.
    Eof,
    /// Buffer capacity exceeded (password ≤ 1024 B).
    TooLong,
    /// I/O error.
    Io(io::Error),
}

impl std::fmt::Display for ReadError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ReadError::Interrupted => f.write_str("interrupted"),
            ReadError::Eof => f.write_str("end of input"),
            ReadError::TooLong => f.write_str("password too long"),
            ReadError::Io(e) => write!(f, "I/O error: {e}"),
        }
    }
}

impl std::error::Error for ReadError {}

impl From<io::Error> for ReadError {
    fn from(e: io::Error) -> Self {
        ReadError::Io(e)
    }
}

static RAW_ACTIVE: AtomicBool = AtomicBool::new(false);

/// Record of the original terminal mode (the hook reads it with `try_lock`).
static ORIG: Mutex<Option<imp::Saved>> = Mutex::new(None);

/// No-echo mode guard.
pub struct RawModeGuard {
    io: RawIo,
}

impl RawModeGuard {
    /// Switches the terminal to no-echo, non-canonical mode.
    ///
    /// # Errors
    /// `tcgetattr`/`tcsetattr` or `GetConsoleMode`/`SetConsoleMode` error (including not a tty).
    pub fn enter(tty: &impl AsRawIo) -> io::Result<Self> {
        let io = tty.raw_io();
        let saved = imp::get(io)?;
        {
            let mut g = ORIG
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            *g = Some(saved);
        }
        imp::set_noecho(io, &saved)?;
        RAW_ACTIVE.store(true, Ordering::SeqCst);
        Ok(Self { io })
    }
}

impl Drop for RawModeGuard {
    fn drop(&mut self) {
        let mut g = ORIG
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if let Some(saved) = g.take() {
            imp::restore(self.io, &saved);
        }
        RAW_ACTIVE.store(false, Ordering::SeqCst);
    }
}

/// Panic hook step 3: restores raw mode if it is on. Does not wait for locks, does not allocate.
pub fn restore_if_raw() {
    if !RAW_ACTIVE.load(Ordering::SeqCst) {
        return;
    }
    if let Some(saved) = ORIG.try_lock().ok().and_then(|mut g| g.take()) {
        imp::restore(saved.io(), &saved);
        RAW_ACTIVE.store(false, Ordering::SeqCst);
    }
}

/// Whether it is a terminal.
#[must_use]
pub fn is_tty(io_: &impl AsRawIo) -> bool {
    imp::is_tty(io_.raw_io())
}

/// Reads one line without echo into `dest` and returns the number of bytes. The line ending
/// (`\n`/`\r`) is not included. Backspace deletes the last Unicode scalar (the deleted bytes are
/// zeroed); Ctrl+U clears the line.
///
/// # Errors
/// [`ReadError`].
pub fn read_line_noecho(tty: &impl AsRawIo, dest: &mut [u8]) -> Result<usize, ReadError> {
    imp::read_line(tty.raw_io(), dest)
}

/// Writes all bytes to the raw fd/handle (loops over EINTR and partial writes).
///
/// # Errors
/// I/O error.
pub fn write_all_raw(out: &impl AsRawIo, mut bytes: &[u8]) -> io::Result<()> {
    let io = out.raw_io();
    while !bytes.is_empty() {
        let n = imp::write(io, bytes)?;
        if n == 0 {
            return Err(io::Error::new(
                io::ErrorKind::WriteZero,
                "zero bytes written",
            ));
        }
        bytes = &bytes[n..];
    }
    Ok(())
}

/// Deletes and zeroes the last Unicode scalar; returns the new length.
fn pop_scalar(dest: &mut [u8], len: usize) -> usize {
    if len == 0 {
        return 0;
    }
    let mut i = len - 1;
    while i > 0 && (dest[i] & 0b1100_0000) == 0b1000_0000 {
        i -= 1;
    }
    for b in &mut dest[i..len] {
        *b = 0;
    }
    i
}

/// Shared line-editing logic for one read character/byte.
enum Edit {
    Done,
    Continue,
}

fn apply_byte(dest: &mut [u8], len: &mut usize, b: u8) -> Result<Edit, ReadError> {
    match b {
        b'\n' | b'\r' => Ok(Edit::Done),
        0x7f | 0x08 => {
            *len = pop_scalar(dest, *len);
            Ok(Edit::Continue)
        }
        0x15 => {
            for x in &mut dest[..*len] {
                *x = 0;
            }
            *len = 0;
            Ok(Edit::Continue)
        }
        0x03 | 0x04 => Err(if b == 0x03 {
            ReadError::Interrupted
        } else {
            ReadError::Eof
        }),
        _ => {
            if *len >= dest.len() {
                return Err(ReadError::TooLong);
            }
            dest[*len] = b;
            *len += 1;
            Ok(Edit::Continue)
        }
    }
}

#[cfg(unix)]
mod imp {
    use super::{Edit, ReadError, apply_byte};
    use crate::RawIo;
    use std::io;

    #[derive(Clone, Copy)]
    pub(super) struct Saved {
        fd: RawIo,
        termios: libc::termios,
    }

    impl Saved {
        pub(super) fn io(&self) -> RawIo {
            self.fd
        }
    }

    pub(super) fn get(fd: RawIo) -> io::Result<Saved> {
        // SAFETY: termios is a plain C struct; zero initialisation is valid, tcgetattr fills it.
        let mut t: libc::termios = unsafe { core::mem::zeroed() };
        // SAFETY: `t` is valid and writable.
        if unsafe { libc::tcgetattr(fd, &raw mut t) } != 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(Saved { fd, termios: t })
    }

    pub(super) fn set_noecho(fd: RawIo, saved: &Saved) -> io::Result<()> {
        let mut t = saved.termios;
        t.c_lflag &= !(libc::ECHO | libc::ECHONL | libc::ICANON);
        // ISIG stays on: Ctrl+C arrives as a signal.
        t.c_cc[libc::VMIN] = 1;
        t.c_cc[libc::VTIME] = 0;
        // SAFETY: `t` is a valid termios; TCSANOW applies it at once.
        if unsafe { libc::tcsetattr(fd, libc::TCSANOW, &raw const t) } != 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(())
    }

    pub(super) fn restore(fd: RawIo, saved: &Saved) {
        // SAFETY: `saved.termios` is a valid struct from tcgetattr.
        let _ = unsafe { libc::tcsetattr(fd, libc::TCSANOW, &raw const saved.termios) };
    }

    pub(super) fn is_tty(fd: RawIo) -> bool {
        // SAFETY: isatty takes only an fd.
        unsafe { libc::isatty(fd) == 1 }
    }

    pub(super) fn write(fd: RawIo, bytes: &[u8]) -> io::Result<usize> {
        loop {
            // SAFETY: `bytes` is a valid slice; the length is correct.
            let n = unsafe { libc::write(fd, bytes.as_ptr().cast::<libc::c_void>(), bytes.len()) };
            if n >= 0 {
                return usize::try_from(n).map_err(io::Error::other);
            }
            let e = io::Error::last_os_error();
            if e.kind() != io::ErrorKind::Interrupted {
                return Err(e);
            }
        }
    }

    /// Waits for readability; `Interrupted` if the self-pipe fires or on EINTR with the flag set.
    fn wait_readable(fd: RawIo) -> Result<(), ReadError> {
        let pipe = crate::signal::self_pipe_read_fd();
        let mut fds = [
            libc::pollfd {
                fd,
                events: libc::POLLIN,
                revents: 0,
            },
            libc::pollfd {
                fd: pipe.unwrap_or(-1),
                events: libc::POLLIN,
                revents: 0,
            },
        ];
        let n = if pipe.is_some() { 2 } else { 1 };
        loop {
            if crate::signal::interrupted() {
                return Err(ReadError::Interrupted);
            }
            // SAFETY: `fds` is a valid array of `n` elements; timeout -1 (forever; returns with EINTR).
            let rc = unsafe { libc::poll(fds.as_mut_ptr(), n, -1) };
            if rc < 0 {
                let e = io::Error::last_os_error();
                if e.kind() == io::ErrorKind::Interrupted {
                    if crate::signal::interrupted() {
                        return Err(ReadError::Interrupted);
                    }
                    continue;
                }
                return Err(ReadError::Io(e));
            }
            if n == 2 && fds[1].revents & libc::POLLIN != 0 {
                return Err(ReadError::Interrupted);
            }
            if fds[0].revents & (libc::POLLIN | libc::POLLHUP | libc::POLLERR) != 0 {
                return Ok(());
            }
        }
    }

    pub(super) fn read_line(fd: RawIo, dest: &mut [u8]) -> Result<usize, ReadError> {
        let mut len = 0usize;
        loop {
            wait_readable(fd)?;
            let mut b = [0u8; 1];
            // SAFETY: `b` is a valid 1-byte buffer.
            let n = unsafe { libc::read(fd, b.as_mut_ptr().cast::<libc::c_void>(), 1) };
            if n < 0 {
                let e = io::Error::last_os_error();
                if e.kind() == io::ErrorKind::Interrupted {
                    if crate::signal::interrupted() {
                        return Err(ReadError::Interrupted);
                    }
                    continue;
                }
                return Err(ReadError::Io(e));
            }
            if n == 0 {
                return if len == 0 {
                    Err(ReadError::Eof)
                } else {
                    Ok(len)
                };
            }
            match apply_byte(dest, &mut len, b[0]) {
                Ok(Edit::Done) => return Ok(len),
                Ok(Edit::Continue) => {}
                Err(ReadError::Eof) if len > 0 => return Ok(len),
                Err(e) => return Err(e),
            }
        }
    }
}

#[cfg(windows)]
mod imp {
    use super::{Edit, ReadError, apply_byte};
    use crate::RawIo;
    use std::io;
    use windows_sys::Win32::Foundation::ERROR_OPERATION_ABORTED;
    use windows_sys::Win32::Storage::FileSystem::WriteFile;
    use windows_sys::Win32::System::Console::{
        CONSOLE_MODE, ENABLE_ECHO_INPUT, ENABLE_LINE_INPUT, ENABLE_PROCESSED_INPUT, GetConsoleMode,
        ReadConsoleW, SetConsoleMode,
    };

    #[derive(Clone, Copy)]
    pub(super) struct Saved {
        h: RawIo,
        mode: CONSOLE_MODE,
    }

    // SAFETY: `h` is only a console handle value (no ownership); moving it between threads is
    // safe.
    unsafe impl Send for Saved {}

    impl Saved {
        pub(super) fn io(&self) -> RawIo {
            self.h
        }
    }

    pub(super) fn get(h: RawIo) -> io::Result<Saved> {
        let mut mode: CONSOLE_MODE = 0;
        // SAFETY: `mode` is a valid output pointer; `h` is the caller's handle.
        if unsafe { GetConsoleMode(h, &raw mut mode) } == 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(Saved { h, mode })
    }

    pub(super) fn set_noecho(h: RawIo, saved: &Saved) -> io::Result<()> {
        let mode = (saved.mode & !(ENABLE_ECHO_INPUT | ENABLE_LINE_INPUT)) | ENABLE_PROCESSED_INPUT;
        // SAFETY: only a handle and a flag.
        if unsafe { SetConsoleMode(h, mode) } == 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(())
    }

    pub(super) fn restore(h: RawIo, saved: &Saved) {
        // SAFETY: only a handle and a flag.
        let _ = unsafe { SetConsoleMode(h, saved.mode) };
    }

    pub(super) fn is_tty(h: RawIo) -> bool {
        let mut mode: CONSOLE_MODE = 0;
        // SAFETY: `mode` is a valid output pointer.
        unsafe { GetConsoleMode(h, &raw mut mode) != 0 }
    }

    pub(super) fn write(h: RawIo, bytes: &[u8]) -> io::Result<usize> {
        let mut written: u32 = 0;
        let len = u32::try_from(bytes.len()).unwrap_or(u32::MAX);
        // SAFETY: `bytes` is a valid slice, `len ≤ bytes.len()`; `written` is a valid output; overlapped NULL.
        let ok = unsafe {
            WriteFile(
                h,
                bytes.as_ptr(),
                len,
                &raw mut written,
                core::ptr::null_mut(),
            )
        };
        if ok == 0 {
            return Err(io::Error::last_os_error());
        }
        usize::try_from(written).map_err(io::Error::other)
    }

    fn read_wchar(h: RawIo) -> Result<Option<u16>, ReadError> {
        let mut wc: u16 = 0;
        let mut n: u32 = 0;
        // SAFETY: `wc` is a valid 1-wchar buffer; `n` is a valid output; input control NULL.
        let ok = unsafe { ReadConsoleW(h, (&raw mut wc).cast(), 1, &raw mut n, core::ptr::null()) };
        if ok == 0 {
            let e = io::Error::last_os_error();
            if crate::signal::interrupted()
                || e.raw_os_error() == Some(i32::try_from(ERROR_OPERATION_ABORTED).unwrap_or(995))
            {
                return Err(ReadError::Interrupted);
            }
            return Err(ReadError::Io(e));
        }
        if crate::signal::interrupted() {
            return Err(ReadError::Interrupted);
        }
        Ok((n == 1).then_some(wc))
    }

    pub(super) fn read_line(h: RawIo, dest: &mut [u8]) -> Result<usize, ReadError> {
        let mut len = 0usize;
        let mut pending_high: Option<u16> = None;
        loop {
            let Some(wc) = read_wchar(h)? else {
                return if len == 0 {
                    Err(ReadError::Eof)
                } else {
                    Ok(len)
                };
            };
            let ch = match (pending_high.take(), wc) {
                (Some(hi), lo) if (0xDC00..=0xDFFF).contains(&lo) => char::from_u32(
                    0x10000 + ((u32::from(hi) - 0xD800) << 10) + (u32::from(lo) - 0xDC00),
                ),
                (None, hi) if (0xD800..=0xDBFF).contains(&hi) => {
                    pending_high = Some(hi);
                    continue;
                }
                (_, w) => char::from_u32(u32::from(w)),
            };
            let Some(ch) = ch else { continue };
            let mut utf8 = [0u8; 4];
            let s = ch.encode_utf8(&mut utf8);
            if s.len() == 1 {
                match apply_byte(dest, &mut len, s.as_bytes()[0]) {
                    Ok(Edit::Done) => return Ok(len),
                    Ok(Edit::Continue) => {}
                    Err(ReadError::Eof) if len > 0 => return Ok(len),
                    Err(e) => return Err(e),
                }
            } else {
                if len + s.len() > dest.len() {
                    return Err(ReadError::TooLong);
                }
                dest[len..len + s.len()].copy_from_slice(s.as_bytes());
                len += s.len();
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn apply_byte_edits_line() {
        let mut d = [0u8; 8];
        let mut len = 0;
        for b in "aş".bytes() {
            assert!(matches!(
                apply_byte(&mut d, &mut len, b),
                Ok(Edit::Continue)
            ));
        }
        assert_eq!(len, 3);
        assert!(matches!(
            apply_byte(&mut d, &mut len, 0x7f),
            Ok(Edit::Continue)
        ));
        assert_eq!(len, 1, "backspace must delete a whole scalar");
        assert_eq!(&d[1..3], &[0, 0], "deleted bytes must be zeroed");
        assert!(matches!(
            apply_byte(&mut d, &mut len, b'\n'),
            Ok(Edit::Done)
        ));
    }

    #[test]
    fn apply_byte_too_long_does_not_write() {
        let mut d = [0u8; 2];
        let mut len = 0;
        assert!(apply_byte(&mut d, &mut len, b'a').is_ok());
        assert!(apply_byte(&mut d, &mut len, b'b').is_ok());
        assert!(matches!(
            apply_byte(&mut d, &mut len, b'c'),
            Err(ReadError::TooLong)
        ));
        assert_eq!(len, 2);
    }
}
