//! Terminal raw-mode (PLAN D3, R5-12, R5-13). Aşama 1'de doldurulur.
//!
//! - `RawModeGuard::enter(tty) -> Result<RawModeGuard>`: özgün `termios`/konsol modu `static`
//!   kayda alınır (`RAW_ACTIVE`), raw moda geçilir; Drop ve panik hook'u (3) geri yükler
//!   (`tcsetattr(TCSANOW)` / `SetConsoleMode`).
//! - `read_secret_interruptible(tty, buf: &mut [u8]) -> Result<usize, ReadError>`: Unix'te
//!   `poll([tty_fd, self_pipe_rd])` + `read` (EINTR ile döner; `SA_RESTART` yok); Windows'ta
//!   `ReadConsoleW` + `CancelSynchronousIo` (DOĞRULANMADI) ya da `WaitForMultipleObjects`.
//!   Tampon çağıranın `SecretBytes`'ıdır; kapasite aşımı hata, büyütme yok (≤ 1024 B).
//! - `write_raw_fd(fd, bytes)`: `--stdout` için `std::io::Stdout` yerine ham fd yazımı.
//! - `is_tty(fd)`.
//! - Windows isimli pipe: yalnızca yerel `\\.\pipe\` ve sahip SID = geçerli kullanıcı
//!   (`GetNamedPipeServerProcessId` / `GetSecurityInfo`, DOĞRULANMADI).
