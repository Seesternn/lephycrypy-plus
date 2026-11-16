//! Sinyal işleme (PLAN F4, R5-12). Aşama 1'de doldurulur.
//!
//! - `install() -> Result<()>`: Unix'te SIGINT/SIGTERM/SIGHUP için doğrudan `sigaction`,
//!   **`SA_RESTART` olmadan**; işleyici yalnızca `INTERRUPTED: AtomicBool` kaldırır ve self-pipe'a
//!   1 bayt yazar (async-signal-safe); ikinci sinyalde `_exit(130)`. Windows'ta
//!   `SetConsoleCtrlHandler` (Ctrl+C/Break: bayrak + TRUE; Close: ≤ ~4,5 s temizlik beklemesi).
//! - `interrupted() -> bool`: her chunk sınırında yoklanır.
//! - `self_pipe_read_fd()`: `term::read_secret_interruptible` için.
//! - `mask_signals_on_this_thread()`: ana iş parçacığı dışındaki iş parçacıklarında
//!   `pthread_sigmask(SIG_BLOCK, {SIGINT, SIGTERM, SIGHUP})`.
//!
//! `signal-hook`/`ctrlc` kullanılmaz (`SA_RESTART` koyarlar; deny.toml'da yasak).
