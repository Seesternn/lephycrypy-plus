//! The `lephycrypy` command line.
//!
//! Exit codes: README › Exit codes; code 2 only from clap. Passwords are never read from
//! argv/env. Process start: `harden()` → panic hook → signal handler → clap →
//! (macOS release) `PT_DENY_ATTACH`.

#![forbid(unsafe_code)]

// A core built with the `test-vectors` feature can never get into a binary.
const _: () = assert!(
    !lephy_core::TEST_VECTORS_ENABLED,
    "lephy-cli cannot be built with the lephy-core/test-vectors feature"
);

use std::path::{Path, PathBuf};
use std::process::ExitCode as ProcessExit;

use clap::{Args, Parser, Subcommand, ValueEnum};
use lephy_core::archive::{ExtractOptions, Report, SymlinkPolicy};
use lephy_core::cipher::AlgId;
use lephy_core::entropy::OsEntropy;
use lephy_core::error::{Error, ExitCode, Result};
use lephy_core::header::ContentType;
use lephy_core::kdf::KdfParams;
use lephy_core::names::escape_display;
use lephy_core::ops::{
    self, DecryptOptions, EncryptOptions, Identity, Input, NewCredentials, Output, PublicKey,
    UnlockOptions,
};
use lephy_core::password::{self, Source};
use lephy_sys::mem::SecretBytes;

#[derive(Parser)]
#[command(
    name = "lephycrypy",
    version,
    about = "lephycrypy+ — encrypt files and folders with a password or public keys",
    after_help = "Exit codes: 0 success · 1 I/O/environment · 2 usage · 3 wrong password/key file/identity · \
                  4 damaged file · 5 cancelled · 6 KDF budget · 7 destination exists · 8 disk space · 130 interrupted"
)]
struct Cli {
    /// Detailed progress and error causes (no secrets).
    #[arg(long, global = true)]
    verbose: bool,
    /// macOS: do not apply `PT_DENY_ATTACH` (only useful for a local unsigned build).
    #[arg(long, global = true, hide = true)]
    allow_debugger: bool,
    #[command(subcommand)]
    command: Command,
}

/// Password source options (mutually exclusive; the terminal if none is given).
#[derive(Args, Clone)]
struct PasswordArgs {
    /// Read the password from stdin until EOF (stdin cannot be a terminal or the input).
    #[cfg_attr(unix, arg(long, conflicts_with_all = ["password_fd", "password_file"]))]
    #[cfg_attr(not(unix), arg(long, conflicts_with = "password_file"))]
    password_stdin: bool,
    /// Read the password from the given file descriptor (Unix only).
    #[cfg(unix)]
    #[arg(long, value_name = "N", conflicts_with = "password_file")]
    password_fd: Option<i32>,
    /// Read the password from a file or named pipe (a file stays on disk as plaintext; prefer tmpfs/pipes).
    #[arg(long, value_name = "PATH")]
    password_file: Option<PathBuf>,
    /// Key file (32 B..1 MiB; its content is part of the key derivation).
    #[arg(long, value_name = "PATH")]
    keyfile: Option<PathBuf>,
}

/// New credentials (rekey/reencrypt).
#[derive(Args, Clone)]
#[allow(clippy::struct_field_names)]
struct NewPasswordArgs {
    /// Read the new password from a file or named pipe.
    #[arg(long, value_name = "PATH")]
    new_password_file: Option<PathBuf>,
    /// Read the new password from the given fd (Unix only).
    #[cfg(unix)]
    #[arg(long, value_name = "N", conflicts_with = "new_password_file")]
    new_password_fd: Option<i32>,
    /// New key file.
    #[arg(long, value_name = "PATH")]
    new_keyfile: Option<PathBuf>,
}

#[derive(Args, Clone, Copy)]
#[allow(clippy::struct_field_names)]
struct KdfArgs {
    /// Argon2id memory (MiB), at least 64.
    #[arg(long, value_name = "MiB", default_value_t = 512)]
    kdf_memory: u32,
    /// Argon2id iterations (1..64).
    #[arg(long, value_name = "T", default_value_t = 3)]
    kdf_time: u32,
    /// Argon2id parallelism (1..64).
    #[arg(long, value_name = "P", default_value_t = 4)]
    kdf_parallelism: u32,
}

impl KdfArgs {
    fn params(self) -> KdfParams {
        KdfParams {
            m_kib: self.kdf_memory.saturating_mul(1024),
            t: self.kdf_time,
            p: self.kdf_parallelism,
        }
    }
}

/// Decryption/extraction policy.
#[derive(Args, Clone, Copy)]
struct UnlockArgs {
    /// Allow exceeding the KDF budget (the RAM threshold still applies).
    #[arg(long)]
    allow_large_kdf: bool,
    /// Fail if memory cannot be locked.
    #[arg(long)]
    strict_memory: bool,
}

impl UnlockArgs {
    const fn opts(self) -> UnlockOptions<'static> {
        UnlockOptions {
            allow_large_kdf: self.allow_large_kdf,
            strict_memory: self.strict_memory,
            identity: None,
        }
    }
}

#[derive(Clone, Copy, ValueEnum)]
enum Alg {
    /// XChaCha20-Poly1305 (default).
    Xchacha20,
    /// AES-256-GCM.
    Aes256gcm,
}

#[derive(Clone, Copy, ValueEnum)]
enum ChunkSize {
    #[value(name = "64k")]
    K64,
    #[value(name = "256k")]
    K256,
    #[value(name = "1m")]
    M1,
    #[value(name = "4m")]
    M4,
    #[value(name = "16m")]
    M16,
}

impl ChunkSize {
    const fn code(self) -> u8 {
        match self {
            ChunkSize::K64 => 0,
            ChunkSize::K256 => 1,
            ChunkSize::M1 => 2,
            ChunkSize::M4 => 3,
            ChunkSize::M16 => 4,
        }
    }
}

#[derive(Clone, Copy, ValueEnum, Default)]
enum RestoreSymlinks {
    /// Safe targets only (relative, without `..`).
    #[default]
    Safe,
    /// Unsafe targets too (with a warning each).
    Unsafe,
}

#[derive(Subcommand)]
enum Command {
    /// Encrypts files or folders ("-" = stdin, raw stream). With several sources each becomes
    /// its own `.lphy` (`--out-dir`).
    Encrypt {
        /// Source file(s)/folder(s) ("-" = stdin, on its own).
        #[arg(required = true, num_args = 1..)]
        inputs: Vec<PathBuf>,
        /// Output path (single source; default: <8 random hex>.lphy).
        #[arg(short, long, value_name = "PATH", conflicts_with = "out_dir")]
        output: Option<PathBuf>,
        /// Output folder: a randomly named `.lphy` for each source (required for several sources).
        #[arg(long, value_name = "DIR")]
        out_dir: Option<PathBuf>,
        /// Algorithm.
        #[arg(long, value_enum, default_value = "xchacha20")]
        alg: Alg,
        /// Chunk size.
        #[arg(long, value_enum, default_value = "1m")]
        chunk_size: ChunkSize,
        #[command(flatten)]
        kdf: KdfArgs,
        #[command(flatten)]
        pw: PasswordArgs,
        /// Encrypt to a public key instead of a password (`lphy1…`, or a file with one key per
        /// line). Repeat for several recipients; any one of them can decrypt.
        #[arg(short = 'r', long = "recipient", value_name = "KEY|FILE")]
        recipients: Vec<String>,
        /// Write a file as a raw stream instead of an archive (the name is not hidden; stdin is always raw).
        #[arg(long)]
        raw: bool,
        /// PADMÉ size padding (raw streams; not with stdin).
        #[arg(long, conflicts_with = "no_pad")]
        pad: bool,
        /// Turn off PADMÉ padding for archives.
        #[arg(long)]
        no_pad: bool,
        /// Treat a skipped entry (FIFO/socket/device, unreadable) as an error (code 4).
        #[arg(long)]
        strict: bool,
        /// Overwrite an existing destination.
        #[arg(long)]
        force: bool,
        /// Fail if memory cannot be locked.
        #[arg(long)]
        strict_memory: bool,
        /// Delete the original after encryption + verification + fsync (residue warning).
        #[arg(long)]
        delete_original: bool,
        /// Like `--delete-original`, but overwrites each file once with random data before
        /// deleting it. Physical erasure is not guaranteed on SSD/APFS and similar. Asks for confirmation.
        #[arg(long)]
        secure_delete: bool,
        /// Compress before encrypting (DEFLATE; format v2). The compressed size can reveal
        /// information about the content; do not use it when an attacker can choose part of the input.
        #[arg(long)]
        compress: bool,
        /// Add Reed–Solomon error correction (~7 % larger): small damage on failing USB sticks/disks
        /// is repaired when decrypting.
        #[arg(long, visible_alias = "ecc")]
        error_correction: bool,
        /// Split the output into parts of this size (e.g. 100m, 650m, 4g; at least 1m). Parts are
        /// written as `.001`, `.002` …; to decrypt, give the `.001` file.
        #[arg(long, value_name = "SIZE", value_parser = parse_size)]
        split_size: Option<u64>,
        /// Do not ask for confirmation for `--secure-delete` (scripts).
        #[arg(long, requires = "secure_delete")]
        yes: bool,
    },
    /// Decrypts a `.lphy` file (archive → folder or single file; raw → file/stdout).
    Decrypt {
        /// Encrypted file.
        input: PathBuf,
        /// Identity file (`.lphykey`) for files encrypted to a public key; the password asked
        /// for is the identity file's.
        #[arg(short = 'i', long, value_name = "PATH")]
        identity: Option<PathBuf>,
        /// Output path (default: the input name without `.lphy`, or `<input>.out`).
        #[arg(short, long, value_name = "PATH", conflicts_with = "stdout")]
        output: Option<PathBuf>,
        /// Write the plaintext to stdout (raw streams only; truncation is detected only at the last chunk).
        #[arg(long)]
        stdout: bool,
        #[command(flatten)]
        pw: PasswordArgs,
        #[command(flatten)]
        unlock: UnlockArgs,
        /// Overwrite an existing destination (a folder is deleted).
        #[arg(long)]
        force: bool,
        /// Restore symbolic links (default: never).
        #[arg(long, value_enum, value_name = "safe|unsafe", num_args = 0..=1, default_missing_value = "safe")]
        restore_symlinks: Option<RestoreSymlinks>,
        /// `_2`, `_3` … for duplicate names (case, NFC).
        #[arg(long)]
        rename_conflicts: bool,
        /// Treat a skipped/changed entry as an error (format/policy → 4, privileges → 1).
        #[arg(long)]
        strict: bool,
        /// Allow extracting into known cloud-sync folders without asking.
        #[arg(long)]
        allow_cloud_dir: bool,
        /// Extract what can be saved from a damaged file (default output `<name>.recovered`).
        /// Parts that fail verification are zero-filled; the output may contain untrustworthy data.
        #[arg(long, conflicts_with_all = ["stdout", "force"])]
        recover: bool,
        /// Archives: extract only this path (and everything below it); repeatable. See `list`.
        #[arg(long, value_name = "PATH", conflicts_with_all = ["stdout", "recover"])]
        only: Vec<String>,
    },
    /// Lists the contents of an encrypted archive without writing anything.
    List {
        /// Encrypted file.
        input: PathBuf,
        /// Identity file (`.lphykey`) for files encrypted to a public key; the password asked
        /// for is the identity file's.
        #[arg(short = 'i', long, value_name = "PATH")]
        identity: Option<PathBuf>,
        #[command(flatten)]
        pw: PasswordArgs,
        #[command(flatten)]
        unlock: UnlockArgs,
    },
    /// Verifies a file without writing anything.
    Verify {
        /// Encrypted file.
        input: PathBuf,
        /// Identity file (`.lphykey`) for files encrypted to a public key; the password asked
        /// for is the identity file's.
        #[arg(short = 'i', long, value_name = "PATH")]
        identity: Option<PathBuf>,
        #[command(flatten)]
        pw: PasswordArgs,
        #[command(flatten)]
        unlock: UnlockArgs,
    },
    /// Shows the unencrypted header metadata (no key derivation).
    Info {
        /// Encrypted file.
        input: PathBuf,
    },
    /// Changes the password; the file key (FK) stays the same — use `reencrypt` for real rotation.
    Rekey {
        /// Encrypted file (changed in place, atomically).
        input: PathBuf,
        #[command(flatten)]
        pw: PasswordArgs,
        #[command(flatten)]
        new: NewPasswordArgs,
        /// New KDF memory (MiB); the old header's parameters if not given.
        #[arg(long, value_name = "MiB")]
        kdf_memory: Option<u32>,
        /// Fully verify the result.
        #[arg(long)]
        verify: bool,
        #[command(flatten)]
        unlock: UnlockArgs,
    },
    /// Re-encrypts every chunk with a new file key (in place, atomically).
    Reencrypt {
        /// Encrypted file.
        input: PathBuf,
        #[command(flatten)]
        pw: PasswordArgs,
        #[command(flatten)]
        new: NewPasswordArgs,
        #[command(flatten)]
        unlock: UnlockArgs,
    },
    /// Generates a random passphrase and writes it to standard output (EFF large wordlist).
    Passphrase {
        /// Number of words (4–16; each word ≈ 12.9 bits).
        #[arg(long, default_value_t = 6)]
        words: usize,
        /// Word separator.
        #[arg(long, default_value = "-")]
        separator: char,
    },
    /// Creates a new identity (X25519 key pair) for recipient encryption. The secret key is
    /// written password-protected to the given `.lphykey` file, the public key to `<name>.pub`
    /// and to standard output. Share only the public key.
    Keygen {
        /// Identity file to create (never overwritten).
        path: PathBuf,
        #[command(flatten)]
        kdf: KdfArgs,
        #[command(flatten)]
        pw: PasswordArgs,
    },
    /// Creates a new key file (random bytes, 0600, never overwrites).
    KeyfileGen {
        /// File to create.
        path: PathBuf,
        /// Number of bytes (32–1048576).
        #[arg(long, default_value_t = 64)]
        size: usize,
    },
    /// Deletes stale `.lphy-tmp-*` files/directories in a directory, after confirmation.
    Cleanup {
        /// Directory to scan.
        dir: PathBuf,
        /// Delete without asking (for non-tty use).
        #[arg(long)]
        yes: bool,
    },
    /// Removable USB media only: wipe it and write the encrypted `.lphy` file.
    Usb {
        #[command(subcommand)]
        cmd: UsbCmd,
    },
}

#[derive(Subcommand)]
enum UsbCmd {
    /// Lists candidate USB volumes and their eligibility (read only).
    List,
    /// Wipes (or formats) a USB volume and writes only the given `.lphy` file.
    Write {
        /// The `.lphy` file to write (only valid encrypted files are accepted).
        source: PathBuf,
        /// Mount point / drive root of the target volume (see `usb list`).
        #[arg(long, value_name = "PATH")]
        target: PathBuf,
        /// Format as exFAT instead of wiping (needs an administrator session on Windows).
        #[arg(long)]
        format: bool,
        /// Fill free space with random data after wiping (not a guarantee of physical erasure).
        #[arg(long)]
        fill_free_space: bool,
        /// Script confirmation: the exact volume label.
        #[arg(long, value_name = "LABEL", requires = "confirm_size_gib")]
        confirm_label: Option<String>,
        /// Script confirmation: size as a whole number of GiB (`floor(bytes / 2^30)`).
        #[arg(long, value_name = "GiB", requires = "confirm_label")]
        confirm_size_gib: Option<u64>,
    },
}

fn main() -> ProcessExit {
    // Before any secret exists: hardening, panic hook, signal handler.
    if let Err(e) = lephy_sys::platform::harden() {
        eprintln!("warning: process hardening partly failed: {e}");
    }
    lephy_sys::platform::install_panic_hook();
    if let Err(e) = lephy_sys::signal::install() {
        eprintln!("warning: the signal handler could not be installed: {e}");
    }

    if lephy_core::FAULT_INJECTION_ENABLED {
        eprintln!("warning: LPHY-FAULT-INJECTION test build; do not use with real data");
    }
    let cli = Cli::parse();
    if cfg!(all(target_os = "macos", not(debug_assertions))) && !cli.allow_debugger {
        let _ = lephy_sys::platform::deny_debugger();
    }

    let verbose = cli.verbose;
    let mut log = |m: &str| {
        if verbose || m.starts_with("warning") {
            eprintln!("{m}");
        }
    };
    let code = match run(&cli.command, &mut log) {
        Ok(()) => ExitCode::Ok,
        Err(e) => {
            if matches!(e, Error::Interrupted) {
                eprintln!("\ninterrupted");
            } else {
                eprintln!("error: {e}");
            }
            if let (true, Some(d)) = (cli.verbose, e.detail()) {
                eprintln!("detail: {d}");
            }
            e.exit_code()
        }
    };
    lephy_sys::signal::mark_cleanup_done();
    exit_with(code)
}

fn exit_with(code: ExitCode) -> ProcessExit {
    u8::try_from(code.code()).map_or(ProcessExit::FAILURE, ProcessExit::from)
}

fn memory_warning(strict: bool) -> Result<()> {
    if lephy_sys::mem::lock_failed() {
        let msg = format!(
            "memory could not be locked ({}); secrets may reach swap",
            lephy_sys::mem::last_lock_error().unwrap_or_default()
        );
        if strict {
            return Err(Error::Environment(format!("--strict-memory: {msg}")));
        }
        eprintln!("warning: {msg}");
    }
    Ok(())
}

fn source_of(pw: &PasswordArgs) -> Source {
    if pw.password_stdin {
        return Source::Stdin;
    }
    #[cfg(unix)]
    if let Some(fd) = pw.password_fd {
        return Source::Fd(fd);
    }
    if let Some(p) = &pw.password_file {
        return Source::File(p.clone());
    }
    Source::Tty
}

fn new_source_of(n: &NewPasswordArgs) -> Source {
    #[cfg(unix)]
    if let Some(fd) = n.new_password_fd {
        return Source::Fd(fd);
    }
    if let Some(p) = &n.new_password_file {
        return Source::File(p.clone());
    }
    Source::Tty
}

/// Reads the password and converts it to NFC; with `confirm`, asks twice on a terminal.
fn read_password(
    source: &Source,
    prompt: &str,
    confirm: bool,
    input_is_stdin: bool,
) -> Result<SecretBytes> {
    if let Source::File(p) = source {
        password::reject_remote_pipe(p)?;
    }
    let raw = password::read_raw(source, prompt, input_is_stdin)?;
    let nfc = password::normalize_nfc(&raw)?;
    drop(raw);
    if confirm && matches!(source, Source::Tty) {
        let raw2 = password::read_raw(source, "Password (again): ", input_is_stdin)?;
        let nfc2 = password::normalize_nfc(&raw2)?;
        if nfc.expose() != nfc2.expose() {
            return Err(Error::Environment("the passwords do not match".into()));
        }
    }
    Ok(nfc)
}

fn keyfile_of(path: Option<&PathBuf>) -> Result<Option<zeroize::Zeroizing<[u8; 32]>>> {
    path.map(|p| password::keyfile_digest_from_path(p))
        .transpose()
}

/// How to remove the originals.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Remove {
    No,
    Plain,
    Overwrite,
}

/// Settings shared by every source in batch encryption (the password is read once).
struct EncryptJob<'a> {
    split: Option<u64>,
    /// Public keys; empty = password encryption.
    recipients: &'a [PublicKey],
    nfc: &'a SecretBytes,
    keyfile: Option<&'a [u8; 32]>,
    opts: &'a EncryptOptions,
    remove: Remove,
}

/// Encrypts one source; optionally verifies it and deletes the original. Each source gets a new
/// salt and a new file key (key derivation runs again for each file).
fn encrypt_one(
    job: &EncryptJob<'_>,
    input: &Path,
    out: &Path,
    is_stdin: bool,
    log: &mut dyn FnMut(&str),
) -> Result<()> {
    let inp = if is_stdin {
        Input::Stdin
    } else {
        Input::Path(input)
    };
    let rep = if job.recipients.is_empty() {
        ops::encrypt(
            &inp,
            out,
            job.nfc,
            job.keyfile,
            job.opts,
            &mut OsEntropy,
            log,
        )?
    } else {
        ops::encrypt_to_recipients(&inp, out, job.recipients, job.opts, &mut OsEntropy, log)?
    };
    if rep.noclobber_fallback {
        eprintln!(
            "warning: the file system does not support atomic no-clobber; check-then-rename was used"
        );
    }
    if let Some(a) = &rep.archive {
        print_report(a, log);
    }
    log(&format!(
        "{} bytes ({}) encrypted → {}",
        rep.plain_len,
        match rep.content_type {
            ContentType::Raw => "raw stream",
            ContentType::Archive => "archive",
        },
        disp(out)
    ));
    let out = if let Some(size) = job.split {
        let parts = lephy_core::split::split_file(out, size)?;
        log(&format!(
            "split into {} parts: {} …",
            parts.len(),
            disp(&parts[0])
        ));
        parts[0].clone()
    } else {
        out.to_path_buf()
    };
    let out = out.as_path();
    if job.remove == Remove::No {
        return Ok(());
    }
    let u = UnlockOptions {
        allow_large_kdf: true,
        strict_memory: job.opts.strict_memory,
        identity: None,
    };
    ops::verify(out, job.nfc, job.keyfile, u, log)?;
    if let Some(d) = out.parent() {
        let _ = lephy_sys::fs::fsync_dir(if d.as_os_str().is_empty() {
            Path::new(".")
        } else {
            d
        });
    }
    if let Some(a) = &rep.archive {
        // Only archived items are deleted; if anything was skipped, nothing is deleted.
        let d = ops::delete_archived_with(a, job.remove == Remove::Overwrite)?;
        for k in &d.kept {
            eprintln!(
                "warning: not deleted (changed after archiving, or not empty): {}",
                disp(k)
            );
        }
    } else if input.symlink_metadata()?.is_file() {
        std::fs::remove_file(input)?;
    }
    eprintln!(
        "warning: original deleted; residue may remain on disk, in snapshots/VSS or in cloud version history"
    );
    Ok(())
}

/// "100m", "4g", "650M", "1048576" → bytes.
fn parse_size(s: &str) -> std::result::Result<u64, String> {
    let s = s.trim().to_ascii_lowercase();
    let (num, mul) = match s.chars().last() {
        Some('k') => (&s[..s.len() - 1], 1u64 << 10),
        Some('m') => (&s[..s.len() - 1], 1 << 20),
        Some('g') => (&s[..s.len() - 1], 1 << 30),
        _ => (s.as_str(), 1),
    };
    let n: u64 = num
        .parse()
        .map_err(|_| format!("invalid size: {s} (e.g. 100m, 4g)"))?;
    let v = n.checked_mul(mul).ok_or("size too large")?;
    if v < lephy_core::split::MIN_PART {
        return Err("the part size must be at least 1m".into());
    }
    Ok(v)
}

fn default_output_name() -> Result<PathBuf> {
    use lephy_core::entropy::Entropy;
    let mut b = [0u8; 4];
    OsEntropy.fill(&mut b)?;
    Ok(PathBuf::from(format!(
        "{:02x}{:02x}{:02x}{:02x}.lphy",
        b[0], b[1], b[2], b[3]
    )))
}

fn disp(p: &Path) -> String {
    escape_display(&p.display().to_string())
}

fn print_report(rep: &Report, log: &mut dyn FnMut(&str)) {
    for (p, why) in &rep.skipped {
        eprintln!("warning: skipped: {} ({why})", escape_display(p));
    }
    for (a, b) in &rep.renamed {
        eprintln!(
            "warning: renamed: {} → {}",
            escape_display(a),
            escape_display(b)
        );
    }
    for w in &rep.warnings {
        eprintln!("warning: {w}");
    }
    log(&format!(
        "{} entries, {} symlinks created",
        rep.entries, rep.symlinks_created
    ));
}

/// Cloud-sync folder check: confirmation or `--allow-cloud-dir`; non-tty → code 5.
fn cloud_check(target: &Path, allow: bool) -> Result<()> {
    if allow {
        return Ok(());
    }
    let Some(root) = lephy_sys::fs::cloud_root_of(target) else {
        return Ok(());
    };
    eprintln!(
        "warning: the destination is inside a cloud-sync folder ({}); plaintext may be uploaded. The list is heuristic and may be incomplete.",
        disp(&root)
    );
    let stdin = std::io::stdin();
    if !lephy_sys::term::is_tty(&stdin) {
        return Err(Error::Cancelled(
            "extracting into a cloud folder needs confirmation (--allow-cloud-dir)".into(),
        ));
    }
    eprint!("Continue? [yes/no]: ");
    let mut line = String::new();
    stdin.read_line(&mut line)?;
    if !matches!(line.trim().to_lowercase().as_str(), "yes" | "evet") {
        return Err(Error::Cancelled("cloud-folder confirmation refused".into()));
    }
    Ok(())
}

#[allow(clippy::too_many_lines)]
fn run(cmd: &Command, log: &mut dyn FnMut(&str)) -> Result<()> {
    match cmd {
        Command::Encrypt {
            inputs,
            output,
            out_dir,
            alg,
            chunk_size,
            kdf,
            pw,
            recipients,
            raw,
            pad,
            no_pad,
            strict,
            force,
            strict_memory,
            delete_original,
            secure_delete,
            split_size,
            compress,
            error_correction,
            yes,
        } => {
            let is_stdin = inputs.iter().any(|i| i.as_os_str() == "-");
            if is_stdin && inputs.len() > 1 {
                return Err(Error::Environment(
                    "stdin (\"-\") can only be used as the only source".into(),
                ));
            }
            if inputs.len() > 1 && out_dir.is_none() {
                return Err(Error::Environment(
                    "--out-dir is required for several sources (each becomes its own .lphy)".into(),
                ));
            }
            if is_stdin && *pad {
                return Err(Error::Environment(
                    "--pad cannot be used with stdin input".into(),
                ));
            }
            let remove = *delete_original || *secure_delete;
            if remove && is_stdin {
                return Err(Error::Environment(
                    "--delete-original cannot be used with stdin".into(),
                ));
            }
            if *secure_delete && !*yes {
                eprintln!(
                    "The originals will be deleted after encryption has been verified, overwritten with random data first.\n\
                     The old content may still remain on SSDs, APFS/Btrfs, snapshots and in cloud history."
                );
                let a = prompt_line("Type 'yes' to confirm: ", "give --yes")?;
                if !matches!(a.trim().to_lowercase().as_str(), "evet" | "yes") {
                    return Err(Error::Cancelled("secure deletion not confirmed".into()));
                }
            }
            let pks = recipient_keys(recipients)?;
            if !pks.is_empty() {
                if pw.keyfile.is_some() || pw.password_file.is_some() || pw.password_stdin {
                    return Err(Error::Environment(
                        "--recipient replaces the password; do not combine it with password or key-file options".into(),
                    ));
                }
                if remove {
                    return Err(Error::Environment(
                        "--delete-original/--secure-delete need a verification that only the recipient can do; delete the originals yourself".into(),
                    ));
                }
            }
            let kdf = kdf.params();
            let (keyfile, nfc) = if pks.is_empty() {
                kdf.check_encrypt_policy()?;
                let keyfile = keyfile_of(pw.keyfile.as_ref())?;
                let source = source_of(pw);
                let nfc = read_password(&source, "Password: ", true, is_stdin)?;
                password::check_encrypt_policy(&nfc)?;
                (keyfile, nfc)
            } else {
                (None, empty_secret()?)
            };
            memory_warning(*strict_memory)?;
            let opts = EncryptOptions {
                alg: match alg {
                    Alg::Xchacha20 => AlgId::XChaCha20Poly1305,
                    Alg::Aes256gcm => AlgId::Aes256Gcm,
                },
                chunk_code: chunk_size.code(),
                kdf,
                force: *force,
                strict_memory: *strict_memory,
                raw: *raw,
                pad: if *pad {
                    Some(true)
                } else if *no_pad {
                    Some(false)
                } else {
                    None
                },
                strict: *strict,
                compress: *compress,
                ecc: *error_correction,
            };
            if split_size.is_some() && is_stdin {
                return Err(Error::Environment(
                    "--split-size works with file output, not with stdin".into(),
                ));
            }
            let job = EncryptJob {
                split: *split_size,
                recipients: &pks,
                nfc: &nfc,
                keyfile: keyfile.as_deref(),
                opts: &opts,
                remove: if *secure_delete {
                    Remove::Overwrite
                } else if *delete_original {
                    Remove::Plain
                } else {
                    Remove::No
                },
            };
            let mut first_err = None;
            let mut ok = 0usize;
            for input in inputs {
                let out = match (output, out_dir) {
                    (Some(o), _) => o.clone(),
                    (None, Some(d)) => d.join(default_output_name()?),
                    (None, None) => default_output_name()?,
                };
                if let Some(o) = output
                    && let (Some(src), Some(dst)) = (input.file_name(), o.file_name())
                {
                    let (s, d) = (src.to_string_lossy(), dst.to_string_lossy());
                    if !is_stdin && d.contains(&*s) {
                        log(&format!(
                            "info: the output name contains the source name ({})",
                            escape_display(&d)
                        ));
                    }
                }
                match encrypt_one(&job, input, &out, is_stdin, log) {
                    Ok(()) => ok += 1,
                    Err(e) if inputs.len() > 1 => {
                        eprintln!("error: {}: {e}", disp(input));
                        first_err.get_or_insert(e);
                    }
                    Err(e) => return Err(e),
                }
            }
            if inputs.len() > 1 {
                log(&format!("{ok}/{} sources encrypted", inputs.len()));
            }
            first_err.map_or(Ok(()), Err)
        }
        Command::Decrypt {
            input,
            identity,
            output,
            stdout,
            pw,
            unlock,
            force,
            restore_symlinks,
            rename_conflicts,
            strict,
            allow_cloud_dir,
            recover,
            only,
        } => {
            let (keyfile, nfc, id) = unlock_material(input, identity.as_deref(), pw, *unlock, log)?;
            memory_warning(unlock.strict_memory)?;
            let unlock_opts = UnlockOptions {
                identity: id.as_ref(),
                ..unlock.opts()
            };
            if *recover {
                let out = output.clone().unwrap_or_else(|| {
                    let s = input
                        .file_name()
                        .map(|f| f.to_string_lossy().into_owned())
                        .unwrap_or_default();
                    let s = s.strip_suffix(".001").unwrap_or(&s);
                    let base = s.strip_suffix(".lphy").unwrap_or(s);
                    input.with_file_name(format!("{base}.recovered"))
                });
                cloud_check(&out, *allow_cloud_dir)?;
                let r = ops::recover(input, &out, &nfc, keyfile.as_deref(), unlock_opts, log)?;
                if r.repaired > 0 {
                    eprintln!("info: error correction repaired {} bytes", r.repaired);
                }
                if r.clean() {
                    eprintln!(
                        "the file is intact; no recovery was needed → {}",
                        disp(&out)
                    );
                    return Ok(());
                }
                eprintln!(
                    "warning: the RECOVERED output may contain unverified data → {}",
                    disp(&out)
                );
                for c in r.bad_chunks.iter().take(20) {
                    let start = c * r.chunk_size as u64;
                    eprintln!(
                        "  damaged part: chunk {c} (about bytes {start}–{}; zero-filled)",
                        start + r.chunk_size as u64
                    );
                }
                if r.bad_chunks.len() > 20 {
                    eprintln!("  … and {} more chunks", r.bad_chunks.len() - 20);
                }
                if r.truncated {
                    eprintln!("  the file is truncated: the last part is missing");
                }
                if let Some(why) = &r.stopped {
                    eprintln!(
                        "  extraction stopped after {} entries: {}",
                        r.entries,
                        escape_display(why)
                    );
                }
                return Err(Error::Corrupt {
                    at: "recovery".into(),
                    detail: Some("the file was damaged; partial output was written".into()),
                });
            }
            let dopts = DecryptOptions {
                unlock: unlock_opts,
                extract: ExtractOptions {
                    strict: *strict,
                    symlinks: match restore_symlinks {
                        None => SymlinkPolicy::None,
                        Some(RestoreSymlinks::Safe) => SymlinkPolicy::Safe,
                        Some(RestoreSymlinks::Unsafe) => SymlinkPolicy::Unsafe,
                    },
                    rename_conflicts: *rename_conflicts,
                    padded: false,
                },
                only: (!only.is_empty()).then_some(only.as_slice()),
            };
            if *stdout {
                eprintln!(
                    "warning: --stdout: truncation cannot be detected until the last chunk is verified; output may be partial"
                );
                let r = ops::decrypt(input, &Output::Stdout, &nfc, keyfile.as_deref(), dopts, log)?;
                if r.repaired > 0 {
                    eprintln!("info: error correction repaired {} bytes", r.repaired);
                }
                log(&format!("{} bytes decrypted (stdout)", r.plain_len));
                return Ok(());
            }
            let out = output.clone().unwrap_or_else(|| {
                let s = input
                    .file_name()
                    .map(|f| f.to_string_lossy().into_owned())
                    .unwrap_or_default();
                let s = s.strip_suffix(".001").unwrap_or(&s);
                let base = s
                    .strip_suffix(".lphy")
                    .map_or_else(|| format!("{s}.out"), str::to_string);
                input.with_file_name(base)
            });
            cloud_check(&out, *allow_cloud_dir)?;
            let r = ops::decrypt(
                input,
                &Output::Path(&out, *force),
                &nfc,
                keyfile.as_deref(),
                dopts,
                log,
            )?;
            if r.repaired > 0 {
                eprintln!("info: error correction repaired {} bytes", r.repaired);
            }
            if r.noclobber_fallback {
                eprintln!(
                    "warning: the file system does not support atomic no-clobber; check-then-rename was used"
                );
            }
            if let Some(a) = &r.archive {
                print_report(a, log);
            }
            log(&format!(
                "{} bytes decrypted → {}",
                r.plain_len,
                disp(&r.target)
            ));
            Ok(())
        }
        Command::Verify {
            input,
            identity,
            pw,
            unlock,
        } => {
            let (keyfile, nfc, id) = unlock_material(input, identity.as_deref(), pw, *unlock, log)?;
            memory_warning(unlock.strict_memory)?;
            let u = UnlockOptions {
                identity: id.as_ref(),
                ..unlock.opts()
            };
            let n = ops::verify(input, &nfc, keyfile.as_deref(), u, log)?;
            println!("verified: {n} bytes");
            Ok(())
        }
        Command::List {
            input,
            identity,
            pw,
            unlock,
        } => {
            let (keyfile, nfc, id) = unlock_material(input, identity.as_deref(), pw, *unlock, log)?;
            memory_warning(unlock.strict_memory)?;
            let u = UnlockOptions {
                identity: id.as_ref(),
                ..unlock.opts()
            };
            let entries = ops::list(input, &nfc, keyfile.as_deref(), u, log)?;
            let (mut files, mut bytes) = (0u64, 0u64);
            for e in &entries {
                let (kind, size) = match e.kind {
                    lephy_core::archive::EntryKind::Dir => ("dir ", String::new()),
                    lephy_core::archive::EntryKind::Symlink => ("link", String::new()),
                    lephy_core::archive::EntryKind::File => {
                        files += 1;
                        bytes += e.size;
                        ("file", e.size.to_string())
                    }
                };
                let path = lephy_core::names::escape_display(&e.path);
                let suffix = if e.kind == lephy_core::archive::EntryKind::Dir {
                    "/"
                } else {
                    ""
                };
                println!("{kind} {size:>14}  {path}{suffix}");
            }
            println!("{} entries, {files} files, {bytes} bytes", entries.len());
            Ok(())
        }
        Command::Info { input } => {
            let h = ops::info(input)?;
            println!("file:         {}", disp(input));
            let version = if h.compressed || h.recipients > 0 {
                2
            } else {
                lephy_core::FORMAT_VERSION
            };
            println!("version:      {version}");
            println!("algorithm:    {}", h.alg.name());
            println!(
                "content:      {}",
                match h.content_type {
                    ContentType::Raw => "raw stream",
                    ContentType::Archive => "archive",
                }
            );
            println!("padding:      {}", if h.padded { "PADMÉ" } else { "none" });
            println!("chunk:        {} KiB", h.chunk_size() / 1024);
            if h.compressed {
                println!("compression:  DEFLATE");
            }
            if h.recipients > 0 {
                println!(
                    "recipients:   {} (public key; needs --identity)",
                    h.recipients
                );
            } else {
                println!(
                    "kdf:          Argon2id m={} MiB t={} p={}",
                    h.kdf.memory_mib(),
                    h.kdf.t,
                    h.kdf.p
                );
                println!(
                    "keyfile:      {}",
                    if h.keyfile { "required" } else { "none" }
                );
                println!("salt:         {}", hex(&h.salt));
                println!("commit_tag:   {}", hex(&h.commit_tag));
            }
            println!(
                "nonce_prefix: {}",
                hex(&h.stream_nonce_prefix[..h.alg.prefix_len()])
            );
            let size = std::fs::metadata(input)?.len();
            let body = size.saturating_sub((256 + h.ext_len()) as u64);
            let cs = h.chunk_size() as u64 + 16;
            println!(
                "size:         {size} bytes (~{} chunks)",
                body.div_ceil(cs).max(1)
            );
            Ok(())
        }
        Command::Rekey {
            input,
            pw,
            new,
            kdf_memory,
            verify,
            unlock,
        } => {
            let old_kf = keyfile_of(pw.keyfile.as_ref())?;
            let new_kf = keyfile_of(new.new_keyfile.as_ref())?;
            let old_src = source_of(pw);
            let new_src = new_source_of(new);
            if matches!(old_src, Source::Stdin) {
                return Err(Error::Environment(
                    "rekey: the old password cannot come from --password-stdin (two passwords are needed)".into(),
                ));
            }
            let old = read_password(&old_src, "Old password: ", false, false)?;
            let newp = read_password(&new_src, "New password: ", true, false)?;
            password::check_encrypt_policy(&newp)?;
            memory_warning(unlock.strict_memory)?;
            let kdf = kdf_memory.map(|m| KdfParams {
                m_kib: m.saturating_mul(1024),
                ..KdfParams::DEFAULT
            });
            if let Some(k) = kdf {
                k.check_encrypt_policy()?;
            }
            let creds = NewCredentials {
                pwd_nfc: &newp,
                keyfile_digest: new_kf.as_deref(),
                kdf,
            };
            ops::rekey(
                input,
                &old,
                old_kf.as_deref(),
                &creds,
                unlock.opts(),
                *verify,
                &mut OsEntropy,
                log,
            )?;
            Ok(())
        }
        Command::Reencrypt {
            input,
            pw,
            new,
            unlock,
        } => {
            let old_kf = keyfile_of(pw.keyfile.as_ref())?;
            let new_kf = keyfile_of(new.new_keyfile.as_ref())?;
            let old_src = source_of(pw);
            let new_src = new_source_of(new);
            if matches!(old_src, Source::Stdin) {
                return Err(Error::Environment(
                    "reencrypt: the old password cannot come from --password-stdin (two passwords are needed)"
                        .into(),
                ));
            }
            let old = read_password(&old_src, "Old password: ", false, false)?;
            let newp = read_password(&new_src, "New password: ", true, false)?;
            password::check_encrypt_policy(&newp)?;
            memory_warning(unlock.strict_memory)?;
            let creds = NewCredentials {
                pwd_nfc: &newp,
                keyfile_digest: new_kf.as_deref(),
                kdf: None,
            };
            let n = ops::reencrypt(
                input,
                &old,
                old_kf.as_deref(),
                &creds,
                unlock.opts(),
                &mut OsEntropy,
                log,
            )?;
            log(&format!("{n} bytes re-encrypted"));
            Ok(())
        }
        Command::Usb { cmd } => run_usb(cmd, log),
        Command::Passphrase { words, separator } => {
            let p = lephy_core::passphrase::generate(
                &mut lephy_core::entropy::OsEntropy,
                *words,
                *separator,
            )?;
            lephy_sys::term::write_all_raw(&std::io::stdout(), p.expose())?;
            lephy_sys::term::write_all_raw(&std::io::stdout(), b"\n")?;
            eprintln!(
                "≈ {:.0} bits; write this passphrase down somewhere safe, it is not shown again",
                lephy_core::passphrase::bits(*words)
            );
            Ok(())
        }
        Command::Keygen { path, kdf, pw } => {
            if pw.keyfile.is_some() {
                return Err(Error::Environment(
                    "keygen: identity files are protected by a password only".into(),
                ));
            }
            let kdf = kdf.params();
            kdf.check_encrypt_policy()?;
            let pub_path = path.with_extension("pub");
            if pub_path.exists() {
                return Err(Error::Exists(disp(&pub_path)));
            }
            let nfc = read_password(&source_of(pw), "Identity password: ", true, false)?;
            password::check_encrypt_policy(&nfc)?;
            let id = Identity::generate(&mut OsEntropy)?;
            lephy_core::recipient::write_identity_file(path, &id, &nfc, kdf, &mut OsEntropy, log)?;
            let pk = id.public().to_string();
            let mut f = std::fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(&pub_path)?;
            std::io::Write::write_all(&mut f, format!("{pk}\n").as_bytes())?;
            println!("{pk}");
            eprintln!(
                "identity: {} (keep it secret; back it up — losing it or its password makes files encrypted to this key unreadable)\npublic key: {} (share this one)",
                disp(path),
                disp(&pub_path)
            );
            Ok(())
        }
        Command::KeyfileGen { path, size } => {
            password::generate_keyfile(path, *size)?;
            eprintln!(
                "key file created: {} ({size} bytes). If you lose it, data encrypted with it cannot be opened; back it up.",
                disp(path)
            );
            Ok(())
        }
        Command::Cleanup { dir, yes } => {
            let stale = lephy_core::io::scan_stale(dir)?;
            if stale.is_empty() {
                println!("no stale temp files");
                return Ok(());
            }
            for p in &stale {
                println!("{}", disp(p));
            }
            eprintln!(
                "warning: decryption temp files may contain plaintext; deleting can leave residue"
            );
            if !*yes {
                let stdin = std::io::stdin();
                if !lephy_sys::term::is_tty(&stdin) {
                    return Err(Error::Cancelled("confirmation needed (--yes)".into()));
                }
                eprint!("Delete {} items? [yes/no]: ", stale.len());
                let mut line = String::new();
                stdin.read_line(&mut line)?;
                if !matches!(line.trim().to_lowercase().as_str(), "yes" | "evet") {
                    return Err(Error::Cancelled("refused by the user".into()));
                }
            }
            let n = lephy_core::io::cleanup(&stale)?;
            println!("{n} deleted");
            Ok(())
        }
    }
}

fn empty_secret() -> Result<SecretBytes> {
    SecretBytes::with_capacity(1).map_err(|e| Error::Environment(format!("locked memory: {e}")))
}

/// `-r` values: `lphy1…` keys or files with one key per line.
fn recipient_keys(values: &[String]) -> Result<Vec<PublicKey>> {
    let mut out = Vec::new();
    for v in values {
        if v.trim_start()
            .starts_with(lephy_core::recipient::PUBLIC_PREFIX)
        {
            out.push(v.parse::<PublicKey>()?);
        } else {
            let text = std::fs::read_to_string(v)
                .map_err(|e| Error::Environment(format!("recipient {}: {e}", escape_display(v))))?;
            let keys = lephy_core::recipient::parse_public_keys(&text)?;
            if keys.is_empty() {
                return Err(Error::Environment(format!(
                    "recipient file has no keys: {}",
                    escape_display(v)
                )));
            }
            out.extend(keys);
        }
    }
    out.dedup();
    Ok(out)
}

/// Key-file digest, password and identity for unlocking.
type UnlockMaterial = (
    Option<zeroize::Zeroizing<[u8; 32]>>,
    SecretBytes,
    Option<Identity>,
);

/// Password/key file for password files, or the opened identity for recipient files. The
/// file's header decides, so the right question is asked.
fn unlock_material(
    input: &Path,
    identity: Option<&Path>,
    pw: &PasswordArgs,
    unlock: UnlockArgs,
    log: &mut dyn FnMut(&str),
) -> Result<UnlockMaterial> {
    let recipients = ops::info(input).map_or(0, |h| h.recipients);
    match (recipients > 0, identity) {
        (true, None) => Err(Error::IdentityRequired),
        (false, Some(_)) => Err(Error::IdentityNotUsed),
        (true, Some(path)) => {
            if pw.keyfile.is_some() {
                return Err(Error::KeyfileNotUsed);
            }
            let nfc = read_password(&source_of(pw), "Identity password: ", false, false)?;
            let id = lephy_core::recipient::read_identity_file(path, &nfc, unlock.opts(), log)?;
            Ok((None, empty_secret()?, Some(id)))
        }
        (false, None) => {
            let keyfile = keyfile_of(pw.keyfile.as_ref())?;
            let nfc = read_password(&source_of(pw), "Password: ", false, false)?;
            Ok((keyfile, nfc, None))
        }
    }
}

fn prompt_line(q: &str, non_tty_hint: &str) -> Result<String> {
    let stdin = std::io::stdin();
    if !lephy_sys::term::is_tty(&stdin) {
        return Err(Error::Cancelled(format!(
            "confirmation needed: {non_tty_hint}"
        )));
    }
    eprint!("{q}");
    let mut line = String::new();
    stdin.read_line(&mut line)?;
    Ok(line.trim_end_matches(['\r', '\n']).to_string())
}

#[allow(clippy::too_many_lines)]
fn run_usb(cmd: &UsbCmd, log: &mut dyn FnMut(&str)) -> Result<()> {
    let platform = lephy_usb::native();
    match cmd {
        UsbCmd::List => {
            let devs = platform.list()?;
            if devs.is_empty() {
                println!("no mounted candidate USB volume");
            }
            for d in devs {
                let verdict = match d.eligibility(platform.require_serial()) {
                    Ok(()) => "eligible".to_string(),
                    Err(why) => format!("NOT ELIGIBLE: {why}"),
                };
                println!(
                    "{}  label={}  {} GiB  {}  bus={}  product={}  → {verdict}",
                    disp(&d.mount),
                    escape_display(&d.label),
                    d.size_gib(),
                    d.fs_type,
                    d.bus,
                    escape_display(&d.product)
                );
            }
            Ok(())
        }
        UsbCmd::Write {
            source,
            target,
            format,
            fill_free_space,
            confirm_label,
            confirm_size_gib,
        } => {
            lephy_usb::engine::check_source(source)?;
            let (dev, dry) = lephy_usb::engine::prepare(platform.as_ref(), target)?;
            println!(
                "TARGET: {}  label={}  {} GiB  {}  product={}",
                disp(&dev.mount),
                escape_display(&dev.label),
                dev.size_gib(),
                dev.fs_type,
                escape_display(&dev.product)
            );
            if *format {
                println!("ACTION: the volume will be FORMATTED as exFAT; all content is lost.");
            } else {
                println!(
                    "TO BE DELETED: {} files, {} directories, {} bytes. First {} paths:",
                    dry.files,
                    dry.dirs,
                    dry.bytes,
                    dry.first.len()
                );
                for p in &dry.first {
                    println!("  {p}");
                }
            }
            eprintln!(
                "warning: because of old FAT/exFAT directory entries, NTFS resident files and wear levelling \
                 there is no guarantee of physical erasure; --format gives no controller-level guarantee either"
            );
            let confirm = if let (Some(l), Some(g)) = (confirm_label, confirm_size_gib) {
                lephy_usb::Confirm {
                    label: l.clone(),
                    size_gib: *g,
                }
            } else {
                let label = prompt_line(
                    "To confirm, type the volume label exactly: ",
                    "give --confirm-label and --confirm-size-gib",
                )?;
                let gib = prompt_line(
                    "To confirm, type the size in GiB (whole number): ",
                    "give --confirm-label and --confirm-size-gib",
                )?;
                let size_gib = gib
                    .trim()
                    .parse::<u64>()
                    .map_err(|_| Error::Cancelled("the size is not a whole number".into()))?;
                lephy_usb::Confirm { label, size_gib }
            };
            let req = lephy_usb::WriteRequest {
                source: source.clone(),
                confirm,
                format: *format,
                fill: *fill_free_space,
                fill_opts: None,
            };
            let mut say = |m: &str| eprintln!("{m}");
            let rep = lephy_usb::engine::execute(platform.as_ref(), &dev, dry, &req, &mut say)?;
            println!(
                "written: {} ({} bytes, BLAKE3 {}) — {}",
                disp(&rep.written),
                rep.bytes,
                &rep.blake3[..16],
                rep.verification
            );
            if rep.verification == lephy_usb::Verification::FromCache {
                eprintln!(
                    "warning: the volume could not be remounted; the read-back may have come from the OS cache"
                );
            }
            log(&format!("steps: {}", rep.steps.join(" → ")));
            Ok(())
        }
    }
}

fn hex(b: &[u8]) -> String {
    use std::fmt::Write as _;
    b.iter()
        .fold(String::with_capacity(b.len() * 2), |mut acc, x| {
            let _ = write!(acc, "{x:02x}");
            acc
        })
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::CommandFactory;

    #[test]
    fn cli_is_well_formed() {
        Cli::command().debug_assert();
    }

    #[test]
    fn no_argv_password_value_argument() {
        // The password value is never taken from argv; there are only source options.
        let cmd = Cli::command();
        for sub in cmd.get_subcommands() {
            for arg in sub.get_arguments() {
                let id = arg.get_id().as_str();
                if id.contains("password") {
                    assert!(
                        id.ends_with("stdin") || id.ends_with("fd") || id.ends_with("file"),
                        "argv password argument: {id}"
                    );
                }
            }
        }
    }

    #[test]
    fn usb_confirm_flags_must_come_together() {
        let r = Cli::try_parse_from([
            "lephycrypy",
            "usb",
            "write",
            "a.lphy",
            "--target",
            "/x",
            "--confirm-label",
            "L",
        ]);
        assert!(r.is_err());
        let r = Cli::try_parse_from([
            "lephycrypy",
            "usb",
            "write",
            "a.lphy",
            "--target",
            "/x",
            "--confirm-label",
            "L",
            "--confirm-size-gib",
            "8",
        ]);
        assert!(r.is_ok());
    }

    #[test]
    fn pad_and_no_pad_conflict_is_clap_error() {
        let r = Cli::try_parse_from(["lephycrypy", "encrypt", "x", "--pad", "--no-pad"]);
        assert!(r.is_err());
        let r = Cli::try_parse_from(["lephycrypy", "decrypt", "x", "--restore-symlinks"]);
        assert!(r.is_ok());
        let r = Cli::try_parse_from(["lephycrypy", "decrypt", "x", "--restore-symlinks", "unsafe"]);
        assert!(r.is_ok());
    }
}
