//! UI-independent logic: mode detection, default output path, background job.
//! Paths come from drag and drop, the file dialogs or the operating system's open requests
//! (THREAT-MODEL › Desktop app).

use crate::i18n::tr;
use std::path::{Path, PathBuf};

use lephy_core::cipher::AlgId;
use lephy_core::entropy::{Entropy, OsEntropy};
use lephy_core::error::{Error, ExitCode, Result};
use lephy_core::header::{HEADER_LEN, Header};
use lephy_core::kdf::KdfParams;
use lephy_core::ops::{self, DecryptOptions, EncryptOptions, Identity, Input, Output, PublicKey};
use lephy_core::password;
use lephy_sys::mem::SecretBytes;

/// Operation mode.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Mode {
    /// File/folder → `.lphy`.
    Encrypt,
    /// `.lphy` → file/folder.
    Decrypt,
}

/// Decrypt if there is a valid `.lphy` header, otherwise encrypt.
#[must_use]
pub fn detect_mode(path: &Path) -> Mode {
    let Ok(md) = path.metadata() else {
        return Mode::Encrypt;
    };
    if !md.is_file() || md.len() < HEADER_LEN as u64 {
        return Mode::Encrypt;
    }
    let mut h = [0u8; HEADER_LEN];
    let ok = std::fs::File::open(path)
        .and_then(|mut f| std::io::Read::read_exact(&mut f, &mut h))
        .is_ok();
    if ok && Header::parse(&h).is_ok() {
        Mode::Decrypt
    } else {
        Mode::Encrypt
    }
}

/// Whether the encrypted file needs a key file (`false` if the header cannot be read).
#[must_use]
pub fn needs_keyfile(path: &Path) -> bool {
    let mut h = [0u8; HEADER_LEN];
    std::fs::File::open(path)
        .and_then(|mut f| std::io::Read::read_exact(&mut f, &mut h))
        .is_ok()
        && Header::parse(&h).is_ok_and(|hd| hd.keyfile)
}

/// Is the file encrypted to public keys (header unreadable: `false`).
#[must_use]
pub fn needs_identity(path: &Path) -> bool {
    ops::info(path).is_ok_and(|h| h.recipients > 0)
}

/// Public keys from text (one per line, `#` comments). `Err`: user-facing message.
///
/// # Errors
/// An invalid line.
pub fn parse_recipients(text: &str) -> std::result::Result<Vec<PublicKey>, String> {
    let mut keys = lephy_core::recipient::parse_public_keys(text).map_err(|_| {
        tr(
            "Geçersiz açık anahtar. Anahtarlar \"lphy1\" ile başlar; her satıra bir tane yazın.",
            "Invalid public key. Keys start with \"lphy1\"; put one per line.",
        )
        .to_string()
    })?;
    keys.dedup();
    Ok(keys)
}

/// Creates a key pair: password-protected identity at `path`, public key next to it as
/// `<name>.pub`. Returns the public key text.
///
/// # Errors
/// Password policy, existing files, I/O.
pub fn create_identity(path: &Path, password: &SecretBytes, kdf_mib: u32) -> Result<String> {
    let nfc = password::normalize_nfc(password)?;
    password::check_encrypt_policy(&nfc)?;
    let pub_path = path.with_extension("pub");
    if pub_path.exists() {
        return Err(Error::Exists(pub_path.display().to_string()));
    }
    let id = Identity::generate(&mut OsEntropy)?;
    let kdf = KdfParams {
        m_kib: kdf_mib.saturating_mul(1024),
        ..KdfParams::DEFAULT
    };
    lephy_core::recipient::write_identity_file(path, &id, &nfc, kdf, &mut OsEntropy, &mut |_| {})?;
    let pk = id.public().to_string();
    std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&pub_path)
        .and_then(|mut f| std::io::Write::write_all(&mut f, format!("{pk}\n").as_bytes()))?;
    Ok(pk)
}

/// Puts non-secret text (a public key) on the system clipboard with the system's own tool. The
/// app itself has no clipboard access, so passwords can never reach it.
///
/// # Errors
/// The tool is missing or failed.
pub fn copy_to_clipboard(text: &str) -> std::io::Result<()> {
    use std::io::Write;
    #[cfg(target_os = "macos")]
    let tool = PathBuf::from("/usr/bin/pbcopy");
    #[cfg(windows)]
    let sys = lephy_sys::vol::win::system_directory()?;
    #[cfg(windows)]
    let tool = sys.join("clip.exe");
    #[cfg(not(any(target_os = "macos", windows)))]
    let tool = PathBuf::from("xclip");
    let mut cmd = std::process::Command::new(tool);
    cmd.env_clear();
    // Windows programs need SystemRoot to load system libraries.
    #[cfg(windows)]
    if let Some(root) = sys.parent() {
        cmd.env("SystemRoot", root);
    }
    let mut child = cmd
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .spawn()?;
    if let Some(mut stdin) = child.stdin.take() {
        stdin.write_all(text.as_bytes())?;
    }
    let status = child.wait()?;
    if status.success() {
        Ok(())
    } else {
        Err(std::io::Error::other("clipboard tool failed"))
    }
}

/// Default output: when encrypting, `<8 random hex>.lphy` in the same directory; when decrypting,
/// the name without `.lphy`, or `<name>.out`.
#[must_use]
pub fn default_output(input: &Path, mode: Mode) -> PathBuf {
    let dir = input.parent().unwrap_or(Path::new("."));
    match mode {
        Mode::Encrypt => {
            let mut b = [0u8; 4];
            let _ = OsEntropy.fill(&mut b);
            dir.join(format!(
                "{:02x}{:02x}{:02x}{:02x}.lphy",
                b[0], b[1], b[2], b[3]
            ))
        }
        Mode::Decrypt => {
            let name = input
                .file_name()
                .map(|f| f.to_string_lossy().into_owned())
                .unwrap_or_default();
            let name = name.strip_suffix(".001").unwrap_or(&name).to_string();
            let base = name
                .strip_suffix(".lphy")
                .map_or_else(|| format!("{name}.out"), str::to_string);
            dir.join(base)
        }
    }
}

/// A source and its destination.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Item {
    /// Source.
    pub input: PathBuf,
    /// Destination.
    pub output: PathBuf,
}

/// Background job. Passwords travel in locked `SecretBytes` and are dropped when the job ends.
#[allow(clippy::struct_excessive_bools)]
pub struct Job {
    /// Mode.
    pub mode: Mode,
    /// Source/destination pairs (several in a batch).
    pub items: Vec<Item>,
    /// Password (raw UTF-8).
    pub password: SecretBytes,
    /// Repeated password when encrypting.
    pub confirm: Option<SecretBytes>,
    /// Argon2id memory (MiB).
    pub kdf_mib: u32,
    /// AES-256-GCM (default XChaCha20-Poly1305).
    pub aes: bool,
    /// PADMÉ for archives.
    pub pad: bool,
    /// Allow extracting into a cloud-sync folder.
    pub allow_cloud: bool,
    /// Optional key file (a second factor besides the password).
    pub keyfile: Option<PathBuf>,
    /// Overwrite and delete the original after encryption is verified (confirmed by the user).
    pub secure_delete: bool,
    /// Split the output into parts of this size (bytes).
    pub split: Option<u64>,
    /// Compress before encrypting.
    pub compress: bool,
    /// Add a Reed–Solomon error-correction envelope.
    pub ecc: bool,
    /// Recovery mode when decrypting: extract what can be saved from a damaged file.
    pub recover: bool,
    /// Encrypt to these public keys instead of the password (empty = password). When decrypting a
    /// file encrypted to public keys: replace its recipients with this list instead (needs
    /// `identity`; nothing is extracted).
    pub recipients: Vec<PublicKey>,
    /// Decrypt with this identity file; `password` is then the identity's password.
    pub identity: Option<PathBuf>,
    /// Decrypting an archive: only list its contents, write nothing.
    pub list_only: bool,
    /// Decrypting an archive: extract only these paths (empty = everything).
    pub only: Vec<String>,
}

/// Job result.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Outcome {
    /// Files or folders written.
    pub outputs: Vec<PathBuf>,
    /// Skipped archive entries (special files, symlinks not created).
    pub skipped: usize,
    /// Failed items: (display name, error text).
    pub failed: Vec<(String, String)>,
    /// Number of items whose original was deleted.
    pub deleted: usize,
    /// Number of paths not deleted (changed after archiving).
    pub kept: usize,
    /// Bytes repaired by error correction (when decrypting).
    pub repaired: u64,
    /// Number of parts zero-filled during recovery because they failed verification.
    pub damaged: usize,
    /// During recovery the file was truncated or extraction stopped early.
    pub incomplete: bool,
    /// Contents of the archive (a listing job; nothing was written).
    pub listing: Option<Vec<lephy_core::archive::ListEntry>>,
    /// The recipient list was replaced with this many keys.
    pub recipients_set: Option<usize>,
}

#[allow(clippy::struct_excessive_bools, reason = "independent job switches")]
struct Ctx<'a> {
    nfc: &'a SecretBytes,
    recipients: &'a [PublicKey],
    identity: Option<&'a Identity>,
    kf: Option<&'a [u8; 32]>,
    opts: Option<EncryptOptions>,
    allow_cloud: bool,
    secure_delete: bool,
    split: Option<u64>,
    recover: bool,
    list_only: bool,
    only: &'a [String],
}

/// Runs the job. With a single item an error is returned directly; in a batch failed items go to
/// `failed` and the rest continue (if all fail, the first error is returned).
///
/// # Errors
/// Core errors (the message and exit-code category are shown in the UI).
#[allow(clippy::too_many_lines, reason = "one linear setup of the job")]
pub fn run(job: Job) -> Result<Outcome> {
    let mut nfc = password::normalize_nfc(&job.password)?;
    drop(job.password);
    let key_mode = job.mode == Mode::Encrypt && !job.recipients.is_empty();
    let identity = match (&job.identity, job.mode) {
        (Some(p), Mode::Decrypt) => {
            let id = lephy_core::recipient::read_identity_file(
                p,
                &nfc,
                ops::UnlockOptions::default(),
                &mut |_| {},
            )?;
            // The file itself needs no password.
            nfc = SecretBytes::with_capacity(1).map_err(|e| Error::Environment(e.to_string()))?;
            Some(id)
        }
        _ => None,
    };
    if job.mode == Mode::Decrypt && !job.recipients.is_empty() {
        let id = identity.as_ref().ok_or(Error::IdentityRequired)?;
        let mut out = Outcome::default();
        for item in &job.items {
            ops::set_recipients(
                &item.input,
                id,
                &job.recipients,
                ops::UnlockOptions::default(),
                &mut OsEntropy,
                &mut |_| {},
            )?;
            out.outputs.push(item.input.clone());
        }
        out.recipients_set = Some(job.recipients.len());
        return Ok(out);
    }
    let keyfile = job
        .keyfile
        .as_deref()
        .map(password::keyfile_digest_from_path)
        .transpose()?;
    let opts = match job.mode {
        Mode::Encrypt => {
            if !key_mode {
                let confirm = job.confirm.ok_or_else(|| {
                    Error::Environment(
                        tr("parolayı tekrar girin", "enter the password again").into(),
                    )
                })?;
                let c = password::normalize_nfc(&confirm)?;
                drop(confirm);
                if c.expose() != nfc.expose() {
                    return Err(Error::Environment(
                        tr("parolalar eşleşmiyor", "passwords do not match").into(),
                    ));
                }
                password::check_encrypt_policy(&nfc)?;
            }
            Some(EncryptOptions {
                alg: if job.aes {
                    AlgId::Aes256Gcm
                } else {
                    AlgId::XChaCha20Poly1305
                },
                chunk_code: 2,
                kdf: KdfParams {
                    m_kib: job.kdf_mib.saturating_mul(1024),
                    ..KdfParams::DEFAULT
                },
                force: false,
                strict_memory: false,
                raw: false,
                pad: Some(job.pad),
                strict: false,
                compress: job.compress,
                ecc: job.ecc,
            })
        }
        Mode::Decrypt => None,
    };
    let ctx = Ctx {
        nfc: &nfc,
        recipients: if key_mode { &job.recipients } else { &[] },
        identity: identity.as_ref(),
        kf: keyfile.as_deref(),
        opts,
        allow_cloud: job.allow_cloud,
        // Deleting needs a verification that only the recipient can do.
        secure_delete: job.secure_delete && job.mode == Mode::Encrypt && !key_mode,
        split: job.split.filter(|_| job.mode == Mode::Encrypt),
        recover: job.recover && job.mode == Mode::Decrypt,
        list_only: job.list_only && job.mode == Mode::Decrypt,
        only: if job.mode == Mode::Decrypt {
            &job.only
        } else {
            &[]
        },
    };
    let single = job.items.len() == 1;
    let mut out = Outcome::default();
    let mut first_err = None;
    for item in &job.items {
        if lephy_sys::signal::interrupted() {
            return Err(Error::Interrupted);
        }
        match run_one(&ctx, item, &mut out) {
            Ok(()) => {}
            Err(e) if single || matches!(e, Error::Interrupted) => return Err(e),
            Err(e) => {
                let name = item
                    .input
                    .file_name()
                    .map(|f| lephy_core::names::escape_display(&f.to_string_lossy()))
                    .unwrap_or_default();
                out.failed.push((name, describe_error(&e)));
                first_err.get_or_insert(e);
            }
        }
    }
    if out.outputs.is_empty()
        && let Some(e) = first_err
    {
        return Err(e);
    }
    Ok(out)
}

fn run_one(ctx: &Ctx<'_>, item: &Item, out: &mut Outcome) -> Result<()> {
    let mut log = |_: &str| {};
    let unlock = ops::UnlockOptions {
        identity: ctx.identity,
        ..ops::UnlockOptions::default()
    };
    if let Some(opts) = &ctx.opts {
        let rep = if ctx.recipients.is_empty() {
            ops::encrypt(
                &Input::Path(&item.input),
                &item.output,
                ctx.nfc,
                ctx.kf,
                opts,
                &mut OsEntropy,
                &mut log,
            )?
        } else {
            ops::encrypt_to_recipients(
                &Input::Path(&item.input),
                &item.output,
                ctx.recipients,
                opts,
                &mut OsEntropy,
                &mut log,
            )?
        };
        let written = match ctx.split {
            Some(size) => lephy_core::split::split_file(&item.output, size)?
                .into_iter()
                .next()
                .unwrap_or_else(|| item.output.clone()),
            None => item.output.clone(),
        };
        out.outputs.push(written.clone());
        out.skipped += rep.archive.as_ref().map_or(0, |a| a.skipped.len());
        if ctx.secure_delete {
            // Before deleting, the written file is verified end to end with the password.
            let u = ops::UnlockOptions {
                allow_large_kdf: true,
                strict_memory: false,
                identity: None,
            };
            ops::verify(&written, ctx.nfc, ctx.kf, u, &mut log)?;
            if let Some(a) = &rep.archive {
                let d = ops::delete_archived_with(a, true)?;
                out.deleted += 1;
                out.kept += d.kept.len();
            }
        }
    } else {
        if !ctx.allow_cloud && lephy_sys::fs::cloud_root_of(&item.output).is_some() {
            return Err(Error::Cancelled(
                tr(
                    "hedef bir bulut senkron klasöründe; devam etmek için onay kutusunu işaretleyin",
                    "the destination is in a cloud-sync folder; tick the box to continue",
                )
                .into(),
            ));
        }
        if ctx.list_only {
            let entries = ops::list(&item.input, ctx.nfc, ctx.kf, unlock, &mut log)?;
            out.listing = Some(entries);
            return Ok(());
        }
        if ctx.recover {
            let r = ops::recover(&item.input, &item.output, ctx.nfc, ctx.kf, unlock, &mut log)?;
            out.outputs.push(r.output.clone());
            out.repaired += r.repaired;
            out.damaged += r.bad_chunks.len();
            out.incomplete |= r.truncated || r.stopped.is_some();
            return Ok(());
        }
        let rep = ops::decrypt(
            &item.input,
            &Output::Path(&item.output, false),
            ctx.nfc,
            ctx.kf,
            DecryptOptions {
                unlock,
                only: (!ctx.only.is_empty()).then_some(ctx.only),
                ..DecryptOptions::default()
            },
            &mut log,
        )?;
        out.outputs.push(rep.target);
        out.repaired += rep.repaired;
        out.skipped += rep.archive.as_ref().map_or(0, |a| a.skipped.len());
    }
    Ok(())
}

/// Estimated total stream bytes for the progress percentage: the total size of the source files
/// when encrypting (symlinks not followed), the file size after the header when decrypting. 0 if unknown.
#[must_use]
pub fn estimate_total(mode: Mode, input: &Path) -> u64 {
    fn walk(p: &Path, depth: u32, acc: &mut u64) {
        let Ok(md) = std::fs::symlink_metadata(p) else {
            return;
        };
        if md.is_file() {
            *acc = acc.saturating_add(md.len());
        } else if md.is_dir()
            && depth < 256
            && let Ok(rd) = std::fs::read_dir(p)
        {
            for e in rd.flatten() {
                walk(&e.path(), depth + 1, acc);
            }
        }
    }
    match mode {
        Mode::Decrypt => {
            let total = if lephy_core::split::is_first_part(input) {
                lephy_core::split::parts(input)
                    .and_then(|p| lephy_core::split::total_len(&p))
                    .unwrap_or(0)
            } else {
                input.metadata().map_or(0, |m| m.len())
            };
            total.saturating_sub(HEADER_LEN as u64)
        }
        Mode::Encrypt => {
            let mut acc = 0;
            walk(input, 0, &mut acc);
            acc
        }
    }
}

/// Error text shown to the user: what happened and what can be done.
#[must_use]
pub fn describe_error(e: &Error) -> String {
    match (e, e.exit_code()) {
        (Error::KeyfileRequired, _) => tr(
            "Bu dosya bir anahtar dosyasıyla şifrelenmiş. Anahtar dosyasını seçin.",
            "This file was encrypted with a key file. Choose the key file.",
        )
        .into(),
        (Error::IdentityRequired, _) => tr(
            "Bu dosya bir açık anahtara şifrelenmiş. Kimlik dosyanızı (.lphykey) seçin.",
            "This file was encrypted to a public key. Choose your identity file (.lphykey).",
        )
        .into(),
        (Error::NoMatchingIdentity, _) => tr(
            "Bu dosya seçtiğiniz kimlik için şifrelenmemiş. Doğru kimlik dosyasını seçin.",
            "This file was not encrypted for the chosen identity. Choose the right identity file.",
        )
        .into(),
        (Error::Corrupt { at, .. }, _) if at == "identity file" => tr(
            "Seçilen dosya bir kimlik dosyası (.lphykey) değil.",
            "The chosen file is not an identity file (.lphykey).",
        )
        .into(),
        (Error::KeyfileNotUsed, _) => tr(
            "Bu dosya anahtar dosyası kullanmıyor. Seçili anahtar dosyasını kaldırın.",
            "This file does not use a key file. Remove the selected key file.",
        )
        .into(),
        (_, ExitCode::WrongPassword) => tr(
            "Parola yanlış. Büyük/küçük harf ve klavye düzenini kontrol edip yeniden deneyin.",
            "Wrong password. Check upper/lower case and the keyboard layout, then try again.",
        )
        .into(),
        (_, ExitCode::Corrupt) => tr(
            "Dosya bozuk ya da değiştirilmiş; içeriği güvenle açılamıyor.",
            "The file is damaged or was modified; its contents cannot be opened safely.",
        )
        .into(),
        (_, ExitCode::Exists) => tr(
            "Kayıt yerinde aynı adla bir dosya var. Başka bir kayıt yeri seçin.",
            "A file with the same name already exists there. Choose another location.",
        )
        .into(),
        (_, ExitCode::DiskSpace) => tr(
            "Diskte yeterli boş alan yok.",
            "There is not enough free disk space.",
        )
        .into(),
        (_, ExitCode::KdfBudget) => tr(
            "Bu ayar için bellek yetmiyor. Gelişmiş ayarlardan bellek miktarını düşürün.",
            "Not enough memory for this setting. Lower the memory in the advanced settings.",
        )
        .into(),
        (_, ExitCode::Interrupted) => tr(
            "İşlem durduruldu. Yarım kalan dosya silindi.",
            "Stopped. The partial file was removed.",
        )
        .into(),
        _ => sentence(&e.to_string()),
    }
}

/// Capitalises the first letter and adds a full stop.
fn sentence(s: &str) -> String {
    let mut c = s.trim().chars();
    let mut out: String = c
        .next()
        .map(|f| f.to_uppercase().collect())
        .unwrap_or_default();
    out.push_str(c.as_str());
    if !out.ends_with(['.', '!', '?']) {
        out.push('.');
    }
    out
}

/// Short information about a source: (display name, description).
#[must_use]
pub fn describe_source(path: &Path, mode: Mode) -> (String, String) {
    let name = path.file_name().map_or_else(
        || lephy_core::names::escape_display(&path.display().to_string()),
        |f| lephy_core::names::escape_display(&f.to_string_lossy()),
    );
    let md = path.metadata().ok();
    let detail = match (mode, md) {
        (_, Some(m)) if m.is_dir() => tr("Klasör", "Folder").to_string(),
        (Mode::Decrypt, Some(m)) => format!(
            "{}, {}",
            tr("Şifreli dosya", "Encrypted file"),
            human_size(m.len())
        ),
        (Mode::Encrypt, Some(m)) => human_size(m.len()),
        (_, None) => tr("Okunamıyor", "Cannot be read").to_string(),
    };
    (name, detail)
}

/// Information from the encrypted file's header that can be read without a password (one line).
/// `None` if the header cannot be read.
#[must_use]
pub fn header_summary(path: &Path) -> Option<String> {
    let h = ops::info(path).ok()?;
    let kind = match h.content_type {
        lephy_core::header::ContentType::Archive => tr("arşiv", "archive"),
        lephy_core::header::ContentType::Raw => tr("ham akış", "raw stream"),
    };
    let mut out = if h.recipients > 0 {
        match crate::i18n::lang() {
            crate::i18n::Lang::Tr => format!(
                "{}, açık anahtar ({} alıcı), {kind}",
                h.alg.name(),
                h.recipients
            ),
            crate::i18n::Lang::En => format!(
                "{}, public key ({} recipients), {kind}",
                h.alg.name(),
                h.recipients
            ),
        }
    } else {
        format!(
            "{}, Argon2id {} MiB, {kind}",
            h.alg.name(),
            h.kdf.memory_mib()
        )
    };
    if h.compressed {
        out.push_str(tr(", sıkıştırılmış", ", compressed"));
    }
    if ops::has_error_correction(path) {
        out.push_str(tr(", hata düzeltmeli", ", error correction"));
    }
    if h.padded {
        out.push_str(tr(", boyut gizli", ", size hidden"));
    }
    if h.keyfile {
        out.push_str(tr(", anahtar dosyası gerekli", ", key file required"));
    }
    Some(out)
}

/// Human-readable size (decimal comma in Turkish).
#[must_use]
#[allow(clippy::cast_precision_loss)]
pub fn human_size(n: u64) -> String {
    const UNITS: [&str; 5] = ["", "KB", "MB", "GB", "TB"];
    let tr_lang = crate::i18n::lang() == crate::i18n::Lang::Tr;
    if n < 1000 {
        return format!("{n} {}", tr("bayt", "bytes"));
    }
    let mut v = n as f64;
    let mut u = 0;
    while v >= 1000.0 && u < UNITS.len() - 1 {
        v /= 1000.0;
        u += 1;
    }
    let s = if v < 10.0 {
        format!("{v:.1}")
    } else {
        format!("{v:.0}")
    };
    let s = if tr_lang { s.replace('.', ",") } else { s };
    format!("{s} {}", UNITS[u])
}

/// Shortens a folder path: the home directory becomes `~`.
#[must_use]
pub fn short_dir(dir: &Path) -> String {
    let home = home_dir();
    match home.as_deref().and_then(|h| dir.strip_prefix(h).ok()) {
        Some(rest) if rest.as_os_str().is_empty() => "~".to_string(),
        Some(rest) => format!("~{}{}", std::path::MAIN_SEPARATOR, rest.display()),
        None => dir.display().to_string(),
    }
}

/// Home directory (no environment variable is read; `std::env::home_dir`).
fn home_dir() -> Option<PathBuf> {
    std::env::home_dir().filter(|h| h.is_absolute())
}

/// Shows it in the file manager (macOS Finder, Windows Explorer). Tools are called by absolute path.
///
/// # Errors
/// The tool could not be started.
pub fn reveal_in_folder(path: &Path) -> std::io::Result<()> {
    #[cfg(target_os = "macos")]
    {
        std::process::Command::new("/usr/bin/open")
            .arg("-R")
            .arg(path)
            .env_clear()
            .spawn()
            .map(drop)
    }
    #[cfg(windows)]
    {
        let sys = lephy_sys::vol::win::system_directory()?;
        let explorer = sys
            .parent()
            .map_or_else(|| sys.join("explorer.exe"), |w| w.join("explorer.exe"));
        let mut arg = std::ffi::OsString::from("/select,");
        arg.push(path);
        // The environment is not inherited (DLL search path etc.); the one variable Explorer needs is passed back.
        let mut cmd = std::process::Command::new(explorer);
        cmd.arg(arg).env_clear();
        if let Some(root) = sys.parent() {
            cmd.env("SystemRoot", root);
        }
        cmd.spawn().map(drop)
    }
    #[cfg(not(any(target_os = "macos", windows)))]
    {
        let _ = path;
        Err(std::io::Error::other("desteklenmiyor"))
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::too_many_lines)]
mod tests {
    use super::*;

    fn secret(s: &str) -> SecretBytes {
        SecretBytes::from_slice(s.as_bytes()).unwrap()
    }

    #[test]
    fn mode_and_default_output() {
        let d = std::env::temp_dir().join(format!("lphy-gui-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(d.join("klasor")).unwrap();
        std::fs::write(d.join("a.txt"), b"hello").unwrap();
        assert_eq!(detect_mode(&d.join("a.txt")), Mode::Encrypt);
        assert_eq!(detect_mode(&d.join("klasor")), Mode::Encrypt);
        let out = default_output(&d.join("a.txt"), Mode::Encrypt);
        let name = out.file_name().unwrap().to_string_lossy().into_owned();
        assert_eq!(out.extension().and_then(|e| e.to_str()), Some("lphy"));
        assert_eq!(name.len(), 13, "{name}");
        assert!(
            !name.contains("a.txt"),
            "çıktı adı kaynak adını sızdırmamalı"
        );
        let job = Job {
            list_only: false,
            only: Vec::new(),
            mode: Mode::Encrypt,
            items: vec![Item {
                input: d.join("a.txt"),
                output: d.join("x.lphy"),
            }],
            password: secret("gui parola 1234"),
            confirm: Some(secret("gui parola 1234")),
            kdf_mib: 64,
            aes: false,
            pad: true,
            allow_cloud: false,
            keyfile: None,
            secure_delete: false,
            split: None,
            compress: false,
            ecc: false,
            recover: false,
            recipients: Vec::new(),
            identity: None,
        };
        run(job).unwrap();
        assert_eq!(detect_mode(&d.join("x.lphy")), Mode::Decrypt);
        assert_eq!(
            estimate_total(Mode::Encrypt, &d),
            5 + std::fs::metadata(d.join("x.lphy")).unwrap().len()
        );
        assert!(estimate_total(Mode::Decrypt, &d.join("x.lphy")) > 0);
        assert!(
            lephy_core::pipeline::progress() > 0,
            "the pipeline must count progress"
        );
        assert_eq!(
            default_output(&d.join("x.lphy"), Mode::Decrypt),
            d.join("x")
        );
        let job = Job {
            list_only: false,
            only: Vec::new(),
            mode: Mode::Decrypt,
            items: vec![Item {
                input: d.join("x.lphy"),
                output: d.join("geri.txt"),
            }],
            password: secret("gui parola 1234"),
            confirm: None,
            kdf_mib: 0,
            aes: false,
            pad: true,
            allow_cloud: false,
            keyfile: None,
            secure_delete: false,
            split: None,
            compress: false,
            ecc: false,
            recover: false,
            recipients: Vec::new(),
            identity: None,
        };
        let out = run(job).unwrap();
        assert_eq!(out.outputs, vec![d.join("geri.txt")]);
        assert_eq!(out.skipped, 0);
        assert_eq!(std::fs::read(d.join("geri.txt")).unwrap(), b"hello");
        // Mismatched repeat and a short password
        for (p, c) in [("gui parola 1234", "başka parola 99"), ("kisa", "kisa")] {
            let job = Job {
                list_only: false,
                only: Vec::new(),
                mode: Mode::Encrypt,
                items: vec![Item {
                    input: d.join("a.txt"),
                    output: d.join("y.lphy"),
                }],
                password: secret(p),
                confirm: Some(secret(c)),
                kdf_mib: 64,
                aes: true,
                pad: false,
                allow_cloud: false,
                keyfile: None,
                secure_delete: false,
                split: None,
                compress: false,
                ecc: false,
                recover: false,
                recipients: Vec::new(),
                identity: None,
            };
            let e = run(job).unwrap_err();
            assert_eq!(e.exit_code(), ExitCode::Io);
            assert!(describe_error(&e).ends_with('.'));
        }
        // Wrong password → code 3
        let job = Job {
            list_only: false,
            only: Vec::new(),
            mode: Mode::Decrypt,
            items: vec![Item {
                input: d.join("x.lphy"),
                output: d.join("z.txt"),
            }],
            password: secret("yanlış parola 1"),
            confirm: None,
            kdf_mib: 0,
            aes: false,
            pad: true,
            allow_cloud: false,
            keyfile: None,
            secure_delete: false,
            split: None,
            compress: false,
            ecc: false,
            recover: false,
            recipients: Vec::new(),
            identity: None,
        };
        let e = run(job).unwrap_err();
        assert_eq!(e.exit_code(), ExitCode::WrongPassword);
        assert!(describe_error(&e).starts_with("Parola yanlış"));
        let _ = std::fs::remove_dir_all(&d);
    }

    #[test]
    fn list_then_extract_selected() {
        let d = std::env::temp_dir().join(format!("lphy-gui-list-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(d.join("src/sub")).unwrap();
        std::fs::write(d.join("src/a.txt"), b"a").unwrap();
        std::fs::write(d.join("src/sub/b.txt"), b"b").unwrap();
        let job = |mode, input: &str, output: &str, list_only, only: Vec<String>| Job {
            list_only,
            only,
            mode,
            items: vec![Item {
                input: d.join(input),
                output: d.join(output),
            }],
            password: secret("list pass 123"),
            confirm: (mode == Mode::Encrypt).then(|| secret("list pass 123")),
            kdf_mib: 64,
            aes: false,
            pad: true,
            allow_cloud: true,
            keyfile: None,
            secure_delete: false,
            split: None,
            compress: false,
            ecc: false,
            recover: false,
            recipients: Vec::new(),
            identity: None,
        };
        run(job(Mode::Encrypt, "src", "s.lphy", false, Vec::new())).unwrap();
        let out = run(job(Mode::Decrypt, "s.lphy", "unused", true, Vec::new())).unwrap();
        let paths: Vec<String> = out.listing.unwrap().into_iter().map(|e| e.path).collect();
        assert_eq!(paths, ["a.txt", "sub", "sub/b.txt"]);
        assert!(!d.join("unused").exists(), "listing writes nothing");
        run(job(
            Mode::Decrypt,
            "s.lphy",
            "back",
            false,
            vec!["sub".into()],
        ))
        .unwrap();
        assert_eq!(std::fs::read(d.join("back/sub/b.txt")).unwrap(), b"b");
        assert!(!d.join("back/a.txt").exists());
        let _ = std::fs::remove_dir_all(&d);
    }

    #[test]
    fn replace_recipients_from_the_app() {
        let d = std::env::temp_dir().join(format!("lphy-gui-rcp-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        std::fs::write(d.join("m.txt"), b"shared").unwrap();
        let pa = create_identity(&d.join("a.lphykey"), &secret("identity pass a"), 64).unwrap();
        let pb = create_identity(&d.join("b.lphykey"), &secret("identity pass b"), 64).unwrap();
        let job = |mode, input: &str, output: &str, keys: &str, id: Option<&str>, pw: &str| Job {
            list_only: false,
            only: Vec::new(),
            mode,
            items: vec![Item {
                input: d.join(input),
                output: d.join(output),
            }],
            password: secret(pw),
            confirm: None,
            kdf_mib: 64,
            aes: false,
            pad: true,
            allow_cloud: true,
            keyfile: None,
            secure_delete: false,
            split: None,
            compress: false,
            ecc: false,
            recover: false,
            recipients: parse_recipients(keys).unwrap(),
            identity: id.map(|i| d.join(i)),
        };
        run(job(Mode::Encrypt, "m.txt", "m.lphy", &pa, None, "")).unwrap();
        // A replaces the list with B only.
        let out = run(job(
            Mode::Decrypt,
            "m.lphy",
            "x",
            &pb,
            Some("a.lphykey"),
            "identity pass a",
        ))
        .unwrap();
        assert_eq!(out.recipients_set, Some(1));
        assert!(!d.join("x").exists(), "nothing is extracted");
        run(job(
            Mode::Decrypt,
            "m.lphy",
            "by-b",
            "",
            Some("b.lphykey"),
            "identity pass b",
        ))
        .unwrap();
        assert_eq!(std::fs::read(d.join("by-b")).unwrap(), b"shared");
        assert!(
            run(job(
                Mode::Decrypt,
                "m.lphy",
                "by-a",
                "",
                Some("a.lphykey"),
                "identity pass a"
            ))
            .is_err()
        );
        let _ = std::fs::remove_dir_all(&d);
    }

    #[test]
    fn recipients_and_identity_roundtrip() {
        let d = std::env::temp_dir().join(format!("lphy-gui-keys-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        std::fs::write(d.join("a.txt"), b"for my friend").unwrap();
        let pk = create_identity(&d.join("me.lphykey"), &secret("identity pass 1"), 64).unwrap();
        assert!(d.join("me.pub").exists());
        // An existing identity is never overwritten.
        assert!(create_identity(&d.join("me.lphykey"), &secret("identity pass 1"), 64).is_err());
        let keys = parse_recipients(&format!("# me\n{pk}\n{pk}\n")).unwrap();
        assert_eq!(keys.len(), 1);
        assert!(parse_recipients("lphy1nope").is_err());
        let base = |mode, input: &str, output: &str| Job {
            list_only: false,
            only: Vec::new(),
            mode,
            items: vec![Item {
                input: d.join(input),
                output: d.join(output),
            }],
            password: secret(""),
            confirm: None,
            kdf_mib: 64,
            aes: false,
            pad: true,
            allow_cloud: true,
            keyfile: None,
            secure_delete: true,
            split: None,
            compress: false,
            ecc: false,
            recover: false,
            recipients: Vec::new(),
            identity: None,
        };
        let mut enc = base(Mode::Encrypt, "a.txt", "x.lphy");
        enc.recipients.clone_from(&keys);
        run(enc).unwrap();
        // Secure delete is skipped: it needs a verification only the recipient can do.
        assert!(d.join("a.txt").exists());
        assert!(needs_identity(&d.join("x.lphy")));
        assert!(header_summary(&d.join("x.lphy")).unwrap().contains('1'));
        let mut dec = base(Mode::Decrypt, "x.lphy", "back.txt");
        assert!(matches!(run(dec), Err(Error::IdentityRequired)));
        dec = base(Mode::Decrypt, "x.lphy", "back.txt");
        dec.identity = Some(d.join("me.lphykey"));
        dec.password = secret("wrong password");
        assert!(matches!(run(dec), Err(Error::WrongPassword)));
        dec = base(Mode::Decrypt, "x.lphy", "back.txt");
        dec.identity = Some(d.join("me.lphykey"));
        dec.password = secret("identity pass 1");
        run(dec).unwrap();
        assert_eq!(std::fs::read(d.join("back.txt")).unwrap(), b"for my friend");
        let _ = std::fs::remove_dir_all(&d);
    }

    #[test]
    fn batch_continues_after_a_failure_and_secure_delete_removes_originals() {
        let d = std::env::temp_dir().join(format!("lphy-gui-batch-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(d.join("out")).unwrap();
        std::fs::write(d.join("a.txt"), b"a").unwrap();
        std::fs::write(d.join("b.txt"), b"b").unwrap();
        let item = |name: &str, out: &str| Item {
            input: d.join(name),
            output: d.join("out").join(out),
        };
        let job = Job {
            list_only: false,
            only: Vec::new(),
            mode: Mode::Encrypt,
            items: vec![
                item("a.txt", "1.lphy"),
                item("yok.txt", "2.lphy"),
                item("b.txt", "3.lphy"),
            ],
            password: secret("toplu parola 1234"),
            confirm: Some(secret("toplu parola 1234")),
            kdf_mib: 64,
            aes: false,
            pad: true,
            allow_cloud: false,
            keyfile: None,
            secure_delete: true,
            split: None,
            compress: false,
            ecc: false,
            recover: false,
            recipients: Vec::new(),
            identity: None,
        };
        let out = run(job).unwrap();
        assert_eq!(out.outputs.len(), 2);
        assert_eq!(out.failed.len(), 1, "{:?}", out.failed);
        assert_eq!(out.deleted, 2);
        assert!(!d.join("a.txt").exists() && !d.join("b.txt").exists());
        // If all fail, an error is returned.
        let job = Job {
            list_only: false,
            only: Vec::new(),
            mode: Mode::Encrypt,
            items: vec![item("yok1", "4.lphy"), item("yok2", "5.lphy")],
            password: secret("toplu parola 1234"),
            confirm: Some(secret("toplu parola 1234")),
            kdf_mib: 64,
            aes: false,
            pad: true,
            allow_cloud: false,
            keyfile: None,
            secure_delete: false,
            split: None,
            compress: false,
            ecc: false,
            recover: false,
            recipients: Vec::new(),
            identity: None,
        };
        assert!(run(job).is_err());
        let _ = std::fs::remove_dir_all(&d);
    }

    #[test]
    fn split_output_roundtrip() {
        let d = std::env::temp_dir().join(format!("lphy-gui-split-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        let data: Vec<u8> = (0..3_500_000u32).map(|i| (i % 253) as u8).collect();
        std::fs::write(d.join("a.bin"), &data).unwrap();
        let mk = |mode, input: &str, output: &str, split| Job {
            list_only: false,
            only: Vec::new(),
            mode,
            items: vec![Item {
                input: d.join(input),
                output: d.join(output),
            }],
            password: secret("bolme parola 1234"),
            confirm: (mode == Mode::Encrypt).then(|| secret("bolme parola 1234")),
            kdf_mib: 64,
            aes: false,
            pad: false,
            allow_cloud: false,
            keyfile: None,
            secure_delete: false,
            split,
            compress: false,
            ecc: false,
            recover: false,
            recipients: Vec::new(),
            identity: None,
        };
        let out = run(mk(Mode::Encrypt, "a.bin", "s.lphy", Some(1024 * 1024))).unwrap();
        assert_eq!(out.outputs, vec![d.join("s.lphy.001")]);
        assert!(d.join("s.lphy.004").exists() && !d.join("s.lphy").exists());
        assert_eq!(detect_mode(&d.join("s.lphy.001")), Mode::Decrypt);
        assert_eq!(
            default_output(&d.join("s.lphy.001"), Mode::Decrypt),
            d.join("s")
        );
        assert!(estimate_total(Mode::Decrypt, &d.join("s.lphy.001")) > 3_000_000);
        run(mk(Mode::Decrypt, "s.lphy.001", "geri.bin", None)).unwrap();
        assert_eq!(std::fs::read(d.join("geri.bin")).unwrap(), data);
        let _ = std::fs::remove_dir_all(&d);
    }

    #[test]
    fn keyfile_roundtrip() {
        let d = std::env::temp_dir().join(format!("lphy-gui-kf-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        std::fs::write(d.join("a.txt"), b"anahtar dosyasi testi").unwrap();
        std::fs::write(d.join("key.bin"), [7u8; 64]).unwrap();
        let job = |mode, input: &str, output: &str, kf: bool| Job {
            list_only: false,
            only: Vec::new(),
            mode,
            items: vec![Item {
                input: d.join(input),
                output: d.join(output),
            }],
            password: secret("gui parola 1234"),
            confirm: (mode == Mode::Encrypt).then(|| secret("gui parola 1234")),
            kdf_mib: 64,
            aes: false,
            pad: true,
            allow_cloud: false,
            keyfile: kf.then(|| d.join("key.bin")),
            secure_delete: false,
            split: None,
            compress: false,
            ecc: false,
            recover: false,
            recipients: Vec::new(),
            identity: None,
        };
        run(job(Mode::Encrypt, "a.txt", "k.lphy", true)).unwrap();
        assert!(needs_keyfile(&d.join("k.lphy")));
        let e = run(job(Mode::Decrypt, "k.lphy", "x.txt", false)).unwrap_err();
        assert!(describe_error(&e).contains("anahtar dosyasıyla"), "{e}");
        assert!(!d.join("x.txt").exists());
        run(job(Mode::Decrypt, "k.lphy", "geri.txt", true)).unwrap();
        assert_eq!(
            std::fs::read(d.join("geri.txt")).unwrap(),
            b"anahtar dosyasi testi"
        );
        let _ = std::fs::remove_dir_all(&d);
    }

    #[test]
    fn sizes_and_sentences() {
        assert_eq!(human_size(0), "0 bayt");
        assert_eq!(human_size(999), "999 bayt");
        assert_eq!(human_size(2_400_000), "2,4 MB");
        assert_eq!(human_size(54_000_000_000), "54 GB");
        assert_eq!(sentence("hedef var"), "Hedef var.");
        assert_eq!(sentence("İşlem bitti."), "İşlem bitti.");
    }
}
