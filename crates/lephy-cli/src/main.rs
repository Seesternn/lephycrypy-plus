//! `lephycrypy` komut satırı (aşama 1: tek dosya / stdin, `content_type = 0`).
//!
//! Çıkış kodları PLAN › Çıkış kodu tablosu; kod 2 yalnızca clap. Parola argv/env'den asla
//! okunmaz (D3). Süreç başı: `harden()` → panik hook'u → sinyal işleyici → clap →
//! (macOS release) `PT_DENY_ATTACH`.

#![forbid(unsafe_code)]

// R5-02: `test-vectors` feature'ı ile derlenen bir çekirdek ikiliye asla giremez.
const _: () = assert!(
    !lephy_core::TEST_VECTORS_ENABLED,
    "lephy-cli, lephy-core/test-vectors feature'ı ile derlenemez (PLAN R5-02)"
);

use std::path::{Path, PathBuf};
use std::process::ExitCode as ProcessExit;

use clap::{Args, Parser, Subcommand, ValueEnum};
use lephy_core::cipher::AlgId;
use lephy_core::entropy::OsEntropy;
use lephy_core::error::{Error, ExitCode, Result};
use lephy_core::kdf::KdfParams;
use lephy_core::ops::{self, EncryptOptions, Input, NewCredentials, Output, UnlockOptions};
use lephy_core::password::{self, Source};
use lephy_sys::mem::SecretBytes;

#[derive(Parser)]
#[command(
    name = "lephycrypy",
    version,
    about = "lephycrypy+ — parolayla dosya/klasör şifreleme",
    after_help = "Çıkış kodları: 0 başarı · 1 G/Ç/ortam · 2 kullanım · 3 parola/keyfile yanlış · \
                  4 dosya bozuk · 5 iptal · 6 KDF bütçesi · 7 hedef var · 8 disk alanı · 130 kesinti"
)]
struct Cli {
    /// Ayrıntılı ilerleme ve hata nedenleri (sır içermez).
    #[arg(long, global = true)]
    verbose: bool,
    /// macOS: `PT_DENY_ATTACH` uygulanmaz (yalnızca yerel imzasız derlemede işe yarar).
    #[arg(long, global = true, hide = true)]
    allow_debugger: bool,
    #[command(subcommand)]
    command: Command,
}

/// Parola kaynağı seçenekleri (birbirini dışlar; hiçbiri yoksa terminal).
#[derive(Args, Clone)]
struct PasswordArgs {
    /// Parolayı stdin'den EOF'a kadar oku (stdin terminal olamaz; giriş de stdin olamaz).
    #[arg(long, conflicts_with_all = ["password_fd", "password_file"])]
    password_stdin: bool,
    /// Parolayı verilen dosya tanıtıcısından oku (yalnızca Unix).
    #[cfg(unix)]
    #[arg(long, value_name = "N", conflicts_with = "password_file")]
    password_fd: Option<i32>,
    /// Parolayı dosyadan ya da isimli pipe'tan oku (diskte düz metin kalır; tmpfs/pipe önerilir).
    #[arg(long, value_name = "YOL")]
    password_file: Option<PathBuf>,
    /// Anahtar dosyası (32 B..1 MiB; içeriği türetmeye girer).
    #[arg(long, value_name = "YOL")]
    keyfile: Option<PathBuf>,
}

/// Yeni kimlik bilgileri (rekey/reencrypt).
#[derive(Args, Clone)]
#[allow(clippy::struct_field_names)]
struct NewPasswordArgs {
    /// Yeni parolayı dosyadan ya da isimli pipe'tan oku.
    #[arg(long, value_name = "YOL")]
    new_password_file: Option<PathBuf>,
    /// Yeni parolayı verilen fd'den oku (yalnızca Unix).
    #[cfg(unix)]
    #[arg(long, value_name = "N", conflicts_with = "new_password_file")]
    new_password_fd: Option<i32>,
    /// Yeni anahtar dosyası.
    #[arg(long, value_name = "YOL")]
    new_keyfile: Option<PathBuf>,
}

#[derive(Args, Clone, Copy)]
#[allow(clippy::struct_field_names)]
struct KdfArgs {
    /// Argon2id belleği (MiB), en az 64.
    #[arg(long, value_name = "MiB", default_value_t = 512)]
    kdf_memory: u32,
    /// Argon2id yineleme (1..64).
    #[arg(long, value_name = "T", default_value_t = 3)]
    kdf_time: u32,
    /// Argon2id paralellik (1..64).
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

#[derive(Clone, Copy, ValueEnum)]
enum Alg {
    /// XChaCha20-Poly1305 (varsayılan).
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

#[derive(Subcommand)]
enum Command {
    /// Dosyayı (ya da "-" ile stdin'i) şifreler.
    Encrypt {
        /// Kaynak dosya ("-" = stdin).
        input: PathBuf,
        /// Çıktı yolu (varsayılan: <8 rastgele hex>.lphy).
        #[arg(short, long, value_name = "YOL")]
        output: Option<PathBuf>,
        /// Algoritma.
        #[arg(long, value_enum, default_value = "xchacha20")]
        alg: Alg,
        /// Chunk boyutu.
        #[arg(long, value_enum, default_value = "1m")]
        chunk_size: ChunkSize,
        #[command(flatten)]
        kdf: KdfArgs,
        #[command(flatten)]
        pw: PasswordArgs,
        /// Hedef varsa üzerine yaz.
        #[arg(long)]
        force: bool,
        /// Bellek kilitlenemezse hata ver.
        #[arg(long)]
        strict_memory: bool,
        /// Şifreleme + doğrulama + fsync sonrası orijinali sil (kalıntı uyarısı).
        #[arg(long)]
        delete_original: bool,
    },
    /// `.lphy` dosyasını çözer.
    Decrypt {
        /// Şifreli dosya.
        input: PathBuf,
        /// Çıktı yolu (varsayılan: giriş adından `.lphy` kaldırılmış ya da `<giriş>.out`).
        #[arg(short, long, value_name = "YOL", conflicts_with = "stdout")]
        output: Option<PathBuf>,
        /// Düz metni stdout'a yaz (son chunk doğrulanana kadar kesme tespit edilemez).
        #[arg(long)]
        stdout: bool,
        #[command(flatten)]
        pw: PasswordArgs,
        /// Hedef varsa üzerine yaz.
        #[arg(long)]
        force: bool,
        /// KDF bütçesi aşımına izin ver (RAM eşiği yine uygulanır).
        #[arg(long)]
        allow_large_kdf: bool,
        /// Bellek kilitlenemezse hata ver.
        #[arg(long)]
        strict_memory: bool,
    },
    /// Dosyayı yazmadan doğrular.
    Verify {
        /// Şifreli dosya.
        input: PathBuf,
        #[command(flatten)]
        pw: PasswordArgs,
        /// KDF bütçesi aşımına izin ver.
        #[arg(long)]
        allow_large_kdf: bool,
        /// Bellek kilitlenemezse hata ver.
        #[arg(long)]
        strict_memory: bool,
    },
    /// Açık başlık meta verisini gösterir (KDF çalıştırmaz).
    Info {
        /// Şifreli dosya.
        input: PathBuf,
    },
    /// Parolayı değiştirir; dosya anahtarı (FK) değişmez — gerçek rotasyon için `reencrypt`.
    Rekey {
        /// Şifreli dosya (yerinde, atomik).
        input: PathBuf,
        #[command(flatten)]
        pw: PasswordArgs,
        #[command(flatten)]
        new: NewPasswordArgs,
        /// Yeni KDF parametreleri (verilmezse eski başlıktaki).
        #[arg(long, value_name = "MiB")]
        kdf_memory: Option<u32>,
        /// Sonucu tam doğrula.
        #[arg(long)]
        verify: bool,
        /// KDF bütçesi aşımına izin ver.
        #[arg(long)]
        allow_large_kdf: bool,
        /// Bellek kilitlenemezse hata ver.
        #[arg(long)]
        strict_memory: bool,
    },
    /// Yeni dosya anahtarı ile tüm chunk'ları yeniden şifreler (yerinde, atomik).
    Reencrypt {
        /// Şifreli dosya.
        input: PathBuf,
        #[command(flatten)]
        pw: PasswordArgs,
        #[command(flatten)]
        new: NewPasswordArgs,
        /// KDF bütçesi aşımına izin ver.
        #[arg(long)]
        allow_large_kdf: bool,
        /// Bellek kilitlenemezse hata ver.
        #[arg(long)]
        strict_memory: bool,
    },
    /// Bir dizindeki bayat `.lphy-tmp-*` dosyalarını onayla siler.
    Cleanup {
        /// Taranacak dizin.
        dir: PathBuf,
        /// Onay istemeden sil (non-tty için).
        #[arg(long)]
        yes: bool,
    },
}

fn main() -> ProcessExit {
    // Hiçbir sır oluşmadan: sertleştirme, panik hook'u, sinyal işleyici (PLAN › Süreç başı).
    if let Err(e) = lephy_sys::platform::harden() {
        eprintln!("uyarı: süreç sertleştirme kısmen başarısız: {e}");
    }
    lephy_sys::platform::install_panic_hook();
    if let Err(e) = lephy_sys::signal::install() {
        eprintln!("uyarı: sinyal işleyici kurulamadı: {e}");
    }

    let cli = Cli::parse();
    if cfg!(all(target_os = "macos", not(debug_assertions))) && !cli.allow_debugger {
        let _ = lephy_sys::platform::deny_debugger();
    }

    let verbose = cli.verbose;
    let mut log = |m: &str| {
        if verbose || m.starts_with("uyarı") {
            eprintln!("{m}");
        }
    };
    let code = match run(&cli.command, &mut log) {
        Ok(()) => ExitCode::Ok,
        Err(e) => {
            if matches!(e, Error::Interrupted) {
                eprintln!("\nkesildi");
            } else {
                eprintln!("hata: {e}");
            }
            if let (true, Some(d)) = (cli.verbose, e.detail()) {
                eprintln!("ayrıntı: {d}");
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
            "bellek kilitlenemedi ({}); sırlar swap'a düşebilir",
            lephy_sys::mem::last_lock_error().unwrap_or_default()
        );
        if strict {
            return Err(Error::Environment(format!("--strict-memory: {msg}")));
        }
        eprintln!("uyarı: {msg}");
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

/// Parolayı okur, NFC'ye çevirir; `confirm` ile terminalde iki kez sorar (D2).
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
        let raw2 = password::read_raw(source, "Parola (tekrar): ", input_is_stdin)?;
        let nfc2 = password::normalize_nfc(&raw2)?;
        if nfc.expose() != nfc2.expose() {
            return Err(Error::Environment("parolalar eşleşmiyor".into()));
        }
    }
    Ok(nfc)
}

fn keyfile_of(path: Option<&PathBuf>) -> Result<Option<[u8; 32]>> {
    path.map(|p| password::keyfile_digest_from_path(p))
        .transpose()
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

fn escape_for_display(s: &str) -> String {
    // C6: kontrol, ANSI, bidi ve format karakterleri `\u{…}` olarak.
    s.chars()
        .map(|c| {
            let cp = c as u32;
            let bidi = (0x202A..=0x202E).contains(&cp) || (0x2066..=0x2069).contains(&cp);
            if c.is_control() || bidi || (0x200B..=0x200F).contains(&cp) || cp == 0xFEFF {
                format!("\\u{{{cp:x}}}")
            } else {
                c.to_string()
            }
        })
        .collect()
}

#[allow(clippy::too_many_lines)]
fn run(cmd: &Command, log: &mut dyn FnMut(&str)) -> Result<()> {
    match cmd {
        Command::Encrypt {
            input,
            output,
            alg,
            chunk_size,
            kdf,
            pw,
            force,
            strict_memory,
            delete_original,
        } => {
            let is_stdin = input.as_os_str() == "-";
            if *delete_original && is_stdin {
                return Err(Error::Environment(
                    "--delete-original stdin ile kullanılamaz".into(),
                ));
            }
            let kdf = kdf.params();
            kdf.check_encrypt_policy()?;
            let out = match output {
                Some(o) => o.clone(),
                None => default_output_name()?,
            };
            if let Some(o) = output
                && let (Some(src), Some(dst)) = (input.file_name(), o.file_name())
            {
                let (s, d) = (src.to_string_lossy(), dst.to_string_lossy());
                if !is_stdin && d.contains(&*s) {
                    log(&format!(
                        "bilgi: çıktı adı kaynak adını içeriyor ({})",
                        escape_for_display(&d)
                    ));
                }
            }
            let keyfile = keyfile_of(pw.keyfile.as_ref())?;
            let source = source_of(pw);
            let nfc = read_password(&source, "Parola: ", true, is_stdin)?;
            password::check_encrypt_policy(&nfc)?;
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
            };
            let inp = if is_stdin {
                Input::Stdin
            } else {
                Input::Path(input)
            };
            let rep = ops::encrypt(
                &inp,
                &out,
                &nfc,
                keyfile.as_ref(),
                &opts,
                &mut OsEntropy,
                log,
            )?;
            if rep.noclobber_fallback {
                eprintln!(
                    "uyarı: dosya sistemi atomik noclobber desteklemiyor; kontrol-sonra-rename kullanıldı"
                );
            }
            log(&format!(
                "{} bayt şifrelendi → {}",
                rep.plain_len,
                escape_for_display(&out.display().to_string())
            ));
            if *delete_original {
                let u = UnlockOptions {
                    allow_large_kdf: true,
                    strict_memory: *strict_memory,
                };
                ops::verify(&out, &nfc, keyfile.as_ref(), u, log)?;
                if let Some(d) = out.parent() {
                    let _ = lephy_sys::fs::fsync_dir(if d.as_os_str().is_empty() {
                        Path::new(".")
                    } else {
                        d
                    });
                }
                std::fs::remove_file(input)?;
                eprintln!(
                    "uyarı: orijinal silindi; disk/snapshot/VSS/bulut sürüm geçmişinde kalıntı olabilir"
                );
            }
            Ok(())
        }
        Command::Decrypt {
            input,
            output,
            stdout,
            pw,
            force,
            allow_large_kdf,
            strict_memory,
        } => {
            let keyfile = keyfile_of(pw.keyfile.as_ref())?;
            let source = source_of(pw);
            let nfc = read_password(&source, "Parola: ", false, false)?;
            memory_warning(*strict_memory)?;
            let u = UnlockOptions {
                allow_large_kdf: *allow_large_kdf,
                strict_memory: *strict_memory,
            };
            if *stdout {
                eprintln!(
                    "uyarı: --stdout: son chunk doğrulanana kadar kesme tespit edilemez; çıktı kısmen yazılmış olabilir"
                );
                let n = ops::decrypt(input, &Output::Stdout, &nfc, keyfile.as_ref(), u, log)?;
                log(&format!("{n} bayt çözüldü (stdout)"));
                return Ok(());
            }
            let out = output.clone().unwrap_or_else(|| {
                let s = input
                    .file_name()
                    .map(|f| f.to_string_lossy().into_owned())
                    .unwrap_or_default();
                let base = s
                    .strip_suffix(".lphy")
                    .map_or_else(|| format!("{s}.out"), str::to_string);
                input.with_file_name(base)
            });
            let n = ops::decrypt(
                input,
                &Output::Path(&out, *force),
                &nfc,
                keyfile.as_ref(),
                u,
                log,
            )?;
            log(&format!(
                "{n} bayt çözüldü → {}",
                escape_for_display(&out.display().to_string())
            ));
            Ok(())
        }
        Command::Verify {
            input,
            pw,
            allow_large_kdf,
            strict_memory,
        } => {
            let keyfile = keyfile_of(pw.keyfile.as_ref())?;
            let source = source_of(pw);
            let nfc = read_password(&source, "Parola: ", false, false)?;
            memory_warning(*strict_memory)?;
            let u = UnlockOptions {
                allow_large_kdf: *allow_large_kdf,
                strict_memory: *strict_memory,
            };
            let n = ops::verify(input, &nfc, keyfile.as_ref(), u, log)?;
            println!("doğrulandı: {n} bayt");
            Ok(())
        }
        Command::Info { input } => {
            let h = ops::info(input)?;
            println!(
                "dosya:        {}",
                escape_for_display(&input.display().to_string())
            );
            println!("sürüm:        {}", lephy_core::FORMAT_VERSION);
            println!("algoritma:    {}", h.alg.name());
            println!(
                "içerik:       {}",
                match h.content_type {
                    lephy_core::header::ContentType::Raw => "ham akış",
                    lephy_core::header::ContentType::Archive => "arşiv",
                }
            );
            println!("dolgu:        {}", if h.padded { "PADMÉ" } else { "yok" });
            println!("chunk:        {} KiB", h.chunk_size() / 1024);
            println!(
                "kdf:          Argon2id m={} MiB t={} p={}",
                h.kdf.memory_mib(),
                h.kdf.t,
                h.kdf.p
            );
            println!(
                "keyfile:      {}",
                if h.keyfile { "gerekli" } else { "yok" }
            );
            println!("salt:         {}", hex(&h.salt));
            println!(
                "nonce_prefix: {}",
                hex(&h.stream_nonce_prefix[..h.alg.prefix_len()])
            );
            println!("commit_tag:   {}", hex(&h.commit_tag));
            let size = std::fs::metadata(input)?.len();
            let body = size.saturating_sub(256);
            let cs = h.chunk_size() as u64 + 16;
            println!(
                "boyut:        {size} bayt (~{} chunk)",
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
            allow_large_kdf,
            strict_memory,
        } => {
            let old_kf = keyfile_of(pw.keyfile.as_ref())?;
            let new_kf = keyfile_of(new.new_keyfile.as_ref())?;
            let old_src = source_of(pw);
            let new_src = new_source_of(new);
            if matches!(old_src, Source::Stdin) {
                return Err(Error::Environment(
                    "rekey: eski parola --password-stdin ile verilemez (iki parola gerekir)".into(),
                ));
            }
            let old = read_password(&old_src, "Eski parola: ", false, false)?;
            let newp = read_password(&new_src, "Yeni parola: ", true, false)?;
            password::check_encrypt_policy(&newp)?;
            memory_warning(*strict_memory)?;
            let u = UnlockOptions {
                allow_large_kdf: *allow_large_kdf,
                strict_memory: *strict_memory,
            };
            let kdf = kdf_memory.map(|m| KdfParams {
                m_kib: m.saturating_mul(1024),
                ..KdfParams::DEFAULT
            });
            if let Some(k) = kdf {
                k.check_encrypt_policy()?;
            }
            let creds = NewCredentials {
                pwd_nfc: &newp,
                keyfile_digest: new_kf.as_ref(),
                kdf,
            };
            ops::rekey(
                input,
                &old,
                old_kf.as_ref(),
                &creds,
                u,
                *verify,
                &mut OsEntropy,
                log,
            )?;
            eprintln!(
                "uyarı: eski parola ve eski dosyanın başlık kopyasına sahip biri bu dosyayı hâlâ açabilir; gerçek rotasyon için `reencrypt`"
            );
            Ok(())
        }
        Command::Reencrypt {
            input,
            pw,
            new,
            allow_large_kdf,
            strict_memory,
        } => {
            let old_kf = keyfile_of(pw.keyfile.as_ref())?;
            let new_kf = keyfile_of(new.new_keyfile.as_ref())?;
            let old_src = source_of(pw);
            let new_src = new_source_of(new);
            if matches!(old_src, Source::Stdin) {
                return Err(Error::Environment(
                    "reencrypt: eski parola --password-stdin ile verilemez (iki parola gerekir)"
                        .into(),
                ));
            }
            let old = read_password(&old_src, "Eski parola: ", false, false)?;
            let newp = read_password(&new_src, "Yeni parola: ", true, false)?;
            password::check_encrypt_policy(&newp)?;
            memory_warning(*strict_memory)?;
            let u = UnlockOptions {
                allow_large_kdf: *allow_large_kdf,
                strict_memory: *strict_memory,
            };
            let creds = NewCredentials {
                pwd_nfc: &newp,
                keyfile_digest: new_kf.as_ref(),
                kdf: None,
            };
            let n = ops::reencrypt(input, &old, old_kf.as_ref(), &creds, u, &mut OsEntropy, log)?;
            log(&format!("{n} bayt yeniden şifrelendi"));
            Ok(())
        }
        Command::Cleanup { dir, yes } => {
            let stale = lephy_core::io::scan_stale(dir)?;
            if stale.is_empty() {
                println!("bayat tmp yok");
                return Ok(());
            }
            for p in &stale {
                println!("{}", escape_for_display(&p.display().to_string()));
            }
            eprintln!("uyarı: çözme tmp'leri düz metin içerebilir; silme kalıntı bırakabilir");
            if !*yes {
                let stdin = std::io::stdin();
                if !lephy_sys::term::is_tty(&stdin) {
                    return Err(Error::Cancelled("onay gerekli (--yes)".into()));
                }
                eprint!("{} dosya silinsin mi? [evet/hayır]: ", stale.len());
                let mut line = String::new();
                std::io::stdin().read_line(&mut line)?;
                if line.trim() != "evet" {
                    return Err(Error::Cancelled("kullanıcı reddetti".into()));
                }
            }
            let n = lephy_core::io::cleanup(&stale)?;
            println!("{n} silindi");
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
        // D3: parola değeri argv'den asla alınmaz; yalnızca kaynak seçenekleri vardır.
        let cmd = Cli::command();
        for sub in cmd.get_subcommands() {
            for arg in sub.get_arguments() {
                let id = arg.get_id().as_str();
                if id.contains("password") {
                    assert!(
                        id.ends_with("stdin") || id.ends_with("fd") || id.ends_with("file"),
                        "argv parola argümanı: {id}"
                    );
                }
            }
        }
    }

    #[test]
    fn escape_hides_ansi_and_bidi() {
        assert_eq!(
            escape_for_display("a\x1b[31mb\u{202e}c"),
            "a\\u{1b}[31mb\\u{202e}c"
        );
    }
}
