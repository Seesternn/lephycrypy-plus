//! `lephycrypy` komut satırı.
//!
//! Çıkış kodları README › Çıkış kodları; kod 2 yalnızca clap. Parola argv/env'den asla
//! okunmaz. Süreç başı: `harden()` → panik hook'u → sinyal işleyici → clap →
//! (macOS release) `PT_DENY_ATTACH`.

#![forbid(unsafe_code)]

// `test-vectors` feature'ı ile derlenen bir çekirdek ikiliye asla giremez.
const _: () = assert!(
    !lephy_core::TEST_VECTORS_ENABLED,
    "lephy-cli, lephy-core/test-vectors feature'ı ile derlenemez"
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
    #[cfg_attr(unix, arg(long, conflicts_with_all = ["password_fd", "password_file"]))]
    #[cfg_attr(not(unix), arg(long, conflicts_with = "password_file"))]
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

/// Çözme/çıkarma politikası.
#[derive(Args, Clone, Copy)]
struct UnlockArgs {
    /// KDF bütçesi aşımına izin ver (RAM eşiği yine uygulanır).
    #[arg(long)]
    allow_large_kdf: bool,
    /// Bellek kilitlenemezse hata ver.
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

#[derive(Clone, Copy, ValueEnum, Default)]
enum RestoreSymlinks {
    /// Yalnızca güvenli (göreli, `..`'siz) hedefler.
    #[default]
    Safe,
    /// Güvensiz hedefler de (her biri için uyarı).
    Unsafe,
}

#[derive(Subcommand)]
enum Command {
    /// Dosya ya da klasörleri şifreler ("-" = stdin, ham akış). Birden çok kaynakta her biri
    /// ayrı bir `.lphy` olur (`--out-dir`).
    Encrypt {
        /// Kaynak dosya/klasör(ler) ("-" = stdin, tek başına).
        #[arg(required = true, num_args = 1..)]
        inputs: Vec<PathBuf>,
        /// Çıktı yolu (tek kaynak; varsayılan: <8 rastgele hex>.lphy).
        #[arg(short, long, value_name = "YOL", conflicts_with = "out_dir")]
        output: Option<PathBuf>,
        /// Çıktı klasörü: her kaynak için rastgele adlı bir `.lphy` (birden çok kaynakta gerekli).
        #[arg(long, value_name = "KLASÖR")]
        out_dir: Option<PathBuf>,
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
        /// Encrypt to a public key instead of a password (`lphy1…`, or a file with one key per
        /// line). Repeat for several recipients; any one of them can decrypt.
        #[arg(short = 'r', long = "recipient", value_name = "KEY|FILE")]
        recipients: Vec<String>,
        /// Dosyayı arşiv yerine ham akış olarak yaz (ad gizlenmez; stdin her zaman ham).
        #[arg(long)]
        raw: bool,
        /// PADMÉ boyut dolgusu (ham akışta; stdin ile kullanılamaz).
        #[arg(long, conflicts_with = "no_pad")]
        pad: bool,
        /// Arşivde PADMÉ dolgusunu kapat.
        #[arg(long)]
        no_pad: bool,
        /// Atlanan giriş (FIFO/soket/aygıt, okunamayan) hata say (kod 4).
        #[arg(long)]
        strict: bool,
        /// Hedef varsa üzerine yaz.
        #[arg(long)]
        force: bool,
        /// Bellek kilitlenemezse hata ver.
        #[arg(long)]
        strict_memory: bool,
        /// Şifreleme + doğrulama + fsync sonrası orijinali sil (kalıntı uyarısı).
        #[arg(long)]
        delete_original: bool,
        /// `--delete-original` gibi, ama silmeden önce her dosyanın üzerine bir kez rastgele veri
        /// yazar. SSD/APFS gibi ortamlarda fiziksel silme garanti edilmez. Onay ister.
        #[arg(long)]
        secure_delete: bool,
        /// Şifrelemeden önce sıkıştır (DEFLATE; biçim v2). Sıkıştırılmış boyut içerik hakkında
        /// bilgi verebilir; saldırganın girdinin bir kısmını seçebildiği durumlarda kullanmayın.
        #[arg(long)]
        compress: bool,
        /// Reed–Solomon hata düzeltme ekle (~%7 büyür): bozulan USB/diskteki küçük hasarları
        /// çözerken onarır.
        #[arg(long, visible_alias = "ecc")]
        error_correction: bool,
        /// Çıktıyı bu boyutta parçalara böl (ör. 100m, 650m, 4g; en az 1m). Parçalar `.001`,
        /// `.002` … olarak yazılır; çözerken `.001` verilmesi yeterlidir.
        #[arg(long, value_name = "BOYUT", value_parser = parse_size)]
        split_size: Option<u64>,
        /// `--secure-delete` için onay sorma (betikler).
        #[arg(long, requires = "secure_delete")]
        yes: bool,
    },
    /// `.lphy` dosyasını çözer (arşiv → klasör ya da tek dosya; ham → dosya/stdout).
    Decrypt {
        /// Şifreli dosya.
        input: PathBuf,
        /// Identity file (`.lphykey`) for files encrypted to a public key; the password asked
        /// for is the identity file's.
        #[arg(short = 'i', long, value_name = "YOL")]
        identity: Option<PathBuf>,
        /// Çıktı yolu (varsayılan: giriş adından `.lphy` kaldırılmış ya da `<giriş>.out`).
        #[arg(short, long, value_name = "YOL", conflicts_with = "stdout")]
        output: Option<PathBuf>,
        /// Düz metni stdout'a yaz (yalnızca ham akış; kesme son chunk'a kadar tespit edilemez).
        #[arg(long)]
        stdout: bool,
        #[command(flatten)]
        pw: PasswordArgs,
        #[command(flatten)]
        unlock: UnlockArgs,
        /// Hedef varsa üzerine yaz (klasörse silinir).
        #[arg(long)]
        force: bool,
        /// Symlink'leri kur (varsayılan: hiç kurulmaz).
        #[arg(long, value_enum, value_name = "safe|unsafe", num_args = 0..=1, default_missing_value = "safe")]
        restore_symlinks: Option<RestoreSymlinks>,
        /// Yinelenen (büyük/küçük harf, NFC) adlarda `_2`, `_3` …
        #[arg(long)]
        rename_conflicts: bool,
        /// Atlanan/değiştirilen giriş hata say (biçim/politika → 4, ayrıcalık → 1).
        #[arg(long)]
        strict: bool,
        /// Bilinen bulut senkron klasörlerine çıkarmaya onay istemeden izin ver.
        #[arg(long)]
        allow_cloud_dir: bool,
        /// Bozuk dosyadan kurtarılabileni çıkar (varsayılan çıktı `<ad>.recovered`).
        /// Doğrulanamayan bölümler sıfırla doldurulur; çıktı güvenilmez veri içerebilir.
        #[arg(long, conflicts_with_all = ["stdout", "force"])]
        recover: bool,
    },
    /// Dosyayı yazmadan doğrular.
    Verify {
        /// Şifreli dosya.
        input: PathBuf,
        /// Identity file (`.lphykey`) for files encrypted to a public key; the password asked
        /// for is the identity file's.
        #[arg(short = 'i', long, value_name = "YOL")]
        identity: Option<PathBuf>,
        #[command(flatten)]
        pw: PasswordArgs,
        #[command(flatten)]
        unlock: UnlockArgs,
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
        /// Yeni KDF belleği (MiB); verilmezse eski başlıktaki parametreler.
        #[arg(long, value_name = "MiB")]
        kdf_memory: Option<u32>,
        /// Sonucu tam doğrula.
        #[arg(long)]
        verify: bool,
        #[command(flatten)]
        unlock: UnlockArgs,
    },
    /// Yeni dosya anahtarı ile tüm chunk'ları yeniden şifreler (yerinde, atomik).
    Reencrypt {
        /// Şifreli dosya.
        input: PathBuf,
        #[command(flatten)]
        pw: PasswordArgs,
        #[command(flatten)]
        new: NewPasswordArgs,
        #[command(flatten)]
        unlock: UnlockArgs,
    },
    /// Rastgele bir kelime öbeği (parola) üretir ve standart çıktıya yazar (EFF büyük listesi).
    Passphrase {
        /// Kelime sayısı (4–16; her kelime ≈ 12,9 bit).
        #[arg(long, default_value_t = 6)]
        words: usize,
        /// Kelime ayracı.
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
    /// Yeni bir anahtar dosyası oluşturur (rastgele bayt, 0600, üzerine yazmaz).
    KeyfileGen {
        /// Oluşturulacak dosya.
        path: PathBuf,
        /// Bayt sayısı (32–1048576).
        #[arg(long, default_value_t = 64)]
        size: usize,
    },
    /// Bir dizindeki bayat `.lphy-tmp-*` dosya/dizinlerini onayla siler.
    Cleanup {
        /// Taranacak dizin.
        dir: PathBuf,
        /// Onay istemeden sil (non-tty için).
        #[arg(long)]
        yes: bool,
    },
    /// Yalnızca çıkarılabilir USB ortamı: temizle ve şifreli `.lphy` dosyasını yaz (1.1).
    Usb {
        #[command(subcommand)]
        cmd: UsbCmd,
    },
}

#[derive(Subcommand)]
enum UsbCmd {
    /// Aday USB birimlerini ve uygunluklarını listeler (salt okunur).
    List,
    /// USB birimini temizler (ya da biçimlendirir) ve yalnızca verilen `.lphy` dosyasını yazar.
    Write {
        /// Yazılacak `.lphy` dosyası (yalnızca geçerli şifreli dosyalar kabul edilir).
        source: PathBuf,
        /// Hedef birimin bağlama noktası / sürücü kökü (`usb list` ile görün).
        #[arg(long, value_name = "YOL")]
        target: PathBuf,
        /// Silme yerine exFAT biçimlendir (Windows'ta yönetici oturumu gerekir).
        #[arg(long)]
        format: bool,
        /// Silmeden sonra boş alanı rastgele veriyle doldur (fiziksel silme garantisi değildir).
        #[arg(long)]
        fill_free_space: bool,
        /// Betik onayı: birim etiketi aynen.
        #[arg(long, value_name = "ETİKET", requires = "confirm_size_gib")]
        confirm_label: Option<String>,
        /// Betik onayı: boyut, GiB tam sayı (`floor(bayt / 2^30)`).
        #[arg(long, value_name = "GiB", requires = "confirm_label")]
        confirm_size_gib: Option<u64>,
    },
}

fn main() -> ProcessExit {
    // Hiçbir sır oluşmadan: sertleştirme, panik hook'u, sinyal işleyici.
    if let Err(e) = lephy_sys::platform::harden() {
        eprintln!("uyarı: süreç sertleştirme kısmen başarısız: {e}");
    }
    lephy_sys::platform::install_panic_hook();
    if let Err(e) = lephy_sys::signal::install() {
        eprintln!("uyarı: sinyal işleyici kurulamadı: {e}");
    }

    if lephy_core::FAULT_INJECTION_ENABLED {
        eprintln!("uyarı: LPHY-FAULT-INJECTION test derlemesi; gerçek veriyle kullanmayın");
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

/// Parolayı okur, NFC'ye çevirir; `confirm` ile terminalde iki kez sorar.
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

fn keyfile_of(path: Option<&PathBuf>) -> Result<Option<zeroize::Zeroizing<[u8; 32]>>> {
    path.map(|p| password::keyfile_digest_from_path(p))
        .transpose()
}

/// Orijinali silme biçimi.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Remove {
    No,
    Plain,
    Overwrite,
}

/// Toplu şifrelemede her kaynak için ortak ayarlar (parola bir kez okunur).
struct EncryptJob<'a> {
    split: Option<u64>,
    /// Public keys; empty = password encryption.
    recipients: &'a [PublicKey],
    nfc: &'a SecretBytes,
    keyfile: Option<&'a [u8; 32]>,
    opts: &'a EncryptOptions,
    remove: Remove,
}

/// Tek kaynağı şifreler; istenirse doğrular ve orijinali siler. Her kaynakta yeni tuz ve
/// yeni dosya anahtarı kullanılır (KDF her dosyada yeniden çalışır).
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
            "uyarı: dosya sistemi atomik noclobber desteklemiyor; kontrol-sonra-rename kullanıldı"
        );
    }
    if let Some(a) = &rep.archive {
        print_report(a, log);
    }
    log(&format!(
        "{} bayt ({}) şifrelendi → {}",
        rep.plain_len,
        match rep.content_type {
            ContentType::Raw => "ham akış",
            ContentType::Archive => "arşiv",
        },
        disp(out)
    ));
    let out = if let Some(size) = job.split {
        let parts = lephy_core::split::split_file(out, size)?;
        log(&format!(
            "{} parçaya bölündü: {} …",
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
        // Yalnızca arşive alınan öğeler silinir; atlanan varsa hiçbir şey silinmez.
        let d = ops::delete_archived_with(a, job.remove == Remove::Overwrite)?;
        for k in &d.kept {
            eprintln!(
                "uyarı: silinmedi (arşivden sonra değişti ya da boş değil): {}",
                disp(k)
            );
        }
    } else if input.symlink_metadata()?.is_file() {
        std::fs::remove_file(input)?;
    }
    eprintln!("uyarı: orijinal silindi; disk/snapshot/VSS/bulut sürüm geçmişinde kalıntı olabilir");
    Ok(())
}

/// "100m", "4g", "650M", "1048576" → bayt.
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
        .map_err(|_| format!("geçersiz boyut: {s} (ör. 100m, 4g)"))?;
    let v = n.checked_mul(mul).ok_or("boyut çok büyük")?;
    if v < lephy_core::split::MIN_PART {
        return Err("parça boyutu en az 1m olmalı".into());
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
        eprintln!("uyarı: atlandı: {} ({why})", escape_display(p));
    }
    for (a, b) in &rep.renamed {
        eprintln!(
            "uyarı: yeniden adlandırıldı: {} → {}",
            escape_display(a),
            escape_display(b)
        );
    }
    for w in &rep.warnings {
        eprintln!("uyarı: {w}");
    }
    log(&format!(
        "{} giriş, {} symlink kuruldu",
        rep.entries, rep.symlinks_created
    ));
}

/// Bulut senkron klasörü denetimi: onay ya da `--allow-cloud-dir`; non-tty → kod 5.
fn cloud_check(target: &Path, allow: bool) -> Result<()> {
    if allow {
        return Ok(());
    }
    let Some(root) = lephy_sys::fs::cloud_root_of(target) else {
        return Ok(());
    };
    eprintln!(
        "uyarı: hedef bir bulut senkron klasörünün altında ({}); düz metin buluta yüklenebilir. Liste sezgiseldir, eksik olabilir.",
        disp(&root)
    );
    let stdin = std::io::stdin();
    if !lephy_sys::term::is_tty(&stdin) {
        return Err(Error::Cancelled(
            "bulut klasörüne çıkarma için onay gerekli (--allow-cloud-dir)".into(),
        ));
    }
    eprint!("Devam edilsin mi? [evet/hayır]: ");
    let mut line = String::new();
    stdin.read_line(&mut line)?;
    if line.trim() != "evet" {
        return Err(Error::Cancelled("bulut klasörü onayı reddedildi".into()));
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
                    "stdin (\"-\") yalnızca tek kaynak olarak kullanılabilir".into(),
                ));
            }
            if inputs.len() > 1 && out_dir.is_none() {
                return Err(Error::Environment(
                    "birden çok kaynakta --out-dir gerekli (her kaynak ayrı bir .lphy olur)".into(),
                ));
            }
            if is_stdin && *pad {
                return Err(Error::Environment(
                    "--pad stdin girişiyle kullanılamaz".into(),
                ));
            }
            let remove = *delete_original || *secure_delete;
            if remove && is_stdin {
                return Err(Error::Environment(
                    "--delete-original stdin ile kullanılamaz".into(),
                ));
            }
            if *secure_delete && !*yes {
                eprintln!(
                    "Orijinaller, şifreleme doğrulandıktan sonra üzerine rastgele veri yazılarak silinecek.\n\
                     SSD, APFS/Btrfs, anlık görüntü ve bulut geçmişinde eski içerik yine de kalabilir."
                );
                let a = prompt_line("Onaylamak için 'evet' yazın: ", "--yes verin")?;
                if !matches!(a.trim().to_lowercase().as_str(), "evet" | "yes") {
                    return Err(Error::Cancelled("güvenli silme onaylanmadı".into()));
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
                let nfc = read_password(&source, "Parola: ", true, is_stdin)?;
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
                    "--split-size stdin ile değil, dosya çıktısıyla kullanılır".into(),
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
                            "bilgi: çıktı adı kaynak adını içeriyor ({})",
                            escape_display(&d)
                        ));
                    }
                }
                match encrypt_one(&job, input, &out, is_stdin, log) {
                    Ok(()) => ok += 1,
                    Err(e) if inputs.len() > 1 => {
                        eprintln!("hata: {}: {e}", disp(input));
                        first_err.get_or_insert(e);
                    }
                    Err(e) => return Err(e),
                }
            }
            if inputs.len() > 1 {
                log(&format!("{ok}/{} kaynak şifrelendi", inputs.len()));
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
                    eprintln!("bilgi: hata düzeltme {} baytı onardı", r.repaired);
                }
                if r.clean() {
                    eprintln!("dosya sağlam; kurtarmaya gerek yoktu → {}", disp(&out));
                    return Ok(());
                }
                eprintln!(
                    "uyarı: KURTARILAN çıktı doğrulanmamış veri içerebilir → {}",
                    disp(&out)
                );
                for c in r.bad_chunks.iter().take(20) {
                    let start = c * r.chunk_size as u64;
                    eprintln!(
                        "  bozuk bölüm: chunk {c} (yaklaşık {start}–{} bayt; sıfırla dolduruldu)",
                        start + r.chunk_size as u64
                    );
                }
                if r.bad_chunks.len() > 20 {
                    eprintln!("  … ve {} chunk daha", r.bad_chunks.len() - 20);
                }
                if r.truncated {
                    eprintln!("  dosya kesilmiş: son bölüm eksik");
                }
                if let Some(why) = &r.stopped {
                    eprintln!(
                        "  çıkarma {} girişten sonra durdu: {}",
                        r.entries,
                        escape_display(why)
                    );
                }
                return Err(Error::Corrupt {
                    at: "kurtarma".into(),
                    detail: Some("dosya bozuktu; kısmi çıktı yazıldı".into()),
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
            };
            if *stdout {
                eprintln!(
                    "uyarı: --stdout: son chunk doğrulanana kadar kesme tespit edilemez; çıktı kısmen yazılmış olabilir"
                );
                let r = ops::decrypt(input, &Output::Stdout, &nfc, keyfile.as_deref(), dopts, log)?;
                if r.repaired > 0 {
                    eprintln!("bilgi: hata düzeltme {} baytı onardı", r.repaired);
                }
                log(&format!("{} bayt çözüldü (stdout)", r.plain_len));
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
                eprintln!("bilgi: hata düzeltme {} baytı onardı", r.repaired);
            }
            if r.noclobber_fallback {
                eprintln!(
                    "uyarı: dosya sistemi atomik noclobber desteklemiyor; kontrol-sonra-rename kullanıldı"
                );
            }
            if let Some(a) = &r.archive {
                print_report(a, log);
            }
            log(&format!(
                "{} bayt çözüldü → {}",
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
            println!("doğrulandı: {n} bayt");
            Ok(())
        }
        Command::Info { input } => {
            let h = ops::info(input)?;
            println!("dosya:        {}", disp(input));
            let version = if h.compressed || h.recipients > 0 {
                2
            } else {
                lephy_core::FORMAT_VERSION
            };
            println!("sürüm:        {version}");
            println!("algoritma:    {}", h.alg.name());
            println!(
                "içerik:       {}",
                match h.content_type {
                    ContentType::Raw => "ham akış",
                    ContentType::Archive => "arşiv",
                }
            );
            println!("dolgu:        {}", if h.padded { "PADMÉ" } else { "yok" });
            println!("chunk:        {} KiB", h.chunk_size() / 1024);
            if h.compressed {
                println!("sıkıştırma:   DEFLATE");
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
                    if h.keyfile { "gerekli" } else { "yok" }
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
            unlock,
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
                    "reencrypt: eski parola --password-stdin ile verilemez (iki parola gerekir)"
                        .into(),
                ));
            }
            let old = read_password(&old_src, "Eski parola: ", false, false)?;
            let newp = read_password(&new_src, "Yeni parola: ", true, false)?;
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
            log(&format!("{n} bayt yeniden şifrelendi"));
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
                "≈ {:.0} bit; bu öbeği güvenli bir yere yazın, tekrar gösterilmez",
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
                "anahtar dosyası oluşturuldu: {} ({size} bayt). Kaybederseniz bu dosyayla şifrelenen veriler açılamaz; yedekleyin.",
                disp(path)
            );
            Ok(())
        }
        Command::Cleanup { dir, yes } => {
            let stale = lephy_core::io::scan_stale(dir)?;
            if stale.is_empty() {
                println!("bayat tmp yok");
                return Ok(());
            }
            for p in &stale {
                println!("{}", disp(p));
            }
            eprintln!("uyarı: çözme tmp'leri düz metin içerebilir; silme kalıntı bırakabilir");
            if !*yes {
                let stdin = std::io::stdin();
                if !lephy_sys::term::is_tty(&stdin) {
                    return Err(Error::Cancelled("onay gerekli (--yes)".into()));
                }
                eprint!("{} öğe silinsin mi? [evet/hayır]: ", stale.len());
                let mut line = String::new();
                stdin.read_line(&mut line)?;
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

fn empty_secret() -> Result<SecretBytes> {
    SecretBytes::with_capacity(1).map_err(|e| Error::Environment(format!("kilitli bellek: {e}")))
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
            let nfc = read_password(&source_of(pw), "Parola: ", false, false)?;
            Ok((keyfile, nfc, None))
        }
    }
}

fn prompt_line(q: &str, non_tty_hint: &str) -> Result<String> {
    let stdin = std::io::stdin();
    if !lephy_sys::term::is_tty(&stdin) {
        return Err(Error::Cancelled(format!("onay gerekli: {non_tty_hint}")));
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
                println!("bağlı aday USB birimi yok");
            }
            for d in devs {
                let verdict = match d.eligibility(platform.require_serial()) {
                    Ok(()) => "uygun".to_string(),
                    Err(why) => format!("UYGUN DEĞİL: {why}"),
                };
                println!(
                    "{}  etiket={}  {} GiB  {}  veriyolu={}  ürün={}  → {verdict}",
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
                "HEDEF: {}  etiket={}  {} GiB  {}  ürün={}",
                disp(&dev.mount),
                escape_display(&dev.label),
                dev.size_gib(),
                dev.fs_type,
                escape_display(&dev.product)
            );
            if *format {
                println!("İŞLEM: birim exFAT olarak BİÇİMLENDİRİLECEK; tüm içerik kaybolur.");
            } else {
                println!(
                    "SİLİNECEK: {} dosya, {} dizin, {} bayt. İlk {} yol:",
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
                "uyarı: FAT/exFAT eski dizin girişleri, NTFS resident dosyalar ve wear-leveling nedeniyle \
                 fiziksel silme garantisi yoktur; --format da denetleyici düzeyinde garanti vermez"
            );
            let confirm = if let (Some(l), Some(g)) = (confirm_label, confirm_size_gib) {
                lephy_usb::Confirm {
                    label: l.clone(),
                    size_gib: *g,
                }
            } else {
                let label = prompt_line(
                    "Onay için birim etiketini aynen yazın: ",
                    "--confirm-label ve --confirm-size-gib verin",
                )?;
                let gib = prompt_line(
                    "Onay için boyutu GiB olarak (tam sayı) yazın: ",
                    "--confirm-label ve --confirm-size-gib verin",
                )?;
                let size_gib = gib
                    .trim()
                    .parse::<u64>()
                    .map_err(|_| Error::Cancelled("boyut tam sayı değil".into()))?;
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
                "yazıldı: {} ({} bayt, BLAKE3 {}) — {}",
                disp(&rep.written),
                rep.bytes,
                &rep.blake3[..16],
                rep.verification
            );
            if rep.verification == lephy_usb::Verification::FromCache {
                eprintln!(
                    "uyarı: birim yeniden bağlanamadı; geri okuma işletim sistemi önbelleğinden yapılmış olabilir"
                );
            }
            log(&format!("adımlar: {}", rep.steps.join(" → ")));
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
