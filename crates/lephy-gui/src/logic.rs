//! Arayüzden bağımsız mantık: mod tespiti, varsayılan çıktı yolu, arka plan işi.
//! Yollar argv'ye gitmez (THREAT-MODEL › açık meta veri): GUI argümansız başlar, kaynak
//! sürükle-bırak ya da dosya seçme penceresiyle gelir.

use crate::i18n::tr;
use std::path::{Path, PathBuf};

use lephy_core::cipher::AlgId;
use lephy_core::entropy::{Entropy, OsEntropy};
use lephy_core::error::{Error, ExitCode, Result};
use lephy_core::header::{HEADER_LEN, Header};
use lephy_core::kdf::KdfParams;
use lephy_core::ops::{self, DecryptOptions, EncryptOptions, Input, Output};
use lephy_core::password;
use lephy_sys::mem::SecretBytes;

/// İşlem modu.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Mode {
    /// Dosya/klasör → `.lphy`.
    Encrypt,
    /// `.lphy` → dosya/klasör.
    Decrypt,
}

/// Geçerli bir `.lphy` başlığı varsa çöz, yoksa şifrele.
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

/// Şifreli dosya anahtar dosyası gerektiriyor mu (başlık okunamazsa `false`).
#[must_use]
pub fn needs_keyfile(path: &Path) -> bool {
    let mut h = [0u8; HEADER_LEN];
    std::fs::File::open(path)
        .and_then(|mut f| std::io::Read::read_exact(&mut f, &mut h))
        .is_ok()
        && Header::parse(&h).is_ok_and(|hd| hd.keyfile)
}

/// Varsayılan çıktı: şifrelemede aynı dizinde `<8 rastgele hex>.lphy` (D1); çözmede `.lphy`
/// kaldırılmış ad ya da `<ad>.out`.
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

/// Bir kaynak ve hedefi.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Item {
    /// Kaynak.
    pub input: PathBuf,
    /// Hedef.
    pub output: PathBuf,
}

/// Arka plan işi. Parolalar kilitli `SecretBytes`'ta taşınır ve iş bitince düşer.
#[allow(clippy::struct_excessive_bools)]
pub struct Job {
    /// Mod.
    pub mode: Mode,
    /// Kaynak/hedef çiftleri (toplu işte birden çok).
    pub items: Vec<Item>,
    /// Parola (ham UTF-8).
    pub password: SecretBytes,
    /// Şifrelemede tekrar.
    pub confirm: Option<SecretBytes>,
    /// Argon2id belleği (MiB).
    pub kdf_mib: u32,
    /// AES-256-GCM (varsayılan XChaCha20-Poly1305).
    pub aes: bool,
    /// Arşivde PADMÉ.
    pub pad: bool,
    /// Bulut senkron klasörüne çıkarmaya izin.
    pub allow_cloud: bool,
    /// İsteğe bağlı anahtar dosyası (parolaya ek ikinci etken).
    pub keyfile: Option<PathBuf>,
    /// Şifreleme doğrulandıktan sonra orijinali üzerine yazarak sil (kullanıcı onayladı).
    pub secure_delete: bool,
    /// Çıktıyı bu boyutta parçalara böl (bayt).
    pub split: Option<u64>,
    /// Şifrelemeden önce sıkıştır.
    pub compress: bool,
    /// Reed–Solomon hata düzeltme zarfı ekle.
    pub ecc: bool,
    /// Çözmede kurtarma modu: bozuk dosyadan kurtarılabileni çıkar.
    pub recover: bool,
}

/// İşin sonucu.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Outcome {
    /// Yazılan dosya ya da klasörler.
    pub outputs: Vec<PathBuf>,
    /// Atlanan arşiv girişleri (özel dosyalar, kurulmayan symlink'ler).
    pub skipped: usize,
    /// Başarısız öğeler: (görünen ad, hata metni).
    pub failed: Vec<(String, String)>,
    /// Orijinali silinen öğe sayısı.
    pub deleted: usize,
    /// Silinemeyen (arşivden sonra değişen) yol sayısı.
    pub kept: usize,
    /// Hata düzeltmenin onardığı bayt sayısı (çözmede).
    pub repaired: u64,
    /// Kurtarmada doğrulanamayıp sıfırla doldurulan bölüm sayısı.
    pub damaged: usize,
    /// Kurtarmada dosya kesikti ya da çıkarma yarıda kaldı.
    pub incomplete: bool,
}

struct Ctx<'a> {
    nfc: &'a SecretBytes,
    kf: Option<&'a [u8; 32]>,
    opts: Option<EncryptOptions>,
    allow_cloud: bool,
    secure_delete: bool,
    split: Option<u64>,
    recover: bool,
}

/// İşi yürütür. Tek öğede hata doğrudan döner; toplu işte başarısız öğeler `failed`'a yazılır,
/// diğerleri işlenmeye devam eder (hepsi başarısızsa ilk hata döner).
///
/// # Errors
/// Çekirdek hataları (mesajı ve çıkış kodu kategorisi arayüzde gösterilir).
pub fn run(job: Job) -> Result<Outcome> {
    let nfc = password::normalize_nfc(&job.password)?;
    drop(job.password);
    let keyfile = job
        .keyfile
        .as_deref()
        .map(password::keyfile_digest_from_path)
        .transpose()?;
    let opts = match job.mode {
        Mode::Encrypt => {
            let confirm = job.confirm.ok_or_else(|| {
                Error::Environment(tr("parolayı tekrar girin", "enter the password again").into())
            })?;
            let c = password::normalize_nfc(&confirm)?;
            drop(confirm);
            if c.expose() != nfc.expose() {
                return Err(Error::Environment(
                    tr("parolalar eşleşmiyor", "passwords do not match").into(),
                ));
            }
            password::check_encrypt_policy(&nfc)?;
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
        kf: keyfile.as_deref(),
        opts,
        allow_cloud: job.allow_cloud,
        secure_delete: job.secure_delete && job.mode == Mode::Encrypt,
        split: job.split.filter(|_| job.mode == Mode::Encrypt),
        recover: job.recover && job.mode == Mode::Decrypt,
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
    if let Some(opts) = &ctx.opts {
        let rep = ops::encrypt(
            &Input::Path(&item.input),
            &item.output,
            ctx.nfc,
            ctx.kf,
            opts,
            &mut OsEntropy,
            &mut log,
        )?;
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
            // Silmeden önce yazılan dosya parolayla baştan sona doğrulanır.
            let u = ops::UnlockOptions {
                allow_large_kdf: true,
                strict_memory: false,
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
        if ctx.recover {
            let r = ops::recover(
                &item.input,
                &item.output,
                ctx.nfc,
                ctx.kf,
                ops::UnlockOptions::default(),
                &mut log,
            )?;
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
            DecryptOptions::default(),
            &mut log,
        )?;
        out.outputs.push(rep.target);
        out.repaired += rep.repaired;
        out.skipped += rep.archive.as_ref().map_or(0, |a| a.skipped.len());
    }
    Ok(())
}

/// İlerleme yüzdesi için tahmini toplam akış baytı: şifrelemede kaynak dosyaların toplam
/// boyutu (symlink izlenmez), çözmede başlık sonrası dosya boyutu. Bilinmiyorsa 0.
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

/// Kullanıcıya gösterilecek hata metni: ne oldu ve ne yapılabilir.
#[must_use]
pub fn describe_error(e: &Error) -> String {
    match (e, e.exit_code()) {
        (Error::KeyfileRequired, _) => tr(
            "Bu dosya bir anahtar dosyasıyla şifrelenmiş. Anahtar dosyasını seçin.",
            "This file was encrypted with a key file. Choose the key file.",
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

/// İlk harfi büyütür, sonuna nokta koyar.
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

/// Kaynak hakkında kısa bilgi: (görünen ad, açıklama).
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

/// Şifreli dosyanın başlığından, parola sorulmadan okunabilen bilgiler (tek satır).
/// Başlık okunamazsa `None`.
#[must_use]
pub fn header_summary(path: &Path) -> Option<String> {
    let h = ops::info(path).ok()?;
    let kind = match h.content_type {
        lephy_core::header::ContentType::Archive => tr("arşiv", "archive"),
        lephy_core::header::ContentType::Raw => tr("ham akış", "raw stream"),
    };
    let mut out = format!(
        "{}, Argon2id {} MiB, {kind}",
        h.alg.name(),
        h.kdf.memory_mib()
    );
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

/// İnsan okunur boyut (Türkçe ondalık virgül).
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

/// Klasör yolunu kısaltır: ev dizini `~` olur.
#[must_use]
pub fn short_dir(dir: &Path) -> String {
    let home = home_dir();
    match home.as_deref().and_then(|h| dir.strip_prefix(h).ok()) {
        Some(rest) if rest.as_os_str().is_empty() => "~".to_string(),
        Some(rest) => format!("~{}{}", std::path::MAIN_SEPARATOR, rest.display()),
        None => dir.display().to_string(),
    }
}

/// Ev dizini (ortam değişkeni okunmaz; `std::env::home_dir`).
fn home_dir() -> Option<PathBuf> {
    std::env::home_dir().filter(|h| h.is_absolute())
}

/// Dosya yöneticisinde gösterir (macOS Finder, Windows Gezgini). Araçlar mutlak yolla çağrılır.
///
/// # Errors
/// Araç başlatılamazsa.
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
        // Ortam devralınmaz (DLL arama yolu vb.); Gezgin için gereken tek değişken geri verilir.
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
        };
        run(job).unwrap();
        assert_eq!(detect_mode(&d.join("x.lphy")), Mode::Decrypt);
        assert_eq!(
            estimate_total(Mode::Encrypt, &d),
            5 + std::fs::metadata(d.join("x.lphy")).unwrap().len()
        );
        assert!(estimate_total(Mode::Decrypt, &d.join("x.lphy")) > 0);
        assert!(lephy_core::pipeline::progress() > 0, "hat ilerleme saymalı");
        assert_eq!(
            default_output(&d.join("x.lphy"), Mode::Decrypt),
            d.join("x")
        );
        let job = Job {
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
        };
        let out = run(job).unwrap();
        assert_eq!(out.outputs, vec![d.join("geri.txt")]);
        assert_eq!(out.skipped, 0);
        assert_eq!(std::fs::read(d.join("geri.txt")).unwrap(), b"hello");
        // Uyuşmayan tekrar ve kısa parola
        for (p, c) in [("gui parola 1234", "başka parola 99"), ("kisa", "kisa")] {
            let job = Job {
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
            };
            let e = run(job).unwrap_err();
            assert_eq!(e.exit_code(), ExitCode::Io);
            assert!(describe_error(&e).ends_with('.'));
        }
        // Yanlış parola → kod 3
        let job = Job {
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
        };
        let e = run(job).unwrap_err();
        assert_eq!(e.exit_code(), ExitCode::WrongPassword);
        assert!(describe_error(&e).starts_with("Parola yanlış"));
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
        };
        let out = run(job).unwrap();
        assert_eq!(out.outputs.len(), 2);
        assert_eq!(out.failed.len(), 1, "{:?}", out.failed);
        assert_eq!(out.deleted, 2);
        assert!(!d.join("a.txt").exists() && !d.join("b.txt").exists());
        // Hepsi başarısızsa hata döner.
        let job = Job {
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
