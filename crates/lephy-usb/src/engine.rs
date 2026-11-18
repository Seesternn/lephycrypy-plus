//! USB işlem motoru.
//!
//! Akış: [`prepare`] (taze tanım → uygunluk → kuru çalıştırma) → kullanıcı onayı (etiket **ve**
//! GiB) → [`execute`]: her adımdan önce fiziksel/birim kimliği yeniden okunur; fark → kod 5 ve
//! sonraki adım çalışmaz. Adımlar: silme ya da `--format` → isteğe bağlı `--fill-free-space` →
//! `.lphy` yazma (atomik) → geri okuma (yeniden bağlama sonrası, değilse "önbellekten
//! doğrulandı").

use std::io::{Read, Write};
use std::path::{Path, PathBuf};

use chacha20::ChaCha20;
use chacha20::cipher::{KeyIvInit, StreamCipher};
use lephy_core::error::{Error, Result};
use lephy_core::header::{HEADER_LEN, Header};
use lephy_core::names::escape_display;

use crate::device::Device;
use crate::platform::Platform;

/// Kökteki sistem klasörleri: klasörün kendisi korunur, içeriği (çöp kutusu, Spotlight dizini,
/// olay günlüğü — eski kullanıcı verisi ya da ondan türetilmiş metin) silinir.
pub const SYSTEM_DIRS: [&str; 4] = [
    "System Volume Information",
    ".Spotlight-V100",
    ".fseventsd",
    ".Trashes",
];
/// Doldurma tamponu üst sınırı.
pub const MAX_FILL_BUFFER: usize = 8 * 1024 * 1024;
/// FAT32 dosya boyutu sınırı.
pub const FAT32_MAX_FILE: u64 = 4 * 1024 * 1024 * 1024 - 1;
/// Dosya başına anahtar akışı üst sınırı: `ChaCha20` (96 bit nonce) 32 bit blok sayacıyla 256 GiB
/// üretir; her dosya ayrı nonce ve ≤ 64 GiB.
pub const MAX_KEYSTREAM_FILE: u64 = 64 * 1024 * 1024 * 1024;
/// Doldurma dosyası öneki.
pub const FILL_PREFIX: &str = ".lphy-fill-";

/// Kuru çalıştırma sonucu.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct DryRun {
    /// Silinecek dosya (ve symlink) sayısı.
    pub files: u64,
    /// Silinecek dizin sayısı.
    pub dirs: u64,
    /// Toplam bayt.
    pub bytes: u64,
    /// İlk 20 yol (kaçışlanmış).
    pub first: Vec<String>,
}

fn is_system(name: &str) -> bool {
    SYSTEM_DIRS.contains(&name)
}

/// Kuru çalıştırma: silinecek her şeyi sayar; symlink takip edilmez.
///
/// # Errors
/// G/Ç.
pub fn dry_run(root: &Path) -> Result<DryRun> {
    let mut out = DryRun::default();
    let mut stack: Vec<(PathBuf, String)> = Vec::new();
    for e in std::fs::read_dir(root)? {
        let e = e?;
        let name = e.file_name().to_string_lossy().into_owned();
        if is_system(&name) {
            // Klasör kalır; içindekiler sayılır (erişilemiyorsa atlanır).
            if let Ok(rd) = std::fs::read_dir(e.path()) {
                for k in rd.filter_map(std::result::Result::ok) {
                    let n = k.file_name().to_string_lossy().into_owned();
                    stack.push((k.path(), format!("{name}/{n}")));
                }
            }
        } else {
            stack.push((e.path(), name));
        }
    }
    stack.sort();
    stack.reverse();
    while let Some((p, rel)) = stack.pop() {
        let md = p.symlink_metadata()?;
        if out.first.len() < 20 {
            out.first.push(escape_display(&rel));
        }
        if md.is_dir() {
            out.dirs += 1;
            let mut kids: Vec<(PathBuf, String)> = std::fs::read_dir(&p)?
                .filter_map(std::result::Result::ok)
                .map(|e| {
                    let n = e.file_name().to_string_lossy().into_owned();
                    (e.path(), format!("{rel}/{n}"))
                })
                .collect();
            kids.sort();
            kids.reverse();
            stack.extend(kids);
        } else {
            out.files += 1;
            out.bytes += md.len();
        }
    }
    Ok(out)
}

/// Kullanıcı dosyalarını siler (kök handle üzerinden; symlink takip edilmez; sistem
/// klasörlerinin yalnızca içi boşaltılır). Silinen giriş sayısı.
///
/// # Errors
/// G/Ç.
pub fn wipe(root: &Path, expect_dev: Option<u64>) -> Result<u64> {
    let dir = cap_std::fs::Dir::open_ambient_dir(root, cap_std::ambient_authority())?;
    // Kimlik açılmış tutamaçtan denetlenir: kontrol sonrası bağlama noktasına başka bir aygıt
    // gelse bile silme yalnızca doğrulanan tutamaç üzerinden yapılır.
    #[cfg(unix)]
    if let Some(want) = expect_dev {
        use cap_std::fs::MetadataExt;
        if dir.dir_metadata()?.dev() != want {
            return Err(Error::Cancelled(
                "hedef aygıt kimliği değişti; hiçbir şey silinmedi".into(),
            ));
        }
    }
    #[cfg(not(unix))]
    let _ = expect_dev;
    let mut n = 0;
    for e in dir.entries()? {
        let e = e?;
        let name = e.file_name();
        let name_s = name.to_string_lossy();
        if is_system(&name_s) {
            n += clear_contents(&dir, &name);
            continue;
        }
        let ft = e.file_type()?;
        if ft.is_dir() && !ft.is_symlink() {
            dir.remove_dir_all(&name)?;
        } else if dir.remove_file(&name).is_err() {
            // Windows dizin symlink'i: remove_dir ile kaldırılır (hedefe dokunmaz).
            dir.remove_dir(&name)?;
        }
        n += 1;
        if lephy_sys::signal::interrupted() {
            return Err(Error::Interrupted);
        }
    }
    let _ = lephy_sys::fs::fsync_dir(root);
    Ok(n)
}

/// Sistem klasörünün içini en iyi çabayla boşaltır (klasör kalır; symlink takip edilmez).
/// Erişilemeyen öğeler (ör. Windows'ta ACL korumalı `System Volume Information`) atlanır.
fn clear_contents(root: &cap_std::fs::Dir, name: &std::ffi::OsStr) -> u64 {
    let Ok(sub) = root.open_dir(name) else {
        return 0;
    };
    let Ok(rd) = sub.entries() else {
        return 0;
    };
    let mut n = 0;
    for e in rd.filter_map(std::result::Result::ok) {
        let child = e.file_name();
        let removed = match e.file_type() {
            Ok(ft) if ft.is_dir() && !ft.is_symlink() => sub.remove_dir_all(&child).is_ok(),
            Ok(_) => sub.remove_file(&child).is_ok() || sub.remove_dir(&child).is_ok(),
            Err(_) => false,
        };
        n += u64::from(removed);
    }
    n
}

/// Boş alan doldurma seçenekleri.
#[derive(Debug, Clone, Copy)]
pub struct FillOptions {
    /// Dosya başına üst sınır (FAT32: 4 GiB − 1).
    pub max_file: u64,
    /// Yazma tamponu (≤ 8 MiB).
    pub buffer: usize,
    /// Yalnızca test: bu kadar bayttan sonra "disk dolu" say.
    pub limit: Option<u64>,
}

impl FillOptions {
    /// Dosya sistemine göre varsayılan.
    #[must_use]
    pub fn for_fs(fs_type: &str) -> Self {
        let fat = matches!(fs_type, "msdos" | "fat" | "fat32" | "fat16" | "vfat");
        Self {
            max_file: if fat { FAT32_MAX_FILE } else { u64::MAX },
            buffer: MAX_FILL_BUFFER,
            limit: None,
        }
    }
}

fn is_disk_full(e: &std::io::Error) -> bool {
    e.kind() == std::io::ErrorKind::StorageFull
        || matches!(e.raw_os_error(), Some(28)) // ENOSPC
        || (cfg!(windows) && matches!(e.raw_os_error(), Some(39 | 112))) // HANDLE_DISK_FULL, DISK_FULL
}

/// Boş alanı `ChaCha20` anahtar akışıyla (dosya başına ayrı nonce) doldurur, fsync eder ve dosyaları siler. Yazılan bayt.
/// FAT/exFAT eski dizin girişleri, NTFS resident dosyalar ve wear-leveling nedeniyle fiziksel
/// silme garantisi **yoktur** (THREAT-MODEL › USB).
///
/// # Errors
/// G/Ç (disk dolu hariç), kesinti.
pub fn fill_free_space(root: &Path, opts: FillOptions) -> Result<u64> {
    let buf_len = opts.buffer.clamp(4096, MAX_FILL_BUFFER);
    let mut key = [0u8; 32];
    getrandom::fill(&mut key).map_err(|e| Error::Environment(format!("OS RNG: {e}")))?;
    let max_file = opts.max_file.min(MAX_KEYSTREAM_FILE);
    let mut buf = vec![0u8; buf_len];
    let mut created: Vec<PathBuf> = Vec::new();
    let mut total: u64 = 0;
    let result = (|| -> Result<()> {
        'files: for idx in 0u64.. {
            let p = root.join(format!("{FILL_PREFIX}{idx:06}"));
            let mut f = std::fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(&p)?;
            created.push(p);
            let mut nonce = [0u8; 12];
            nonce[..8].copy_from_slice(&idx.to_le_bytes());
            let mut ks = ChaCha20::new(&key.into(), &nonce.into());
            let mut in_file: u64 = 0;
            loop {
                if lephy_sys::signal::interrupted() {
                    return Err(Error::Interrupted);
                }
                let room_file = max_file - in_file;
                let room_limit = opts.limit.map_or(u64::MAX, |l| l.saturating_sub(total));
                if room_limit == 0 {
                    let _ = f.sync_all();
                    break 'files;
                }
                if room_file == 0 {
                    f.sync_all()?;
                    continue 'files;
                }
                let n = usize::try_from(room_file.min(room_limit).min(buf_len as u64))
                    .unwrap_or(buf_len);
                buf[..n].fill(0);
                ks.apply_keystream(&mut buf[..n]);
                match f.write(&buf[..n]) {
                    Ok(0) => {
                        let _ = f.sync_all();
                        break 'files;
                    }
                    Ok(k) => {
                        in_file += k as u64;
                        total += k as u64;
                    }
                    Err(e) if is_disk_full(&e) => {
                        let _ = f.sync_all();
                        break 'files;
                    }
                    Err(e) => return Err(Error::Io(e)),
                }
            }
        }
        Ok(())
    })();
    zeroize::Zeroize::zeroize(&mut key);
    for p in &created {
        let _ = std::fs::remove_file(p);
    }
    let _ = lephy_sys::fs::fsync_dir(root);
    result.map(|()| total)
}

/// Kullanıcı onayı: etiket aynen **ve** GiB tam sayı.
#[derive(Debug, Clone)]
pub struct Confirm {
    /// Yazılan etiket.
    pub label: String,
    /// Yazılan boyut (GiB).
    pub size_gib: u64,
}

/// Geri okuma türü.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Verification {
    /// Ayır + yeniden bağla sonrası okundu.
    AfterRemount,
    /// Yeniden bağlanamadı; önbellekten doğrulandı (`F_NOCACHE` mevcut sayfaları boşaltmaz).
    FromCache,
}

impl std::fmt::Display for Verification {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Verification::AfterRemount => "yeniden bağlama sonrası doğrulandı",
            Verification::FromCache => "önbellekten doğrulandı",
        })
    }
}

/// İstek.
#[derive(Debug, Clone)]
pub struct WriteRequest {
    /// Yazılacak `.lphy` dosyası.
    pub source: PathBuf,
    /// Onay.
    pub confirm: Confirm,
    /// Silme yerine exFAT biçimlendirme.
    pub format: bool,
    /// Silme/biçimlendirme sonrası boş alanı doldur.
    pub fill: bool,
    /// Doldurma seçenekleri (`None` = dosya sistemine göre).
    pub fill_opts: Option<FillOptions>,
}

/// Rapor.
#[derive(Debug, Clone)]
pub struct WriteReport {
    /// Kuru çalıştırma.
    pub dry_run: DryRun,
    /// Silinen üst düzey giriş.
    pub wiped: u64,
    /// Doldurulan bayt.
    pub filled: u64,
    /// Yazılan dosya.
    pub written: PathBuf,
    /// Yazılan bayt.
    pub bytes: u64,
    /// BLAKE3 (hex).
    pub blake3: String,
    /// Geri okuma türü.
    pub verification: Verification,
    /// Çalışan adımlar (sırayla).
    pub steps: Vec<&'static str>,
}

/// Kaynağın geçerli bir `.lphy` olduğunu doğrular (yalnızca şifreli dosyalar yazılır). Boyut.
///
/// # Errors
/// Kod 1 (geçersiz/okunamıyor).
pub fn check_source(source: &Path) -> Result<u64> {
    let mut f = std::fs::File::open(source)?;
    let mut h = [0u8; HEADER_LEN];
    f.read_exact(&mut h)
        .map_err(|_| Error::Environment("kaynak .lphy değil (başlık kısa)".into()))?;
    Header::parse(&h).map_err(|_| {
        Error::Environment("yalnızca geçerli .lphy (şifreli) dosyaları USB'ye yazılır".into())
    })?;
    Ok(f.metadata()?.len())
}

/// Taze tanım + uygunluk + kuru çalıştırma (onaydan önce gösterilir).
///
/// # Errors
/// Kod 1: uygun değil (bypass yok).
pub fn prepare(platform: &dyn Platform, target: &Path) -> Result<(Device, DryRun)> {
    let dev = platform.describe(target)?;
    dev.eligibility(platform.require_serial())
        .map_err(|why| Error::Environment(format!("hedef USB ortamı değil: {why}")))?;
    let dr = dry_run(&dev.mount)?;
    Ok((dev, dr))
}

fn recheck(platform: &dyn Platform, snap: &Device, physical_only: bool) -> Result<Device> {
    let now = platform
        .describe(&snap.mount)
        .map_err(|e| Error::Cancelled(format!("hedef aygıt yeniden okunamadı: {e}")))?;
    let a = &now.identity;
    let b = &snap.identity;
    let same_physical = a.disk == b.disk && a.size_bytes == b.size_bytes;
    let same_volume = a.volume == b.volume && a.dev_id == b.dev_id;
    if !same_physical || (!physical_only && !same_volume) {
        return Err(Error::Cancelled(
            "hedef aygıt kimliği değişti; işlem durduruldu".into(),
        ));
    }
    if let Err(why) = now.eligibility(platform.require_serial()) {
        return Err(Error::Cancelled(format!("hedef artık uygun değil: {why}")));
    }
    Ok(now)
}

fn copy_and_hash(src: &Path, dst: &Path) -> Result<(u64, String)> {
    let mut input = std::fs::File::open(src)?;
    let mut w = lephy_core::io::AtomicWriter::create(dst, false)?;
    let mut h = blake3::Hasher::new();
    let mut buf = vec![0u8; 1 << 20];
    let mut total = 0u64;
    loop {
        let n = input.read(&mut buf)?;
        if n == 0 {
            break;
        }
        h.update(&buf[..n]);
        w.file().write_all(&buf[..n])?;
        total += n as u64;
        if lephy_sys::signal::interrupted() {
            return Err(Error::Interrupted);
        }
    }
    w.commit(false)?;
    Ok((total, h.finalize().to_hex().to_string()))
}

fn hash_file(f: &mut std::fs::File) -> Result<String> {
    let mut h = blake3::Hasher::new();
    let mut buf = vec![0u8; 1 << 20];
    loop {
        let n = f.read(&mut buf)?;
        if n == 0 {
            break;
        }
        h.update(&buf[..n]);
    }
    Ok(h.finalize().to_hex().to_string())
}

/// Onaylı işlemi yürütür. `snap`: [`prepare`]'in döndürdüğü tanım.
///
/// # Errors
/// 5 (onay uyuşmazlığı, kimlik değişti), 1, 7, 8, 130.
pub fn execute(
    platform: &dyn Platform,
    snap: &Device,
    dry: DryRun,
    req: &WriteRequest,
    log: &mut dyn FnMut(&str),
) -> Result<WriteReport> {
    // 0b: onay — etiket aynen, GiB tam sayı.
    if req.confirm.label != snap.label || req.confirm.size_gib != snap.size_gib() {
        return Err(Error::Cancelled(format!(
            "onay uyuşmuyor: etiket {:?} / {} GiB bekleniyordu",
            snap.label,
            snap.size_gib()
        )));
    }
    let size = check_source(&req.source)?;
    let name = req
        .source
        .file_name()
        .ok_or_else(|| Error::Environment("kaynak dosya adı yok".into()))?
        .to_owned();
    let mut steps = Vec::new();
    let mut cur = snap.clone();

    // 1) silme ya da biçimlendirme
    cur = recheck(platform, &cur, false)?;
    let wiped = if req.format {
        steps.push("format");
        log("biçimlendiriliyor (exFAT)…");
        platform.format(&cur, &cur.label)?;
        // Biçimlendirme birim kimliğini değiştirir: fiziksel kimlik karşılaştırılır, yeni
        // birim kimliği anlık görüntü olur.
        cur = recheck(platform, &cur, true)?;
        0
    } else {
        steps.push("wipe");
        log("kullanıcı dosyaları siliniyor…");
        wipe(&cur.mount, Some(cur.identity.dev_id))?
    };

    // 2) boş alan doldurma
    let mut filled = 0;
    if req.fill {
        cur = recheck(platform, &cur, false)?;
        steps.push("fill");
        log("boş alan dolduruluyor…");
        let opts = req
            .fill_opts
            .unwrap_or_else(|| FillOptions::for_fs(&cur.fs_type));
        filled = fill_free_space(&cur.mount, opts)?;
    }

    // 3) yazma
    cur = recheck(platform, &cur, false)?;
    lephy_core::io::precheck_space(&cur.mount, size)?;
    steps.push("write");
    log("şifreli dosya yazılıyor…");
    let target = cur.mount.join(&name);
    let (bytes, digest) = copy_and_hash(&req.source, &target)?;

    // 4) geri okuma
    cur = recheck(platform, &cur, false)?;
    steps.push("verify");
    let (verification, read_path) = match platform.remount(&cur)? {
        Some(new_mount) => {
            let mut moved = cur.clone();
            moved.mount.clone_from(&new_mount);
            let _ = recheck(platform, &moved, true)?;
            (Verification::AfterRemount, new_mount.join(&name))
        }
        None => (Verification::FromCache, target.clone()),
    };
    let mut f = lephy_sys::vol::open_nocache(&read_path)?;
    let back = hash_file(&mut f)?;
    if back != digest {
        return Err(Error::Corrupt {
            at: "USB geri okuma".into(),
            detail: Some("yazılan dosyanın BLAKE3'ü kaynakla uyuşmuyor".into()),
        });
    }
    Ok(WriteReport {
        dry_run: dry,
        wiped,
        filled,
        written: read_path,
        bytes,
        blake3: digest,
        verification,
        steps,
    })
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::panic)]
mod tests {
    use super::*;
    use crate::device::{Bus, sample};
    use std::cell::{Cell, RefCell};

    /// Sahte platform: hacim = geçici dizin; `describe` çağrı sayacı ve kimlik değişimi enjekte.
    struct Fake {
        dev: RefCell<Device>,
        describes: Cell<usize>,
        change_identity_at: Option<usize>,
        remount: bool,
        formatted: Cell<bool>,
    }

    impl Fake {
        fn new(root: &Path) -> Self {
            let mut d = sample(root.to_path_buf());
            // Silme açılan tutamacın aygıt kimliğini denetler: test birimi gerçek klasördür.
            d.identity.dev_id = lephy_sys::vol::device_id(root).unwrap_or(42);
            Self {
                dev: RefCell::new(d),
                describes: Cell::new(0),
                change_identity_at: None,
                remount: false,
                formatted: Cell::new(false),
            }
        }
    }

    impl Platform for Fake {
        fn list(&self) -> Result<Vec<Device>> {
            Ok(vec![self.dev.borrow().clone()])
        }
        fn describe(&self, _mount: &Path) -> Result<Device> {
            let n = self.describes.get() + 1;
            self.describes.set(n);
            let mut d = self.dev.borrow().clone();
            if self.change_identity_at.is_some_and(|k| n >= k) {
                d.identity.disk = "BAŞKA DİSK".into();
            }
            Ok(d)
        }
        fn remount(&self, dev: &Device) -> Result<Option<PathBuf>> {
            Ok(self.remount.then(|| dev.mount.clone()))
        }
        fn format(&self, _dev: &Device, _label: &str) -> Result<()> {
            self.formatted.set(true);
            self.dev.borrow_mut().identity.volume = "YENİ-VOL".into();
            Ok(())
        }
        fn require_serial(&self) -> bool {
            true
        }
    }

    fn tmp(tag: &str) -> PathBuf {
        let d = std::env::temp_dir().join(format!("lphy-usb-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        d
    }

    fn populate(vol: &Path) {
        std::fs::create_dir_all(vol.join("belgeler/alt")).unwrap();
        std::fs::write(vol.join("belgeler/a.txt"), b"aaaa").unwrap();
        std::fs::write(vol.join("belgeler/alt/b.bin"), vec![1u8; 1000]).unwrap();
        std::fs::write(vol.join("kok.txt"), b"x").unwrap();
        for s in SYSTEM_DIRS {
            std::fs::create_dir_all(vol.join(s)).unwrap();
            std::fs::write(vol.join(s).join("keep"), b"k").unwrap();
        }
    }

    fn lphy_source(dir: &Path) -> PathBuf {
        // Geçerli bir başlıklı (biçimce) sahte .lphy: ops ile küçük KDF'li gerçek şifreleme.
        let src = dir.join("in.txt");
        std::fs::write(&src, b"usb test icerigi").unwrap();
        let out = dir.join("yedek.lphy");
        let p = lephy_core::password::normalize_nfc(
            &lephy_sys::mem::SecretBytes::from_slice(b"usb test parola").unwrap(),
        )
        .unwrap();
        let opts = lephy_core::ops::EncryptOptions {
            alg: lephy_core::cipher::AlgId::XChaCha20Poly1305,
            chunk_code: 0,
            kdf: lephy_core::kdf::KdfParams {
                m_kib: 65536,
                t: 1,
                p: 1,
            },
            force: false,
            strict_memory: false,
            raw: false,
            pad: None,
            strict: false,
            compress: false,
            ecc: false,
        };
        lephy_core::ops::encrypt(
            &lephy_core::ops::Input::Path(&src),
            &out,
            &p,
            None,
            &opts,
            &mut lephy_core::entropy::OsEntropy,
            &mut |_| {},
        )
        .unwrap();
        out
    }

    fn ok_confirm(d: &Device) -> Confirm {
        Confirm {
            label: d.label.clone(),
            size_gib: d.size_gib(),
        }
    }

    #[test]
    fn dry_run_and_wipe_empty_system_dirs_and_do_not_follow_symlinks() {
        let base = tmp("wipe");
        let vol = base.join("vol");
        std::fs::create_dir(&vol).unwrap();
        populate(&vol);
        let outside = base.join("disarida.txt");
        std::fs::write(&outside, b"dokunma").unwrap();
        #[cfg(unix)]
        {
            std::os::unix::fs::symlink(&outside, vol.join("bag")).unwrap();
            std::os::unix::fs::symlink(&base, vol.join("dizin-bag")).unwrap();
        }
        let dr = dry_run(&vol).unwrap();
        assert!(dr.first.iter().any(|p| p == "belgeler/alt/b.bin"));
        // Sistem klasörlerinin içeriği (eski çöp kutusu, Spotlight dizini) silinecekler arasında.
        assert!(
            dr.first.iter().any(|p| p == ".Trashes/keep"),
            "{:?}",
            dr.first
        );
        assert!(dr.bytes >= 1005);
        let n = wipe(&vol, Some(lephy_sys::vol::device_id(&vol).unwrap())).unwrap();
        assert!(n >= 2);
        let left: Vec<String> = std::fs::read_dir(&vol)
            .unwrap()
            .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
            .collect();
        for s in SYSTEM_DIRS {
            assert!(left.contains(&s.to_string()), "{s} klasörü kalmalı");
            assert!(
                !vol.join(s).join("keep").exists(),
                "{s} içeriği silinmeli (eski kullanıcı verisi)"
            );
        }
        assert_eq!(
            left.len(),
            SYSTEM_DIRS.len(),
            "yalnızca sistem klasörleri kalmalı: {left:?}"
        );
        assert_eq!(
            std::fs::read(&outside).unwrap(),
            b"dokunma",
            "symlink hedefi silinmemeli"
        );
        assert!(base.join("vol").exists());
        let _ = std::fs::remove_dir_all(&base);
    }

    #[cfg(unix)]
    #[test]
    fn wipe_refuses_other_device() {
        let base = tmp("wipedev");
        std::fs::write(base.join("a"), b"a").unwrap();
        let real = lephy_sys::vol::device_id(&base).unwrap();
        let e = wipe(&base, Some(real.wrapping_add(1))).unwrap_err();
        assert_eq!(e.exit_code(), lephy_core::error::ExitCode::Cancelled);
        assert!(
            base.join("a").exists(),
            "farklı aygıtta hiçbir şey silinmemeli"
        );
        let _ = std::fs::remove_dir_all(&base);
    }

    #[test]
    fn fill_multi_file_with_cap_and_cleanup() {
        let vol = tmp("fill");
        let opts = FillOptions {
            max_file: 300_000,
            buffer: 64 * 1024,
            limit: Some(1_000_000),
        };
        let n = fill_free_space(&vol, opts).unwrap();
        assert_eq!(n, 1_000_000);
        let left: Vec<_> = std::fs::read_dir(&vol).unwrap().collect();
        assert!(left.is_empty(), "doldurma dosyaları silinmeli");
        assert_eq!(FillOptions::for_fs("msdos").max_file, FAT32_MAX_FILE);
        assert_eq!(FillOptions::for_fs("exfat").buffer, MAX_FILL_BUFFER);
        assert!(FillOptions::for_fs("apfs").max_file > FAT32_MAX_FILE);
        let _ = std::fs::remove_dir_all(&vol);
    }

    #[test]
    fn full_flow_writes_verifies_and_records_steps() {
        let base = tmp("flow");
        let vol = base.join("vol");
        std::fs::create_dir(&vol).unwrap();
        populate(&vol);
        let src = lphy_source(&base);
        for remount in [false, true] {
            let mut fake = Fake::new(&vol);
            fake.remount = remount;
            let (dev, dr) = prepare(&fake, &vol).unwrap();
            let req = WriteRequest {
                source: src.clone(),
                confirm: ok_confirm(&dev),
                format: false,
                fill: true,
                fill_opts: Some(FillOptions {
                    max_file: 100_000,
                    buffer: 4096,
                    limit: Some(250_000),
                }),
            };
            let rep = execute(&fake, &dev, dr, &req, &mut |_| {}).unwrap();
            assert_eq!(rep.steps, vec!["wipe", "fill", "write", "verify"]);
            assert_eq!(rep.filled, 250_000);
            assert_eq!(
                std::fs::read(vol.join("yedek.lphy")).unwrap(),
                std::fs::read(&src).unwrap()
            );
            assert_eq!(
                rep.verification,
                if remount {
                    Verification::AfterRemount
                } else {
                    Verification::FromCache
                }
            );
            assert_eq!(
                rep.verification.to_string().contains("önbellekten"),
                !remount
            );
            assert!(!vol.join("belgeler").exists());
            std::fs::remove_file(vol.join("yedek.lphy")).unwrap();
            populate(&vol);
        }
        let _ = std::fs::remove_dir_all(&base);
    }

    #[test]
    fn wrong_label_or_size_is_code_5_and_nothing_deleted() {
        let base = tmp("confirm");
        let vol = base.join("vol");
        std::fs::create_dir(&vol).unwrap();
        populate(&vol);
        let src = lphy_source(&base);
        let fake = Fake::new(&vol);
        let (dev, dr) = prepare(&fake, &vol).unwrap();
        for c in [
            Confirm {
                label: "lephytest".into(),
                size_gib: dev.size_gib(),
            },
            Confirm {
                label: dev.label.clone(),
                size_gib: dev.size_gib() + 1,
            },
        ] {
            let req = WriteRequest {
                source: src.clone(),
                confirm: c,
                format: false,
                fill: false,
                fill_opts: None,
            };
            let e = execute(&fake, &dev, dr.clone(), &req, &mut |_| {}).unwrap_err();
            assert_eq!(e.exit_code(), lephy_core::error::ExitCode::Cancelled);
            assert!(
                vol.join("belgeler/a.txt").exists(),
                "hiçbir dosya silinmemeli"
            );
        }
        let _ = std::fs::remove_dir_all(&base);
    }

    #[test]
    fn identity_change_between_steps_is_code_5_and_later_steps_do_not_run() {
        let base = tmp("ident");
        let vol = base.join("vol");
        std::fs::create_dir(&vol).unwrap();
        populate(&vol);
        let src = lphy_source(&base);
        // describe #1: prepare, #2: silme öncesi (aynı), #3: doldurma öncesi → değişti.
        let mut fake = Fake::new(&vol);
        fake.change_identity_at = Some(3);
        let (dev, dr) = prepare(&fake, &vol).unwrap();
        let req = WriteRequest {
            source: src.clone(),
            confirm: ok_confirm(&dev),
            format: false,
            fill: true,
            fill_opts: Some(FillOptions {
                max_file: 1000,
                buffer: 4096,
                limit: Some(1000),
            }),
        };
        let e = execute(&fake, &dev, dr, &req, &mut |_| {}).unwrap_err();
        assert_eq!(e.exit_code(), lephy_core::error::ExitCode::Cancelled);
        assert!(!vol.join("yedek.lphy").exists(), "yazma adımı çalışmamalı");
        assert_eq!(fake.describes.get(), 3);
        // Silme öncesinde değişirse hiçbir şey silinmez.
        populate(&vol);
        let mut fake = Fake::new(&vol);
        fake.change_identity_at = Some(2);
        let (dev, dr) = prepare(&fake, &vol).unwrap();
        let req = WriteRequest {
            source: src,
            confirm: ok_confirm(&dev),
            format: false,
            fill: false,
            fill_opts: None,
        };
        assert!(execute(&fake, &dev, dr, &req, &mut |_| {}).is_err());
        assert!(vol.join("belgeler/a.txt").exists());
        let _ = std::fs::remove_dir_all(&base);
    }

    #[test]
    fn ineligible_target_is_code_1_without_bypass() {
        let vol = tmp("inelig");
        let fake = Fake::new(&vol);
        fake.dev.borrow_mut().bus = Bus::Other("SATA".into());
        let e = prepare(&fake, &vol).unwrap_err();
        assert_eq!(e.exit_code(), lephy_core::error::ExitCode::Io);
        fake.dev.borrow_mut().bus = Bus::Usb;
        fake.dev.borrow_mut().serial = Some(String::new());
        assert!(prepare(&fake, &vol).is_err(), "boş seri reddedilmeli");
        let _ = std::fs::remove_dir_all(&vol);
    }

    #[test]
    fn non_lphy_source_rejected_and_format_path_rechecks_physical_identity() {
        let base = tmp("fmt");
        let vol = base.join("vol");
        std::fs::create_dir(&vol).unwrap();
        let plain = base.join("duz.txt");
        std::fs::write(&plain, vec![b'a'; 400]).unwrap();
        let fake = Fake::new(&vol);
        let (dev, dr) = prepare(&fake, &vol).unwrap();
        let req = WriteRequest {
            source: plain,
            confirm: ok_confirm(&dev),
            format: false,
            fill: false,
            fill_opts: None,
        };
        let e = execute(&fake, &dev, dr.clone(), &req, &mut |_| {}).unwrap_err();
        assert!(e.to_string().contains(".lphy"));
        let src = lphy_source(&base);
        let req = WriteRequest {
            source: src,
            confirm: ok_confirm(&dev),
            format: true,
            fill: false,
            fill_opts: None,
        };
        let rep = execute(&fake, &dev, dr, &req, &mut |_| {}).unwrap();
        assert!(fake.formatted.get());
        assert_eq!(rep.steps, vec!["format", "write", "verify"]);
        let _ = std::fs::remove_dir_all(&base);
    }
}
