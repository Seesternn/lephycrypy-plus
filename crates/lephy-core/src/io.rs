//! Atomik yazma ve tmp yönetimi.
//!
//! - Tmp adı `.lphy-tmp-<16 hex>` (macOS'ta `.noindex` sonekli; Windows'ta
//!   `FILE_ATTRIBUTE_NOT_CONTENT_INDEXED`), hedef dizinde, `create_new`, 0600.
//! - [`AtomicWriter::commit`]: `sync_all` → noclobber rename (`--force`: replace) → dizin fsync.
//!   Noclobber desteklenmeyen FS'de `lstat` + düz rename geri dönüşü ve uyarı (yarış penceresi
//!   THREAT-MODEL'de).
//! - Tmp yolu panik hook'u için `lephy_sys::fs::tmp_register` ile kayda alınır; Drop'ta
//!   (commit edilmediyse) silinir.
//! - [`scan_stale`] / [`cleanup`]: bayat tmp'ler. [`precheck_space`]: kod 8.

use std::fs::{File, OpenOptions};
use std::path::{Path, PathBuf};

use crate::entropy::{Entropy, OsEntropy};
use crate::error::{Error, Result};

/// Tmp ad öneki.
pub const TMP_PREFIX: &str = ".lphy-tmp-";
/// FAT32 dosya boyutu sınırı.
pub const FAT32_MAX: u64 = 4 * 1024 * 1024 * 1024 - 1;

fn hex16(entropy: &mut dyn Entropy) -> Result<String> {
    use std::fmt::Write as _;
    let mut b = [0u8; 8];
    entropy.fill(&mut b)?;
    Ok(b.iter().fold(String::with_capacity(16), |mut acc, x| {
        let _ = write!(acc, "{x:02x}");
        acc
    }))
}

/// Hedef dizinde yeni tmp adı.
///
/// # Errors
/// RNG hatası.
pub fn tmp_name(entropy: &mut dyn Entropy) -> Result<String> {
    let mut s = format!("{TMP_PREFIX}{}", hex16(entropy)?);
    if cfg!(target_os = "macos") {
        s.push_str(".noindex");
    }
    Ok(s)
}

/// Commit sonucu.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CommitOutcome {
    /// Noclobber desteklenmediği için kontrol-sonra-rename yoluna düşüldü (uyarı gerekir).
    pub noclobber_fallback: bool,
}

/// Atomik dosya yazıcısı.
pub struct AtomicWriter {
    file: Option<File>,
    tmp_path: PathBuf,
    target: PathBuf,
    tmp_id: lephy_sys::fs::TmpId,
    committed: bool,
}

impl AtomicWriter {
    /// `target`'ın dizininde tmp dosyası oluşturur. Hedef varsa ve `force` değilse kod 7 — bu
    /// denetim hem burada (erken) hem commit'te (atomik) yapılır.
    ///
    /// # Errors
    /// Kod 7 (`Exists`), kod 1 (G/Ç).
    pub fn create(target: &Path, force: bool) -> Result<Self> {
        if !force && target.symlink_metadata().is_ok() {
            return Err(Error::Exists(target.display().to_string()));
        }
        let dir = target
            .parent()
            .filter(|p| !p.as_os_str().is_empty())
            .map_or_else(|| PathBuf::from("."), Path::to_path_buf);
        let mut entropy = OsEntropy;
        let mut opts = OpenOptions::new();
        opts.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            opts.mode(0o600);
        }
        // Ad çakışmasında (16 hex) yeniden dene.
        let (file, tmp_path) = loop {
            let p = dir.join(tmp_name(&mut entropy)?);
            match opts.open(&p) {
                Ok(f) => break (f, p),
                Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {}
                Err(e) => return Err(Error::Io(e)),
            }
        };
        let _ = lephy_sys::fs::mark_not_content_indexed(&tmp_path);
        let tmp_id = lephy_sys::fs::tmp_register(&tmp_path)?;
        Ok(Self {
            file: Some(file),
            tmp_path,
            target: target.to_path_buf(),
            tmp_id,
            committed: false,
        })
    }

    /// Yazılacak dosya.
    ///
    /// # Panics
    /// Olmaz: `file` yalnızca `commit` içinde alınır.
    #[allow(clippy::missing_panics_doc, clippy::expect_used)]
    pub fn file(&mut self) -> &mut File {
        self.file.as_mut().expect("AtomicWriter: file")
    }

    /// Tmp yolu (test/teşhis).
    #[must_use]
    pub fn tmp_path(&self) -> &Path {
        &self.tmp_path
    }

    /// Unix'te hedef izinlerini ayarlar (son adım); diğerlerinde no-op.
    ///
    /// # Errors
    /// G/Ç.
    pub fn set_mode(&mut self, mode: u32) -> Result<()> {
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            self.file()
                .set_permissions(std::fs::Permissions::from_mode(mode & 0o777))?;
        }
        let _ = mode;
        Ok(())
    }

    /// fsync → rename → dizin fsync.
    ///
    /// # Errors
    /// Kod 7 (hedef var), kod 1.
    pub fn commit(mut self, force: bool) -> Result<CommitOutcome> {
        let file = self
            .file
            .take()
            .ok_or_else(|| Error::Environment("AtomicWriter yeniden commit".into()))?;
        file.sync_all()?;
        drop(file);
        let mut outcome = CommitOutcome {
            noclobber_fallback: false,
        };
        if force {
            lephy_sys::fs::rename_replace(&self.tmp_path, &self.target)?;
        } else {
            match lephy_sys::fs::rename_noclobber(&self.tmp_path, &self.target) {
                Ok(()) => {}
                Err(lephy_sys::fs::NoclobberError::Exists) => {
                    return Err(Error::Exists(self.target.display().to_string()));
                }
                Err(lephy_sys::fs::NoclobberError::Unsupported) => {
                    // Geri dönüş: kontrol-sonra-rename (yarış penceresi THREAT-MODEL'de).
                    if self.target.symlink_metadata().is_ok() {
                        return Err(Error::Exists(self.target.display().to_string()));
                    }
                    lephy_sys::fs::rename_replace(&self.tmp_path, &self.target)?;
                    outcome.noclobber_fallback = true;
                }
                Err(lephy_sys::fs::NoclobberError::Io(e)) => return Err(Error::Io(e)),
            }
        }
        self.committed = true;
        lephy_sys::fs::tmp_unregister(self.tmp_id);
        if let Some(dir) = self.target.parent().filter(|p| !p.as_os_str().is_empty()) {
            let _ = lephy_sys::fs::fsync_dir(dir);
        } else {
            let _ = lephy_sys::fs::fsync_dir(Path::new("."));
        }
        Ok(outcome)
    }
}

impl Drop for AtomicWriter {
    fn drop(&mut self) {
        if !self.committed {
            drop(self.file.take());
            let _ = std::fs::remove_file(&self.tmp_path);
            lephy_sys::fs::tmp_unregister(self.tmp_id);
        }
    }
}

/// Dizindeki bayat tmp dosyaları (`.lphy-tmp-*`, `.noindex` soneki dahil).
///
/// # Errors
/// Dizin okunamadı.
pub fn scan_stale(dir: &Path) -> Result<Vec<PathBuf>> {
    let mut out = Vec::new();
    for e in std::fs::read_dir(dir)? {
        let e = e?;
        if e.file_name().to_string_lossy().starts_with(TMP_PREFIX) {
            out.push(e.path());
        }
    }
    out.sort();
    Ok(out)
}

/// Verilen tmp yollarını siler (onay çağıranda). Silinen sayı.
///
/// # Errors
/// G/Ç.
pub fn cleanup(paths: &[PathBuf]) -> Result<usize> {
    let mut n = 0;
    for p in paths {
        let md = p.symlink_metadata()?;
        if md.is_dir() {
            std::fs::remove_dir_all(p)?;
        } else {
            std::fs::remove_file(p)?;
        }
        n += 1;
    }
    Ok(n)
}

/// Boş alan ve FAT32 ön kontrolü (kod 8). `needed` = tahmini çıktı boyutu.
///
/// # Errors
/// `Error::DiskSpace`.
pub fn precheck_space(dir: &Path, needed: u64) -> Result<()> {
    if let Some(free) = lephy_sys::fs::free_space(dir)
        .ok()
        .filter(|free| *free < needed)
    {
        return Err(Error::DiskSpace(format!(
            "~{} MiB gerekli, {} MiB boş",
            needed / 1024 / 1024,
            free / 1024 / 1024
        )));
    }
    if needed > FAT32_MAX && lephy_sys::fs::is_fat(dir).unwrap_or(false) {
        return Err(Error::DiskSpace(
            "FAT32 birimde dosya 4 GiB'ı aşamaz".into(),
        ));
    }
    Ok(())
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::panic)]
mod tests {
    use super::*;
    use std::io::Write;

    fn tmpdir(tag: &str) -> PathBuf {
        let d = std::env::temp_dir().join(format!("lphy-io-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        d
    }

    #[test]
    fn commit_moves_tmp_to_target_and_leaves_no_tmp() {
        let d = tmpdir("commit");
        let target = d.join("out.lphy");
        let mut w = AtomicWriter::create(&target, false).unwrap();
        assert!(
            w.tmp_path()
                .file_name()
                .unwrap()
                .to_string_lossy()
                .starts_with(TMP_PREFIX)
        );
        if cfg!(target_os = "macos") {
            assert!(w.tmp_path().to_string_lossy().ends_with(".noindex"));
        }
        w.file().write_all(b"data").unwrap();
        w.commit(false).unwrap();
        assert_eq!(std::fs::read(&target).unwrap(), b"data");
        assert!(scan_stale(&d).unwrap().is_empty());
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(
                std::fs::metadata(&target).unwrap().permissions().mode() & 0o777,
                0o600
            );
        }
        let _ = std::fs::remove_dir_all(&d);
    }

    #[test]
    fn drop_without_commit_removes_tmp() {
        let d = tmpdir("drop");
        let target = d.join("out.lphy");
        {
            let mut w = AtomicWriter::create(&target, false).unwrap();
            w.file().write_all(b"x").unwrap();
        }
        assert!(!target.exists());
        assert!(scan_stale(&d).unwrap().is_empty());
        let _ = std::fs::remove_dir_all(&d);
    }

    #[test]
    fn existing_target_is_code_7_unless_force() {
        let d = tmpdir("exists");
        let target = d.join("out.lphy");
        std::fs::write(&target, b"old").unwrap();
        assert!(matches!(
            AtomicWriter::create(&target, false),
            Err(Error::Exists(_))
        ));
        let mut w = AtomicWriter::create(&target, true).unwrap();
        w.file().write_all(b"new").unwrap();
        w.commit(true).unwrap();
        assert_eq!(std::fs::read(&target).unwrap(), b"new");
        let _ = std::fs::remove_dir_all(&d);
    }

    #[test]
    fn stale_scan_and_cleanup() {
        let d = tmpdir("stale");
        let p = d.join(".lphy-tmp-0011223344556677.noindex");
        std::fs::write(&p, b"x").unwrap();
        let s = scan_stale(&d).unwrap();
        assert_eq!(s, vec![p.clone()]);
        assert_eq!(cleanup(&s).unwrap(), 1);
        assert!(!p.exists());
        let _ = std::fs::remove_dir_all(&d);
    }
}
