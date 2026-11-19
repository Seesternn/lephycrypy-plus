//! Folder vault: an encrypted folder (`.lphy` archive locked with a password) is decrypted once
//! into a private place, worked on like a normal folder, and "Save and lock" encrypts it again
//! with the same password and settings, replaces the original atomically and destroys the open
//! copy.
//!
//! The place is a RAM disk on macOS (decrypted data never reaches the SSD) and a hidden,
//! non-indexed folder in `%LOCALAPPDATA%` on Windows (overwritten once, then removed, when
//! closed). While a vault is open its password stays in locked memory: locking needs it.

use std::path::{Path, PathBuf};

use lephy_core::cipher::AlgId;
use lephy_core::entropy::{Entropy, OsEntropy};
use lephy_core::error::{Error, Result};
use lephy_core::header::ContentType;
use lephy_core::kdf::KdfParams;
use lephy_core::ops::{self, DecryptOptions, EncryptOptions, Input, Output, UnlockOptions};
use lephy_core::password;
use lephy_sys::mem::SecretBytes;
use lephy_sys::ramdisk::RamDisk;

use crate::i18n::tr;

/// Where the open vault lives.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Place {
    /// macOS RAM disk.
    Ram(RamDisk),
    /// A private folder (Windows; also used by the tests).
    Folder(PathBuf),
}

impl Place {
    /// Base directory of the place.
    #[must_use]
    pub fn base(&self) -> &Path {
        match self {
            Self::Ram(d) => &d.mount,
            Self::Folder(p) => p,
        }
    }
}

/// An open vault.
pub struct Vault {
    /// The encrypted file it came from (replaced on lock).
    pub source: PathBuf,
    /// Where the open copy is.
    pub place: Place,
    /// The open folder.
    pub root: PathBuf,
    nfc: SecretBytes,
    keyfile: Option<zeroize::Zeroizing<[u8; 32]>>,
    alg: AlgId,
    kdf: KdfParams,
    pad: bool,
    compress: bool,
    opened: [u8; 32],
}

/// Why a file cannot be opened as a vault (`None`: it can).
#[must_use]
pub fn unsuitable(path: &Path) -> Option<&'static str> {
    let name = path.to_string_lossy().to_lowercase();
    if lephy_core::split::is_first_part(path) || name.ends_with(".001") {
        return Some(tr(
            "Parçalı dosyalar kasa olarak açılamaz.",
            "Split files cannot be opened as a vault.",
        ));
    }
    let mut magic = [0u8; 8];
    if std::fs::File::open(path)
        .and_then(|mut f| std::io::Read::read_exact(&mut f, &mut magic))
        .is_ok()
        && magic == lephy_core::envelope::MAGIC
    {
        return Some(tr(
            "Hata düzeltmeli dosyalar kasa olarak açılamaz.",
            "Files with error correction cannot be opened as a vault.",
        ));
    }
    match ops::info(path) {
        Err(_) => Some(tr("Dosya okunamadı.", "The file could not be read.")),
        Ok(h) if h.recipients > 0 => Some(tr(
            "Açık anahtarla şifrelenmiş dosyalar kasa olarak açılamaz (yeniden şifrelemek için alıcıların anahtarları gerekir).",
            "Files encrypted to public keys cannot be opened as a vault (locking again needs the recipients' keys).",
        )),
        Ok(h) if h.content_type != ContentType::Archive => Some(tr(
            "Yalnızca şifreli klasörler kasa olarak açılabilir.",
            "Only encrypted folders can be opened as a vault.",
        )),
        Ok(_) => None,
    }
}

/// A short random ASCII tag for names.
fn tag() -> Result<String> {
    let mut b = [0u8; 6];
    OsEntropy.fill(&mut b)?;
    Ok(b.iter().fold(String::new(), |mut s, x| {
        use std::fmt::Write as _;
        let _ = write!(s, "{x:02x}");
        s
    }))
}

/// Private folder for Windows vaults: `%LOCALAPPDATA%\lephycrypy+\vaults`.
#[must_use]
pub fn folder_base() -> Option<PathBuf> {
    lephy_sys::fs::app_local_dir().map(|d| d.join("vaults"))
}

/// Makes the place. `folder`: use a private folder under it instead of a RAM disk.
fn make_place(content: u64, folder: Option<&Path>) -> Result<Place> {
    let t = tag()?;
    if let Some(base) = folder {
        let dir = base.join(&t);
        if lephy_sys::fs::cloud_root_of(&dir).is_some() {
            return Err(Error::Environment(
                tr(
                    "kasa klasörü bir bulut senkron klasöründe olamaz",
                    "the vault folder cannot be in a cloud-sync folder",
                )
                .into(),
            ));
        }
        std::fs::create_dir_all(&dir)?;
        let _ = lephy_sys::fs::mark_not_content_indexed(&dir);
        return Ok(Place::Folder(dir));
    }
    let size = lephy_sys::ramdisk::size_for(content);
    if let Some(mem) = lephy_sys::ramdisk::memory_bytes()
        && size > mem / 2
    {
        return Err(Error::Environment(
            tr(
                "kasa bu bilgisayarın belleğine sığmıyor",
                "the vault does not fit in this computer's memory",
            )
            .into(),
        ));
    }
    Ok(Place::Ram(lephy_sys::ramdisk::create(&t, size)?))
}

/// Overwrites every regular file once with random data, then removes the tree. Symbolic links
/// are removed, not followed.
fn wipe_tree(root: &Path) -> std::io::Result<()> {
    let mut stack = vec![root.to_path_buf()];
    while let Some(p) = stack.pop() {
        let Ok(md) = p.symlink_metadata() else {
            continue;
        };
        if md.is_dir() {
            if let Ok(rd) = std::fs::read_dir(&p) {
                stack.extend(rd.flatten().map(|e| e.path()));
            }
        } else if md.is_file() {
            let mut left = md.len();
            if let Ok(f) = std::fs::OpenOptions::new().write(true).open(&p) {
                let mut buf = zeroize::Zeroizing::new(vec![0u8; 1 << 20]);
                let mut w = &f;
                while left > 0 {
                    let n = usize::try_from(left.min(buf.len() as u64)).unwrap_or(buf.len());
                    if OsEntropy.fill(&mut buf[..n]).is_err() {
                        break;
                    }
                    if std::io::Write::write_all(&mut w, &buf[..n]).is_err() {
                        break;
                    }
                    left -= n as u64;
                }
                let _ = f.sync_all();
            }
        }
    }
    std::fs::remove_dir_all(root)
}

/// Destroys a place: detach the RAM disk, or wipe and remove the folder.
///
/// # Errors
/// A program still has a file open (RAM disk without `force`), or I/O.
pub fn destroy_place(place: &Place, force: bool) -> std::io::Result<()> {
    match place {
        Place::Ram(d) => lephy_sys::ramdisk::destroy(d, force),
        Place::Folder(p) => wipe_tree(p),
    }
}

/// Fingerprint of a tree: paths, kinds, sizes and modification times (BLAKE3).
fn fingerprint(root: &Path) -> [u8; 32] {
    let mut items = Vec::new();
    let mut stack = vec![root.to_path_buf()];
    while let Some(p) = stack.pop() {
        let Ok(md) = p.symlink_metadata() else {
            continue;
        };
        let rel = p
            .strip_prefix(root)
            .unwrap_or(&p)
            .to_string_lossy()
            .into_owned();
        let mtime = md
            .modified()
            .ok()
            .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
            .map_or(0, |d| d.as_nanos());
        items.push(format!("{rel}\0{}\0{}\0{mtime}", md.is_dir(), md.len()));
        if md.is_dir()
            && let Ok(rd) = std::fs::read_dir(&p)
        {
            stack.extend(rd.flatten().map(|e| e.path()));
        }
    }
    items.sort();
    let mut h = blake3::Hasher::new();
    for i in &items {
        h.update(i.as_bytes());
        h.update(b"\n");
    }
    *h.finalize().as_bytes()
}

/// The folder name of a vault: the encrypted file's name without `.lphy`.
fn folder_name(source: &Path) -> String {
    let n = source
        .file_name()
        .map(|f| f.to_string_lossy().into_owned())
        .unwrap_or_default();
    let n = n.strip_suffix(".lphy").unwrap_or(&n).to_owned();
    if n.is_empty() { "vault".into() } else { n }
}

impl Vault {
    /// Opens `source` into a new place. `folder`: a private folder base instead of a RAM disk.
    ///
    /// # Errors
    /// Unsuitable file, wrong password, no room, I/O. The place is destroyed again on failure.
    pub fn open(
        source: &Path,
        password: &SecretBytes,
        keyfile: Option<&Path>,
        folder: Option<&Path>,
    ) -> Result<Self> {
        if let Some(why) = unsuitable(source) {
            return Err(Error::Environment(why.into()));
        }
        let h = ops::info(source)?;
        let nfc = password::normalize_nfc(password)?;
        let kf = keyfile
            .map(password::keyfile_digest_from_path)
            .transpose()?;
        let content = crate::logic::estimate_total(crate::logic::Mode::Decrypt, source);
        let place = make_place(content, folder)?;
        let root = place.base().join(folder_name(source));
        let r = ops::decrypt(
            source,
            &Output::Path(&root, false),
            &nfc,
            kf.as_deref(),
            DecryptOptions {
                unlock: UnlockOptions::default(),
                ..DecryptOptions::default()
            },
            &mut |_| {},
        );
        let fail = |e: Error| {
            let _ = destroy_place(&place, true);
            e
        };
        r.map_err(fail)?;
        if !root.is_dir() {
            return Err(fail(Error::Environment(
                tr(
                    "bu arşiv bir klasör değil, tek bir dosya; kasa yalnızca klasörler için",
                    "this archive holds a single file, not a folder; vaults are for folders",
                )
                .into(),
            )));
        }
        let opened = fingerprint(&root);
        Ok(Self {
            source: source.to_path_buf(),
            place,
            root,
            nfc,
            keyfile: kf,
            alg: h.alg,
            kdf: h.kdf,
            pad: h.padded,
            compress: h.compressed,
            opened,
        })
    }

    /// Creates a new, empty vault at `dest` (a `.lphy` that must not exist yet) with default
    /// settings, then opens it. The password must meet the encryption policy.
    ///
    /// # Errors
    /// `dest` exists, weak password, I/O, or as [`Self::open`].
    pub fn create(
        dest: &Path,
        password: &SecretBytes,
        keyfile: Option<&Path>,
        folder: Option<&Path>,
    ) -> Result<Self> {
        if dest.symlink_metadata().is_ok() {
            return Err(Error::Exists(dest.display().to_string()));
        }
        let nfc = password::normalize_nfc(password)?;
        password::check_encrypt_policy(&nfc)?;
        let kf = keyfile
            .map(password::keyfile_digest_from_path)
            .transpose()?;
        let empty = std::env::temp_dir()
            .join(format!("lphy-new-{}", tag()?))
            .join(folder_name(dest));
        std::fs::create_dir_all(&empty)?;
        let opts = EncryptOptions {
            alg: AlgId::XChaCha20Poly1305,
            chunk_code: 2,
            kdf: KdfParams::DEFAULT,
            force: false,
            strict_memory: false,
            raw: false,
            pad: Some(true),
            strict: false,
            compress: false,
            ecc: false,
        };
        let r = ops::encrypt(
            &Input::Path(&empty),
            dest,
            &nfc,
            kf.as_deref(),
            &opts,
            &mut OsEntropy,
            &mut |_| {},
        );
        if let Some(parent) = empty.parent() {
            let _ = std::fs::remove_dir_all(parent);
        }
        r?;
        Self::open(dest, password, keyfile, folder)
    }

    /// A second handle on the same open vault (secrets copied into locked memory), for the
    /// background watch that locks it while the window cannot run.
    #[must_use]
    pub fn duplicate(&self) -> Option<Self> {
        Some(Self {
            source: self.source.clone(),
            place: self.place.clone(),
            root: self.root.clone(),
            nfc: SecretBytes::from_slice(self.nfc.expose()).ok()?,
            keyfile: self.keyfile.clone(),
            alg: self.alg,
            kdf: self.kdf,
            pad: self.pad,
            compress: self.compress,
            opened: self.opened,
        })
    }

    /// Something in the folder changed since it was opened.
    #[must_use]
    pub fn changed(&self) -> bool {
        fingerprint(&self.root) != self.opened
    }

    /// Encrypts the folder again next to the original, verifies it and replaces the original
    /// atomically. The open copy is left in place (close it with [`Self::close`]). On any error
    /// the original is untouched.
    ///
    /// # Errors
    /// I/O, no room, a file in use, interruption.
    pub fn save(&mut self) -> Result<()> {
        let dir = self
            .source
            .parent()
            .filter(|d| !d.as_os_str().is_empty())
            .unwrap_or(Path::new("."));
        let tmp = dir.join(lephy_core::io::tmp_name(&mut OsEntropy)?);
        let opts = EncryptOptions {
            alg: self.alg,
            chunk_code: 2,
            kdf: self.kdf,
            force: false,
            strict_memory: false,
            raw: false,
            pad: Some(self.pad),
            strict: false,
            compress: self.compress,
            ecc: false,
        };
        let kf = self.keyfile.as_deref();
        let r = ops::encrypt(
            &Input::Path(&self.root),
            &tmp,
            &self.nfc,
            kf,
            &opts,
            &mut OsEntropy,
            &mut |_| {},
        )
        .and_then(|_| {
            ops::verify(
                &tmp,
                &self.nfc,
                kf,
                UnlockOptions {
                    allow_large_kdf: true,
                    ..UnlockOptions::default()
                },
                &mut |_| {},
            )
        })
        .and_then(|_| lephy_sys::fs::rename_replace(&tmp, &self.source).map_err(Error::from));
        if r.is_err() {
            let _ = std::fs::remove_file(&tmp);
        }
        r?;
        let _ = lephy_sys::fs::fsync_dir(dir);
        self.opened = fingerprint(&self.root);
        Ok(())
    }

    /// Destroys the open copy (without saving). `force`: detach even if a program still has a
    /// file open.
    ///
    /// # Errors
    /// Busy RAM disk or I/O; the vault stays open then.
    pub fn close(&self, force: bool) -> std::io::Result<()> {
        destroy_place(&self.place, force)
    }
}

/// Vault places left from an earlier run (a crash): RAM disks on macOS, folders elsewhere.
#[must_use]
pub fn leftovers() -> Vec<Place> {
    let mut out: Vec<Place> = lephy_sys::ramdisk::leftovers()
        .into_iter()
        .map(Place::Ram)
        .collect();
    if cfg!(windows)
        && let Some(base) = folder_base()
        && let Ok(rd) = std::fs::read_dir(base)
    {
        out.extend(
            rd.flatten()
                .filter(|e| e.path().is_dir())
                .map(|e| Place::Folder(e.path())),
        );
    }
    out
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    fn secret(s: &str) -> SecretBytes {
        SecretBytes::from_slice(s.as_bytes()).unwrap()
    }

    fn encrypt_folder(src: &Path, out: &Path, pw: &str) {
        let opts = EncryptOptions {
            alg: AlgId::XChaCha20Poly1305,
            chunk_code: 2,
            kdf: KdfParams {
                m_kib: 64 * 1024,
                ..KdfParams::DEFAULT
            },
            force: false,
            strict_memory: false,
            raw: false,
            pad: Some(true),
            strict: false,
            compress: false,
            ecc: false,
        };
        ops::encrypt(
            &Input::Path(src),
            out,
            &password::normalize_nfc(&secret(pw)).unwrap(),
            None,
            &opts,
            &mut OsEntropy,
            &mut |_| {},
        )
        .unwrap();
    }

    #[test]
    fn open_change_save_close_roundtrip() {
        let d = std::env::temp_dir().join(format!("lphy-vault-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(d.join("work/sub")).unwrap();
        std::fs::write(d.join("work/a.txt"), b"one").unwrap();
        std::fs::write(d.join("work/sub/b.txt"), b"two").unwrap();
        let lphy = d.join("work.lphy");
        encrypt_folder(&d.join("work"), &lphy, "vault pass 1234");
        let base = d.join("places");
        let pw = secret("vault pass 1234");

        // Unchanged: closing leaves the file byte for byte.
        let before = std::fs::read(&lphy).unwrap();
        let v = Vault::open(&lphy, &pw, None, Some(&base)).unwrap();
        assert_eq!(std::fs::read(v.root.join("sub/b.txt")).unwrap(), b"two");
        assert!(!v.changed());
        v.close(false).unwrap();
        assert!(!v.place.base().exists());
        assert_eq!(std::fs::read(&lphy).unwrap(), before);

        // Change, save, close: the file holds the change and opens with the same password.
        let mut v = Vault::open(&lphy, &pw, None, Some(&base)).unwrap();
        std::fs::write(v.root.join("new.txt"), b"added").unwrap();
        std::fs::write(v.root.join("a.txt"), b"one, edited").unwrap();
        assert!(v.changed());
        v.save().unwrap();
        assert!(!v.changed());
        v.close(false).unwrap();
        let v = Vault::open(&lphy, &pw, None, Some(&base)).unwrap();
        assert_eq!(std::fs::read(v.root.join("new.txt")).unwrap(), b"added");
        assert_eq!(std::fs::read(v.root.join("a.txt")).unwrap(), b"one, edited");
        v.close(false).unwrap();
        // No temp file is left next to the original.
        let names: Vec<_> = std::fs::read_dir(&d)
            .unwrap()
            .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
            .collect();
        assert!(
            names.iter().all(|n| !n.starts_with(".lphy-tmp")),
            "{names:?}"
        );
        // A wrong password opens nothing and leaves no place behind.
        assert!(Vault::open(&lphy, &secret("wrong pass 0000"), None, Some(&base)).is_err());
        assert_eq!(std::fs::read_dir(&base).unwrap().count(), 0);
        let _ = std::fs::remove_dir_all(&d);
    }

    /// The real thing on macOS: a RAM disk. Run by hand with `--ignored`.
    #[test]
    #[ignore = "attaches a real RAM disk"]
    fn ram_disk_vault() {
        let d = std::env::temp_dir().join(format!("lphy-vault-ram-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(d.join("work")).unwrap();
        std::fs::write(d.join("work/a.txt"), b"one").unwrap();
        let lphy = d.join("work.lphy");
        encrypt_folder(&d.join("work"), &lphy, "vault pass 1234");
        let mut v = Vault::open(&lphy, &secret("vault pass 1234"), None, None).unwrap();
        assert!(matches!(v.place, Place::Ram(_)));
        assert!(v.root.starts_with("/Volumes"));
        std::fs::write(v.root.join("b.txt"), b"two").unwrap();
        v.save().unwrap();
        v.close(false).unwrap();
        assert!(!v.root.exists());
        assert!(lephy_sys::ramdisk::leftovers().is_empty());
        let v = Vault::open(&lphy, &secret("vault pass 1234"), None, Some(&d.join("p"))).unwrap();
        assert_eq!(std::fs::read(v.root.join("b.txt")).unwrap(), b"two");
        v.close(false).unwrap();
        let _ = std::fs::remove_dir_all(&d);
    }

    #[test]
    fn create_an_empty_vault() {
        let d = std::env::temp_dir().join(format!("lphy-vault-new-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        let dest = d.join("Notlar.lphy");
        let pw = secret("new vault pass 1234");
        let mut v = Vault::create(&dest, &pw, None, Some(&d.join("p"))).unwrap();
        assert!(v.root.ends_with("Notlar"));
        assert_eq!(std::fs::read_dir(&v.root).unwrap().count(), 0);
        std::fs::write(v.root.join("ilk.txt"), b"hello").unwrap();
        v.save().unwrap();
        v.close(false).unwrap();
        let v = Vault::open(&dest, &pw, None, Some(&d.join("p"))).unwrap();
        assert_eq!(std::fs::read(v.root.join("ilk.txt")).unwrap(), b"hello");
        v.close(false).unwrap();
        // Never over an existing file, never with a weak password.
        assert!(Vault::create(&dest, &pw, None, Some(&d.join("p"))).is_err());
        assert!(
            Vault::create(
                &d.join("weak.lphy"),
                &secret("short"),
                None,
                Some(&d.join("p"))
            )
            .is_err()
        );
        let _ = std::fs::remove_dir_all(&d);
    }

    #[test]
    #[cfg(unix)]
    fn failed_save_keeps_the_original() {
        let d = std::env::temp_dir().join(format!("lphy-vault-ro-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(d.join("enc")).unwrap();
        std::fs::create_dir_all(d.join("work")).unwrap();
        std::fs::write(d.join("work/a.txt"), b"one").unwrap();
        let lphy = d.join("enc/work.lphy");
        encrypt_folder(&d.join("work"), &lphy, "vault pass 1234");
        let before = std::fs::read(&lphy).unwrap();
        let mut v =
            Vault::open(&lphy, &secret("vault pass 1234"), None, Some(&d.join("p"))).unwrap();
        std::fs::write(v.root.join("a.txt"), b"changed").unwrap();
        // The folder of the original becomes read-only: the new file cannot be written there.
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(d.join("enc"), std::fs::Permissions::from_mode(0o500))
                .unwrap();
            assert!(v.save().is_err());
            std::fs::set_permissions(d.join("enc"), std::fs::Permissions::from_mode(0o700))
                .unwrap();
            assert_eq!(std::fs::read(&lphy).unwrap(), before);
            assert!(v.changed(), "the change is still open");
        }
        v.close(true).unwrap();
        let _ = std::fs::remove_dir_all(&d);
    }

    #[test]
    fn unsuitable_files_are_named() {
        let d = std::env::temp_dir().join(format!("lphy-vault-un-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        std::fs::write(d.join("a.txt"), b"one").unwrap();
        let mut o = EncryptOptions {
            alg: AlgId::XChaCha20Poly1305,
            chunk_code: 2,
            kdf: KdfParams {
                m_kib: 64 * 1024,
                ..KdfParams::DEFAULT
            },
            force: false,
            strict_memory: false,
            raw: true,
            pad: Some(false),
            strict: false,
            compress: false,
            ecc: false,
        };
        let nfc = password::normalize_nfc(&secret("vault pass 1234")).unwrap();
        ops::encrypt(
            &Input::Path(&d.join("a.txt")),
            &d.join("raw.lphy"),
            &nfc,
            None,
            &o,
            &mut OsEntropy,
            &mut |_| {},
        )
        .unwrap();
        assert!(unsuitable(&d.join("raw.lphy")).is_some());
        o.raw = false;
        o.ecc = true;
        ops::encrypt(
            &Input::Path(&d.join("a.txt")),
            &d.join("ecc.lphy"),
            &nfc,
            None,
            &o,
            &mut OsEntropy,
            &mut |_| {},
        )
        .unwrap();
        assert!(unsuitable(&d.join("ecc.lphy")).is_some());
        assert!(unsuitable(&d.join("missing.lphy")).is_some());
        // A single-file archive is refused when opened.
        o.ecc = false;
        ops::encrypt(
            &Input::Path(&d.join("a.txt")),
            &d.join("one.lphy"),
            &nfc,
            None,
            &o,
            &mut OsEntropy,
            &mut |_| {},
        )
        .unwrap();
        assert!(unsuitable(&d.join("one.lphy")).is_none());
        assert!(
            Vault::open(
                &d.join("one.lphy"),
                &secret("vault pass 1234"),
                None,
                Some(&d.join("p"))
            )
            .is_err()
        );
        let _ = std::fs::remove_dir_all(&d);
    }
}
