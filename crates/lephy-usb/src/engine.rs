//! USB operation engine.
//!
//! Flow: [`prepare`] (fresh description → eligibility → dry run) → user confirmation (label **and**
//! GiB) → [`execute`]: the physical/volume identity is re-read before every step; a difference →
//! code 5 and the next step does not run. Steps: wipe or `--format` → optional `--fill-free-space` →
//! write the `.lphy` (atomically) → read back (after remounting; otherwise "verified from
//! cache").

use std::io::{Read, Write};
use std::path::{Path, PathBuf};

use chacha20::ChaCha20;
use chacha20::cipher::{KeyIvInit, StreamCipher};
use lephy_core::error::{Error, Result};
use lephy_core::header::{HEADER_LEN, Header};
use lephy_core::names::escape_display;

use crate::device::Device;
use crate::platform::Platform;

/// System folders at the root: the folder itself is kept, its content (trash, Spotlight index,
/// event log — old user data or text derived from it) is deleted.
pub const SYSTEM_DIRS: [&str; 4] = [
    "System Volume Information",
    ".Spotlight-V100",
    ".fseventsd",
    ".Trashes",
];
/// Upper limit of the fill buffer.
pub const MAX_FILL_BUFFER: usize = 8 * 1024 * 1024;
/// FAT32 file-size limit.
pub const FAT32_MAX_FILE: u64 = 4 * 1024 * 1024 * 1024 - 1;
/// Upper limit of the key stream per file: `ChaCha20` (96-bit nonce) with a 32-bit block counter
/// produces 256 GiB; each file gets its own nonce and ≤ 64 GiB.
pub const MAX_KEYSTREAM_FILE: u64 = 64 * 1024 * 1024 * 1024;
/// Fill file prefix.
pub const FILL_PREFIX: &str = ".lphy-fill-";

/// Dry-run result.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct DryRun {
    /// Number of files (and symlinks) to delete.
    pub files: u64,
    /// Number of directories to delete.
    pub dirs: u64,
    /// Total bytes.
    pub bytes: u64,
    /// First 20 paths (escaped).
    pub first: Vec<String>,
}

fn is_system(name: &str) -> bool {
    SYSTEM_DIRS.contains(&name)
}

/// Dry run: counts everything that will be deleted; symlinks are not followed.
///
/// # Errors
/// I/O.
pub fn dry_run(root: &Path) -> Result<DryRun> {
    let mut out = DryRun::default();
    let mut stack: Vec<(PathBuf, String)> = Vec::new();
    for e in std::fs::read_dir(root)? {
        let e = e?;
        let name = e.file_name().to_string_lossy().into_owned();
        if is_system(&name) {
            // The folder stays; its content is counted (skipped if inaccessible).
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

/// Deletes user files (through the root handle; symlinks not followed; system folders are only
/// emptied). Returns the number of entries deleted.
///
/// # Errors
/// I/O.
pub fn wipe(root: &Path, expect_dev: Option<u64>) -> Result<u64> {
    let dir = cap_std::fs::Dir::open_ambient_dir(root, cap_std::ambient_authority())?;
    // The identity is checked on the opened handle: even if another device appears at the mount
    // point after the check, deletion only goes through the verified handle.
    #[cfg(unix)]
    if let Some(want) = expect_dev {
        use cap_std::fs::MetadataExt;
        if dir.dir_metadata()?.dev() != want {
            return Err(Error::Cancelled(
                "the target device identity changed; nothing was deleted".into(),
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
            // Windows directory symlink: removed with remove_dir (the target is not touched).
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

/// Empties a system folder on a best-effort basis (the folder stays; symlinks not followed).
/// Inaccessible items (e.g. the ACL-protected `System Volume Information` on Windows) are skipped.
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

/// Free-space fill options.
#[derive(Debug, Clone, Copy)]
pub struct FillOptions {
    /// Upper limit per file (FAT32: 4 GiB − 1).
    pub max_file: u64,
    /// Write buffer (≤ 8 MiB).
    pub buffer: usize,
    /// Test only: treat the disk as full after this many bytes.
    pub limit: Option<u64>,
}

impl FillOptions {
    /// Default for the file system.
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

/// Fills free space with a `ChaCha20` key stream (a separate nonce per file), fsyncs and deletes the files. Returns bytes written.
/// Because of old FAT/exFAT directory entries, NTFS resident files and wear levelling there is
/// **no** guarantee of physical erasure (THREAT-MODEL › USB).
///
/// # Errors
/// I/O (except disk full), interruption.
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

/// User confirmation: the exact label **and** the whole number of GiB.
#[derive(Debug, Clone)]
pub struct Confirm {
    /// Label typed.
    pub label: String,
    /// Size typed (GiB).
    pub size_gib: u64,
}

/// Kind of read-back.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Verification {
    /// Read after eject + remount.
    AfterRemount,
    /// Could not remount; verified from cache (`F_NOCACHE` does not drop existing pages).
    FromCache,
}

impl std::fmt::Display for Verification {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Verification::AfterRemount => "verified after remounting",
            Verification::FromCache => "verified from cache",
        })
    }
}

/// Request.
#[derive(Debug, Clone)]
pub struct WriteRequest {
    /// The `.lphy` file to write.
    pub source: PathBuf,
    /// Confirmation.
    pub confirm: Confirm,
    /// exFAT format instead of wiping.
    pub format: bool,
    /// Fill free space after wiping/formatting.
    pub fill: bool,
    /// Fill options (`None` = by file system).
    pub fill_opts: Option<FillOptions>,
}

/// Report.
#[derive(Debug, Clone)]
pub struct WriteReport {
    /// Dry run.
    pub dry_run: DryRun,
    /// Top-level entries deleted.
    pub wiped: u64,
    /// Bytes filled.
    pub filled: u64,
    /// File written.
    pub written: PathBuf,
    /// Bytes written.
    pub bytes: u64,
    /// BLAKE3 (hex).
    pub blake3: String,
    /// Kind of read-back.
    pub verification: Verification,
    /// Steps run (in order).
    pub steps: Vec<&'static str>,
}

/// Checks that the source is a valid `.lphy` (only encrypted files are written). Returns the size.
///
/// # Errors
/// Code 1 (invalid/unreadable).
pub fn check_source(source: &Path) -> Result<u64> {
    let mut f = std::fs::File::open(source)?;
    let mut h = [0u8; HEADER_LEN];
    f.read_exact(&mut h).map_err(|_| {
        Error::Environment("the source is not a .lphy file (header too short)".into())
    })?;
    Header::parse(&h).map_err(|_| {
        Error::Environment("only valid .lphy (encrypted) files are written to USB".into())
    })?;
    Ok(f.metadata()?.len())
}

/// Fresh description + eligibility + dry run (shown before confirmation).
///
/// # Errors
/// Code 1: not eligible (no bypass).
pub fn prepare(platform: &dyn Platform, target: &Path) -> Result<(Device, DryRun)> {
    let dev = platform.describe(target)?;
    dev.eligibility(platform.require_serial())
        .map_err(|why| Error::Environment(format!("the target is not USB media: {why}")))?;
    let dr = dry_run(&dev.mount)?;
    Ok((dev, dr))
}

fn recheck(platform: &dyn Platform, snap: &Device, physical_only: bool) -> Result<Device> {
    let now = platform
        .describe(&snap.mount)
        .map_err(|e| Error::Cancelled(format!("the target device could not be read again: {e}")))?;
    let a = &now.identity;
    let b = &snap.identity;
    let same_physical = a.disk == b.disk && a.size_bytes == b.size_bytes;
    let same_volume = a.volume == b.volume && a.dev_id == b.dev_id;
    if !same_physical || (!physical_only && !same_volume) {
        return Err(Error::Cancelled(
            "the target device identity changed; the operation was stopped".into(),
        ));
    }
    if let Err(why) = now.eligibility(platform.require_serial()) {
        return Err(Error::Cancelled(format!(
            "the target is no longer eligible: {why}"
        )));
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

/// Runs the confirmed operation. `snap`: the description returned by [`prepare`].
///
/// # Errors
/// 5 (confirmation mismatch, identity changed), 1, 7, 8, 130.
pub fn execute(
    platform: &dyn Platform,
    snap: &Device,
    dry: DryRun,
    req: &WriteRequest,
    log: &mut dyn FnMut(&str),
) -> Result<WriteReport> {
    // 0b: confirmation — exact label, whole GiB.
    if req.confirm.label != snap.label || req.confirm.size_gib != snap.size_gib() {
        return Err(Error::Cancelled(format!(
            "confirmation does not match: expected label {:?} / {} GiB",
            snap.label,
            snap.size_gib()
        )));
    }
    let size = check_source(&req.source)?;
    let name = req
        .source
        .file_name()
        .ok_or_else(|| Error::Environment("the source has no file name".into()))?
        .to_owned();
    let mut steps = Vec::new();
    let mut cur = snap.clone();

    // 1) wipe or format
    cur = recheck(platform, &cur, false)?;
    let wiped = if req.format {
        steps.push("format");
        log("formatting (exFAT)…");
        platform.format(&cur, &cur.label)?;
        // Formatting changes the volume identity: the physical identity is compared and the new
        // volume identity becomes the snapshot.
        cur = recheck(platform, &cur, true)?;
        0
    } else {
        steps.push("wipe");
        log("deleting user files…");
        wipe(&cur.mount, Some(cur.identity.dev_id))?
    };

    // 2) fill free space
    let mut filled = 0;
    if req.fill {
        cur = recheck(platform, &cur, false)?;
        steps.push("fill");
        log("filling free space…");
        let opts = req
            .fill_opts
            .unwrap_or_else(|| FillOptions::for_fs(&cur.fs_type));
        filled = fill_free_space(&cur.mount, opts)?;
    }

    // 3) write
    cur = recheck(platform, &cur, false)?;
    lephy_core::io::precheck_space(&cur.mount, size)?;
    steps.push("write");
    log("writing the encrypted file…");
    let target = cur.mount.join(&name);
    let (bytes, digest) = copy_and_hash(&req.source, &target)?;

    // 4) read back
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
            at: "USB read-back".into(),
            detail: Some("the BLAKE3 of the written file does not match the source".into()),
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

    /// Fake platform: volume = temp directory; `describe` call counter and identity change injection.
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
            // Deletion checks the device identity of the opened handle: the test volume is a real folder.
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
        // A fake .lphy with a valid header: real encryption through ops with a small KDF.
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
        // The content of system folders (old trash, Spotlight index) is among what gets deleted.
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
            assert!(left.contains(&s.to_string()), "the {s} folder must stay");
            assert!(
                !vol.join(s).join("keep").exists(),
                "the content of {s} must be deleted (old user data)"
            );
        }
        assert_eq!(
            left.len(),
            SYSTEM_DIRS.len(),
            "only the system folders may remain: {left:?}"
        );
        assert_eq!(
            std::fs::read(&outside).unwrap(),
            b"dokunma",
            "a symlink target must not be deleted"
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
            "nothing may be deleted on a different device"
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
        assert!(left.is_empty(), "fill files must be deleted");
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
                rep.verification.to_string().contains("from cache"),
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
                "no file may be deleted"
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
        // describe #1: prepare, #2: before wiping (same), #3: before filling → changed.
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
        assert!(
            !vol.join("yedek.lphy").exists(),
            "the write step must not run"
        );
        assert_eq!(fake.describes.get(), 3);
        // If it changes before wiping, nothing is deleted.
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
        assert!(
            prepare(&fake, &vol).is_err(),
            "an empty serial must be refused"
        );
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
