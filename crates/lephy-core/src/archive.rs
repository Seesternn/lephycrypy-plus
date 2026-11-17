//! Çerçeveli arşiv konteyneri (FORMAT.md › Arşiv).
//!
//! Giriş: `[u8 tür 0/1/2/255][u16 LE yol_len][yol NFC, '/'][u32 LE mode][i64 LE mtime]`;
//! dosya/symlink verisi `[u32 LE len][bytes]…[u32 0]` (symlink: tek çerçeve). END: tür 255,
//! `yol_len` 0, mode 0, mtime 0. Padded ise END sonrası sıfır dolgu (`pad::padme`).
//!
//! - [`ArchiveWriter`]: `Read` adaptörü; kaynak ağacı özyinelemesiz (açık yığın) ve sıralı
//!   (bayt sırası) dolaşır; symlink takip edilmez, hedefi ham saklanır; FIFO/soket/aygıt
//!   atlanır ve raporlanır (`--strict` → 4). Çerçeve verisi ≤ 1 MiB'lık sıfırlanan ara
//!   tampondan akar (küçük sapma).
//! - [`Extractor`]: `Write` adaptörü; cap-std kök handle'ı (`Dir`) ile tüm yol çözümlemesi
//!   handle'a göre, symlink takip edilmez; dosyalar `create_new` 0600, dizinler `create_dir`;
//!   yinelenen (NFC + katlama) → 4 (`--rename-conflicts` ile `_2`); Windows ad kuralları;
//!   symlink'ler END'den sonra politikaya göre; mode/mtime en sonda derinden yüzeye.

use std::collections::HashSet;
use std::fs::File;
use std::io::{self, Read, Write};
use std::path::{Path, PathBuf};

use zeroize::Zeroizing;

use crate::error::{Error, FormatViolation, Result, StrictViolation};
use crate::names::{
    self, MAX_ENTRIES, MAX_FRAME, MAX_MTIME_ABS, MAX_TOTAL_PATH_BYTES, SymlinkClass,
};
use crate::pad::padme;

/// Giriş türleri.
pub const T_FILE: u8 = 0;
/// Dizin.
pub const T_DIR: u8 = 1;
/// Symlink.
pub const T_SYMLINK: u8 = 2;
/// END.
pub const T_END: u8 = 255;
/// Yazıcı çerçeve boyutu.
const WRITE_FRAME: usize = 1024 * 1024;
/// Sabit giriş başlığı: tür (1) + `yol_len` (2) + mode (4) + mtime (8), yol hariç.
const FIXED_HEADER: usize = 15;

/// Atlanan/değiştirilen girişler raporu.
#[derive(Debug, Default, Clone)]
pub struct Report {
    /// Atlanan girişler: (yol, neden).
    pub skipped: Vec<(String, String)>,
    /// Yeniden adlandırılanlar: (eski, yeni).
    pub renamed: Vec<(String, String)>,
    /// Uyarılar.
    pub warnings: Vec<String>,
    /// Kurulan symlink sayısı.
    pub symlinks_created: usize,
    /// Giriş sayısı (END hariç).
    pub entries: usize,
    /// Arşive gerçekten alınan kaynak öğeler (yalnızca yazıcı doldurur). `--delete-original`
    /// yalnızca bunları siler.
    pub archived: Vec<Archived>,
}

/// Arşive alınmış bir kaynak öğe.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Archived {
    /// Kaynaktaki mutlak yol.
    pub path: PathBuf,
    /// Dizin mi.
    pub is_dir: bool,
    /// Okunduğu andaki (aygıt, inode); Unix dışında `None`.
    pub id: Option<(u64, u64)>,
}

#[cfg(unix)]
#[allow(clippy::unnecessary_wraps)] // Unix dışında None döner; imza ortak.
fn id_of(md: &std::fs::Metadata) -> Option<(u64, u64)> {
    use std::os::unix::fs::MetadataExt;
    Some((md.dev(), md.ino()))
}

#[cfg(not(unix))]
const fn id_of(_md: &std::fs::Metadata) -> Option<(u64, u64)> {
    None
}

impl Report {
    fn skip(&mut self, path: &str, why: &str, strict: bool) -> io::Result<()> {
        self.skipped.push((path.to_string(), why.to_string()));
        if strict {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                StrictViolation(format!("{} atlandı ({why})", names::escape_display(path))),
            ));
        }
        Ok(())
    }
}

fn mtime_of(md: &std::fs::Metadata) -> i64 {
    md.modified()
        .ok()
        .and_then(|t| match t.duration_since(std::time::UNIX_EPOCH) {
            Ok(d) => i64::try_from(d.as_secs()).ok(),
            Err(e) => i64::try_from(e.duration().as_secs()).ok().map(|s| -s),
        })
        .unwrap_or(0)
        .clamp(-MAX_MTIME_ABS, MAX_MTIME_ABS)
}

fn mode_of(md: &std::fs::Metadata) -> u32 {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        md.permissions().mode() & 0o7777
    }
    #[cfg(not(unix))]
    {
        let ro = md.permissions().readonly();
        if md.is_dir() {
            0o755
        } else if ro {
            0o444
        } else {
            0o644
        }
    }
}

// ---------------------------------------------------------------------------------------------
// Yazıcı
// ---------------------------------------------------------------------------------------------

enum Kind {
    File,
    Dir,
    Symlink,
}

struct Work {
    rel: String,
    abs: PathBuf,
    /// Kaynak dizin köküne göre yol (kök dosyaysa boş).
    sub: PathBuf,
    kind: Kind,
}

enum WState {
    Next,
    File(File),
    Done,
}

/// Arşiv yazıcı (`Read`): `root` bir dizinse içeriği (kök adı hariç), dosyaysa tek giriş.
pub struct ArchiveWriter {
    /// Kaynak bir dizinse kök tutamacı: tüm açma/listeleme köke göre yapılır; kaynak okunurken
    /// bir öğe symlink ile değiştirilse bile kökün dışına çıkılamaz (cap-std).
    root: Option<cap_std::fs::Dir>,
    stack: Vec<Work>,
    state: WState,
    pending: Zeroizing<Vec<u8>>,
    pos: usize,
    strict: bool,
    entries: usize,
    total_path_bytes: u64,
    dedup: HashSet<[u8; 16]>,
    /// Rapor (atlananlar, katlama çakışma uyarıları).
    pub report: Report,
}

impl ArchiveWriter {
    /// Kurar; `root` dosya ya da dizin (symlink kök takip edilmez: kök symlink ise hata).
    ///
    /// # Errors
    /// Kod 1.
    pub fn new(root: &Path, strict: bool) -> Result<Self> {
        let md = root.symlink_metadata()?;
        let mut stack = Vec::new();
        let mut root_dir = None;
        let mut root_md = None;
        if md.is_dir() {
            let d = cap_std::fs::Dir::open_ambient_dir(root, cap_std::ambient_authority())?;
            push_children(&mut stack, &d, root, Path::new(""), "")?;
            root_md = Some(d.try_clone()?.into_std_file().metadata()?);
            root_dir = Some(d);
        } else if md.is_file() {
            let name = root
                .file_name()
                .ok_or_else(|| Error::Environment("kaynak adı yok".into()))?;
            let rel = names::to_archive_path(Path::new(name))?;
            stack.push(Work {
                rel,
                abs: root.to_path_buf(),
                sub: PathBuf::new(),
                kind: Kind::File,
            });
        } else {
            return Err(Error::Environment(format!(
                "{} normal dosya ya da dizin değil",
                root.display()
            )));
        }
        let mut report = Report::default();
        if let Some(m) = root_md {
            // Kök dizin listede ilk: dizinler tersten silindiği için en son silinir.
            report.archived.push(Archived {
                path: root.to_path_buf(),
                is_dir: true,
                id: id_of(&m),
            });
        }
        Ok(Self {
            root: root_dir,
            stack,
            state: WState::Next,
            pending: Zeroizing::new(Vec::with_capacity(WRITE_FRAME + 4)),
            pos: 0,
            strict,
            entries: 0,
            total_path_bytes: 0,
            dedup: HashSet::with_capacity(1 << 16),
            report,
        })
    }

    /// Dizin girişini kaydeder ve çocuklarını yığına ekler; `Ok(false)` = atlandı.
    fn dir_entry(&mut self, root: &cap_std::fs::Dir, w: &Work) -> io::Result<bool> {
        // Meta veri açılmış tutamaçtan: okuma ile kayıt arasında değişemez.
        let md = root.open_dir(&w.sub)?.into_std_file().metadata()?;
        if !md.is_dir() {
            self.report.skip(&w.rel, "dizin değişti", self.strict)?;
            return Ok(false);
        }
        self.account(&w.rel, 0)?;
        self.put_record(T_DIR, &w.rel, mode_of(&md), mtime_of(&md));
        push_children(&mut self.stack, root, &w.abs, &w.sub, &w.rel)
            .map_err(|e| io::Error::other(e.to_string()))?;
        self.report.archived.push(Archived {
            path: w.abs.clone(),
            is_dir: true,
            id: id_of(&md),
        });
        Ok(true)
    }

    /// Dosyayı açar: dizin kaynağında köke göre (cap-std), tek dosya kaynağında yolla.
    fn open_file(&self, w: &Work) -> io::Result<File> {
        match &self.root {
            Some(d) => d.open(&w.sub).map(cap_std::fs::File::into_std),
            None => File::open(&w.abs),
        }
    }

    fn account(&mut self, rel: &str, extra: usize) -> io::Result<()> {
        self.entries += 1;
        if self.entries > MAX_ENTRIES {
            return Err(FormatViolation::io_at("arşiv", "giriş sayısı > 1 000 000"));
        }
        self.total_path_bytes += rel.len() as u64 + extra as u64;
        if self.total_path_bytes > MAX_TOTAL_PATH_BYTES {
            return Err(FormatViolation::io_at("arşiv", "toplam yol baytı > 64 MiB"));
        }
        if !self.dedup.insert(names::fold_key(rel)) {
            self.report.warnings.push(format!(
                "harf/NFC katlamasında çakışan ad: {} (büyük/küçük harf duyarsız dosya sisteminde çıkarma başarısız olur)",
                names::escape_display(rel)
            ));
        }
        Ok(())
    }

    fn put_record(&mut self, ty: u8, rel: &str, mode: u32, mtime: i64) {
        let p = &mut *self.pending;
        p.push(ty);
        let len = u16::try_from(rel.len()).unwrap_or(u16::MAX);
        p.extend_from_slice(&len.to_le_bytes());
        p.extend_from_slice(rel.as_bytes());
        p.extend_from_slice(&mode.to_le_bytes());
        p.extend_from_slice(&mtime.to_le_bytes());
    }

    /// `pending`'i bir sonraki üretimle doldurur; `Ok(false)` = bitti.
    #[allow(clippy::too_many_lines)]
    fn refill(&mut self) -> io::Result<bool> {
        self.pending.clear();
        self.pos = 0;
        loop {
            match std::mem::replace(&mut self.state, WState::Next) {
                WState::Done => {
                    self.state = WState::Done;
                    return Ok(false);
                }
                WState::File(mut f) => {
                    self.pending.resize(4 + WRITE_FRAME, 0);
                    let mut n = 0;
                    while n < WRITE_FRAME {
                        match f.read(&mut self.pending[4 + n..]) {
                            Ok(0) => break,
                            Ok(k) => n += k,
                            Err(e) if e.kind() == io::ErrorKind::Interrupted => {
                                if lephy_sys::signal::interrupted() {
                                    return Err(e);
                                }
                            }
                            Err(e) => return Err(e),
                        }
                    }
                    let len = u32::try_from(n).unwrap_or(0);
                    self.pending[..4].copy_from_slice(&len.to_le_bytes());
                    if n == 0 {
                        self.pending.truncate(4); // [u32 0] sonlandırıcı
                        self.state = WState::Next;
                    } else {
                        self.pending.truncate(4 + n);
                        self.state = WState::File(f);
                    }
                    return Ok(true);
                }
                WState::Next => {
                    let Some(w) = self.stack.pop() else {
                        self.put_record(T_END, "", 0, 0);
                        self.report.entries = self.entries;
                        self.state = WState::Done;
                        return Ok(true);
                    };
                    match w.kind {
                        Kind::Dir => {
                            let Some(root) = self.root.take() else {
                                return Err(io::Error::other("dizin girişi kök olmadan"));
                            };
                            let r = self.dir_entry(&root, &w);
                            self.root = Some(root);
                            if r? {
                                return Ok(true);
                            }
                        }
                        Kind::File => {
                            let pre = match &self.root {
                                Some(d) => d.symlink_metadata(&w.sub)?.is_file(),
                                None => w.abs.symlink_metadata()?.is_file(),
                            };
                            if !pre {
                                self.report
                                    .skip(&w.rel, "normal dosya değil", self.strict)?;
                                continue;
                            }
                            let f = match self.open_file(&w) {
                                Ok(f) => f,
                                Err(e) => {
                                    self.report.skip(
                                        &w.rel,
                                        &format!("açılamadı: {e}"),
                                        self.strict,
                                    )?;
                                    continue;
                                }
                            };
                            // Açılan nesne denetlenir (fstat): kontrol ile açma arasında
                            // değiştirilen öğe arşive girmez.
                            let md = f.metadata()?;
                            if !md.is_file() {
                                self.report
                                    .skip(&w.rel, "normal dosya değil", self.strict)?;
                                continue;
                            }
                            self.account(&w.rel, 0)?;
                            self.put_record(T_FILE, &w.rel, mode_of(&md), mtime_of(&md));
                            self.report.archived.push(Archived {
                                path: w.abs.clone(),
                                is_dir: false,
                                id: id_of(&md),
                            });
                            self.state = WState::File(f);
                            return Ok(true);
                        }
                        Kind::Symlink => {
                            let target = match &self.root {
                                // Ham hedef (mutlak hedefler de kaydedilir; çıkarma politikası
                                // ayrıca karar verir).
                                Some(d) => link_bytes(&d.read_link_contents(&w.sub)?),
                                None => read_link_bytes(&w.abs)?,
                            };
                            if names::validate_symlink_target(&target).is_err() {
                                self.report.skip(
                                    &w.rel,
                                    "symlink hedefi 1..=4096 B / NUL",
                                    self.strict,
                                )?;
                                continue;
                            }
                            self.account(&w.rel, target.len())?;
                            self.put_record(T_SYMLINK, &w.rel, 0, 0);
                            let len = u32::try_from(target.len()).unwrap_or(0);
                            self.pending.extend_from_slice(&len.to_le_bytes());
                            self.pending.extend_from_slice(&target);
                            self.pending.extend_from_slice(&0u32.to_le_bytes());
                            let id = self.root.as_ref().and_then(|d| link_id(d, &w.sub));
                            self.report.archived.push(Archived {
                                path: w.abs.clone(),
                                is_dir: false,
                                id,
                            });
                            return Ok(true);
                        }
                    }
                }
            }
        }
    }

    /// Giriş sayısı (END hariç).
    #[must_use]
    pub const fn entries(&self) -> usize {
        self.entries
    }
}

/// Symlink'in kendisinin (aygıt, inode) kimliği; Unix dışında `None`.
fn link_id(root: &cap_std::fs::Dir, sub: &Path) -> Option<(u64, u64)> {
    let m = root.symlink_metadata(sub).ok()?;
    #[cfg(unix)]
    {
        use cap_std::fs::MetadataExt;
        Some((m.dev(), m.ino()))
    }
    #[cfg(not(unix))]
    {
        let _ = m;
        None
    }
}

fn read_link_bytes(p: &Path) -> io::Result<Vec<u8>> {
    Ok(link_bytes(&std::fs::read_link(p)?))
}

fn link_bytes(t: &Path) -> Vec<u8> {
    #[cfg(unix)]
    {
        use std::os::unix::ffi::OsStrExt;
        t.as_os_str().as_bytes().to_vec()
    }
    #[cfg(not(unix))]
    {
        t.to_string_lossy().replace('\\', "/").into_bytes()
    }
}

/// Dizin çocuklarını (bayt sırasında, tersten yığına) ekler. Listeleme ve sınıflandırma kök
/// tutamacına göredir (`sub` köke göre yol; `abs` yalnızca rapor ve silme içindir).
fn push_children(
    stack: &mut Vec<Work>,
    root: &cap_std::fs::Dir,
    abs_dir: &Path,
    sub: &Path,
    rel_prefix: &str,
) -> Result<()> {
    let mut items: Vec<(Vec<u8>, std::ffi::OsString)> = Vec::new();
    let rd = if sub.as_os_str().is_empty() {
        root.entries()?
    } else {
        root.read_dir(sub)?
    };
    for e in rd {
        let name = e?.file_name();
        let bytes = name.to_string_lossy().into_owned().into_bytes();
        items.push((bytes, name));
    }
    items.sort_by(|a, b| b.0.cmp(&a.0)); // tersten: pop ile artan sıra
    for (_, name) in items {
        let child_sub = sub.join(&name);
        let md = root.symlink_metadata(&child_sub)?;
        let comp = names::to_archive_path(Path::new(&name))?;
        let rel = if rel_prefix.is_empty() {
            comp
        } else {
            format!("{rel_prefix}/{comp}")
        };
        let kind = if md.file_type().is_symlink() {
            Kind::Symlink
        } else if md.is_dir() {
            Kind::Dir
        } else {
            Kind::File // FIFO/soket/aygıt: refill'de "normal dosya değil" ile atlanır
        };
        stack.push(Work {
            rel,
            abs: abs_dir.join(&name),
            sub: child_sub,
            kind,
        });
    }
    Ok(())
}

impl Read for ArchiveWriter {
    fn read(&mut self, out: &mut [u8]) -> io::Result<usize> {
        if out.is_empty() {
            return Ok(0);
        }
        loop {
            if self.pos < self.pending.len() {
                let n = (self.pending.len() - self.pos).min(out.len());
                out[..n].copy_from_slice(&self.pending[self.pos..self.pos + n]);
                self.pos += n;
                return Ok(n);
            }
            if !self.refill()? {
                return Ok(0);
            }
        }
    }
}

/// Arşiv akışına PADMÉ dolgusu ekleyen `Read` sarmalayıcısı: END'e kadar yazılan bayt sayısına
/// göre sıfır ekler.
pub struct ArchivePadReader<R: Read> {
    inner: R,
    emitted: u64,
    inner_done: bool,
    target: u64,
}

impl<R: Read> ArchivePadReader<R> {
    /// Kurar.
    pub fn new(inner: R) -> Self {
        Self {
            inner,
            emitted: 0,
            inner_done: false,
            target: 0,
        }
    }

    /// İç okuyucuyu geri alır (rapor için).
    pub fn into_inner(self) -> R {
        self.inner
    }
}

impl<R: Read> Read for ArchivePadReader<R> {
    fn read(&mut self, out: &mut [u8]) -> io::Result<usize> {
        if out.is_empty() {
            return Ok(0);
        }
        if !self.inner_done {
            let n = self.inner.read(out)?;
            if n > 0 {
                self.emitted += n as u64;
                return Ok(n);
            }
            self.inner_done = true;
            self.target = padme(self.emitted);
        }
        let remaining = self.target - self.emitted;
        if remaining == 0 {
            return Ok(0);
        }
        let n = usize::try_from(remaining.min(out.len() as u64)).unwrap_or(out.len());
        out[..n].fill(0);
        self.emitted += n as u64;
        Ok(n)
    }
}

// ---------------------------------------------------------------------------------------------
// Çıkarıcı
// ---------------------------------------------------------------------------------------------

/// Symlink kurma politikası.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum SymlinkPolicy {
    /// Hiç kurma (varsayılan).
    #[default]
    None,
    /// Yalnızca güvenli hedefler.
    Safe,
    /// Güvensizler de (her biri için uyarı).
    Unsafe,
}

/// Çıkarma seçenekleri.
#[derive(Debug, Clone, Copy, Default)]
pub struct ExtractOptions {
    /// Atlanan/değiştirilen giriş hata (biçim/politika → 4, ortam → 1).
    pub strict: bool,
    /// Symlink politikası.
    pub symlinks: SymlinkPolicy,
    /// Yinelenen adlarda `_2`, `_3` …
    pub rename_conflicts: bool,
    /// Başlıktaki `padded` bayrağı: END sonrası sıfır dolgu beklenir.
    pub padded: bool,
}

enum PState {
    /// Giriş başlığı toplanıyor.
    Header,
    /// Çerçeve uzunluğu (4 B).
    FrameLen,
    /// Çerçeve verisi; kalan bayt.
    FrameData(usize),
    /// END sonrası.
    Trailer,
}

enum Current {
    File(cap_std::fs::File),
    /// Yalnızca doğrulama: içerik okunur ve atılır.
    Discard,
    Symlink {
        target: Vec<u8>,
        frames: usize,
    },
}

struct Deferred {
    off: usize,
    len: usize,
    mode: u32,
    mtime: i64,
    depth: usize,
}

/// Arşiv çıkarıcı (`Write`). `root` tmp dizinin cap-std handle'ıdır (0700, çağıran oluşturur);
/// `None` ise yalnızca yapı doğrulanır, diske hiçbir şey yazılmaz (`Extractor::verifier`).
pub struct Extractor {
    root: Option<cap_std::fs::Dir>,
    opts: ExtractOptions,
    state: PState,
    hdr: Vec<u8>,
    cur: Option<Current>,
    cur_path: String,
    path_arena: Vec<u8>,
    deferred: Vec<Deferred>,
    symlinks: Vec<(String, Vec<u8>)>,
    dedup: HashSet<[u8; 16]>,
    entries: usize,
    total_path_bytes: u64,
    consumed: u64,
    end_at: u64,
    end_seen: bool,
    dirs: HashSet<String>,
    /// Rapor.
    pub report: Report,
    /// Tek üst düzey dosya (düzleştirme için): END sonrası `Some(ad)` ise arşivde yalnızca o
    /// dosya vardır.
    pub single_file: Option<String>,
    top_level: usize,
}

impl Extractor {
    /// `tmp_dir`: var olan boş tmp dizini.
    ///
    /// # Errors
    /// Kod 1.
    pub fn new(tmp_dir: &Path, opts: ExtractOptions) -> Result<Self> {
        let root = cap_std::fs::Dir::open_ambient_dir(tmp_dir, cap_std::ambient_authority())?;
        Ok(Self::with_root(Some(root), opts))
    }

    /// Yalnızca doğrulayan çıkarıcı: yol kuralları, yinelenenler, sınırlar, END ve dolgu
    /// çıkarmadaki gibi denetlenir; diske yazılmaz, symlink kurulmaz.
    #[must_use]
    pub fn verifier(opts: ExtractOptions) -> Self {
        Self::with_root(None, opts)
    }

    fn with_root(root: Option<cap_std::fs::Dir>, opts: ExtractOptions) -> Self {
        Self {
            root,
            opts,
            state: PState::Header,
            hdr: Vec::with_capacity(FIXED_HEADER + 256),
            cur: None,
            cur_path: String::new(),
            path_arena: Vec::new(),
            deferred: Vec::new(),
            symlinks: Vec::new(),
            dedup: HashSet::with_capacity(1 << 20),
            entries: 0,
            total_path_bytes: 0,
            consumed: 0,
            end_at: 0,
            end_seen: false,
            dirs: HashSet::new(),
            report: Report::default(),
            single_file: None,
            top_level: 0,
        }
    }

    fn violation(d: &str) -> io::Error {
        FormatViolation::io_at("arşiv", d)
    }

    /// Yol doğrulama, Windows düzeltme, yinelenen denetimi; nihai yolu döner.
    fn admit_path(&mut self, raw: &[u8], ty: u8) -> io::Result<String> {
        let s = names::validate_archive_path(raw).map_err(|e| Self::violation(&e.to_string()))?;
        let mut path = s.to_string();
        if cfg!(windows) {
            let mut changed = false;
            let comps: Vec<String> = path
                .split('/')
                .map(|c| {
                    let (n, ch) = names::windows_sanitize(c);
                    changed |= ch;
                    n
                })
                .collect();
            if changed {
                let new = comps.join("/");
                if self.opts.strict {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        StrictViolation(format!(
                            "Windows ad kuralı: {}",
                            names::escape_display(&path)
                        )),
                    ));
                }
                self.report.renamed.push((path.clone(), new.clone()));
                path = new;
            }
        }
        self.entries += 1;
        if self.entries > MAX_ENTRIES {
            return Err(Self::violation("giriş sayısı > 1 000 000"));
        }
        self.total_path_bytes += path.len() as u64;
        if self.total_path_bytes > MAX_TOTAL_PATH_BYTES {
            return Err(Self::violation("toplam yol baytı > 64 MiB"));
        }
        if !self.dedup.insert(names::fold_key(&path)) {
            if !self.opts.rename_conflicts {
                return Err(Self::violation(&format!(
                    "yinelenen yol (NFC/harf katlaması): {}",
                    names::escape_display(&path)
                )));
            }
            let orig = path.clone();
            let mut i = 2;
            loop {
                let cand = format!("{orig}_{i}");
                if self.dedup.insert(names::fold_key(&cand)) {
                    path = cand;
                    break;
                }
                i += 1;
            }
            self.report.renamed.push((orig, path.clone()));
        }
        // Üst dizin varlığı (yazıcı dizinleri önce yazar).
        if let Some((parent, _)) = path.rsplit_once('/')
            && !self.dirs.contains(parent)
        {
            return Err(Self::violation(&format!(
                "üst dizin girişi eksik: {}",
                names::escape_display(parent)
            )));
        }
        if !path.contains('/') {
            self.top_level += 1;
            self.single_file = if self.top_level == 1 && ty == T_FILE {
                Some(path.clone())
            } else {
                None
            };
        }
        Ok(path)
    }

    fn defer(&mut self, path: &str, mode: u32, mtime: i64) {
        let off = self.path_arena.len();
        self.path_arena.extend_from_slice(path.as_bytes());
        self.deferred.push(Deferred {
            off,
            len: path.len(),
            mode,
            mtime,
            depth: path.matches('/').count(),
        });
    }

    fn begin_entry(&mut self) -> io::Result<()> {
        let ty = self.hdr[0];
        let plen = usize::from(u16::from_le_bytes([self.hdr[1], self.hdr[2]]));
        let raw = self.hdr[3..3 + plen].to_vec();
        let mode = u32::from_le_bytes(self.hdr[3 + plen..7 + plen].try_into().unwrap_or([0; 4]));
        let mtime = i64::from_le_bytes(self.hdr[7 + plen..15 + plen].try_into().unwrap_or([0; 8]));
        self.hdr.clear();
        if ty == T_END {
            if plen != 0 || mode != 0 || mtime != 0 {
                return Err(Self::violation("END girişi alanları sıfır olmalı"));
            }
            self.end_seen = true;
            self.end_at = self.consumed;
            self.state = PState::Trailer;
            return Ok(());
        }
        if !(-MAX_MTIME_ABS..=MAX_MTIME_ABS).contains(&mtime) {
            return Err(Self::violation("mtime aralık dışı"));
        }
        let path = self.admit_path(&raw, ty)?;
        match ty {
            T_DIR => {
                if let Some(root) = &self.root {
                    root.create_dir(&path).map_err(|e| {
                        if e.kind() == io::ErrorKind::AlreadyExists {
                            Self::violation(&format!(
                                "dizin zaten var: {}",
                                names::escape_display(&path)
                            ))
                        } else {
                            e
                        }
                    })?;
                }
                self.dirs.insert(path.clone());
                self.defer(&path, mode & SAFE_MODE_MASK, mtime);
                self.state = PState::Header;
            }
            T_FILE => {
                let cur = if let Some(root) = &self.root {
                    let mut oo = cap_std::fs::OpenOptions::new();
                    oo.write(true).create_new(true);
                    #[cfg(unix)]
                    {
                        use cap_std::fs::OpenOptionsExt;
                        oo.mode(0o600);
                    }
                    let f = root.open_with(&path, &oo).map_err(|e| {
                        if e.kind() == io::ErrorKind::AlreadyExists {
                            Self::violation(&format!(
                                "dosya zaten var: {}",
                                names::escape_display(&path)
                            ))
                        } else {
                            e
                        }
                    })?;
                    Current::File(f)
                } else {
                    Current::Discard
                };
                self.cur = Some(cur);
                self.cur_path = path.clone();
                self.defer(&path, mode & SAFE_MODE_MASK, mtime);
                self.state = PState::FrameLen;
            }
            T_SYMLINK => {
                self.cur = Some(Current::Symlink {
                    target: Vec::new(),
                    frames: 0,
                });
                self.cur_path = path;
                self.state = PState::FrameLen;
            }
            _ => return Err(Self::violation("bilinmeyen giriş türü")),
        }
        Ok(())
    }

    fn end_entry(&mut self) -> io::Result<()> {
        match self.cur.take() {
            Some(Current::File(f)) => {
                f.sync_all()?;
                drop(f);
            }
            Some(Current::Discard) | None => {}
            Some(Current::Symlink { target, frames }) => {
                if frames != 1 {
                    return Err(Self::violation("symlink hedefi tek çerçevede olmalı"));
                }
                names::validate_symlink_target(&target)
                    .map_err(|e| Self::violation(&e.to_string()))?;
                self.total_path_bytes += target.len() as u64;
                if self.total_path_bytes > MAX_TOTAL_PATH_BYTES {
                    return Err(Self::violation("toplam yol baytı > 64 MiB"));
                }
                let p = std::mem::take(&mut self.cur_path);
                self.symlinks.push((p, target));
            }
        }
        self.state = PState::Header;
        Ok(())
    }

    /// Bayt tüketir; tüketilen sayıyı döner (her zaman `buf.len()` ya da hata).
    fn consume(&mut self, buf: &[u8]) -> io::Result<()> {
        let mut rest = buf;
        while !rest.is_empty() {
            match self.state {
                PState::Header => {
                    // Tür + yol_len için 3 bayt, sonra toplam 15 + yol_len.
                    let need = if self.hdr.len() < 3 {
                        3
                    } else {
                        FIXED_HEADER + usize::from(u16::from_le_bytes([self.hdr[1], self.hdr[2]]))
                    };
                    let take = (need - self.hdr.len()).min(rest.len());
                    self.hdr.extend_from_slice(&rest[..take]);
                    rest = &rest[take..];
                    self.consumed += take as u64;
                    let plen = if self.hdr.len() >= 3 {
                        usize::from(u16::from_le_bytes([self.hdr[1], self.hdr[2]]))
                    } else {
                        continue;
                    };
                    if self.hdr.len() == FIXED_HEADER + plen {
                        self.begin_entry()?;
                    }
                }
                PState::FrameLen => {
                    let take = (4 - self.hdr.len()).min(rest.len());
                    self.hdr.extend_from_slice(&rest[..take]);
                    rest = &rest[take..];
                    self.consumed += take as u64;
                    if self.hdr.len() == 4 {
                        let len =
                            u32::from_le_bytes(self.hdr[..4].try_into().unwrap_or([0; 4])) as usize;
                        self.hdr.clear();
                        if len == 0 {
                            self.end_entry()?;
                        } else if len > MAX_FRAME {
                            return Err(Self::violation("çerçeve > 16 MiB"));
                        } else {
                            // Symlink hedefi tam olarak bir çerçevedir: her yeni çerçeve sayılır.
                            if let Some(Current::Symlink { frames, .. }) = self.cur.as_mut() {
                                *frames += 1;
                                if *frames > 1 {
                                    return Err(Self::violation(
                                        "symlink hedefi tek çerçevede olmalı",
                                    ));
                                }
                            }
                            self.state = PState::FrameData(len);
                        }
                    }
                }
                PState::FrameData(remaining) => {
                    let take = remaining.min(rest.len());
                    match self.cur.as_mut() {
                        Some(Current::File(f)) => f.write_all(&rest[..take])?,
                        Some(Current::Discard) => {}
                        Some(Current::Symlink { target, .. }) => {
                            if target.len() + take > names::MAX_SYMLINK_TARGET {
                                return Err(Self::violation("symlink hedefi > 4096 B"));
                            }
                            target.extend_from_slice(&rest[..take]);
                        }
                        None => return Err(Self::violation("çerçeve verisi girişsiz")),
                    }
                    rest = &rest[take..];
                    self.consumed += take as u64;
                    self.state = if remaining == take {
                        PState::FrameLen
                    } else {
                        PState::FrameData(remaining - take)
                    };
                }
                PState::Trailer => {
                    if !self.opts.padded {
                        return Err(Self::violation("END sonrası veri"));
                    }
                    if rest.iter().any(|&b| b != 0) {
                        return Err(Self::violation("END sonrası sıfır olmayan dolgu"));
                    }
                    self.consumed += rest.len() as u64;
                    rest = &[];
                }
            }
        }
        Ok(())
    }

    /// Akış bittiğinde: END/dolgu denetimi, symlink'ler, mode/mtime (derinden yüzeye).
    ///
    /// # Errors
    /// Kod 4 (END eksik, dolgu uzunluğu), kod 1 (ortam; `--strict` ayrıcalık).
    pub fn finish(mut self) -> Result<Report> {
        if !self.end_seen {
            return Err(Error::Corrupt {
                at: "arşiv".into(),
                detail: Some("END girişi eksik".into()),
            });
        }
        if self.opts.padded && self.consumed != padme(self.end_at) {
            return Err(Error::Corrupt {
                at: "arşiv".into(),
                detail: Some("PADMÉ toplam uzunluk uyuşmuyor".into()),
            });
        }
        self.report.entries = self.entries;
        let Some(root) = self.root.take() else {
            // Doğrulama: diske dokunulmaz; symlink hedefleri zaten end_entry'de denetlendi.
            return Ok(self.report);
        };
        // (2) symlink'ler
        let links = std::mem::take(&mut self.symlinks);
        for (path, target) in links {
            let class = names::classify_symlink_target(&target);
            let create = matches!(
                (self.opts.symlinks, class),
                (SymlinkPolicy::Unsafe, _) | (SymlinkPolicy::Safe, SymlinkClass::Safe)
            );
            if !create {
                let why = if class == SymlinkClass::Unsafe {
                    "güvensiz symlink hedefi, kurulmadı"
                } else {
                    "symlink kurulmadı (--restore-symlinks yok)"
                };
                self.report.skipped.push((path.clone(), why.into()));
                if self.opts.strict && class == SymlinkClass::Unsafe {
                    return Err(Error::Corrupt {
                        at: "arşiv".into(),
                        detail: Some(format!(
                            "--strict: güvensiz symlink {}",
                            names::escape_display(&path)
                        )),
                    });
                }
                continue;
            }
            if class == SymlinkClass::Unsafe {
                self.report.warnings.push(format!(
                    "güvensiz symlink kuruldu: {} → {}",
                    names::escape_display(&path),
                    names::escape_display(&String::from_utf8_lossy(&target))
                ));
            }
            if self.dedup.contains(&names::fold_key(&path)) {
                // admit_path zaten ekledi; var olan ad FS tarafından reddedilir.
            }
            match create_symlink(&root, &path, &target) {
                Ok(()) => self.report.symlinks_created += 1,
                Err(e) if e.kind() == io::ErrorKind::AlreadyExists => {
                    return Err(Error::Corrupt {
                        at: "arşiv".into(),
                        detail: Some(format!(
                            "symlink adı zaten var: {}",
                            names::escape_display(&path)
                        )),
                    });
                }
                Err(e) => {
                    self.report
                        .skipped
                        .push((path.clone(), format!("symlink kurulamadı: {e}")));
                    if self.opts.strict {
                        return Err(Error::Environment(format!(
                            "--strict: symlink kurulamadı ({}): {e}",
                            names::escape_display(&path)
                        )));
                    }
                }
            }
        }
        // (3) mode/mtime derinden yüzeye
        let mut deferred = std::mem::take(&mut self.deferred);
        deferred.sort_by_key(|d| std::cmp::Reverse(d.depth));
        for d in deferred {
            let path = String::from_utf8_lossy(&self.path_arena[d.off..d.off + d.len]).into_owned();
            apply_metadata(&root, &path, d.mode, d.mtime);
        }
        Ok(self.report)
    }
}

fn create_symlink(root: &cap_std::fs::Dir, path: &str, target: &[u8]) -> io::Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::ffi::OsStrExt;
        let t = std::ffi::OsStr::from_bytes(target);
        root.symlink(t, path)
    }
    #[cfg(windows)]
    {
        let t = String::from_utf8_lossy(target).replace('/', "\\");
        // Hedef kök içinde bir dizine çözülüyorsa dizin bağı.
        let is_dir = root
            .metadata(Path::new(path).parent().unwrap_or(Path::new("")).join(&t))
            .is_ok_and(|m| m.is_dir());
        if is_dir {
            root.symlink_dir(&t, path)
        } else {
            root.symlink_file(&t, path)
        }
    }
    #[cfg(not(any(unix, windows)))]
    {
        let _ = (root, path, target);
        Err(io::Error::new(io::ErrorKind::Unsupported, "symlink"))
    }
}

/// Çıkarılan girişlere uygulanan izin maskesi: setuid/setgid/sticky ve grup/diğerleri için
/// yazma izni her zaman kaldırılır (arşivi hazırlayan kişi alıcıda dünya-yazılabilir dizin
/// bırakamaz).
pub const SAFE_MODE_MASK: u32 = 0o755;

/// mode/mtime best-effort (izinler `SAFE_MODE_MASK` ile kısıtlanmıştır).
fn apply_metadata(root: &cap_std::fs::Dir, path: &str, mode: u32, mtime: i64) {
    // Platformun zaman aralığını aşan değer (Windows'ta Unix'ten dar) atlanır: `+`/`-` taşmada
    // panikler, bu da kötü niyetli bir arşivle çıkarmayı çökertebilirdi.
    let d = std::time::Duration::from_secs(mtime.unsigned_abs());
    let t = if mtime >= 0 {
        std::time::UNIX_EPOCH.checked_add(d)
    } else {
        std::time::UNIX_EPOCH.checked_sub(d)
    };
    let is_dir = root.metadata(path).is_ok_and(|m| m.is_dir());
    if is_dir {
        if let Some(t) = t
            && let Ok(d) = root.open_dir(path)
        {
            let _ = d.into_std_file().set_modified(t);
        }
    } else if let Some(t) = t {
        let mut oo = cap_std::fs::OpenOptions::new();
        oo.write(true);
        if let Ok(f) = root.open_with(path, &oo) {
            let _ = f.into_std().set_modified(t);
        }
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let p = std::fs::Permissions::from_mode(mode & SAFE_MODE_MASK);
        let _ = root.set_permissions(path, cap_std::fs::Permissions::from_std(p));
    }
    #[cfg(not(unix))]
    {
        if mode & 0o200 == 0
            && !is_dir
            && let Ok(md) = root.metadata(path)
        {
            let mut p = md.permissions();
            p.set_readonly(true);
            let _ = root.set_permissions(path, p);
        }
    }
}

impl Write for Extractor {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.consume(buf)?;
        Ok(buf.len())
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::panic, clippy::cast_possible_truncation)]
mod tests {
    use super::*;

    fn tmp(tag: &str) -> PathBuf {
        let d = std::env::temp_dir().join(format!("lphy-arc-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        d
    }

    fn extract_all(bytes: &[u8], opts: ExtractOptions, tag: &str) -> (PathBuf, Result<Report>) {
        let out = tmp(tag);
        let root = out.join("root");
        std::fs::create_dir(&root).unwrap();
        let mut ex = Extractor::new(&root, opts).unwrap();
        for chunk in bytes.chunks(13) {
            if let Err(e) = ex.write_all(chunk) {
                return (out, Err(Error::from_io(e)));
            }
        }
        (out, ex.finish())
    }

    fn record(ty: u8, path: &str, mode: u32, mtime: i64) -> Vec<u8> {
        let mut v = vec![ty];
        v.extend_from_slice(&(path.len() as u16).to_le_bytes());
        v.extend_from_slice(path.as_bytes());
        v.extend_from_slice(&mode.to_le_bytes());
        v.extend_from_slice(&mtime.to_le_bytes());
        v
    }

    fn frames(data: &[u8]) -> Vec<u8> {
        let mut v = Vec::new();
        if !data.is_empty() {
            v.extend_from_slice(&(data.len() as u32).to_le_bytes());
            v.extend_from_slice(data);
        }
        v.extend_from_slice(&0u32.to_le_bytes());
        v
    }

    fn end() -> Vec<u8> {
        record(T_END, "", 0, 0)
    }

    #[test]
    fn roundtrip_tree_with_empty_dir_nfd_name_and_symlink() {
        let src = tmp("src");
        std::fs::create_dir_all(src.join("d1/d2")).unwrap();
        std::fs::create_dir_all(src.join("empty")).unwrap();
        std::fs::write(src.join("d1/a.txt"), b"alpha").unwrap();
        std::fs::write(src.join("d1/d2/b.bin"), vec![9u8; 3000]).unwrap();
        std::fs::write(src.join("s\u{0327}.txt"), b"nfd").unwrap();
        #[cfg(unix)]
        {
            std::os::unix::fs::symlink("d1/a.txt", src.join("link")).unwrap();
            std::os::unix::fs::symlink("/etc/passwd", src.join("badlink")).unwrap();
        }
        let mut w = ArchiveWriter::new(&src, false).unwrap();
        let mut bytes = Vec::new();
        w.read_to_end(&mut bytes).unwrap();
        assert!(w.report.skipped.is_empty());
        assert_eq!(w.report.entries, w.entries());
        assert!(w.report.entries >= 6);
        // adlar NFC
        let nfc = "ş.txt".as_bytes();
        let nfd = "s\u{0327}.txt".as_bytes();
        assert!(bytes.windows(nfc.len()).any(|x| x == nfc));
        assert!(!bytes.windows(nfd.len()).any(|x| x == nfd));

        let (out, rep) = extract_all(
            &bytes,
            ExtractOptions {
                symlinks: SymlinkPolicy::Safe,
                ..Default::default()
            },
            "dst",
        );
        let rep = rep.unwrap();
        let root = out.join("root");
        assert_eq!(std::fs::read(root.join("d1/a.txt")).unwrap(), b"alpha");
        assert_eq!(
            std::fs::read(root.join("d1/d2/b.bin")).unwrap(),
            vec![9u8; 3000]
        );
        assert!(root.join("empty").is_dir());
        assert_eq!(std::fs::read(root.join("ş.txt")).unwrap(), b"nfd");
        #[cfg(unix)]
        {
            assert_eq!(
                std::fs::read_link(root.join("link")).unwrap(),
                PathBuf::from("d1/a.txt")
            );
            assert!(
                !root.join("badlink").exists() && root.join("badlink").symlink_metadata().is_err()
            );
            assert_eq!(rep.symlinks_created, 1);
            assert!(
                rep.skipped
                    .iter()
                    .any(|(p, why)| p == "badlink" && why.contains("güvensiz"))
            );
        }
        let _ = (
            rep,
            std::fs::remove_dir_all(&src),
            std::fs::remove_dir_all(&out),
        );
    }

    #[test]
    fn zip_slip_and_structure_violations_are_code_4_without_leaving_files() {
        let cases: Vec<(&str, Vec<u8>)> = vec![
            (
                "dotdot",
                [record(T_FILE, "../x", 0o644, 0), frames(b"x"), end()].concat(),
            ),
            (
                "abs",
                [record(T_FILE, "/etc/x", 0o644, 0), frames(b"x"), end()].concat(),
            ),
            (
                "backslash",
                [record(T_FILE, "a\\b", 0o644, 0), frames(b"x"), end()].concat(),
            ),
            (
                "drive",
                [record(T_FILE, "C:x", 0o644, 0), frames(b"x"), end()].concat(),
            ),
            (
                "missing-parent",
                [record(T_FILE, "nodir/x", 0o644, 0), frames(b"x"), end()].concat(),
            ),
            (
                "dup-case",
                [
                    record(T_FILE, "a.txt", 0o644, 0),
                    frames(b"1"),
                    record(T_FILE, "A.TXT", 0o644, 0),
                    frames(b"2"),
                    end(),
                ]
                .concat(),
            ),
            (
                "no-end",
                [record(T_FILE, "a", 0o644, 0), frames(b"1")].concat(),
            ),
            (
                "after-end",
                [record(T_FILE, "a", 0o644, 0), frames(b"1"), end(), vec![0]].concat(),
            ),
            (
                "big-frame",
                [
                    record(T_FILE, "a", 0o644, 0),
                    (17u32 * 1024 * 1024).to_le_bytes().to_vec(),
                ]
                .concat(),
            ),
            ("deep", {
                let p = std::iter::repeat_n("a/", 257).collect::<String>() + "z";
                [record(T_FILE, &p, 0o644, 0), frames(b"1"), end()].concat()
            }),
            (
                "mtime",
                [record(T_FILE, "a", 0o644, 1 << 41), frames(b"1"), end()].concat(),
            ),
            ("bad-end", [record(T_END, "", 1, 0)].concat()),
        ];
        for (name, bytes) in cases {
            let (out, r) = extract_all(&bytes, ExtractOptions::default(), name);
            match r {
                Err(Error::Corrupt { .. }) => {}
                other => panic!("{name}: {other:?}"),
            }
            let _ = std::fs::remove_dir_all(&out);
        }
    }

    #[test]
    fn symlink_then_file_through_it_does_not_escape() {
        // symlink-dizin-sonra-dosya: `l -> ../outside` sonra `l/x` → l kurulmadan dosya gelir;
        // üst dizin girişi (`l`) yoktur → 4; symlink'ler zaten END sonrası kurulur.
        let bytes = [
            record(T_SYMLINK, "l", 0, 0),
            frames(b"../outside"),
            record(T_FILE, "l/x", 0o644, 0),
            frames(b"pwned"),
            end(),
        ]
        .concat();
        let (out, r) = extract_all(
            &bytes,
            ExtractOptions {
                symlinks: SymlinkPolicy::Unsafe,
                ..Default::default()
            },
            "slip",
        );
        assert!(matches!(r, Err(Error::Corrupt { .. })));
        assert!(!out.join("outside").exists());
        let _ = std::fs::remove_dir_all(&out);
    }

    fn verify_all(bytes: &[u8], opts: ExtractOptions) -> Result<Report> {
        let mut ex = Extractor::verifier(opts);
        for chunk in bytes.chunks(13) {
            ex.write_all(chunk).map_err(Error::from_io)?;
        }
        ex.finish()
    }

    #[test]
    fn extreme_mtimes_do_not_panic() {
        // Biçimin izin verdiği uç değerler, platformun zaman aralığını aşsa bile (Windows)
        // çıkarmayı durdurmamalı; zaman yalnızca atlanır.
        let bytes = [
            record(T_FILE, "ileri", 0o644, MAX_MTIME_ABS),
            frames(b"a"),
            record(T_FILE, "geri", 0o644, -MAX_MTIME_ABS),
            frames(b"b"),
            end(),
        ]
        .concat();
        let (out, r) = extract_all(&bytes, ExtractOptions::default(), "mtime");
        r.unwrap();
        assert_eq!(std::fs::read(out.join("root/ileri")).unwrap(), b"a");
        let _ = std::fs::remove_dir_all(out);
    }

    #[test]
    fn symlink_target_split_over_two_frames_is_rejected() {
        let mut two = record(T_SYMLINK, "l", 0, 0);
        two.extend_from_slice(&1u32.to_le_bytes());
        two.extend_from_slice(b"a");
        two.extend_from_slice(&1u32.to_le_bytes());
        two.extend_from_slice(b"b");
        two.extend_from_slice(&0u32.to_le_bytes());
        let bytes = [two, end()].concat();
        assert!(matches!(
            verify_all(&bytes, ExtractOptions::default()),
            Err(Error::Corrupt { .. })
        ));
        let (out, r) = extract_all(&bytes, ExtractOptions::default(), "symframes");
        assert!(matches!(r, Err(Error::Corrupt { .. })));
        let _ = std::fs::remove_dir_all(out);
    }

    #[test]
    fn verifier_accepts_what_extraction_accepts_and_writes_nothing() {
        let good = [
            record(T_DIR, "d", 0o755, 0),
            record(T_FILE, "d/a", 0o644, 0),
            frames(b"veri"),
            end(),
        ]
        .concat();
        let rep = verify_all(&good, ExtractOptions::default()).unwrap();
        assert_eq!(rep.entries, 2);
        // Yinelenen ad, eksik üst dizin, END yok: çıkarmada olduğu gibi reddedilir.
        let dup = [
            record(T_FILE, "a", 0o644, 0),
            frames(b"1"),
            record(T_FILE, "A", 0o644, 0),
            frames(b"2"),
            end(),
        ]
        .concat();
        assert!(verify_all(&dup, ExtractOptions::default()).is_err());
        let orphan = [record(T_FILE, "yok/a", 0o644, 0), frames(b"1"), end()].concat();
        assert!(verify_all(&orphan, ExtractOptions::default()).is_err());
        let no_end = [record(T_FILE, "a", 0o644, 0), frames(b"1")].concat();
        assert!(verify_all(&no_end, ExtractOptions::default()).is_err());
    }

    #[test]
    fn setuid_cleared_and_rename_conflicts() {
        let bytes = [
            record(T_DIR, "d", 0o4755, 100),
            record(T_FILE, "d/a", 0o6777, 200),
            frames(b"x"),
            record(T_FILE, "d/A", 0o644, 0),
            frames(b"y"),
            end(),
        ]
        .concat();
        let (out, r) = extract_all(
            &bytes,
            ExtractOptions {
                rename_conflicts: true,
                ..Default::default()
            },
            "setuid",
        );
        let rep = r.unwrap();
        assert_eq!(rep.renamed.len(), 1);
        assert_eq!(rep.renamed[0].1, "d/A_2");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let m = std::fs::metadata(out.join("root/d/a"))
                .unwrap()
                .permissions()
                .mode()
                & 0o7777;
            assert_eq!(m, 0o755, "dünya-yazılabilir izin kaldırılmalı");
            let d = std::fs::metadata(out.join("root/d"))
                .unwrap()
                .permissions()
                .mode()
                & 0o7777;
            assert_eq!(d, 0o755);
        }
        let mt = std::fs::metadata(out.join("root/d/a"))
            .unwrap()
            .modified()
            .unwrap();
        assert_eq!(
            mt.duration_since(std::time::UNIX_EPOCH).unwrap().as_secs(),
            200
        );
        let _ = std::fs::remove_dir_all(&out);
    }

    #[test]
    fn padded_trailer_rules() {
        let body = [record(T_FILE, "a", 0o644, 0), frames(b"hi"), end()].concat();
        let target = padme(body.len() as u64) as usize;
        let mut padded = body.clone();
        padded.resize(target, 0);
        let (out, r) = extract_all(
            &padded,
            ExtractOptions {
                padded: true,
                ..Default::default()
            },
            "pad-ok",
        );
        r.unwrap();
        let _ = std::fs::remove_dir_all(&out);
        let mut bad = padded.clone();
        if bad.len() > body.len() {
            *bad.last_mut().unwrap() = 1;
            let (out, r) = extract_all(
                &bad,
                ExtractOptions {
                    padded: true,
                    ..Default::default()
                },
                "pad-nz",
            );
            assert!(matches!(r, Err(Error::Corrupt { .. })));
            let _ = std::fs::remove_dir_all(&out);
        }
        let (out, r) = extract_all(
            &body[..body.len()],
            ExtractOptions {
                padded: true,
                ..Default::default()
            },
            "pad-short",
        );
        if target != body.len() {
            assert!(matches!(r, Err(Error::Corrupt { .. })));
        }
        let _ = std::fs::remove_dir_all(&out);
        // ArchivePadReader üretimi tam P(n)
        let mut r = ArchivePadReader::new(&body[..]);
        let mut v = Vec::new();
        r.read_to_end(&mut v).unwrap();
        assert_eq!(v.len(), target);
        assert_eq!(&v[..body.len()], &body[..]);
    }

    #[test]
    fn single_file_detection_and_strict_skip() {
        let bytes = [record(T_FILE, "only.txt", 0o644, 0), frames(b"1"), end()].concat();
        let out = tmp("single");
        let root = out.join("root");
        std::fs::create_dir(&root).unwrap();
        let mut ex = Extractor::new(&root, ExtractOptions::default()).unwrap();
        ex.write_all(&bytes).unwrap();
        assert_eq!(ex.single_file.as_deref(), Some("only.txt"));
        ex.finish().unwrap();
        let _ = std::fs::remove_dir_all(&out);

        #[cfg(unix)]
        {
            let src = tmp("fifo");
            std::fs::write(src.join("a"), b"1").unwrap();
            let fifo = src.join("fifo");
            let c = std::ffi::CString::new(fifo.to_string_lossy().into_owned()).unwrap();
            // mkfifo'yu lephy-sys dışından çağıramayız (forbid unsafe): `mkfifo` komutu ile.
            let st = std::process::Command::new("mkfifo")
                .arg(&fifo)
                .status()
                .unwrap();
            assert!(st.success());
            let _ = c;
            let mut w = ArchiveWriter::new(&src, false).unwrap();
            w.read_to_end(&mut Vec::new()).unwrap();
            assert_eq!(w.report.skipped.len(), 1);
            let mut w = ArchiveWriter::new(&src, true).unwrap();
            let e = w.read_to_end(&mut Vec::new()).unwrap_err();
            assert!(matches!(Error::from_io(e), Error::Corrupt { .. }));
            let _ = std::fs::remove_dir_all(&src);
        }
    }
}
