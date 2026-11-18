//! Üst düzey işlemler: başlık kurma/açma, `encrypt`, `decrypt`, `verify`, `info`, `rekey`,
//! `reencrypt` (Rekey ve reencrypt; Çözme sırası; Arşiv).
//!
//! Dosya ve klasörler arşiv (`content_type = 1`, varsayılan PADMÉ); stdin ve `--raw`
//! ham akış (`content_type = 0`, isteğe bağlı PADMÉ). Çıkarma tmp dizinine (cap-std kök handle)
//! ve sonunda noclobber rename; tek üst düzey dosyalı arşivde dosya doğrudan hedefe taşınır.

use std::fs::File;
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};

use lephy_sys::mem::SecretBytes;
use subtle::ConstantTimeEq;

use crate::archive::{ArchivePadReader, ArchiveWriter, ExtractOptions, Extractor, Report};
use crate::cipher::{AlgId, SharedCipher, TAG_LEN};
use crate::entropy::{Entropy, OsEntropy};
use crate::error::{Error, Result};
use crate::header::{
    ContentType, HEADER_LEN, Header, MAC_END, NewHeaderParams, WRAP_AAD_END, chunk_aad,
};
use crate::io::AtomicWriter;
use crate::kdf::{self, KEY_LEN, KdfParams};
use crate::pad::{RawPadReader, RawPadWriter};
use crate::pipeline::{StreamParams, decrypt_stream, encrypt_stream, verify_stream};
pub use crate::recipient::{Identity, PublicKey};

fn arena_err(e: impl std::fmt::Display) -> Error {
    Error::Environment(format!("kilitli bellek: {e}"))
}

/// Çözme/doğrulama politikası seçenekleri.
#[derive(Debug, Clone, Copy, Default)]
pub struct UnlockOptions<'a> {
    /// Bütçe aşımına izin (`--allow-large-kdf`); RAM eşiği yine de uygulanır.
    pub allow_large_kdf: bool,
    /// Kilit başarısızlığı hata (`--strict-memory`).
    pub strict_memory: bool,
    /// Identity for files encrypted to public keys (`--identity`).
    pub identity: Option<&'a Identity>,
}

/// Açılmış başlık: FK ve alt anahtarlar kilitli arenada.
pub struct Unlocked {
    /// Ayrıştırılmış başlık.
    pub header: Header,
    /// Ham başlık baytları.
    pub bytes: [u8; HEADER_LEN],
    /// Recipient stanzas that follow the header (empty for password files).
    pub ext: Vec<u8>,
    /// Dosya anahtarı.
    pub fk: SecretBytes,
    /// `data_key`.
    pub data_key: SecretBytes,
}

/// Kilitli bellekteki anahtarı kopyalamadan 32 baytlık diziye ödünç verir.
fn key32(s: &SecretBytes) -> Result<&[u8; KEY_LEN]> {
    s.expose()
        .try_into()
        .map_err(|_| Error::Environment("anahtar 32 bayt değil".into()))
}

fn strict_memory_check(strict: bool) -> Result<()> {
    if strict && lephy_sys::mem::lock_failed() {
        return Err(Error::Environment(format!(
            "--strict-memory: bellek kilitlenemedi ({})",
            lephy_sys::mem::last_lock_error().unwrap_or_default()
        )));
    }
    Ok(())
}

/// FORMAT.md › Çözme sırası, adım 2–8. `keyfile_digest`: `--keyfile` verildiyse BLAKE3'ü.
///
/// # Errors
/// 3 (parola/keyfile/bayrak), 4 (başlık), 6 (bütçe), 1.
pub fn unlock_header(
    bytes: &[u8; HEADER_LEN],
    ext: &[u8],
    pwd_nfc: &SecretBytes,
    keyfile_digest: Option<&[u8; 32]>,
    opts: UnlockOptions<'_>,
    log: &mut dyn FnMut(&str),
) -> Result<Unlocked> {
    // 1
    let header = Header::parse(bytes)?;
    if ext.len() != header.ext_len() {
        return Err(Error::Corrupt {
            at: "başlık".into(),
            detail: Some("recipient stanzas truncated".into()),
        });
    }
    if header.recipients > 0 {
        if keyfile_digest.is_some() {
            return Err(Error::KeyfileNotUsed);
        }
        let Some(id) = opts.identity else {
            return Err(Error::IdentityRequired);
        };
        let fk = crate::recipient::unwrap_with(bytes, header.alg, ext, id)?;
        return finish_unlock(header, bytes, ext, fk);
    }
    if opts.identity.is_some() {
        return Err(Error::IdentityNotUsed);
    }
    // 2 keyfile bayrak/argüman tutarlılığı (KDF'siz)
    match (header.keyfile, keyfile_digest.is_some()) {
        (true, false) => return Err(Error::KeyfileRequired),
        (false, true) => return Err(Error::KeyfileNotUsed),
        _ => {}
    }
    // 3 bütçe / RAM
    let ram = lephy_sys::platform::physical_memory_bytes().ok();
    header.kdf.check_budget(opts.allow_large_kdf, ram)?;
    log(&format!(
        "KDF: Argon2id ~{} MiB × {} yineleme × {} lane",
        header.kdf.memory_mib(),
        header.kdf.t,
        header.kdf.p
    ));
    // 4 KDF
    let a_out = kdf::argon2_out(pwd_nfc.expose(), &header.salt, &header.kdf)?;
    let kek = kdf::derive_kek(a_out, keyfile_digest, &header.salt)?;
    log("KDF tamamlandı");
    strict_memory_check(opts.strict_memory)?;
    // 5 commit_tag sabit zamanlı
    let (wrap_key, commit) = kdf::derive_wrap_and_commit(&kek, &header.salt)?;
    drop(kek);
    if commit.ct_eq(&header.commit_tag).unwrap_u8() != 1 {
        return Err(Error::WrongPassword);
    }
    // 6 unwrap
    let wrapper = SharedCipher::new(header.alg, key32(&wrap_key)?)?;
    drop(wrap_key);
    let mut fk = SecretBytes::with_capacity(KEY_LEN).map_err(arena_err)?;
    fk.push_slice(&header.wrapped_fk[..KEY_LEN])
        .map_err(arena_err)?;
    let mut tag = [0u8; TAG_LEN];
    tag.copy_from_slice(&header.wrapped_fk[KEY_LEN..]);
    let ok = wrapper.open_in_place(
        &header.wrap_nonce[..header.alg.nonce_len()],
        &bytes[..WRAP_AAD_END],
        fk.expose_mut(),
        &tag,
    )?;
    if ok.is_err() {
        return Err(Error::Corrupt {
            at: "başlık".into(),
            detail: Some("wrapped_fk doğrulanamadı (commit geçti)".into()),
        });
    }
    finish_unlock(header, bytes, ext, fk)
}

/// `header_mac` input: `header[0..224] ‖ recipient stanzas`.
fn mac_input(bytes: &[u8; HEADER_LEN], ext: &[u8]) -> Vec<u8> {
    let mut v = Vec::with_capacity(MAC_END + ext.len());
    v.extend_from_slice(&bytes[..MAC_END]);
    v.extend_from_slice(ext);
    v
}

/// Steps 7–8: FK subkeys and `header_mac`.
fn finish_unlock(
    header: Header,
    bytes: &[u8; HEADER_LEN],
    ext: &[u8],
    fk: SecretBytes,
) -> Result<Unlocked> {
    let (data_key, mac_key) = kdf::derive_fk_subkeys(&fk, &header.stream_nonce_prefix)?;
    let mac = kdf::header_mac(&mac_key, &mac_input(bytes, ext))?;
    drop(mac_key);
    if mac.ct_eq(&header.header_mac).unwrap_u8() != 1 {
        return Err(Error::Corrupt {
            at: "başlık".into(),
            detail: Some("header_mac uyuşmuyor".into()),
        });
    }
    Ok(Unlocked {
        header,
        bytes: *bytes,
        ext: ext.to_vec(),
        fk,
        data_key,
    })
}

/// New header for a file encrypted to `recipients` (no password slot). Entropy order:
/// `stream_nonce_prefix`, FK, then per recipient the ephemeral secret and `wrap_nonce`.
///
/// # Errors
/// 1 (RNG, locked memory, too many or invalid recipients).
pub fn build_recipient_header(
    params: &NewHeaderParams,
    recipients: &[PublicKey],
    entropy: &mut dyn Entropy,
) -> Result<Unlocked> {
    let count = u16::try_from(recipients.len())
        .ok()
        .filter(|n| (1..=crate::header::MAX_RECIPIENTS).contains(n))
        .ok_or_else(|| {
            Error::Environment(format!(
                "1 to {} recipients are allowed",
                crate::header::MAX_RECIPIENTS
            ))
        })?;
    let mut prefix = [0u8; 24];
    entropy.fill(&mut prefix[..params.alg.prefix_len()])?;
    let mut fk = SecretBytes::with_capacity(KEY_LEN).map_err(arena_err)?;
    fk.set_len(KEY_LEN).map_err(arena_err)?;
    entropy.fill(fk.expose_mut())?;
    let mut header = Header {
        alg: params.alg,
        content_type: params.content_type,
        padded: params.padded,
        chunk_code: params.chunk_code,
        kdf: KdfParams {
            m_kib: 0,
            t: 0,
            p: 0,
        },
        keyfile: false,
        compressed: params.compressed,
        recipients: count,
        salt: [0u8; 32],
        stream_nonce_prefix: prefix,
        wrap_nonce: [0u8; 24],
        commit_tag: [0u8; 32],
        wrapped_fk: [0u8; 48],
        header_mac: [0u8; 32],
    };
    let partial = header.to_bytes();
    let ext = crate::recipient::wrap_for(&partial, params.alg, &fk, recipients, entropy)?;
    let (data_key, mac_key) = kdf::derive_fk_subkeys(&fk, &prefix)?;
    header.header_mac = kdf::header_mac(&mac_key, &mac_input(&partial, &ext))?;
    drop(mac_key);
    let bytes = header.to_bytes();
    Ok(Unlocked {
        header,
        bytes,
        ext,
        fk,
        data_key,
    })
}

/// `rekey` için korunan malzeme: FK ve `stream_nonce_prefix` (ikisi de yoksa yeni üretilir).
#[derive(Default, Clone, Copy)]
pub struct Reuse<'a> {
    /// Korunan FK.
    pub fk: Option<&'a SecretBytes>,
    /// Korunan `stream_nonce_prefix`.
    pub prefix: Option<&'a [u8; 24]>,
}

/// Yeni başlık kurar (şifreleme, rekey, reencrypt). Entropi sırası: salt, prefix, `wrap_nonce`,
/// FK (`reuse` ile verilenler istenmez — `rekey`).
///
/// # Errors
/// 1, 6.
pub fn build_header(
    params: &NewHeaderParams,
    pwd_nfc: &SecretBytes,
    keyfile_digest: Option<&[u8; 32]>,
    reuse: Reuse<'_>,
    entropy: &mut dyn Entropy,
    strict_memory: bool,
    log: &mut dyn FnMut(&str),
) -> Result<Unlocked> {
    let existing_fk = reuse.fk;
    let existing_prefix = reuse.prefix;
    params.kdf.check_encrypt_policy()?;
    let ram = lephy_sys::platform::physical_memory_bytes().ok();
    params.kdf.check_budget(true, ram)?;
    let mut salt = [0u8; 32];
    entropy.fill(&mut salt)?;
    let mut prefix = [0u8; 24];
    if let Some(p) = existing_prefix {
        prefix = *p;
    } else {
        entropy.fill(&mut prefix[..params.alg.prefix_len()])?;
    }
    let mut wrap_nonce = [0u8; 24];
    entropy.fill(&mut wrap_nonce[..params.alg.nonce_len()])?;
    let mut fk = SecretBytes::with_capacity(KEY_LEN).map_err(arena_err)?;
    fk.set_len(KEY_LEN).map_err(arena_err)?;
    if let Some(e) = existing_fk {
        fk.expose_mut().copy_from_slice(e.expose());
    } else {
        entropy.fill(fk.expose_mut())?;
    }
    log(&format!(
        "KDF: Argon2id ~{} MiB × {} yineleme × {} lane",
        params.kdf.memory_mib(),
        params.kdf.t,
        params.kdf.p
    ));
    let a_out = kdf::argon2_out(pwd_nfc.expose(), &salt, &params.kdf)?;
    let kek = kdf::derive_kek(a_out, keyfile_digest, &salt)?;
    log("KDF tamamlandı");
    strict_memory_check(strict_memory)?;
    let (wrap_key, commit_tag) = kdf::derive_wrap_and_commit(&kek, &salt)?;
    drop(kek);
    let mut header = Header {
        alg: params.alg,
        content_type: params.content_type,
        padded: params.padded,
        chunk_code: params.chunk_code,
        kdf: params.kdf,
        keyfile: keyfile_digest.is_some(),
        compressed: params.compressed,
        recipients: 0,
        salt,
        stream_nonce_prefix: prefix,
        wrap_nonce,
        commit_tag,
        wrapped_fk: [0u8; 48],
        header_mac: [0u8; 32],
    };
    let partial = header.to_bytes();
    let wrapper = SharedCipher::new(params.alg, key32(&wrap_key)?)?;
    drop(wrap_key);
    let mut wrapped = [0u8; 48];
    wrapped[..KEY_LEN].copy_from_slice(fk.expose());
    let tag = wrapper.seal_in_place(
        &wrap_nonce[..params.alg.nonce_len()],
        &partial[..WRAP_AAD_END],
        &mut wrapped[..KEY_LEN],
    )?;
    wrapped[KEY_LEN..].copy_from_slice(&tag);
    header.wrapped_fk = wrapped;
    let (data_key, mac_key) = kdf::derive_fk_subkeys(&fk, &prefix)?;
    let pre = header.to_bytes();
    header.header_mac = kdf::header_mac(&mac_key, &pre[..MAC_END])?;
    drop(mac_key);
    let bytes = header.to_bytes();
    Ok(Unlocked {
        header,
        bytes,
        ext: Vec::new(),
        fk,
        data_key,
    })
}

/// Şifreleme seçenekleri. Bayraklar CLI bayraklarını birebir yansıtır (durum makinesi değil).
#[derive(Debug, Clone, Copy)]
#[allow(clippy::struct_excessive_bools)]
pub struct EncryptOptions {
    /// Algoritma.
    pub alg: AlgId,
    /// `chunk_code`.
    pub chunk_code: u8,
    /// KDF.
    pub kdf: KdfParams,
    /// Hedef varsa üzerine yaz.
    pub force: bool,
    /// `--strict-memory`.
    pub strict_memory: bool,
    /// Dosya girişini arşiv yerine ham akış olarak yaz (`--raw`); stdin her zaman ham.
    pub raw: bool,
    /// PADMÉ: `None` = varsayılan (arşivde açık, ham akışta kapalı).
    pub pad: Option<bool>,
    /// Atlanan giriş hata (`--strict`).
    pub strict: bool,
    /// Şifrelemeden önce sıkıştır (biçim v2; yan kanal uyarısı: `compress.rs`).
    pub compress: bool,
    /// Çıktıyı Reed–Solomon hata düzeltme zarfına sar (`envelope.rs`; ~%7 büyür).
    pub ecc: bool,
}

/// Şifreleme girişi.
pub enum Input<'a> {
    /// Dosya ya da klasör yolu.
    Path(&'a Path),
    /// Standart girdi (ham akış; boyut bilinmez; PADMÉ kullanılamaz).
    Stdin,
}

/// Sıkıştırmalı şifreleme gövdesi: kaynak → DEFLATE → [PADMÉ sıfırları] → STREAM.
fn encrypt_compressed(
    sp: &StreamParams<'_>,
    input: &Input<'_>,
    content_type: ContentType,
    padded: bool,
    opts: &EncryptOptions,
    sink: &mut (dyn Write + Send),
    report: &mut EncryptReport,
) -> Result<u64> {
    use crate::compress::DeflateReader;
    match (input, content_type) {
        (Input::Stdin, _) => {
            let stdin = std::io::stdin();
            if lephy_sys::term::is_tty(&stdin) {
                return Err(Error::Environment(
                    "stdin bir terminal; giriş verisi bekleniyor".into(),
                ));
            }
            let mut r = DeflateReader::new(stdin, false);
            encrypt_stream(sp, &mut r, &mut *sink).map_err(map_adaptor)
        }
        (Input::Path(p), ContentType::Raw) => {
            let mut r = DeflateReader::new(File::open(p)?, padded);
            encrypt_stream(sp, &mut r, &mut *sink).map_err(map_adaptor)
        }
        (Input::Path(p), ContentType::Archive) => {
            let mut r = DeflateReader::new(ArchiveWriter::new(p, opts.strict)?, padded);
            let n = encrypt_stream(sp, &mut r, &mut *sink).map_err(map_adaptor)?;
            report.archive = Some(r.into_inner().report);
            Ok(n)
        }
    }
}

/// Orijinal silme sonucu.
#[derive(Debug, Default)]
pub struct DeleteReport {
    /// Silinen öğe sayısı.
    pub removed: usize,
    /// Silinmeyenler: arşivden sonra değişen ya da boş olmayan dizinler (yeni dosya eklenmiş).
    pub kept: Vec<PathBuf>,
}

/// Yalnızca arşive gerçekten alınmış kaynak öğeleri siler. Atlanan bir giriş varsa hiçbir şey
/// silinmez (kod 5). Her dosya için okunduğu andaki (aygıt, inode) yeniden denetlenir; değişen
/// öğe ve boş olmayan dizin yerinde bırakılır. Önce dosyalar, sonra dizinler en derinden.
///
/// # Errors
/// Atlanan giriş varsa kod 5.
pub fn delete_archived(rep: &Report) -> Result<DeleteReport> {
    delete_archived_with(rep, false)
}

/// [`delete_archived`] gibi; `overwrite` ise her dosyanın üzerine silinmeden önce bir kez
/// rastgele veri yazılır ve fiziksel ortama indirilir. Birden çok sabit bağlantısı olan dosyanın
/// üzerine yazılmaz (diğer adlar aynı veriyi gösterir), yalnızca bu ad silinir. SSD'lerde
/// (aşınma dengeleme), kopyala-üzerine-yaz dosya sistemlerinde (APFS, Btrfs, `ReFS`), anlık
/// görüntülerde ve bulut geçmişinde eski içerik yine de kalabilir.
///
/// # Errors
/// Atlanan giriş varsa kod 5; RNG hatası.
pub fn delete_archived_with(rep: &Report, overwrite: bool) -> Result<DeleteReport> {
    if !rep.skipped.is_empty() {
        return Err(Error::Cancelled(format!(
            "{} giriş arşive alınmadı; orijinal hiç silinmedi",
            rep.skipped.len()
        )));
    }
    let mut out = DeleteReport::default();
    for a in rep.archived.iter().filter(|a| !a.is_dir) {
        if overwrite && same_item(a) && overwrite_in_place(a).is_err() {
            out.kept.push(a.path.clone());
            continue;
        }
        if same_item(a) && std::fs::remove_file(&a.path).is_ok() {
            out.removed += 1;
        } else {
            out.kept.push(a.path.clone());
        }
    }
    for a in rep.archived.iter().rev().filter(|a| a.is_dir) {
        if same_item(a) && std::fs::remove_dir(&a.path).is_ok() {
            out.removed += 1;
        } else {
            out.kept.push(a.path.clone());
        }
    }
    Ok(out)
}

/// Dosyanın üzerine bir kez rastgele veri yazar. Açılan nesnenin kimliği (fstat) arşive alınan
/// öğeyle karşılaştırılır: arada symlink ya da başka bir dosyayla değiştirilmişse dokunulmaz.
fn overwrite_in_place(a: &crate::archive::Archived) -> Result<()> {
    let f = std::fs::OpenOptions::new().write(true).open(&a.path)?;
    let md = f.metadata()?;
    if !md.is_file() {
        return Err(Error::Environment("normal dosya değil".into()));
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        if a.id
            .is_some_and(|(dev, ino)| md.dev() != dev || md.ino() != ino)
        {
            return Err(Error::Environment("dosya arşivden sonra değişti".into()));
        }
        if md.nlink() > 1 {
            return Ok(()); // yalnızca bu ad silinecek
        }
    }
    let mut left = md.len();
    let mut buf = zeroize::Zeroizing::new(vec![0u8; 1 << 20]);
    let mut w = &f;
    while left > 0 {
        let n = usize::try_from(left.min(buf.len() as u64)).unwrap_or(buf.len());
        OsEntropy.fill(&mut buf[..n])?;
        w.write_all(&buf[..n])?;
        left -= n as u64;
    }
    lephy_sys::fs::full_sync(&f)?;
    Ok(())
}

/// Yol hâlâ arşive alınan öğeyi mi gösteriyor (tür ve, Unix'te, aygıt + inode).
fn same_item(a: &crate::archive::Archived) -> bool {
    let Ok(md) = a.path.symlink_metadata() else {
        return false;
    };
    if md.is_dir() != a.is_dir {
        return false;
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        a.id.is_none_or(|(dev, ino)| md.dev() == dev && md.ino() == ino)
    }
    #[cfg(not(unix))]
    {
        true
    }
}

/// Şifreleme raporu.
#[derive(Debug, Clone, Default)]
pub struct EncryptReport {
    /// Düz metin bayt (dolgu dahil akış uzunluğu).
    pub plain_len: u64,
    /// Noclobber geri dönüşü kullanıldı (uyarı).
    pub noclobber_fallback: bool,
    /// Arşiv raporu (atlananlar, uyarılar).
    pub archive: Option<Report>,
    /// İçerik türü.
    pub content_type: ContentType,
}

fn output_inside_source(src: &Path, out: &Path) -> bool {
    let Ok(a) = src.canonicalize() else {
        return false;
    };
    let out_dir = out
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or(Path::new("."));
    let Ok(b) = out_dir.canonicalize() else {
        return false;
    };
    let target = b.join(out.file_name().unwrap_or_default());
    target == a || target.starts_with(&a)
}

/// Dosya/klasör (arşiv) ya da stdin/`--raw` (ham akış) şifreleme.
///
/// # Errors
/// 1, 4 (`--strict`), 6, 7, 8, 130.
pub fn encrypt(
    input: &Input<'_>,
    output: &Path,
    pwd_nfc: &SecretBytes,
    keyfile_digest: Option<&[u8; 32]>,
    opts: &EncryptOptions,
    entropy: &mut dyn Entropy,
    log: &mut dyn FnMut(&str),
) -> Result<EncryptReport> {
    encrypt_with(
        input,
        output,
        Lock::Password(pwd_nfc, keyfile_digest),
        opts,
        entropy,
        log,
    )
}

/// Like [`encrypt`], but the file key is wrapped for X25519 `recipients` instead of a
/// password (format v2). `opts.kdf` is not used.
///
/// # Errors
/// As [`encrypt`].
pub fn encrypt_to_recipients(
    input: &Input<'_>,
    output: &Path,
    recipients: &[PublicKey],
    opts: &EncryptOptions,
    entropy: &mut dyn Entropy,
    log: &mut dyn FnMut(&str),
) -> Result<EncryptReport> {
    encrypt_with(
        input,
        output,
        Lock::Recipients(recipients),
        opts,
        entropy,
        log,
    )
}

/// How the file key is protected.
#[derive(Clone, Copy)]
enum Lock<'a> {
    Password(&'a SecretBytes, Option<&'a [u8; 32]>),
    Recipients(&'a [PublicKey]),
}

#[allow(clippy::too_many_lines)] // giriş türü × dolgu dallanması tek yerde okunur kalsın
fn encrypt_with(
    input: &Input<'_>,
    output: &Path,
    lock: Lock<'_>,
    opts: &EncryptOptions,
    entropy: &mut dyn Entropy,
    log: &mut dyn FnMut(&str),
) -> Result<EncryptReport> {
    // Kaynak/hedef ilişkisi.
    let (content_type, padded) = match input {
        Input::Path(p) => {
            if output_inside_source(p, output) {
                return Err(Error::Environment(
                    "çıktı yolu kaynak ağacının içinde ya da kaynağın kendisi".into(),
                ));
            }
            let md = p.symlink_metadata()?;
            if md.file_type().is_symlink() {
                return Err(Error::Environment(
                    "kaynak bir symlink; takip edilmez".into(),
                ));
            }
            if md.is_dir() || !opts.raw {
                (ContentType::Archive, opts.pad.unwrap_or(true))
            } else {
                (ContentType::Raw, opts.pad.unwrap_or(false))
            }
        }
        Input::Stdin => {
            if opts.pad == Some(true) {
                return Err(Error::Environment(
                    "stdin girişinde PADMÉ kullanılamaz".into(),
                ));
            }
            (ContentType::Raw, false)
        }
    };
    let params = NewHeaderParams {
        alg: opts.alg,
        content_type,
        padded,
        chunk_code: opts.chunk_code,
        kdf: opts.kdf,
        keyfile: matches!(lock, Lock::Password(_, Some(_))),
        compressed: opts.compress,
    };
    // Boş alan ön kontrolü (yalnızca dosya; klasörde boyut önceden bilinmez).
    if let Input::Path(p) = input
        && let Ok(md) = p.metadata()
        && md.is_file()
    {
        let size = md.len();
        let chunk = crate::header::chunk_size_for(opts.chunk_code).unwrap_or(1 << 20) as u64;
        let ext = match lock {
            Lock::Recipients(r) => (r.len() * crate::header::STANZA_LEN) as u64,
            Lock::Password(..) => 0,
        };
        let est = HEADER_LEN as u64 + ext + size + 64 + (size / chunk + 1) * TAG_LEN as u64;
        let dir = output
            .parent()
            .filter(|d| !d.as_os_str().is_empty())
            .unwrap_or(Path::new("."));
        crate::io::precheck_space(dir, est)?;
    }
    let unlocked = match lock {
        Lock::Password(pwd_nfc, keyfile_digest) => build_header(
            &params,
            pwd_nfc,
            keyfile_digest,
            Reuse::default(),
            entropy,
            opts.strict_memory,
            log,
        )?,
        Lock::Recipients(r) => build_recipient_header(&params, r, entropy)?,
    };
    let cipher = SharedCipher::new(opts.alg, key32(&unlocked.data_key)?)?;
    let aad = chunk_aad(&unlocked.bytes);
    let mut w = AtomicWriter::create(output, opts.force)?;
    let file = w.file();
    let mut ecc_w = None;
    // Hata düzeltme açıksa her şey (başlık dahil) zarf yazıcısından geçer.
    let sink: &mut (dyn Write + Send) = if opts.ecc {
        ecc_w.insert(crate::envelope::EncodeWriter::new(&mut *file)?)
    } else {
        file
    };
    sink.write_all(&unlocked.bytes)?;
    sink.write_all(&unlocked.ext)?;
    let sp = StreamParams {
        cipher: &cipher,
        prefix: &unlocked.header.stream_nonce_prefix,
        aad: &aad,
        chunk_size: unlocked.header.chunk_size(),
    };
    let mut report = EncryptReport {
        content_type,
        ..Default::default()
    };
    report.plain_len = match (input, content_type, padded) {
        _ if opts.compress => encrypt_compressed(
            &sp,
            input,
            content_type,
            padded,
            opts,
            &mut *sink,
            &mut report,
        )?,
        (Input::Stdin, _, _) => {
            let mut stdin = std::io::stdin();
            if lephy_sys::term::is_tty(&stdin) {
                return Err(Error::Environment(
                    "stdin bir terminal; giriş verisi bekleniyor".into(),
                ));
            }
            encrypt_stream(&sp, &mut stdin, &mut *sink)?
        }
        (Input::Path(p), ContentType::Raw, false) => {
            let mut f = File::open(p)?;
            encrypt_stream(&sp, &mut f, &mut *sink)?
        }
        (Input::Path(p), ContentType::Raw, true) => {
            let f = File::open(p)?;
            let len = f.metadata()?.len();
            let mut r = RawPadReader::new(f, len);
            encrypt_stream(&sp, &mut r, &mut *sink)?
        }
        (Input::Path(p), ContentType::Archive, pad) => {
            let aw = ArchiveWriter::new(p, opts.strict)?;
            let n;
            let rep;
            if pad {
                let mut r = ArchivePadReader::new(aw);
                n = encrypt_stream(&sp, &mut r, &mut *sink).map_err(map_adaptor)?;
                rep = r.into_inner().report;
            } else {
                let mut r = aw;
                n = encrypt_stream(&sp, &mut r, &mut *sink).map_err(map_adaptor)?;
                rep = r.report;
            }
            report.archive = Some(rep);
            n
        }
    };
    if let Some(e) = ecc_w {
        e.finish()?;
    }
    let outcome = w.commit(opts.force)?;
    report.noclobber_fallback = outcome.noclobber_fallback;
    Ok(report)
}

/// Pipeline'dan dönen `Io` hatası adaptör kaynaklıysa (`FormatViolation`/`StrictViolation`) kod 4.
fn map_adaptor(e: Error) -> Error {
    match e {
        Error::Io(io) => Error::from_io(io),
        other => other,
    }
}

/// Başlığı okur (256 B).
fn read_header(f: &mut dyn Read) -> Result<[u8; HEADER_LEN]> {
    let mut b = [0u8; HEADER_LEN];
    let mut n = 0;
    while n < HEADER_LEN {
        match f.read(&mut b[n..]) {
            Ok(0) => {
                return Err(Error::Corrupt {
                    at: "başlık".into(),
                    detail: Some("dosya 256 bayttan kısa".into()),
                });
            }
            Ok(k) => n += k,
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => {}
            Err(e) => return Err(Error::Io(e)),
        }
    }
    Ok(b)
}

/// Reads the recipient stanzas that follow a header (none for password files). A header that
/// does not parse yields no stanzas; `unlock_header` then reports it.
fn read_ext(f: &mut dyn Read, b: &[u8; HEADER_LEN]) -> Result<Vec<u8>> {
    let Ok(h) = Header::parse(b) else {
        return Ok(Vec::new());
    };
    let mut ext = vec![0u8; h.ext_len()];
    let mut n = 0;
    while n < ext.len() {
        match f.read(&mut ext[n..]) {
            Ok(0) => {
                ext.truncate(n);
                break;
            }
            Ok(k) => n += k,
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => {}
            Err(e) => return Err(Error::Io(e)),
        }
    }
    Ok(ext)
}

/// Açık meta veri (KDF çalıştırmadan).
///
/// # Errors
/// 4, 1.
pub fn info(path: &Path) -> Result<Header> {
    let mut input = open_input(path, false)?;
    let b = read_header(&mut input.reader)?;
    Header::parse(&b)
}

/// Çözme hedefi.
pub enum Output<'a> {
    /// Dosya ya da klasör (atomik; `bool` = `--force`).
    Path(&'a Path, bool),
    /// Standart çıktı (ham fd; yalnızca ham akış; kısmi çıktı uyarısı çağıranda).
    Stdout,
}

struct RawStdout;

impl Write for RawStdout {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        lephy_sys::term::write_all_raw(&std::io::stdout(), buf)?;
        Ok(buf.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

fn open_and_unlock(
    path: &Path,
    pwd_nfc: &SecretBytes,
    keyfile_digest: Option<&[u8; 32]>,
    opts: UnlockOptions<'_>,
    log: &mut dyn FnMut(&str),
) -> Result<(File, Unlocked)> {
    let mut f = File::open(path)?;
    let b = read_header(&mut f)?;
    // rekey/reencrypt only: they replace the password slot.
    if Header::parse(&b).is_ok_and(|h| h.recipients > 0) {
        return Err(Error::Environment(
            "this file is encrypted to public keys; rekey and reencrypt work only on password files"
                .into(),
        ));
    }
    let u = unlock_header(&b, &[], pwd_nfc, keyfile_digest, opts, log)?;
    Ok((f, u))
}

/// Şifreli girdi akışı: tek dosya ya da bir parça kümesinin ilki (`….001`). Döner: okuyucu ve
/// toplam bayt.
/// Şifreli girdi: tek dosya ya da parça kümesi; hata düzeltme zarfı varsa kendiliğinden açılır.
struct OpenedInput {
    reader: Box<dyn Read + Send>,
    /// Diskteki toplam bayt (alan ön kontrolü için).
    total: u64,
    /// Zarf varsa onarım sayaçları.
    stats: Option<std::sync::Arc<crate::envelope::Stats>>,
}

fn open_input(path: &Path, lenient: bool) -> Result<OpenedInput> {
    let (mut raw, total): (Box<dyn Read + Send>, u64) = if crate::split::is_first_part(path) {
        let parts = crate::split::parts(path)?;
        let total = crate::split::total_len(&parts)?;
        (Box::new(crate::split::JoinReader::new(parts)), total)
    } else {
        let f = File::open(path)?;
        let total = f.metadata()?.len();
        (Box::new(f), total)
    };
    let mut area = [0u8; crate::envelope::HEADER_AREA];
    let mut n = 0;
    while n < area.len() {
        match raw.read(&mut area[n..]) {
            Ok(0) => break,
            Ok(k) => n += k,
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => {}
            Err(e) => return Err(Error::Io(e)),
        }
    }
    if n == area.len() && crate::envelope::looks_like_envelope(&area) {
        let stats = std::sync::Arc::new(crate::envelope::Stats::default());
        let r = crate::envelope::DecodeReader::with_header(
            &area,
            raw,
            lenient,
            std::sync::Arc::clone(&stats),
        )
        .map_err(Error::from_io)?;
        return Ok(OpenedInput {
            reader: Box::new(r),
            total,
            stats: Some(stats),
        });
    }
    let prefix = std::io::Cursor::new(area[..n].to_vec());
    Ok(OpenedInput {
        reader: Box::new(prefix.chain(raw)),
        total,
        stats: None,
    })
}

/// Dosya hata düzeltme zarfıyla mı sarılmış.
#[must_use]
pub fn has_error_correction(path: &Path) -> bool {
    let mut b = [0u8; 8];
    // Parça kümesinde zarf başlığı ilk parçadadır.
    File::open(path)
        .and_then(|mut f| f.read_exact(&mut b))
        .is_ok()
        && crate::envelope::looks_like_envelope(&b)
}

/// [`open_and_unlock`] gibi; parça kümelerini de okur (çözme ve doğrulama).
fn open_stream_and_unlock(
    path: &Path,
    pwd_nfc: &SecretBytes,
    keyfile_digest: Option<&[u8; 32]>,
    opts: UnlockOptions<'_>,
    lenient: bool,
    log: &mut dyn FnMut(&str),
) -> Result<(OpenedInput, Unlocked)> {
    let mut input = open_input(path, lenient)?;
    let b = read_header(&mut input.reader)?;
    let ext = read_ext(&mut input.reader, &b)?;
    let u = unlock_header(&b, &ext, pwd_nfc, keyfile_digest, opts, log)?;
    Ok((input, u))
}

/// Çözme raporu.
#[derive(Debug, Clone, Default)]
pub struct DecryptReport {
    /// Düz metin bayt (ham: `L`; arşiv: akış uzunluğu).
    pub plain_len: u64,
    /// Arşiv raporu.
    pub archive: Option<Report>,
    /// Noclobber geri dönüşü.
    pub noclobber_fallback: bool,
    /// Nihai hedef yolu.
    pub target: PathBuf,
    /// Hata düzeltme zarfının onardığı bayt sayısı.
    pub repaired: u64,
}

/// Çözme seçenekleri (arşiv için).
#[derive(Debug, Clone, Copy, Default)]
pub struct DecryptOptions<'a> {
    /// Kilit/bütçe.
    pub unlock: UnlockOptions<'a>,
    /// Çıkarma politikası (`padded` başlıktan doldurulur).
    pub extract: ExtractOptions,
}

/// Dizin oluşturur (0700) ve Windows'ta indeksleme dışı bırakır.
fn create_tmp_dir(dir: &Path) -> Result<()> {
    // Doğrudan 0700 ile oluşturulur (umask sonrası chmod arasında açık kalmaz).
    #[cfg_attr(not(unix), allow(unused_mut))]
    let mut b = std::fs::DirBuilder::new();
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt;
        b.mode(0o700);
    }
    b.create(dir)?;
    let _ = lephy_sys::fs::mark_not_content_indexed(dir);
    Ok(())
}

/// Çözme. Döner: rapor.
///
/// # Errors
/// 3, 4, 6, 7, 8, 1, 130.
#[allow(clippy::too_many_lines)]
pub fn decrypt(
    path: &Path,
    output: &Output<'_>,
    pwd_nfc: &SecretBytes,
    keyfile_digest: Option<&[u8; 32]>,
    opts: DecryptOptions<'_>,
    log: &mut dyn FnMut(&str),
) -> Result<DecryptReport> {
    let (input, u) =
        open_stream_and_unlock(path, pwd_nfc, keyfile_digest, opts.unlock, false, log)?;
    let (mut f, in_len, stats) = (input.reader, input.total, input.stats);
    let cipher = SharedCipher::new(u.header.alg, key32(&u.data_key)?)?;
    let aad = chunk_aad(&u.bytes);
    let sp = StreamParams {
        cipher: &cipher,
        prefix: &u.header.stream_nonce_prefix,
        aad: &aad,
        chunk_size: u.header.chunk_size(),
    };
    let mut report = DecryptReport::default();
    match (u.header.content_type, output) {
        (ContentType::Raw, Output::Stdout) if u.header.compressed => {
            let mut iw = crate::compress::InflateWriter::new(RawStdout, u.header.padded);
            decrypt_stream(&sp, &mut f, &mut iw).map_err(map_adaptor)?;
            report.plain_len = iw.finish().map_err(Error::from_io)?.1;
        }
        (ContentType::Raw, Output::Stdout) => {
            let mut so = RawStdout;
            report.plain_len = if u.header.padded {
                let mut w = RawPadWriter::new(&mut so);
                decrypt_stream(&sp, &mut f, &mut w).map_err(map_adaptor)?;
                w.finish().map_err(Error::from_io)?.1
            } else {
                decrypt_stream(&sp, &mut f, &mut so)?
            };
        }
        (ContentType::Raw, Output::Path(out, force)) => {
            let total = in_len;
            let dir = out
                .parent()
                .filter(|d| !d.as_os_str().is_empty())
                .unwrap_or(Path::new("."));
            crate::io::precheck_space(dir, total)?;
            let mut w = AtomicWriter::create(out, *force)?;
            report.plain_len = if u.header.compressed {
                let mut iw = crate::compress::InflateWriter::new(w.file(), u.header.padded);
                decrypt_stream(&sp, &mut f, &mut iw).map_err(map_adaptor)?;
                iw.finish().map_err(Error::from_io)?.1
            } else if u.header.padded {
                let mut pw = RawPadWriter::new(w.file());
                decrypt_stream(&sp, &mut f, &mut pw).map_err(map_adaptor)?;
                pw.finish().map_err(Error::from_io)?.1
            } else {
                decrypt_stream(&sp, &mut f, w.file())?
            };
            let o = w.commit(*force)?;
            report.noclobber_fallback = o.noclobber_fallback;
            report.target = out.to_path_buf();
        }
        (ContentType::Archive, Output::Stdout) => {
            return Err(Error::Environment(
                "arşiv içeriği stdout'a yazılamaz; -o ile bir hedef verin".into(),
            ));
        }
        (ContentType::Archive, Output::Path(out, force)) => {
            if !force && out.symlink_metadata().is_ok() {
                return Err(Error::Exists(out.display().to_string()));
            }
            let total = in_len;
            let parent = out
                .parent()
                .filter(|d| !d.as_os_str().is_empty())
                .unwrap_or(Path::new("."));
            crate::io::precheck_space(parent, total)?;
            let mut ent = OsEntropy;
            // Ad `.lphy-tmp-` ile başlar: `cleanup` bulur, çıktı adı sızmaz.
            let tmp = parent.join(crate::io::tmp_name(&mut ent)?);
            create_tmp_dir(&tmp)?;
            let guard = TmpDirGuard {
                path: tmp.clone(),
                keep: false,
            };
            let mut eo = opts.extract;
            // Sıkıştırmada dolgu sıkıştırılmış akışın sonundadır (InflateWriter denetler).
            eo.padded = u.header.padded && !u.header.compressed;
            let mut ex = Extractor::new(&tmp, eo)?;
            if u.header.compressed {
                let mut iw = crate::compress::InflateWriter::new(ex, u.header.padded);
                report.plain_len = decrypt_stream(&sp, &mut f, &mut iw).map_err(map_adaptor)?;
                ex = iw.finish().map_err(Error::from_io)?.0;
            } else {
                report.plain_len = decrypt_stream(&sp, &mut f, &mut ex).map_err(map_adaptor)?;
            }
            let single = ex.single_file.clone();
            let rep = ex.finish()?;
            // Tek üst düzey dosya: dosyayı doğrudan hedefe taşı, tmp dizini sil.
            let src: PathBuf = match &single {
                Some(name) if rep.entries == 1 && rep.symlinks_created == 0 => tmp.join(name),
                _ => tmp.clone(),
            };
            let fallback = move_into_place(&src, out, *force)?;
            report.noclobber_fallback = fallback;
            report.archive = Some(rep);
            report.target = out.to_path_buf();
            if single.is_some() && src != tmp {
                let _ = std::fs::remove_dir_all(&tmp);
            }
            let mut guard = guard;
            guard.keep = true;
            let _ = lephy_sys::fs::fsync_dir(parent);
        }
    }
    if let Some(st) = stats {
        report.repaired = st.corrected.load(std::sync::atomic::Ordering::Relaxed);
    }
    Ok(report)
}

struct TmpDirGuard {
    path: PathBuf,
    keep: bool,
}

impl Drop for TmpDirGuard {
    fn drop(&mut self) {
        if !self.keep {
            let _ = std::fs::remove_dir_all(&self.path);
        }
    }
}

/// rekey/reencrypt yerinde değiştirir: symlink'te bağlantının kendisi, hardlink'te yalnızca bu ad
/// değişir, eski başlık/parola gerçek dosyada ya da diğer adlarda kalırdı. Bu yüzden reddedilir.
fn require_plain_file(path: &Path) -> Result<std::fs::Metadata> {
    if has_error_correction(path) {
        return Err(Error::Environment(
            "hata düzeltmeli dosya yerinde değiştirilemez; önce çözüp yeniden şifreleyin".into(),
        ));
    }
    if crate::split::is_first_part(path) {
        return Err(Error::Environment(
            "parçalara bölünmüş dosya yerinde değiştirilemez; önce parçaları birleştirin".into(),
        ));
    }
    let md = path.symlink_metadata()?;
    if md.file_type().is_symlink() {
        return Err(Error::Environment(
            "dosya bir symlink; gerçek dosyanın yolunu verin (yoksa eski parola gerçek dosyada kalır)"
                .into(),
        ));
    }
    if !md.is_file() {
        return Err(Error::Environment("normal bir dosya değil".into()));
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        if md.nlink() > 1 {
            return Err(Error::Environment(format!(
                "dosyanın {} sabit bağlantısı (hardlink) var; diğer adlar eski parolayla açılmaya devam eder",
                md.nlink()
            )));
        }
    }
    Ok(md)
}

/// Noclobber rename; geri dönüş bayrağı. `--force`: var olan hedef önce rastgele bir tmp adına
/// taşınır, yeni çıktı yerine konunca silinir; yerine koyma başarısız olursa geri alınır. Böylece
/// hiçbir anda hedef de yedek de kaybolmaz.
fn move_into_place(src: &Path, dst: &Path, force: bool) -> Result<bool> {
    let mut backup: Option<(PathBuf, bool)> = None;
    if force && let Ok(md) = dst.symlink_metadata() {
        let parent = dst
            .parent()
            .filter(|d| !d.as_os_str().is_empty())
            .unwrap_or(Path::new("."));
        let b = parent.join(crate::io::tmp_name(&mut OsEntropy)?);
        std::fs::rename(dst, &b)?;
        backup = Some((b, md.is_dir() && !md.file_type().is_symlink()));
    }
    let r = place(src, dst);
    if let Some((b, is_dir)) = backup {
        if r.is_ok() {
            let _ = if is_dir {
                std::fs::remove_dir_all(&b)
            } else {
                std::fs::remove_file(&b)
            };
        } else {
            let _ = std::fs::rename(&b, dst);
        }
    }
    r
}

fn place(src: &Path, dst: &Path) -> Result<bool> {
    match lephy_sys::fs::rename_noclobber(src, dst) {
        Ok(()) => Ok(false),
        Err(lephy_sys::fs::NoclobberError::Exists) => Err(Error::Exists(dst.display().to_string())),
        Err(lephy_sys::fs::NoclobberError::Unsupported) => {
            if dst.symlink_metadata().is_ok() {
                return Err(Error::Exists(dst.display().to_string()));
            }
            lephy_sys::fs::rename_replace(src, dst)?;
            Ok(true)
        }
        Err(lephy_sys::fs::NoclobberError::Io(e)) => Err(Error::Io(e)),
    }
}

/// Kurtarma raporu.
#[derive(Debug, Default, Clone)]
pub struct RecoverReport {
    /// Kurtarılan dosya ya da klasör.
    pub output: PathBuf,
    /// Doğrulanamayıp sıfırla doldurulan chunk numaraları.
    pub bad_chunks: Vec<u64>,
    /// Chunk boyutu (bozuk bayt aralıklarını hesaplamak için).
    pub chunk_size: usize,
    /// Dosya kesilmiş.
    pub truncated: bool,
    /// Hata düzeltme zarfının onardığı bayt.
    pub repaired: u64,
    /// Arşivde kurtarılan giriş sayısı.
    pub entries: usize,
    /// Çıkarma ya da açma nerede durdu (varsa).
    pub stopped: Option<String>,
}

impl RecoverReport {
    /// Tamamen sağlam mı (kurtarmaya gerek yoktu).
    #[must_use]
    pub fn clean(&self) -> bool {
        self.bad_chunks.is_empty() && !self.truncated && self.stopped.is_none()
    }
}

/// Bozuk bir dosyadan kurtarılabileni çıkarır. Başlık açılabilmelidir (parola ve, varsa,
/// hata düzeltme zarfı). Doğrulanamayan chunk'lar sıfırla doldurulur; arşivde ilk bozulmaya
/// kadarki tam girişler çıkarılır. Çıktı **doğrulanmamış veri içerebilir** ve asla var olan bir
/// yolun üzerine yazılmaz.
///
/// # Errors
/// 3 (parola), 4 (başlık okunamaz), 7 (hedef var), 1, 130.
#[allow(clippy::too_many_lines)]
pub fn recover(
    path: &Path,
    output: &Path,
    pwd_nfc: &SecretBytes,
    keyfile_digest: Option<&[u8; 32]>,
    opts: UnlockOptions<'_>,
    log: &mut dyn FnMut(&str),
) -> Result<RecoverReport> {
    use crate::compress::InflateWriter;
    if output.symlink_metadata().is_ok() {
        return Err(Error::Exists(output.display().to_string()));
    }
    let (input, u) = open_stream_and_unlock(path, pwd_nfc, keyfile_digest, opts, true, log)?;
    let (mut f, stats) = (input.reader, input.stats);
    let cipher = SharedCipher::new(u.header.alg, key32(&u.data_key)?)?;
    let aad = chunk_aad(&u.bytes);
    let sp = StreamParams {
        cipher: &cipher,
        prefix: &u.header.stream_nonce_prefix,
        aad: &aad,
        chunk_size: u.header.chunk_size(),
    };
    let mut rep = RecoverReport {
        output: output.to_path_buf(),
        chunk_size: u.header.chunk_size(),
        ..RecoverReport::default()
    };
    // 1) Akışı (bozuk chunk'lar sıfırlanmış) geçici, 0600 bir dosyaya çöz.
    let parent = output
        .parent()
        .filter(|d| !d.as_os_str().is_empty())
        .unwrap_or(Path::new("."));
    let scratch_target = parent.join(crate::io::tmp_name(&mut OsEntropy)?);
    let mut scratch = AtomicWriter::create(&scratch_target, false)?;
    let st = crate::pipeline::recover_stream(&sp, &mut f, scratch.file())?;
    rep.bad_chunks = st.bad_chunks;
    rep.truncated = st.truncated;
    if let Some(s) = &stats {
        rep.repaired = s.corrected.load(std::sync::atomic::Ordering::Relaxed);
    }
    let stream_path = scratch.tmp_path().to_path_buf();
    let mut stream = File::open(&stream_path)?;
    // 2) İçerik türüne göre ikinci geçiş; ilk hatada durulur, o ana kadarki çıktı korunur.
    let copy_until_error = |src: &mut File, dst: &mut dyn Write| -> Option<String> {
        let mut buf = zeroize::Zeroizing::new(vec![0u8; 1 << 20]);
        loop {
            match src.read(&mut buf[..]) {
                Ok(0) => return None,
                Ok(n) => {
                    if let Err(e) = dst.write_all(&buf[..n]) {
                        return Some(e.to_string());
                    }
                }
                Err(e) => return Some(e.to_string()),
            }
        }
    };
    match u.header.content_type {
        ContentType::Raw => {
            let mut w = AtomicWriter::create(output, false)?;
            if u.header.compressed {
                let mut iw = InflateWriter::new(w.file(), u.header.padded);
                rep.stopped = copy_until_error(&mut stream, &mut iw);
                if rep.stopped.is_none()
                    && let Err(e) = iw.finish()
                {
                    rep.stopped = Some(e.to_string());
                }
            } else if u.header.padded {
                let mut len = [0u8; 8];
                if stream.read_exact(&mut len).is_ok() {
                    let l = u64::from_le_bytes(len);
                    let mut lim = (&mut stream).take(l);
                    std::io::copy(&mut lim, w.file())?;
                } else {
                    rep.stopped = Some("uzunluk öneki okunamadı".into());
                }
            } else {
                std::io::copy(&mut stream, w.file())?;
            }
            w.commit(false)?;
        }
        ContentType::Archive => {
            let tmp = parent.join(crate::io::tmp_name(&mut OsEntropy)?);
            create_tmp_dir(&tmp)?;
            let guard = TmpDirGuard {
                path: tmp.clone(),
                keep: false,
            };
            let eo = ExtractOptions {
                padded: u.header.padded && !u.header.compressed,
                ..ExtractOptions::default()
            };
            let ex = Extractor::new(&tmp, eo)?;
            let ex = if u.header.compressed {
                let mut iw = InflateWriter::new(ex, u.header.padded);
                rep.stopped = copy_until_error(&mut stream, &mut iw);
                iw.into_inner()
            } else {
                let mut ex = ex;
                rep.stopped = copy_until_error(&mut stream, &mut ex);
                ex
            };
            let r = ex.salvage();
            rep.entries = r.entries;
            move_into_place(&tmp, output, false)?;
            let mut guard = guard;
            guard.keep = true;
        }
    }
    drop(stream);
    drop(scratch); // geçici düz metin akışı silinir
    if !rep.clean() {
        log(&format!(
            "kurtarma: {} doğrulanamayan chunk{}",
            rep.bad_chunks.len(),
            if rep.truncated {
                ", dosya kesilmiş"
            } else {
                ""
            }
        ));
    }
    Ok(rep)
}

/// Doğrulama (diske yazmadan). Etiketlerin yanında içerik yapısı da denetlenir: arşivde yol
/// kuralları, yinelenen adlar, sınırlar, END ve dolgu; ham akışta PADMÉ dolgusu. Böylece
/// `verify` geçen bir dosya `decrypt`'te biçim hatası vermez. Döner: düz metin akış uzunluğu.
///
/// # Errors
/// 3, 4, 6, 1, 130.
pub fn verify(
    path: &Path,
    pwd_nfc: &SecretBytes,
    keyfile_digest: Option<&[u8; 32]>,
    opts: UnlockOptions<'_>,
    log: &mut dyn FnMut(&str),
) -> Result<u64> {
    let (input, u) = open_stream_and_unlock(path, pwd_nfc, keyfile_digest, opts, false, log)?;
    let mut f = input.reader;
    let cipher = SharedCipher::new(u.header.alg, key32(&u.data_key)?)?;
    let aad = chunk_aad(&u.bytes);
    let sp = StreamParams {
        cipher: &cipher,
        prefix: &u.header.stream_nonce_prefix,
        aad: &aad,
        chunk_size: u.header.chunk_size(),
    };
    match u.header.content_type {
        ContentType::Archive if u.header.compressed => {
            let ex = Extractor::verifier(ExtractOptions::default());
            let mut iw = crate::compress::InflateWriter::new(ex, u.header.padded);
            let n = decrypt_stream(&sp, &mut f, &mut iw).map_err(map_adaptor)?;
            iw.finish().map_err(Error::from_io)?.0.finish()?;
            Ok(n)
        }
        ContentType::Raw if u.header.compressed => {
            let mut iw = crate::compress::InflateWriter::new(std::io::sink(), u.header.padded);
            decrypt_stream(&sp, &mut f, &mut iw).map_err(map_adaptor)?;
            Ok(iw.finish().map_err(Error::from_io)?.1)
        }
        ContentType::Archive => {
            let eo = ExtractOptions {
                padded: u.header.padded,
                ..ExtractOptions::default()
            };
            let mut ex = Extractor::verifier(eo);
            let n = decrypt_stream(&sp, &mut f, &mut ex).map_err(map_adaptor)?;
            ex.finish()?;
            Ok(n)
        }
        ContentType::Raw if u.header.padded => {
            let mut pw = RawPadWriter::new(std::io::sink());
            decrypt_stream(&sp, &mut f, &mut pw).map_err(map_adaptor)?;
            Ok(pw.finish().map_err(Error::from_io)?.1)
        }
        ContentType::Raw => verify_stream(&sp, &mut f),
    }
}

/// Yeni kimlik bilgileri (rekey/reencrypt).
pub struct NewCredentials<'a> {
    /// Yeni parola (NFC).
    pub pwd_nfc: &'a SecretBytes,
    /// Yeni keyfile özeti.
    pub keyfile_digest: Option<&'a [u8; 32]>,
    /// Yeni KDF parametreleri (`None` = eski başlıktaki).
    pub kdf: Option<KdfParams>,
}

/// `rekey`: FK aynı kalır; yeni `salt`/`wrap_nonce`/`commit_tag`/`wrapped_fk`/`header_mac`;
/// chunk'lar aynen kopyalanır; atomik. `data_key` değişmediğinden `stream_nonce_prefix` korunur.
///
/// # Errors
/// 3, 4, 6, 1, 130.
#[allow(clippy::too_many_arguments)]
pub fn rekey(
    path: &Path,
    old_pwd: &SecretBytes,
    old_keyfile: Option<&[u8; 32]>,
    new: &NewCredentials<'_>,
    opts: UnlockOptions<'_>,
    verify_after: bool,
    entropy: &mut dyn Entropy,
    log: &mut dyn FnMut(&str),
) -> Result<()> {
    let orig_md = require_plain_file(path)?;
    let (mut f, u) = open_and_unlock(path, old_pwd, old_keyfile, opts, log)?;
    let params = NewHeaderParams {
        alg: u.header.alg,
        content_type: u.header.content_type,
        padded: u.header.padded,
        chunk_code: u.header.chunk_code,
        kdf: new.kdf.unwrap_or(u.header.kdf),
        keyfile: new.keyfile_digest.is_some(),
        compressed: u.header.compressed,
    };
    let nu = build_header(
        &params,
        new.pwd_nfc,
        new.keyfile_digest,
        Reuse {
            fk: Some(&u.fk),
            prefix: Some(&u.header.stream_nonce_prefix),
        },
        entropy,
        opts.strict_memory,
        log,
    )?;
    debug_assert_eq!(chunk_aad(&u.bytes), chunk_aad(&nu.bytes));
    let out_path: PathBuf = path.to_path_buf();
    let mut w = AtomicWriter::create(&out_path, true)?;
    w.file().write_all(&nu.bytes)?;
    f.seek(SeekFrom::Start(HEADER_LEN as u64))?;
    copy_rest(&mut f, w.file())?;
    // Windows açık bir dosyanın üzerine yeniden adlandırmaya izin vermez: kaynak önce kapanır.
    drop(f);
    w.commit(true)?;
    // Yeni dosya 0600 oluşur; özgün izinler korunur.
    let _ = std::fs::set_permissions(path, orig_md.permissions());
    log(
        "uyarı: eski parola ve eski dosyanın başlık kopyasına sahip biri bu dosyayı hâlâ açabilir; gerçek rotasyon için `reencrypt`",
    );
    if verify_after {
        verify(path, new.pwd_nfc, new.keyfile_digest, opts, log)?;
    }
    Ok(())
}

fn copy_rest(src: &mut File, dst: &mut File) -> Result<()> {
    let mut buf = vec![0u8; 1 << 20]; // ciphertext; sır değil
    loop {
        let n = match src.read(&mut buf) {
            Ok(0) => break,
            Ok(n) => n,
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => {
                if lephy_sys::signal::interrupted() {
                    return Err(Error::Interrupted);
                }
                continue;
            }
            Err(e) => return Err(Error::Io(e)),
        };
        dst.write_all(&buf[..n])?;
        if lephy_sys::signal::interrupted() {
            return Err(Error::Interrupted);
        }
    }
    Ok(())
}

/// `reencrypt`: yeni FK ve `stream_nonce_prefix`, tüm chunk'lar yeniden şifrelenir; atomik.
/// İçerik türü ve dolgu aynen korunur (düz metin akışı geçirilir, ayrıştırılmaz).
///
/// # Errors
/// 3, 4, 6, 1, 130.
pub fn reencrypt(
    path: &Path,
    old_pwd: &SecretBytes,
    old_keyfile: Option<&[u8; 32]>,
    new: &NewCredentials<'_>,
    opts: UnlockOptions<'_>,
    entropy: &mut dyn Entropy,
    log: &mut dyn FnMut(&str),
) -> Result<u64> {
    let orig_md = require_plain_file(path)?;
    let (mut f, u) = open_and_unlock(path, old_pwd, old_keyfile, opts, log)?;
    let params = NewHeaderParams {
        alg: u.header.alg,
        content_type: u.header.content_type,
        padded: u.header.padded,
        chunk_code: u.header.chunk_code,
        kdf: new.kdf.unwrap_or(u.header.kdf),
        keyfile: new.keyfile_digest.is_some(),
        compressed: u.header.compressed,
    };
    let nu = build_header(
        &params,
        new.pwd_nfc,
        new.keyfile_digest,
        Reuse::default(),
        entropy,
        opts.strict_memory,
        log,
    )?;
    let old_cipher = SharedCipher::new(u.header.alg, key32(&u.data_key)?)?;
    let old_aad = chunk_aad(&u.bytes);
    let new_cipher = SharedCipher::new(nu.header.alg, key32(&nu.data_key)?)?;
    let new_aad = chunk_aad(&nu.bytes);
    let mut w = AtomicWriter::create(path, true)?;
    w.file().write_all(&nu.bytes)?;
    let old_sp = StreamParams {
        cipher: &old_cipher,
        prefix: &u.header.stream_nonce_prefix,
        aad: &old_aad,
        chunk_size: u.header.chunk_size(),
    };
    let new_sp = StreamParams {
        cipher: &new_cipher,
        prefix: &nu.header.stream_nonce_prefix,
        aad: &new_aad,
        chunk_size: nu.header.chunk_size(),
    };
    let n = crate::pipeline::reencrypt_stream(&old_sp, &new_sp, &mut f, w.file())?;
    // Windows açık bir dosyanın üzerine yeniden adlandırmaya izin vermez: kaynak önce kapanır.
    drop(f);
    w.commit(true)?;
    // Yeni dosya 0600 oluşur; özgün izinler korunur.
    let _ = std::fs::set_permissions(path, orig_md.permissions());
    Ok(n)
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::panic, clippy::too_many_lines)]
mod tests {
    use super::*;
    use crate::archive::SymlinkPolicy;

    fn pwd(s: &str) -> SecretBytes {
        crate::password::normalize_nfc(&SecretBytes::from_slice(s.as_bytes()).unwrap()).unwrap()
    }

    fn small_kdf() -> KdfParams {
        KdfParams {
            m_kib: 65536,
            t: 1,
            p: 1,
        }
    }

    fn opts(raw: bool, pad: Option<bool>) -> EncryptOptions {
        EncryptOptions {
            alg: AlgId::XChaCha20Poly1305,
            chunk_code: 0,
            kdf: small_kdf(),
            force: false,
            strict_memory: false,
            raw,
            pad,
            strict: false,
            compress: false,
            ecc: false,
        }
    }

    fn tmpdir(tag: &str) -> PathBuf {
        let d = std::env::temp_dir().join(format!("lphy-ops-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        d
    }

    fn encrypt_dir(d: &Path, src: &Path, out: &str) -> Report {
        let rep = encrypt(
            &Input::Path(src),
            &d.join(out),
            &pwd("silme testi parola"),
            None,
            &opts(false, Some(false)),
            &mut OsEntropy,
            &mut |_| {},
        )
        .unwrap();
        rep.archive.unwrap()
    }

    #[test]
    fn recipients_roundtrip_and_errors() {
        let d = tmpdir("recipients");
        let src = d.join("kaynak");
        std::fs::create_dir_all(src.join("alt")).unwrap();
        std::fs::write(src.join("a.txt"), b"for several people").unwrap();
        std::fs::write(src.join("alt/b.txt"), vec![7u8; 200_000]).unwrap();
        let ids: Vec<Identity> = (0..2)
            .map(|_| Identity::generate(&mut OsEntropy).unwrap())
            .collect();
        let pks: Vec<PublicKey> = ids.iter().map(Identity::public).collect();
        let none = pwd("");
        for (i, (compress, ecc)) in [(false, false), (true, false), (false, true)]
            .into_iter()
            .enumerate()
        {
            let mut o = opts(false, None);
            o.compress = compress;
            o.ecc = ecc;
            let out = d.join(format!("r{i}.lphy"));
            encrypt_to_recipients(
                &Input::Path(&src),
                &out,
                &pks,
                &o,
                &mut OsEntropy,
                &mut |_| {},
            )
            .unwrap();
            let h = info(&out).unwrap();
            assert_eq!(h.recipients, 2);
            for (j, id) in ids.iter().enumerate() {
                let u = UnlockOptions {
                    identity: Some(id),
                    ..UnlockOptions::default()
                };
                verify(&out, &none, None, u, &mut |_| {}).unwrap();
                let back = d.join(format!("geri-{i}-{j}"));
                let dopts = DecryptOptions {
                    unlock: u,
                    ..DecryptOptions::default()
                };
                decrypt(
                    &out,
                    &Output::Path(&back, false),
                    &none,
                    None,
                    dopts,
                    &mut |_| {},
                )
                .unwrap();
                assert_eq!(
                    std::fs::read(back.join("a.txt")).unwrap(),
                    b"for several people"
                );
                assert_eq!(
                    std::fs::read(back.join("alt/b.txt")).unwrap().len(),
                    200_000
                );
            }
        }
        let out = d.join("r0.lphy");
        // No identity, a stranger, a key file: code 3, before any output.
        let u = UnlockOptions::default();
        assert!(matches!(
            verify(&out, &none, None, u, &mut |_| {}),
            Err(Error::IdentityRequired)
        ));
        let stranger = Identity::generate(&mut OsEntropy).unwrap();
        let u = UnlockOptions {
            identity: Some(&stranger),
            ..UnlockOptions::default()
        };
        assert!(matches!(
            verify(&out, &none, None, u, &mut |_| {}),
            Err(Error::NoMatchingIdentity)
        ));
        let u = UnlockOptions {
            identity: Some(&ids[0]),
            ..UnlockOptions::default()
        };
        assert!(matches!(
            verify(&out, &none, Some(&[1; 32]), u, &mut |_| {}),
            Err(Error::KeyfileNotUsed)
        ));
        // Tampering with a stanza or truncating the stanzas is code 4.
        let orig = std::fs::read(&out).unwrap();
        for pos in [
            HEADER_LEN + 3,
            HEADER_LEN + 2 * crate::header::STANZA_LEN - 1,
        ] {
            let mut bad = orig.clone();
            bad[pos] ^= 1;
            let t = d.join("bad.lphy");
            std::fs::write(&t, &bad).unwrap();
            let r = verify(&t, &none, None, u, &mut |_| {});
            assert!(
                matches!(r, Err(Error::Corrupt { .. } | Error::NoMatchingIdentity)),
                "{pos}: {r:?}"
            );
            // The other recipient's stanza is untouched; the header MAC still catches it.
            let u1 = UnlockOptions {
                identity: Some(&ids[1]),
                ..UnlockOptions::default()
            };
            let r = verify(&t, &none, None, u1, &mut |_| {});
            assert!(matches!(r, Err(Error::Corrupt { .. })), "{pos}: {r:?}");
        }
        let t = d.join("short.lphy");
        std::fs::write(&t, &orig[..HEADER_LEN + 100]).unwrap();
        assert!(matches!(
            verify(&t, &none, None, u, &mut |_| {}),
            Err(Error::Corrupt { .. })
        ));
        // A password file refuses an identity; rekey refuses a recipient file.
        let pw_out = d.join("pw.lphy");
        let p = pwd("parola parola 1");
        encrypt(
            &Input::Path(&src),
            &pw_out,
            &p,
            None,
            &opts(false, None),
            &mut OsEntropy,
            &mut |_| {},
        )
        .unwrap();
        assert!(matches!(
            verify(&pw_out, &p, None, u, &mut |_| {}),
            Err(Error::IdentityNotUsed)
        ));
        let newc = NewCredentials {
            pwd_nfc: &p,
            keyfile_digest: None,
            kdf: None,
        };
        assert!(
            rekey(
                &out,
                &none,
                None,
                &newc,
                u,
                false,
                &mut OsEntropy,
                &mut |_| {}
            )
            .is_err()
        );
        assert_eq!(std::fs::read(&out).unwrap(), orig);
        // Too many / no recipients.
        assert!(
            encrypt_to_recipients(
                &Input::Path(&src),
                &d.join("none.lphy"),
                &[],
                &opts(false, None),
                &mut OsEntropy,
                &mut |_| {},
            )
            .is_err()
        );
        let _ = std::fs::remove_dir_all(&d);
    }

    #[test]
    fn compressed_roundtrips_archive_and_raw() {
        let d = tmpdir("compress");
        let src = d.join("kaynak");
        std::fs::create_dir_all(src.join("alt")).unwrap();
        let text: Vec<u8> = b"tekrar eden metin "
            .iter()
            .copied()
            .cycle()
            .take(400_000)
            .collect();
        std::fs::write(src.join("a.txt"), &text).unwrap();
        std::fs::write(
            src.join("alt/b.bin"),
            (0..50_000u32)
                .map(|i| i.to_le_bytes()[0])
                .collect::<Vec<_>>(),
        )
        .unwrap();
        let p = pwd("sikistirma parola 1");
        for (raw, pad) in [
            (false, Some(true)),
            (false, Some(false)),
            (true, Some(true)),
            (true, Some(false)),
        ] {
            let mut o = opts(raw, pad);
            o.compress = true;
            let input = if raw { src.join("a.txt") } else { src.clone() };
            let out = d.join(format!("c-{raw}-{pad:?}.lphy"));
            encrypt(
                &Input::Path(&input),
                &out,
                &p,
                None,
                &o,
                &mut OsEntropy,
                &mut |_| {},
            )
            .unwrap();
            let h = info(&out).unwrap();
            assert!(h.compressed);
            let bytes = std::fs::read(&out).unwrap();
            assert_eq!(
                u16::from_le_bytes([bytes[6], bytes[7]]),
                crate::header::VERSION_2
            );
            if raw {
                assert!(bytes.len() < text.len() / 10, "sıkışmalı: {}", bytes.len());
            }
            let u = UnlockOptions::default();
            verify(&out, &p, None, u, &mut |_| {}).unwrap();
            let back = d.join(format!("geri-{raw}-{pad:?}"));
            let dopts = DecryptOptions {
                unlock: u,
                ..DecryptOptions::default()
            };
            decrypt(
                &out,
                &Output::Path(&back, false),
                &p,
                None,
                dopts,
                &mut |_| {},
            )
            .unwrap();
            if raw {
                assert_eq!(std::fs::read(&back).unwrap(), text);
            } else {
                assert_eq!(std::fs::read(back.join("a.txt")).unwrap(), text);
                assert_eq!(std::fs::read(back.join("alt/b.bin")).unwrap().len(), 50_000);
            }
        }
        let _ = std::fs::remove_dir_all(&d);
    }

    #[test]
    fn v1_files_stay_v1_and_v2_flags_are_checked() {
        let d = tmpdir("v1v2");
        std::fs::write(d.join("a.txt"), b"a").unwrap();
        let out = d.join("v1.lphy");
        encrypt(
            &Input::Path(&d.join("a.txt")),
            &out,
            &pwd("surum parola 12"),
            None,
            &opts(false, None),
            &mut OsEntropy,
            &mut |_| {},
        )
        .unwrap();
        let mut b: [u8; HEADER_LEN] = std::fs::read(&out).unwrap()[..HEADER_LEN]
            .try_into()
            .unwrap();
        assert_eq!(u16::from_le_bytes([b[6], b[7]]), crate::header::VERSION);
        assert_eq!(b[12], 0);
        // v1'de özellik baytı yasak; v2'de bilinmeyen bit yasak.
        b[12] = 1;
        assert!(Header::parse(&b).is_err());
        b[6] = 2;
        b[12] = 0x02;
        assert!(Header::parse(&b).is_err());
        b[12] = 0x01;
        assert!(Header::parse(&b).unwrap().compressed);
        let _ = std::fs::remove_dir_all(&d);
    }

    #[test]
    fn error_correction_repairs_damage_with_and_without_split() {
        let d = tmpdir("ecc");
        let data: Vec<u8> = (0..2_500_000u32)
            .map(|i| i.to_le_bytes()[0] ^ 0x5a)
            .collect();
        std::fs::write(d.join("a.bin"), &data).unwrap();
        let p = pwd("hata duzeltme parola");
        let mut o = opts(true, Some(false));
        o.ecc = true;
        let out = d.join("e.lphy");
        encrypt(
            &Input::Path(&d.join("a.bin")),
            &out,
            &p,
            None,
            &o,
            &mut OsEntropy,
            &mut |_| {},
        )
        .unwrap();
        assert!(has_error_correction(&out));
        assert!(info(&out).is_ok(), "bilgi zarfın içinden okunur");
        // Gövdenin ortasında 900 baytlık bozulma.
        let mut bytes = std::fs::read(&out).unwrap();
        for x in &mut bytes[200_000..200_900] {
            *x ^= 0xff;
        }
        std::fs::write(&out, &bytes).unwrap();
        let rep = decrypt(
            &out,
            &Output::Path(&d.join("geri.bin"), false),
            &p,
            None,
            DecryptOptions::default(),
            &mut |_| {},
        )
        .unwrap();
        assert_eq!(std::fs::read(d.join("geri.bin")).unwrap(), data);
        assert_eq!(rep.repaired, 900);
        verify(&out, &p, None, UnlockOptions::default(), &mut |_| {}).unwrap();
        assert!(
            require_plain_file(&out).is_err(),
            "zarflı dosyada rekey reddedilir"
        );
        // Zarf + bölme.
        let parts = crate::split::split_file(&out, crate::split::MIN_PART).unwrap();
        assert!(parts.len() >= 2);
        decrypt(
            &parts[0],
            &Output::Path(&d.join("geri2.bin"), false),
            &p,
            None,
            DecryptOptions::default(),
            &mut |_| {},
        )
        .unwrap();
        assert_eq!(std::fs::read(d.join("geri2.bin")).unwrap(), data);
        let _ = std::fs::remove_dir_all(&d);
    }

    #[test]
    fn recover_raw_zero_fills_only_damaged_chunks() {
        let d = tmpdir("recraw");
        // chunk_code 0 = 64 KiB; 5 chunk'lık veri.
        let data: Vec<u8> = (0..(5 * 65536 + 100u32))
            .map(|i| i.to_le_bytes()[1])
            .collect();
        std::fs::write(d.join("a.bin"), &data).unwrap();
        let p = pwd("kurtarma parola 12");
        let out = d.join("r.lphy");
        encrypt(
            &Input::Path(&d.join("a.bin")),
            &out,
            &p,
            None,
            &opts(true, Some(false)),
            &mut OsEntropy,
            &mut |_| {},
        )
        .unwrap();
        let mut b = std::fs::read(&out).unwrap();
        // 2. chunk'ın ortası (başlık 256 B, chunk diskte 65536+16).
        b[256 + 65_552 + 30_000] ^= 0xff;
        std::fs::write(&out, &b).unwrap();
        assert!(
            decrypt(
                &out,
                &Output::Path(&d.join("x"), false),
                &p,
                None,
                DecryptOptions::default(),
                &mut |_| {}
            )
            .is_err()
        );
        let rep = recover(
            &out,
            &d.join("kurtarilan.bin"),
            &p,
            None,
            UnlockOptions::default(),
            &mut |_| {},
        )
        .unwrap();
        assert_eq!(rep.bad_chunks, vec![1]);
        assert!(!rep.truncated);
        let got = std::fs::read(d.join("kurtarilan.bin")).unwrap();
        assert_eq!(got.len(), data.len());
        assert_eq!(&got[..65536], &data[..65536]);
        assert!(got[65536..131_072].iter().all(|&x| x == 0));
        assert_eq!(&got[131_072..], &data[131_072..]);
        // Kesilmiş dosya.
        std::fs::write(&out, &b[..b.len() - 40_000]).unwrap();
        let rep = recover(
            &out,
            &d.join("kesik.bin"),
            &p,
            None,
            UnlockOptions::default(),
            &mut |_| {},
        )
        .unwrap();
        assert!(rep.truncated || !rep.bad_chunks.is_empty());
        // Var olan hedefin üzerine yazılmaz.
        assert!(matches!(
            recover(
                &out,
                &d.join("kesik.bin"),
                &p,
                None,
                UnlockOptions::default(),
                &mut |_| {}
            ),
            Err(Error::Exists(_))
        ));
        assert!(
            crate::io::scan_stale(&d).unwrap().is_empty(),
            "geçici dosya kalmamalı"
        );
        let _ = std::fs::remove_dir_all(&d);
    }

    #[test]
    fn recover_archive_keeps_entries_before_the_damage() {
        let d = tmpdir("recarch");
        let src = d.join("kaynak");
        std::fs::create_dir_all(&src).unwrap();
        std::fs::write(src.join("a.txt"), b"ilk dosya").unwrap();
        std::fs::write(src.join("b.bin"), vec![3u8; 300_000]).unwrap();
        std::fs::write(src.join("c.txt"), b"son dosya").unwrap();
        let p = pwd("kurtarma parola 12");
        let out = d.join("ar.lphy");
        encrypt(
            &Input::Path(&src),
            &out,
            &p,
            None,
            &opts(false, Some(false)),
            &mut OsEntropy,
            &mut |_| {},
        )
        .unwrap();
        let mut b = std::fs::read(&out).unwrap();
        let mid = b.len() / 2;
        b[mid] ^= 0x01;
        std::fs::write(&out, &b).unwrap();
        let rep = recover(
            &out,
            &d.join("kurtarilan"),
            &p,
            None,
            UnlockOptions::default(),
            &mut |_| {},
        )
        .unwrap();
        assert!(!rep.bad_chunks.is_empty());
        assert_eq!(
            std::fs::read(d.join("kurtarilan/a.txt")).unwrap(),
            b"ilk dosya"
        );
        assert!(crate::io::scan_stale(&d).unwrap().is_empty());
        let _ = std::fs::remove_dir_all(&d);
    }

    #[test]
    fn force_replace_restores_backup_on_failure() {
        let d = tmpdir("forceswap");
        let dst = d.join("hedef");
        std::fs::create_dir_all(&dst).unwrap();
        std::fs::write(dst.join("eski.txt"), b"eski").unwrap();
        // Kaynak yok: yerine koyma başarısız olur, eski hedef geri gelmeli.
        assert!(move_into_place(&d.join("yok"), &dst, true).is_err());
        assert_eq!(std::fs::read(dst.join("eski.txt")).unwrap(), b"eski");
        // Başarılı değiştirme: yeni içerik, yedek kalmaz.
        let src = d.join("yeni");
        std::fs::create_dir_all(&src).unwrap();
        std::fs::write(src.join("yeni.txt"), b"yeni").unwrap();
        move_into_place(&src, &dst, true).unwrap();
        assert!(dst.join("yeni.txt").exists() && !dst.join("eski.txt").exists());
        assert!(
            crate::io::scan_stale(&d).unwrap().is_empty(),
            "yedek kalmamalı"
        );
        let _ = std::fs::remove_dir_all(&d);
    }

    #[cfg(unix)]
    #[test]
    fn rekey_refuses_symlink_and_hardlink() {
        let d = tmpdir("rekeylink");
        let rep_path = d.join("f.lphy");
        std::fs::write(d.join("a.txt"), b"a").unwrap();
        encrypt(
            &Input::Path(&d.join("a.txt")),
            &rep_path,
            &pwd("rekey parola 1234"),
            None,
            &opts(false, None),
            &mut OsEntropy,
            &mut |_| {},
        )
        .unwrap();
        std::os::unix::fs::symlink(&rep_path, d.join("link.lphy")).unwrap();
        assert!(require_plain_file(&d.join("link.lphy")).is_err());
        std::fs::hard_link(&rep_path, d.join("hard.lphy")).unwrap();
        assert!(require_plain_file(&rep_path).is_err());
        std::fs::remove_file(d.join("hard.lphy")).unwrap();
        assert!(require_plain_file(&rep_path).is_ok());
        let _ = std::fs::remove_dir_all(&d);
    }

    #[test]
    fn delete_archived_removes_only_what_was_archived() {
        let d = tmpdir("delarch");
        let src = d.join("kaynak");
        std::fs::create_dir_all(src.join("alt")).unwrap();
        std::fs::write(src.join("a.txt"), b"a").unwrap();
        std::fs::write(src.join("alt/b.txt"), b"b").unwrap();
        let rep = encrypt_dir(&d, &src, "o1.lphy");
        assert_eq!(rep.archived.len(), 4, "{:?}", rep.archived); // kök, a.txt, alt, alt/b.txt
        // Arşivden sonra eklenen dosya korunur; içinde olduğu dizin de (boş değil) korunur.
        std::fs::write(src.join("alt/yeni.txt"), b"yeni").unwrap();
        let del = delete_archived(&rep).unwrap();
        assert!(src.join("alt/yeni.txt").exists());
        assert!(!src.join("a.txt").exists());
        assert!(!src.join("alt/b.txt").exists());
        assert!(del.kept.iter().any(|k| k.ends_with("alt")));
        assert!(del.kept.contains(&src), "boş olmayan kök korunur");
        // Yeni dosya yokken her şey (kök dahil) silinir.
        std::fs::write(src.join("c.txt"), b"c").unwrap();
        let rep = encrypt_dir(&d, &src, "o1b.lphy");
        delete_archived(&rep).unwrap();
        assert!(!src.exists());
        let _ = std::fs::remove_dir_all(&d);
    }

    #[cfg(unix)]
    #[test]
    fn secure_overwrite_replaces_content_and_respects_hard_links() {
        let d = tmpdir("shred");
        let src = d.join("kaynak");
        std::fs::create_dir_all(&src).unwrap();
        std::fs::write(src.join("a.txt"), vec![b'A'; 3000]).unwrap();
        std::fs::write(src.join("b.txt"), b"bbbb").unwrap();
        std::fs::hard_link(src.join("b.txt"), d.join("b-baska-ad.txt")).unwrap();
        let rep = encrypt_dir(&d, &src, "s.lphy");
        let a = rep
            .archived
            .iter()
            .find(|x| x.path.ends_with("a.txt"))
            .unwrap();
        overwrite_in_place(a).unwrap();
        let after = std::fs::read(src.join("a.txt")).unwrap();
        assert_eq!(after.len(), 3000);
        assert_ne!(after, vec![b'A'; 3000], "içerik rastgele veriyle değişmeli");
        let b = rep
            .archived
            .iter()
            .find(|x| x.path.ends_with("b.txt"))
            .unwrap();
        overwrite_in_place(b).unwrap();
        assert_eq!(
            std::fs::read(d.join("b-baska-ad.txt")).unwrap(),
            b"bbbb",
            "diğer ada dokunulmaz"
        );
        let del = delete_archived_with(&rep, true).unwrap();
        assert!(!src.exists(), "{:?}", del.kept);
        assert_eq!(std::fs::read(d.join("b-baska-ad.txt")).unwrap(), b"bbbb");
        let _ = std::fs::remove_dir_all(&d);
    }

    #[cfg(unix)]
    #[test]
    fn delete_archived_refuses_when_entries_were_skipped() {
        use std::os::unix::fs::PermissionsExt;
        let d = tmpdir("delskip");
        let src = d.join("kaynak");
        std::fs::create_dir_all(&src).unwrap();
        std::fs::write(src.join("ok.txt"), b"ok").unwrap();
        std::fs::write(src.join("kilitli.txt"), b"gizli").unwrap();
        std::fs::set_permissions(
            src.join("kilitli.txt"),
            std::fs::Permissions::from_mode(0o000),
        )
        .unwrap();
        if std::fs::File::open(src.join("kilitli.txt")).is_ok() {
            // root olarak çalışıyor: okunamaz dosya üretilemez.
            let _ = std::fs::remove_dir_all(&d);
            return;
        }
        let rep = encrypt_dir(&d, &src, "o2.lphy");
        assert_eq!(rep.skipped.len(), 1);
        let e = delete_archived(&rep).unwrap_err();
        assert_eq!(e.exit_code(), crate::error::ExitCode::Cancelled);
        assert!(src.join("ok.txt").exists(), "hiçbir şey silinmemeli");
        assert!(src.join("kilitli.txt").exists());
        std::fs::set_permissions(
            src.join("kilitli.txt"),
            std::fs::Permissions::from_mode(0o600),
        )
        .unwrap();
        let _ = std::fs::remove_dir_all(&d);
    }

    #[cfg(unix)]
    #[test]
    fn delete_archived_keeps_replaced_file() {
        let d = tmpdir("delswap");
        let src = d.join("kaynak");
        std::fs::create_dir_all(&src).unwrap();
        std::fs::write(src.join("a.txt"), b"a").unwrap();
        let rep = encrypt_dir(&d, &src, "o3.lphy");
        // Arşivden sonra aynı adla başka bir dosya (farklı inode) konur: silinmemeli.
        std::fs::remove_file(src.join("a.txt")).unwrap();
        std::fs::write(src.join("b.tmp"), b"tut").unwrap();
        std::fs::write(src.join("a.txt"), b"baska").unwrap();
        let del = delete_archived(&rep).unwrap();
        assert!(src.join("a.txt").exists());
        assert!(del.kept.iter().any(|k| k.ends_with("a.txt")));
        let _ = std::fs::remove_dir_all(&d);
    }

    #[test]
    fn raw_roundtrip_wrong_password_keyfile_and_rekey() {
        let d = tmpdir("rt");
        let src = d.join("in.bin");
        let data: Vec<u8> = (0..300_000u32).map(|i| (i % 253) as u8).collect();
        std::fs::write(&src, &data).unwrap();
        let out = d.join("out.lphy");
        let o = opts(true, None);
        let mut log = |_: &str| {};
        let p = pwd("doğru parola!");
        let kf = kdf::keyfile_digest(&[0x42; 64]);
        let rep = encrypt(
            &Input::Path(&src),
            &out,
            &p,
            Some(&kf),
            &o,
            &mut OsEntropy,
            &mut log,
        )
        .unwrap();
        assert_eq!(rep.plain_len, data.len() as u64);
        assert_eq!(rep.content_type, ContentType::Raw);
        assert_eq!(
            std::fs::metadata(&out).unwrap().len(),
            256 + data.len() as u64 + 5 * 16
        );
        let ct = std::fs::read(&out).unwrap();
        assert!(!ct.windows(64).any(|w| w == &data[1000..1064]));

        let u = UnlockOptions::default();
        assert!(matches!(
            verify(&out, &pwd("yanlış parola"), Some(&kf), u, &mut log),
            Err(Error::WrongPassword)
        ));
        assert!(matches!(
            verify(&out, &p, None, u, &mut log),
            Err(Error::KeyfileRequired)
        ));
        let kf2 = kdf::keyfile_digest(&[0x43; 64]);
        assert!(matches!(
            verify(&out, &p, Some(&kf2), u, &mut log),
            Err(Error::WrongPassword)
        ));
        assert_eq!(
            verify(&out, &p, Some(&kf), u, &mut log).unwrap(),
            data.len() as u64
        );
        let mut bad = ct.clone();
        bad[256 + 70_000] ^= 1;
        let badp = d.join("bad.lphy");
        std::fs::write(&badp, &bad).unwrap();
        match verify(&badp, &p, Some(&kf), u, &mut log) {
            Err(Error::Corrupt { at, .. }) => assert_eq!(at, "chunk 1"),
            o => panic!("{o:?}"),
        }
        let mut bad = ct.clone();
        bad[230] ^= 1;
        std::fs::write(&badp, &bad).unwrap();
        match verify(&badp, &p, Some(&kf), u, &mut log) {
            Err(Error::Corrupt { at, .. }) => assert_eq!(at, "başlık"),
            o => panic!("{o:?}"),
        }
        let dec = d.join("dec.bin");
        let dopts = DecryptOptions::default();
        let r = decrypt(
            &out,
            &Output::Path(&dec, false),
            &p,
            Some(&kf),
            dopts,
            &mut log,
        )
        .unwrap();
        assert_eq!(r.plain_len, data.len() as u64);
        assert_eq!(std::fs::read(&dec).unwrap(), data);
        assert!(matches!(
            decrypt(
                &out,
                &Output::Path(&dec, false),
                &p,
                Some(&kf),
                dopts,
                &mut log
            ),
            Err(Error::Exists(_))
        ));
        let p2 = pwd("yeni parola 123");
        let newc = NewCredentials {
            pwd_nfc: &p2,
            keyfile_digest: None,
            kdf: None,
        };
        rekey(
            &out,
            &p,
            Some(&kf),
            &newc,
            u,
            true,
            &mut OsEntropy,
            &mut log,
        )
        .unwrap();
        let ct2 = std::fs::read(&out).unwrap();
        assert_eq!(&ct2[256..], &ct[256..]);
        assert_ne!(&ct2[224..256], &ct[224..256]);
        assert_eq!(&ct2[64..88], &ct[64..88]);
        assert!(matches!(
            verify(&out, &p, Some(&kf), u, &mut log),
            Err(Error::KeyfileNotUsed)
        ));
        assert_eq!(
            verify(&out, &p2, None, u, &mut log).unwrap(),
            data.len() as u64
        );
        let mut frank = ct[..256].to_vec();
        frank.extend_from_slice(&ct2[256..]);
        std::fs::write(&badp, &frank).unwrap();
        assert_eq!(
            verify(&badp, &p, Some(&kf), u, &mut log).unwrap(),
            data.len() as u64
        );
        let p3 = pwd("üçüncü parola!!");
        let newc = NewCredentials {
            pwd_nfc: &p3,
            keyfile_digest: None,
            kdf: None,
        };
        let m = reencrypt(&out, &p2, None, &newc, u, &mut OsEntropy, &mut log).unwrap();
        assert_eq!(m, data.len() as u64);
        let ct3 = std::fs::read(&out).unwrap();
        assert_ne!(&ct3[256..], &ct[256..]);
        let mut frank = ct[..256].to_vec();
        frank.extend_from_slice(&ct3[256..]);
        std::fs::write(&badp, &frank).unwrap();
        assert!(matches!(
            verify(&badp, &p, Some(&kf), u, &mut log),
            Err(Error::Corrupt { .. })
        ));
        let dec2 = d.join("dec2.bin");
        decrypt(
            &out,
            &Output::Path(&dec2, false),
            &p3,
            None,
            dopts,
            &mut log,
        )
        .unwrap();
        assert_eq!(std::fs::read(&dec2).unwrap(), data);
        let h = info(&out).unwrap();
        assert_eq!(h.kdf, small_kdf());
        assert!(crate::io::scan_stale(&d).unwrap().is_empty());
        let _ = std::fs::remove_dir_all(&d);
    }

    #[test]
    fn raw_padded_roundtrip_and_size_change() {
        let d = tmpdir("pad");
        let src = d.join("in.bin");
        std::fs::write(&src, vec![3u8; 1000]).unwrap();
        let out = d.join("out.lphy");
        let p = pwd("parola parola");
        let mut log = |_: &str| {};
        let rep = encrypt(
            &Input::Path(&src),
            &out,
            &p,
            None,
            &opts(true, Some(true)),
            &mut OsEntropy,
            &mut log,
        )
        .unwrap();
        assert_eq!(rep.plain_len, crate::pad::padme(1008));
        assert!(info(&out).unwrap().padded);
        let dec = d.join("dec.bin");
        let r = decrypt(
            &out,
            &Output::Path(&dec, false),
            &p,
            None,
            DecryptOptions::default(),
            &mut log,
        )
        .unwrap();
        assert_eq!(r.plain_len, 1000);
        assert_eq!(std::fs::read(&dec).unwrap(), vec![3u8; 1000]);
        // reencrypt dolgulu ham akışı da taşır
        let p2 = pwd("ikinci parola!");
        reencrypt(
            &out,
            &p,
            None,
            &NewCredentials {
                pwd_nfc: &p2,
                keyfile_digest: None,
                kdf: None,
            },
            UnlockOptions::default(),
            &mut OsEntropy,
            &mut log,
        )
        .unwrap();
        let dec2 = d.join("dec2.bin");
        decrypt(
            &out,
            &Output::Path(&dec2, false),
            &p2,
            None,
            DecryptOptions::default(),
            &mut log,
        )
        .unwrap();
        assert_eq!(std::fs::read(&dec2).unwrap(), vec![3u8; 1000]);
        let _ = std::fs::remove_dir_all(&d);
    }

    #[test]
    fn archive_roundtrip_dir_single_file_and_strings() {
        let d = tmpdir("arc");
        let src = d.join("tree");
        std::fs::create_dir_all(src.join("sub/deep")).unwrap();
        std::fs::write(src.join("gizli-ad.txt"), b"content-one").unwrap();
        std::fs::write(src.join("sub/deep/x.bin"), vec![1u8; 70_000]).unwrap();
        std::fs::create_dir_all(src.join("empty")).unwrap();
        let out = d.join("tree.lphy");
        let p = pwd("parola parola");
        let mut log = |_: &str| {};
        let rep = encrypt(
            &Input::Path(&src),
            &out,
            &p,
            None,
            &opts(false, None),
            &mut OsEntropy,
            &mut log,
        )
        .unwrap();
        assert_eq!(rep.content_type, ContentType::Archive);
        let h = info(&out).unwrap();
        assert!(h.padded);
        assert_eq!(h.content_type, ContentType::Archive);
        let ct = std::fs::read(&out).unwrap();
        assert!(
            !ct.windows(12).any(|w| w == b"gizli-ad.txt"),
            "ad şifreli çıktıda görünmemeli"
        );
        // çıktı kaynak ağacının içinde → kod 1
        assert!(matches!(
            encrypt(
                &Input::Path(&src),
                &src.join("x.lphy"),
                &p,
                None,
                &opts(false, None),
                &mut OsEntropy,
                &mut log
            ),
            Err(Error::Environment(_))
        ));
        let dst = d.join("restored");
        let dopts = DecryptOptions {
            unlock: UnlockOptions::default(),
            extract: ExtractOptions {
                symlinks: SymlinkPolicy::Safe,
                ..Default::default()
            },
        };
        let r = decrypt(&out, &Output::Path(&dst, false), &p, None, dopts, &mut log).unwrap();
        assert_eq!(r.archive.as_ref().unwrap().entries, 5);
        assert_eq!(
            std::fs::read(dst.join("gizli-ad.txt")).unwrap(),
            b"content-one"
        );
        assert_eq!(
            std::fs::read(dst.join("sub/deep/x.bin")).unwrap(),
            vec![1u8; 70_000]
        );
        assert!(dst.join("empty").is_dir());
        assert!(crate::io::scan_stale(&d).unwrap().is_empty());
        assert!(matches!(
            decrypt(&out, &Output::Path(&dst, false), &p, None, dopts, &mut log),
            Err(Error::Exists(_))
        ));
        // tek dosya → arşiv, çözümde düzleştirilir
        let single = d.join("tree/gizli-ad.txt");
        let out2 = d.join("single.lphy");
        encrypt(
            &Input::Path(&single),
            &out2,
            &p,
            None,
            &opts(false, None),
            &mut OsEntropy,
            &mut log,
        )
        .unwrap();
        assert_eq!(info(&out2).unwrap().content_type, ContentType::Archive);
        let dst2 = d.join("single-out.txt");
        let r = decrypt(
            &out2,
            &Output::Path(&dst2, false),
            &p,
            None,
            dopts,
            &mut log,
        )
        .unwrap();
        assert_eq!(r.target, dst2);
        assert!(dst2.is_file());
        assert_eq!(std::fs::read(&dst2).unwrap(), b"content-one");
        assert!(crate::io::scan_stale(&d).unwrap().is_empty());
        // --force ile var olan dizinin üzerine
        let r = decrypt(&out, &Output::Path(&dst, true), &p, None, dopts, &mut log).unwrap();
        assert!(r.archive.is_some());
        // bozuk arşiv içeriği (END sonrası sıfır olmayan) → 4 ve tmp yok: bunu `archive` testleri kapsar.
        let _ = std::fs::remove_dir_all(&d);
    }

    #[test]
    fn reserved_byte_rejected_before_kdf() {
        let mut b = [0u8; 256];
        b[..6].copy_from_slice(b"LPHY+\0");
        b[6] = 1;
        b[8] = 1;
        b[13] = 1;
        b[16..20].copy_from_slice(&(4u32 * 1024 * 1024).to_le_bytes());
        b[20..24].copy_from_slice(&64u32.to_le_bytes());
        b[24..28].copy_from_slice(&1u32.to_le_bytes());
        b[12] = 1;
        let p = pwd("parola parola");
        match unlock_header(&b, &[], &p, None, UnlockOptions::default(), &mut |_| {}) {
            Err(Error::Corrupt { at, .. }) => assert_eq!(at, "başlık"),
            Err(o) => panic!("{o:?}"),
            Ok(_) => panic!("başlık kabul edildi"),
        }
        b[12] = 0;
        assert!(matches!(
            unlock_header(&b, &[], &p, None, UnlockOptions::default(), &mut |_| {}),
            Err(Error::KdfBudget(_))
        ));
    }
}
