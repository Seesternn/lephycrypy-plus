//! Üst düzey işlemler: başlık kurma/açma, `encrypt`, `decrypt`, `verify`, `info`, `rekey`,
//! `reencrypt` (PLAN › Kriptografik tasarım, Rekey ve reencrypt, Çözme sırası).
//!
//! Aşama 1: yalnızca `content_type = 0` (ham akış), PADMÉ kapalı. Arşiv ve dolgu aşama 2.

use std::fs::File;
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};

use lephy_sys::mem::SecretBytes;
use subtle::ConstantTimeEq;

use crate::cipher::{AlgId, SharedCipher, TAG_LEN};
use crate::entropy::Entropy;
use crate::error::{Error, Result};
use crate::header::{
    ContentType, HEADER_LEN, Header, MAC_END, NewHeaderParams, WRAP_AAD_END, chunk_aad,
};
use crate::io::AtomicWriter;
use crate::kdf::{self, KEY_LEN, KdfParams};
use crate::pipeline::{StreamParams, decrypt_stream, encrypt_stream, verify_stream};

fn arena_err(e: impl std::fmt::Display) -> Error {
    Error::Environment(format!("kilitli bellek: {e}"))
}

/// Çözme/doğrulama politikası seçenekleri.
#[derive(Debug, Clone, Copy, Default)]
pub struct UnlockOptions {
    /// Bütçe aşımına izin (`--allow-large-kdf`); RAM eşiği yine de uygulanır.
    pub allow_large_kdf: bool,
    /// Kilit başarısızlığı hata (`--strict-memory`).
    pub strict_memory: bool,
}

/// Açılmış başlık: FK ve alt anahtarlar kilitli arenada.
pub struct Unlocked {
    /// Ayrıştırılmış başlık.
    pub header: Header,
    /// Ham başlık baytları.
    pub bytes: [u8; HEADER_LEN],
    /// Dosya anahtarı.
    pub fk: SecretBytes,
    /// `data_key`.
    pub data_key: SecretBytes,
}

fn key32(s: &SecretBytes) -> Result<[u8; KEY_LEN]> {
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
    pwd_nfc: &SecretBytes,
    keyfile_digest: Option<&[u8; 32]>,
    opts: UnlockOptions,
    log: &mut dyn FnMut(&str),
) -> Result<Unlocked> {
    // 1
    let header = Header::parse(bytes)?;
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
    let wrapper = SharedCipher::new(header.alg, &key32(&wrap_key)?)?;
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
    // 7 türet, 8 header_mac
    let (data_key, mac_key) = kdf::derive_fk_subkeys(&fk, &header.stream_nonce_prefix)?;
    let mac = kdf::header_mac(&mac_key, &bytes[..MAC_END])?;
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
        salt,
        stream_nonce_prefix: prefix,
        wrap_nonce,
        commit_tag,
        wrapped_fk: [0u8; 48],
        header_mac: [0u8; 32],
    };
    let partial = header.to_bytes();
    let wrapper = SharedCipher::new(params.alg, &key32(&wrap_key)?)?;
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
        fk,
        data_key,
    })
}

/// Şifreleme seçenekleri.
#[derive(Debug, Clone, Copy)]
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
}

/// Şifreleme girişi.
pub enum Input<'a> {
    /// Dosya yolu.
    Path(&'a Path),
    /// Standart girdi (boyut bilinmez; PADMÉ kullanılamaz).
    Stdin,
}

/// Şifreleme raporu.
#[derive(Debug, Clone, Copy)]
pub struct EncryptReport {
    /// Düz metin bayt.
    pub plain_len: u64,
    /// Noclobber geri dönüşü kullanıldı (uyarı).
    pub noclobber_fallback: bool,
}

fn open_input(input: &Input<'_>) -> Result<Box<dyn Read + Send>> {
    match input {
        Input::Path(p) => {
            let md = std::fs::metadata(p)?;
            if !md.is_file() {
                return Err(Error::Environment(format!(
                    "{} normal bir dosya değil (klasörler aşama 2'de)",
                    p.display()
                )));
            }
            Ok(Box::new(File::open(p)?))
        }
        Input::Stdin => {
            let stdin = std::io::stdin();
            if lephy_sys::term::is_tty(&stdin) {
                return Err(Error::Environment(
                    "stdin bir terminal; giriş verisi bekleniyor".into(),
                ));
            }
            Ok(Box::new(stdin))
        }
    }
}

/// Tek dosya / stdin şifreleme (`content_type = 0`).
///
/// # Errors
/// 1, 6, 7, 8, 130.
#[allow(clippy::too_many_arguments)]
pub fn encrypt(
    input: &Input<'_>,
    output: &Path,
    pwd_nfc: &SecretBytes,
    keyfile_digest: Option<&[u8; 32]>,
    opts: &EncryptOptions,
    entropy: &mut dyn Entropy,
    log: &mut dyn FnMut(&str),
) -> Result<EncryptReport> {
    // Çıktı yolu kaynak dosyanın kendisi olamaz.
    if let Input::Path(p) = input
        && let (Ok(a), Ok(b)) = (p.canonicalize(), output.canonicalize())
        && a == b
    {
        return Err(Error::Environment("çıktı yolu girişle aynı".into()));
    }
    let mut reader = open_input(input)?;
    let params = NewHeaderParams {
        alg: opts.alg,
        content_type: ContentType::Raw,
        padded: false,
        chunk_code: opts.chunk_code,
        kdf: opts.kdf,
        keyfile: keyfile_digest.is_some(),
    };
    if let Input::Path(p) = input {
        let size = std::fs::metadata(p)?.len();
        let chunk = crate::header::chunk_size_for(opts.chunk_code).unwrap_or(1 << 20) as u64;
        let est = HEADER_LEN as u64 + size + (size / chunk + 1) * TAG_LEN as u64;
        let dir = output
            .parent()
            .filter(|d| !d.as_os_str().is_empty())
            .unwrap_or(Path::new("."));
        crate::io::precheck_space(dir, est)?;
    }
    let unlocked = build_header(
        &params,
        pwd_nfc,
        keyfile_digest,
        Reuse::default(),
        entropy,
        opts.strict_memory,
        log,
    )?;
    let cipher = SharedCipher::new(opts.alg, &key32(&unlocked.data_key)?)?;
    let aad = chunk_aad(&unlocked.bytes);
    let mut w = AtomicWriter::create(output, opts.force)?;
    w.file().write_all(&unlocked.bytes)?;
    let sp = StreamParams {
        cipher: &cipher,
        prefix: &unlocked.header.stream_nonce_prefix,
        aad: &aad,
        chunk_size: unlocked.header.chunk_size(),
    };
    let plain_len = encrypt_stream(&sp, reader.as_mut(), w.file())?;
    let outcome = w.commit(opts.force)?;
    Ok(EncryptReport {
        plain_len,
        noclobber_fallback: outcome.noclobber_fallback,
    })
}

/// Başlığı okur (256 B).
fn read_header(f: &mut File) -> Result<[u8; HEADER_LEN]> {
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

/// Açık meta veri (KDF çalıştırmadan).
///
/// # Errors
/// 4, 1.
pub fn info(path: &Path) -> Result<Header> {
    let mut f = File::open(path)?;
    let b = read_header(&mut f)?;
    Header::parse(&b)
}

/// Çözme hedefi.
pub enum Output<'a> {
    /// Dosya (atomik yazma).
    Path(&'a Path, bool),
    /// Standart çıktı (ham fd; kısmi çıktı uyarısı çağıranda).
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
    opts: UnlockOptions,
    log: &mut dyn FnMut(&str),
) -> Result<(File, Unlocked)> {
    let mut f = File::open(path)?;
    let b = read_header(&mut f)?;
    let u = unlock_header(&b, pwd_nfc, keyfile_digest, opts, log)?;
    Ok((f, u))
}

/// Çözme (`content_type = 0`). Döner: düz metin bayt sayısı.
///
/// # Errors
/// 3, 4, 6, 7, 8, 1, 130.
pub fn decrypt(
    path: &Path,
    output: &Output<'_>,
    pwd_nfc: &SecretBytes,
    keyfile_digest: Option<&[u8; 32]>,
    opts: UnlockOptions,
    log: &mut dyn FnMut(&str),
) -> Result<u64> {
    let (mut f, u) = open_and_unlock(path, pwd_nfc, keyfile_digest, opts, log)?;
    if u.header.content_type != ContentType::Raw {
        return Err(Error::Environment(
            "arşiv içeriği aşama 2'de desteklenir".into(),
        ));
    }
    if u.header.padded {
        return Err(Error::Environment(
            "PADMÉ dolgulu içerik aşama 2'de desteklenir".into(),
        ));
    }
    let cipher = SharedCipher::new(u.header.alg, &key32(&u.data_key)?)?;
    let aad = chunk_aad(&u.bytes);
    let sp = StreamParams {
        cipher: &cipher,
        prefix: &u.header.stream_nonce_prefix,
        aad: &aad,
        chunk_size: u.header.chunk_size(),
    };
    match output {
        Output::Path(out, force) => {
            let total = std::fs::metadata(path)?.len();
            let dir = out
                .parent()
                .filter(|d| !d.as_os_str().is_empty())
                .unwrap_or(Path::new("."));
            crate::io::precheck_space(dir, total)?;
            let mut w = AtomicWriter::create(out, *force)?;
            let n = decrypt_stream(&sp, &mut f, w.file())?;
            let o = w.commit(*force)?;
            if o.noclobber_fallback {
                log(
                    "uyarı: dosya sistemi atomik noclobber desteklemiyor; kontrol-sonra-rename kullanıldı",
                );
            }
            Ok(n)
        }
        Output::Stdout => {
            let mut so = RawStdout;
            decrypt_stream(&sp, &mut f, &mut so)
        }
    }
}

/// Doğrulama (yazmadan). Döner: düz metin bayt sayısı.
///
/// # Errors
/// 3, 4, 6, 1, 130.
pub fn verify(
    path: &Path,
    pwd_nfc: &SecretBytes,
    keyfile_digest: Option<&[u8; 32]>,
    opts: UnlockOptions,
    log: &mut dyn FnMut(&str),
) -> Result<u64> {
    let (mut f, u) = open_and_unlock(path, pwd_nfc, keyfile_digest, opts, log)?;
    let cipher = SharedCipher::new(u.header.alg, &key32(&u.data_key)?)?;
    let aad = chunk_aad(&u.bytes);
    let sp = StreamParams {
        cipher: &cipher,
        prefix: &u.header.stream_nonce_prefix,
        aad: &aad,
        chunk_size: u.header.chunk_size(),
    };
    verify_stream(&sp, &mut f)
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

/// `rekey`: FK aynı kalır; yeni `salt`/`wrap_nonce`/`commit_tag`/`wrapped_fk`/`header_mac`; chunk'lar aynen
/// kopyalanır; atomik. `data_key` değişmediğinden `stream_nonce_prefix` korunur.
///
/// # Errors
/// 3, 4, 6, 1, 130.
#[allow(clippy::too_many_arguments)]
pub fn rekey(
    path: &Path,
    old_pwd: &SecretBytes,
    old_keyfile: Option<&[u8; 32]>,
    new: &NewCredentials<'_>,
    opts: UnlockOptions,
    verify_after: bool,
    entropy: &mut dyn Entropy,
    log: &mut dyn FnMut(&str),
) -> Result<()> {
    let (mut f, u) = open_and_unlock(path, old_pwd, old_keyfile, opts, log)?;
    let params = NewHeaderParams {
        alg: u.header.alg,
        content_type: u.header.content_type,
        padded: u.header.padded,
        chunk_code: u.header.chunk_code,
        kdf: new.kdf.unwrap_or(u.header.kdf),
        keyfile: new.keyfile_digest.is_some(),
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
    w.commit(true)?;
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

/// Bellek içi boru: çözücü yazar, şifreleyici okur (düz metin diske inmez).
struct PipeWriter(crossbeam_channel::Sender<zeroize::Zeroizing<Vec<u8>>>);
struct PipeReader {
    rx: crossbeam_channel::Receiver<zeroize::Zeroizing<Vec<u8>>>,
    cur: zeroize::Zeroizing<Vec<u8>>,
    pos: usize,
}

impl Write for PipeWriter {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.0
            .send(zeroize::Zeroizing::new(buf.to_vec()))
            .map_err(|_| std::io::Error::other("boru kapandı"))?;
        Ok(buf.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

impl Read for PipeReader {
    fn read(&mut self, out: &mut [u8]) -> std::io::Result<usize> {
        if self.pos >= self.cur.len() {
            match self.rx.recv() {
                Ok(v) => {
                    self.cur = v;
                    self.pos = 0;
                }
                Err(_) => return Ok(0),
            }
        }
        let n = (self.cur.len() - self.pos).min(out.len());
        out[..n].copy_from_slice(&self.cur[self.pos..self.pos + n]);
        self.pos += n;
        Ok(n)
    }
}

/// `reencrypt`: yeni FK ve `stream_nonce_prefix`, tüm chunk'lar yeniden şifrelenir; atomik.
///
/// # Errors
/// 3, 4, 6, 1, 130.
pub fn reencrypt(
    path: &Path,
    old_pwd: &SecretBytes,
    old_keyfile: Option<&[u8; 32]>,
    new: &NewCredentials<'_>,
    opts: UnlockOptions,
    entropy: &mut dyn Entropy,
    log: &mut dyn FnMut(&str),
) -> Result<u64> {
    let (mut f, u) = open_and_unlock(path, old_pwd, old_keyfile, opts, log)?;
    if u.header.content_type != ContentType::Raw || u.header.padded {
        return Err(Error::Environment(
            "arşiv/dolgulu içerik aşama 2'de desteklenir".into(),
        ));
    }
    let params = NewHeaderParams {
        alg: u.header.alg,
        content_type: u.header.content_type,
        padded: u.header.padded,
        chunk_code: u.header.chunk_code,
        kdf: new.kdf.unwrap_or(u.header.kdf),
        keyfile: new.keyfile_digest.is_some(),
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
    let old_cipher = SharedCipher::new(u.header.alg, &key32(&u.data_key)?)?;
    let old_aad = chunk_aad(&u.bytes);
    let new_cipher = SharedCipher::new(nu.header.alg, &key32(&nu.data_key)?)?;
    let new_aad = chunk_aad(&nu.bytes);
    let mut w = AtomicWriter::create(path, true)?;
    w.file().write_all(&nu.bytes)?;
    let (tx, rx) = crossbeam_channel::bounded(4);
    let mut pw = PipeWriter(tx);
    let mut pr = PipeReader {
        rx,
        cur: zeroize::Zeroizing::new(Vec::new()),
        pos: 0,
    };
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
    let out_file = w.file();
    let (dec, enc) = std::thread::scope(|s| {
        let dec = s.spawn(move || {
            let _ = lephy_sys::signal::mask_signals_on_this_thread();
            let r = decrypt_stream(&old_sp, &mut f, &mut pw);
            drop(pw);
            r
        });
        let enc = encrypt_stream(&new_sp, &mut pr, out_file);
        drop(pr);
        (
            dec.join().unwrap_or_else(|_| {
                Err(Error::Environment("çözücü iş parçacığı panikledi".into()))
            }),
            enc,
        )
    });
    let n = dec?;
    let m = enc?;
    if n != m {
        return Err(Error::Environment(
            "yeniden şifrelemede uzunluk uyuşmazlığı".into(),
        ));
    }
    w.commit(true)?;
    Ok(n)
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::panic, clippy::too_many_lines)]
mod tests {
    use super::*;
    use crate::entropy::OsEntropy;

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

    fn tmpdir(tag: &str) -> PathBuf {
        let d = std::env::temp_dir().join(format!("lphy-ops-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        d
    }

    #[test]
    fn full_roundtrip_wrong_password_keyfile_and_rekey() {
        let d = tmpdir("rt");
        let src = d.join("in.bin");
        let data: Vec<u8> = (0..300_000u32).map(|i| (i % 253) as u8).collect();
        std::fs::write(&src, &data).unwrap();
        let out = d.join("out.lphy");
        let opts = EncryptOptions {
            alg: AlgId::XChaCha20Poly1305,
            chunk_code: 0,
            kdf: small_kdf(),
            force: false,
            strict_memory: false,
        };
        let mut log = |_: &str| {};
        let p = pwd("doğru parola!");
        let kf = kdf::keyfile_digest(&[0x42; 64]);
        let rep = encrypt(
            &Input::Path(&src),
            &out,
            &p,
            Some(&kf),
            &opts,
            &mut OsEntropy,
            &mut log,
        )
        .unwrap();
        assert_eq!(rep.plain_len, data.len() as u64);
        assert_eq!(
            std::fs::metadata(&out).unwrap().len(),
            256 + data.len() as u64 + 5 * 16
        );
        // şifreli çıktıda düz metin yok
        let ct = std::fs::read(&out).unwrap();
        assert!(!ct.windows(64).any(|w| w == &data[1000..1064]));

        let u = UnlockOptions::default();
        // yanlış parola → 3
        assert!(matches!(
            verify(&out, &pwd("yanlış parola"), Some(&kf), u, &mut log),
            Err(Error::WrongPassword)
        ));
        // keyfile yok → 3 (ayrı mesaj)
        assert!(matches!(
            verify(&out, &p, None, u, &mut log),
            Err(Error::KeyfileRequired)
        ));
        // yanlış keyfile → 3
        let kf2 = kdf::keyfile_digest(&[0x43; 64]);
        assert!(matches!(
            verify(&out, &p, Some(&kf2), u, &mut log),
            Err(Error::WrongPassword)
        ));
        // doğru
        assert_eq!(
            verify(&out, &p, Some(&kf), u, &mut log).unwrap(),
            data.len() as u64
        );
        // bozuk chunk → 4
        let mut bad = ct.clone();
        bad[256 + 70_000] ^= 1;
        let badp = d.join("bad.lphy");
        std::fs::write(&badp, &bad).unwrap();
        match verify(&badp, &p, Some(&kf), u, &mut log) {
            Err(Error::Corrupt { at, .. }) => assert_eq!(at, "chunk 1"),
            o => panic!("{o:?}"),
        }
        // bozuk header_mac → 4 başlık
        let mut bad = ct.clone();
        bad[230] ^= 1;
        std::fs::write(&badp, &bad).unwrap();
        match verify(&badp, &p, Some(&kf), u, &mut log) {
            Err(Error::Corrupt { at, .. }) => assert_eq!(at, "başlık"),
            o => panic!("{o:?}"),
        }
        // çöz
        let dec = d.join("dec.bin");
        let n = decrypt(&out, &Output::Path(&dec, false), &p, Some(&kf), u, &mut log).unwrap();
        assert_eq!(n, data.len() as u64);
        assert_eq!(std::fs::read(&dec).unwrap(), data);
        // hedef var → 7
        assert!(matches!(
            decrypt(&out, &Output::Path(&dec, false), &p, Some(&kf), u, &mut log),
            Err(Error::Exists(_))
        ));
        // rekey: FK aynı, chunk'lar aynı, header_mac farklı
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
        assert_eq!(&ct2[256..], &ct[256..], "chunk'lar bire bir aynı");
        assert_ne!(&ct2[224..256], &ct[224..256], "header_mac değişti");
        assert_eq!(&ct2[64..88], &ct[64..88], "stream_nonce_prefix korunur");
        assert!(matches!(
            verify(&out, &p, Some(&kf), u, &mut log),
            Err(Error::KeyfileNotUsed)
        ));
        assert_eq!(
            verify(&out, &p2, None, u, &mut log).unwrap(),
            data.len() as u64
        );
        // R4-Y2: eski başlık + eski parola yeni dosyayı açar
        let mut frank = ct[..256].to_vec();
        frank.extend_from_slice(&ct2[256..]);
        std::fs::write(&badp, &frank).unwrap();
        assert_eq!(
            verify(&badp, &p, Some(&kf), u, &mut log).unwrap(),
            data.len() as u64
        );
        // reencrypt: sonra eski başlık açamaz
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
        decrypt(&out, &Output::Path(&dec2, false), &p3, None, u, &mut log).unwrap();
        assert_eq!(std::fs::read(&dec2).unwrap(), data);
        // info KDF'siz
        let h = info(&out).unwrap();
        assert_eq!(h.kdf, small_kdf());
        assert!(crate::io::scan_stale(&d).unwrap().is_empty());
        let _ = std::fs::remove_dir_all(&d);
    }

    #[test]
    fn reserved_byte_rejected_before_kdf() {
        // KDF çağrı sayacı yerine: 4 GiB'lık (bütçe dışı) KDF parametreli ama reserved≠0 başlık,
        // KDF çalışsaydı kod 6 verirdi; kod 4 gelmesi KDF'den önce reddedildiğini gösterir.
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
        match unlock_header(&b, &p, None, UnlockOptions::default(), &mut |_| {}) {
            Err(Error::Corrupt { at, .. }) => assert_eq!(at, "başlık"),
            Err(o) => panic!("{o:?}"),
            Ok(_) => panic!("başlık kabul edildi"),
        }
        b[12] = 0;
        assert!(matches!(
            unlock_header(&b, &p, None, UnlockOptions::default(), &mut |_| {}),
            Err(Error::KdfBudget(_))
        ));
    }
}
