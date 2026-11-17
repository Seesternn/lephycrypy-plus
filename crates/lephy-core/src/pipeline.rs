//! Paralel STREAM hattı.
//!
//! okuyucu (çağıran iş parçacığı) → bounded `work` kanalı → işçi iş parçacıkları
//! (`seal/open_chunk(index, last)`) → bounded `done` kanalı → sıralı yazıcı (`BTreeMap`) →
//! `free` kanalı → okuyucu. Tüm tamponlar tek `LargeSecretBuf<u8>` havuzundadır:
//! `nbuf = clamp(64 MiB / chunk_size, 2, 8)`, her tampon `chunk_size + 17` B (ileri okuma).
//! Yerinde şifreleme; düz metin tamponları yazıcı iade etmeden önce sıfırlanır.
//!
//! İlerleme garantisi: tampon okuyucuya ancak havuzdan alınırsa verilir ve o anda indeksi
//! atanır; işçiler indeksten bağımsızdır; yazıcı en düşük bekleyen indeksi yazınca tamponu iade
//! eder; havuzdaki tüm tamponlar `nbuf`'tan küçük bir indeks penceresinde olduğundan en düşük
//! indeks her zaman ya bir işçide ya da yazıcıdadır.
//!
//! Kesinti: her aşama her chunk'ta `lephy_sys::signal::interrupted()` yoklar; `Err(Interrupted)`
//! kanalları kapatır, hat normal yoldan çözülür (Drop'lar çalışır).
//!
//! `BufReader`/`BufWriter`/`Stdout` yasaktır (clippy.toml); okuyucu/yazıcı doğrudan havuz
//! tamponunu kullanır. `std::thread::scope` kullanılır (rayon yerine): işçi iş parçacıkları
//! başlarken sinyal maskesi kurar.

use std::collections::BTreeMap;
use std::io::{Read, Write};
use std::sync::Mutex;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};

use crossbeam_channel::{Receiver, Sender, bounded};
use lephy_sys::mem::LargeSecretBuf;
use zeroize::Zeroize;

use crate::cipher::{SharedCipher, TAG_LEN};
use crate::error::{Error, Result};
use crate::stream::{open_chunk, seal_chunk};

/// Süreç genelinde hattın sırayla yazdığı (ya da doğruladığı) akış baytı. Yalnızca ilerleme göstergesi içindir; aynı anda
/// birden çok hat çalışırsa toplamı gösterir.
static PROGRESS: AtomicU64 = AtomicU64::new(0);

/// İlerleme sayacını sıfırlar.
pub fn reset_progress() {
    PROGRESS.store(0, Ordering::Relaxed);
}

/// Son sıfırlamadan bu yana hattın yazdığı bayt.
#[must_use]
pub fn progress() -> u64 {
    PROGRESS.load(Ordering::Relaxed)
}

/// Hat parametreleri.
pub struct StreamParams<'a> {
    /// AEAD (paylaşımlı, arenada).
    pub cipher: &'a SharedCipher,
    /// `stream_nonce_prefix` (24 B).
    pub prefix: &'a [u8; 24],
    /// `chunk_aad`.
    pub aad: &'a [u8; 32],
    /// Chunk boyutu.
    pub chunk_size: usize,
}

/// Havuz tampon sayısı: `clamp(64 MiB / chunk_size, 2, 8)`.
#[must_use]
pub fn pool_buffers(chunk_size: usize) -> usize {
    ((64 * 1024 * 1024) / chunk_size.max(1)).clamp(2, 8)
}

/// İşçi sayısı: `available_parallelism` ≤ 8.
#[must_use]
pub fn worker_count() -> usize {
    std::thread::available_parallelism()
        .map_or(1, usize::from)
        .clamp(1, 8)
}

struct Buf<'p> {
    data: &'p mut [u8],
}

struct Job<'p> {
    index: u32,
    len: usize,
    last: bool,
    buf: Buf<'p>,
}

struct Done<'p> {
    index: u32,
    out_len: usize,
    buf: Buf<'p>,
}

struct Shared {
    failed: AtomicBool,
    error: Mutex<Option<Error>>,
}

impl Shared {
    fn fail(&self, e: Error) {
        if !self.failed.swap(true, Ordering::SeqCst) {
            *self
                .error
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner) = Some(e);
        }
    }
    fn check(&self) -> Result<()> {
        if lephy_sys::signal::interrupted() {
            self.fail(Error::Interrupted);
        }
        if self.failed.load(Ordering::SeqCst) {
            return Err(Error::Interrupted); // gerçek hata `take_error` ile alınır
        }
        Ok(())
    }
    fn take_error(&self) -> Option<Error> {
        self.error
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .take()
    }
}

/// `dest` dolana ya da EOF'a kadar okur; okunan bayt sayısı.
fn read_full(r: &mut dyn Read, dest: &mut [u8], shared: &Shared) -> Result<usize> {
    let mut n = 0;
    while n < dest.len() {
        match r.read(&mut dest[n..]) {
            Ok(0) => break,
            Ok(k) => n += k,
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => {
                shared.check()?;
            }
            Err(e) => return Err(Error::Io(e)),
        }
    }
    Ok(n)
}

/// Hat yönü.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Mode {
    Encrypt,
    Decrypt,
    Verify,
    /// Eski anahtarla aç, aynı tamponda yeni anahtarla mühürle: düz metin kilitli havuzdan
    /// hiç çıkmaz.
    Reencrypt,
}

/// Düz metni şifreler; şifreli chunk'ları `output`'a yazar. Döner: düz metin bayt sayısı.
///
/// # Errors
/// G/Ç (1), kesinti (130), AEAD/arena (1).
pub fn encrypt_stream(
    p: &StreamParams<'_>,
    input: &mut (dyn Read + Send),
    output: &mut (dyn Write + Send),
) -> Result<u64> {
    run(p, None, input, Some(output), Mode::Encrypt)
}

/// Şifreli akışı (`old`) çözüp aynı chunk sınırlarıyla `new` ile yeniden şifreler. Düz metin
/// yalnızca kilitli havuz tamponlarında bulunur. İki parametre kümesinin chunk boyutu aynı
/// olmalıdır. Döner: düz metin bayt sayısı.
///
/// # Errors
/// Kod 4 (eski akış bozuk), 1, 130.
pub fn reencrypt_stream(
    old: &StreamParams<'_>,
    new: &StreamParams<'_>,
    input: &mut (dyn Read + Send),
    output: &mut (dyn Write + Send),
) -> Result<u64> {
    if old.chunk_size != new.chunk_size {
        return Err(Error::Environment(
            "yeniden şifrelemede chunk boyutu değişemez".into(),
        ));
    }
    run(old, Some(new), input, Some(output), Mode::Reencrypt)
}

/// Şifreli akışı çözer; düz metni `output`'a yazar. Döner: düz metin bayt sayısı.
///
/// # Errors
/// Kod 4 (`Corrupt { at: "chunk N" }`), 1, 130.
pub fn decrypt_stream(
    p: &StreamParams<'_>,
    input: &mut (dyn Read + Send),
    output: &mut (dyn Write + Send),
) -> Result<u64> {
    run(p, None, input, Some(output), Mode::Decrypt)
}

/// Şifreli akışı yazmadan doğrular. Döner: düz metin bayt sayısı.
///
/// # Errors
/// Kod 4, 1, 130.
pub fn verify_stream(p: &StreamParams<'_>, input: &mut (dyn Read + Send)) -> Result<u64> {
    run(p, None, input, None, Mode::Verify)
}

fn chunk_err(index: u32) -> Error {
    Error::Corrupt {
        at: format!("chunk {index}"),
        detail: Some("AEAD doğrulaması başarısız ya da chunk uzunluğu geçersiz".into()),
    }
}

#[allow(clippy::too_many_lines)]
fn run(
    p: &StreamParams<'_>,
    next_params: Option<&StreamParams<'_>>,
    input: &mut (dyn Read + Send),
    output: Option<&mut (dyn Write + Send)>,
    mode: Mode,
) -> Result<u64> {
    let chunk_size = p.chunk_size;
    let stride = chunk_size + TAG_LEN + 1;
    let nbuf = pool_buffers(chunk_size);
    let mut pool = LargeSecretBuf::<u8>::new_filled(nbuf * stride, 0)
        .map_err(|e| Error::Environment(format!("chunk havuzu: {e}")))?;
    let shared = Shared {
        failed: AtomicBool::new(false),
        error: Mutex::new(None),
    };
    let (free_tx, free_rx): (Sender<Buf<'_>>, Receiver<Buf<'_>>) = bounded(nbuf);
    let (work_tx, work_rx): (Sender<Job<'_>>, Receiver<Job<'_>>) = bounded(nbuf);
    let (done_tx, done_rx): (Sender<Done<'_>>, Receiver<Done<'_>>) = bounded(nbuf);
    for data in pool.as_mut_slice().chunks_exact_mut(stride) {
        let _ = free_tx.send(Buf { data });
    }
    let workers = worker_count();
    let total = Mutex::new(0u64);
    let shared_ref = &shared;
    let total_ref = &total;
    let mut plain_in: u64 = 0;

    std::thread::scope(|s| {
        // İşçiler
        for _ in 0..workers {
            let work_rx = work_rx.clone();
            let done_tx = done_tx.clone();
            s.spawn(move || {
                let _ = lephy_sys::signal::mask_signals_on_this_thread();
                while let Ok(job) = work_rx.recv() {
                    if shared_ref.check().is_err() {
                        break;
                    }
                    let Job {
                        index,
                        len,
                        last,
                        buf,
                    } = job;
                    let r = match mode {
                        Mode::Encrypt => {
                            seal_chunk(p.cipher, p.prefix, p.aad, index, last, buf.data, len)
                                .map(Some)
                        }
                        Mode::Decrypt | Mode::Verify => {
                            open_chunk(p.cipher, p.prefix, p.aad, index, last, buf.data, len)
                        }
                        Mode::Reencrypt => {
                            match open_chunk(p.cipher, p.prefix, p.aad, index, last, buf.data, len)
                            {
                                Ok(Some(plain)) => next_params.map_or_else(
                                    || Err(Error::Environment("yeni anahtar yok".into())),
                                    |q| {
                                        seal_chunk(
                                            q.cipher, q.prefix, q.aad, index, last, buf.data, plain,
                                        )
                                        .map(Some)
                                    },
                                ),
                                other => other,
                            }
                        }
                    };
                    match r {
                        Ok(Some(out_len)) => {
                            if done_tx
                                .send(Done {
                                    index,
                                    out_len,
                                    buf,
                                })
                                .is_err()
                            {
                                break;
                            }
                        }
                        Ok(None) => {
                            shared_ref.fail(chunk_err(index));
                            break;
                        }
                        Err(e) => {
                            shared_ref.fail(e);
                            break;
                        }
                    }
                }
            });
        }
        drop(work_rx);
        drop(done_tx);

        // Yazıcı
        s.spawn(move || {
            let _ = lephy_sys::signal::mask_signals_on_this_thread();
            let mut out = output;
            let mut pending: BTreeMap<u32, Done<'_>> = BTreeMap::new();
            let mut next: u32 = 0;
            let mut written: u64 = 0;
            while let Ok(d) = done_rx.recv() {
                pending.insert(d.index, d);
                while let Some(d) = pending.remove(&next) {
                    if shared_ref.check().is_err() {
                        return;
                    }
                    let Done { out_len, buf, .. } = d;
                    if let Some(o) = out.as_deref_mut()
                        && let Err(e) = write_all_retry(o, &buf.data[..out_len], shared_ref)
                    {
                        shared_ref.fail(e);
                        return;
                    }
                    written += out_len as u64;
                    PROGRESS.fetch_add(out_len as u64, Ordering::Relaxed);
                    // panik hook testi: 4. chunk'ta bilinçli panik (yalnızca test derlemesi).
                    #[cfg(feature = "fault-injection")]
                    assert!(
                        next != 3,
                        "LPHY-FAULT-INJECTION: pipeline ortası panik (yalnızca test derlemesi)"
                    );
                    buf.data.zeroize();
                    next = next.wrapping_add(1);
                    if free_tx.send(buf).is_err() {
                        return;
                    }
                }
            }
            *total_ref
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner) = written;
        });

        // Okuyucu (bu iş parçacığı)
        let r = read_loop(input, &free_rx, &work_tx, chunk_size, mode, shared_ref);
        drop(work_tx);
        match r {
            Ok(n) => plain_in = n,
            Err(e) => shared_ref.fail(e),
        }
    });

    if let Some(e) = shared.take_error() {
        return Err(e);
    }
    let written = *total
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    Ok(match mode {
        Mode::Encrypt => plain_in,
        Mode::Decrypt | Mode::Verify => written,
        Mode::Reencrypt => {
            let per = (chunk_size + TAG_LEN) as u64;
            plain_in - plain_in.div_ceil(per) * TAG_LEN as u64
        }
    })
}

fn write_all_retry(o: &mut (dyn Write + Send), mut data: &[u8], shared: &Shared) -> Result<()> {
    while !data.is_empty() {
        match o.write(data) {
            Ok(0) => {
                return Err(Error::Io(std::io::Error::new(
                    std::io::ErrorKind::WriteZero,
                    "0 bayt",
                )));
            }
            Ok(n) => data = &data[n..],
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => shared.check()?,
            Err(e) => return Err(Error::Io(e)),
        }
    }
    Ok(())
}

fn read_loop<'p>(
    input: &mut (dyn Read + Send),
    free_rx: &Receiver<Buf<'p>>,
    work_tx: &Sender<Job<'p>>,
    chunk_size: usize,
    mode: Mode,
    shared: &Shared,
) -> Result<u64> {
    // Şifrelemede chunk_size+1, çözmede chunk_size+16+1 bayt okunur; fazla bayt sonraki
    // tampona taşınır (carry) ve son chunk tespiti böyle yapılır.
    let unit = match mode {
        Mode::Encrypt => chunk_size,
        Mode::Decrypt | Mode::Verify | Mode::Reencrypt => chunk_size + TAG_LEN,
    };
    let mut carry: Option<u8> = None;
    let mut index: u64 = 0;
    let mut total_in: u64 = 0;
    loop {
        shared.check()?;
        let Ok(buf) = free_rx.recv() else {
            return Ok(total_in); // yazıcı çıktı (hata zaten kaydedildi)
        };
        let mut n = 0;
        if let Some(c) = carry.take() {
            buf.data[0] = c;
            n = 1;
        }
        n += read_full(input, &mut buf.data[n..=unit], shared)?;
        let last = n <= unit;
        let len = if last {
            n
        } else {
            carry = Some(buf.data[unit]);
            unit
        };
        let idx = u32::try_from(index).map_err(|_| match mode {
            Mode::Encrypt => Error::Environment("girdi 2^32 chunk'ı aşıyor".into()),
            Mode::Decrypt | Mode::Verify | Mode::Reencrypt => Error::Corrupt {
                at: "chunk 4294967296".into(),
                detail: Some("chunk sayısı 2^32'yi aşıyor".into()),
            },
        })?;
        if mode != Mode::Encrypt && len < TAG_LEN {
            // Son chunk tag'den kısa → biçim ihlali (son chunk'tan sonra artık bayt dahil).
            return Err(chunk_err(idx));
        }
        if work_tx
            .send(Job {
                index: idx,
                len,
                last,
                buf,
            })
            .is_err()
        {
            return Ok(total_in);
        }
        total_in += len as u64;
        index += 1;
        if last {
            return Ok(total_in);
        }
        // Şifrelemede: taşınan bayt varsa akış devam eder; `len == unit` ve EOF tam katta ise bir
        // sonraki okuma 0 bayt + carry 1 bayt → 1 baytlık son chunk (kanonik değil!). Bunu
        // önlemek için carry'yi okuyup EOF görünce bir sonraki tur `n = 1` olur; bu yalnızca
        // taşınan bayt gerçekten varsa olur, yani içerik tam kat DEĞİLDİR. Tam katta
        // `read_full` tam `unit` bayt döndürür ve `n == unit` → `last` olur, ek chunk yazılmaz.
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::panic)]
mod tests {
    use super::*;
    use crate::cipher::AlgId;

    fn params(cipher: &SharedCipher, chunk: usize) -> StreamParams<'_> {
        StreamParams {
            cipher,
            prefix: &[7u8; 24],
            aad: &[3u8; 32],
            chunk_size: chunk,
        }
    }

    fn roundtrip(alg: AlgId, chunk: usize, data: &[u8]) -> Vec<u8> {
        let c = SharedCipher::new(alg, &[9u8; 32]).unwrap();
        // chunk_size test için 64 KiB'ten küçük olabilir; biçimde 64 KiB..16 MiB.
        let p = params(&c, chunk);
        let mut ct = Vec::new();
        let mut inp: &[u8] = data;
        let n = encrypt_stream(&p, &mut inp, &mut ct).unwrap();
        assert_eq!(n, data.len() as u64);
        let mut pt = Vec::new();
        let mut inp: &[u8] = &ct;
        let m = decrypt_stream(&p, &mut inp, &mut pt).unwrap();
        assert_eq!(m, data.len() as u64);
        assert_eq!(pt, data);
        let mut inp: &[u8] = &ct;
        assert_eq!(verify_stream(&p, &mut inp).unwrap(), data.len() as u64);
        ct
    }

    #[test]
    fn canonical_last_chunk_rules() {
        let chunk = 1024;
        // 0 bayt → tek boş son chunk (16 B)
        let ct = roundtrip(AlgId::XChaCha20Poly1305, chunk, b"");
        assert_eq!(ct.len(), 16);
        // tam kat → ek boş chunk yok
        let data = vec![1u8; chunk * 3];
        let ct = roundtrip(AlgId::XChaCha20Poly1305, chunk, &data);
        assert_eq!(ct.len(), 3 * (chunk + 16));
        // tam kat + 1
        let data = vec![2u8; chunk * 3 + 1];
        let ct = roundtrip(AlgId::Aes256Gcm, chunk, &data);
        assert_eq!(ct.len(), 3 * (chunk + 16) + 1 + 16);
        // tek kısa chunk
        roundtrip(AlgId::Aes256Gcm, chunk, b"hello");
    }

    #[test]
    fn trailing_byte_and_truncation_are_corrupt() {
        let c = SharedCipher::new(AlgId::XChaCha20Poly1305, &[1u8; 32]).unwrap();
        let p = params(&c, 1024);
        let data = vec![5u8; 2048];
        let mut ct = Vec::new();
        let mut inp: &[u8] = &data;
        encrypt_stream(&p, &mut inp, &mut ct).unwrap();
        // son chunk'tan sonra 1 fazla bayt → 4
        let mut bad = ct.clone();
        bad.push(0);
        let mut inp: &[u8] = &bad;
        match verify_stream(&p, &mut inp) {
            Err(Error::Corrupt { at, .. }) => assert!(at.starts_with("chunk")),
            other => panic!("{other:?}"),
        }
        // kesilmiş → 4 (son chunk doğrulanamaz)
        let mut inp: &[u8] = &ct[..ct.len() - 1];
        assert!(matches!(
            verify_stream(&p, &mut inp),
            Err(Error::Corrupt { .. })
        ));
        // bozuk bayt → 4
        let mut bad = ct.clone();
        bad[10] ^= 1;
        let mut inp: &[u8] = &bad;
        match verify_stream(&p, &mut inp) {
            Err(Error::Corrupt { at, .. }) => assert_eq!(at, "chunk 0"),
            other => panic!("{other:?}"),
        }
        // boş ciphertext → 4
        let mut inp: &[u8] = &[];
        assert!(matches!(
            verify_stream(&p, &mut inp),
            Err(Error::Corrupt { .. })
        ));
    }

    #[test]
    fn many_chunks_with_small_pool_complete() {
        // E3: nbuf=8 (chunk küçük), 10k chunk tamamlanır.
        let data: Vec<u8> = (0..10_000u32 * 64).map(|i| (i % 251) as u8).collect();
        roundtrip(AlgId::XChaCha20Poly1305, 64, &data);
    }
}
