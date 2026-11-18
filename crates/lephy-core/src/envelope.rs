//! Hata düzeltme zarfı: şifreli `.lphy` dosyasının **dışına** sarılan Reed–Solomon katmanı.
//!
//! Zarf şifrelemeden bağımsızdır: içteki `.lphy` bayt bayt aynı kalır, yalnızca disk/USB
//! bozulmalarına karşı korunur. Bütünlük yine STREAM'in kimlik doğrulamasından gelir; zarf
//! yalnızca küçük hasarları **onarır**.
//!
//! Düzen:
//! ```text
//! [başlık 64 B] × 3            (her kopya kendi BLAKE3 sağlamasıyla)
//! [blok]…                      blok = D kod sözcüğü × N bayt, serpiştirilmiş
//! ```
//! Başlık: `magic "LPHYRS1\0"` ‖ `version u16 = 1` ‖ `k u16` ‖ `nsym u16` ‖ `d u16` ‖
//! `payload_len u64` ‖ 8 B sıfır ‖ `BLAKE3(ilk 32 B)`. Her blok `D × k` veri baytını taşır (son
//! blok sıfırla tamamlanır); veri baytı `j`, kod sözcüğü `j mod D`'nin `j / D`. sembolüdür;
//! diskte de bayt `t`, kod sözcüğü `t mod D`'nin `t / D`. sembolüdür. Böylece `B` baytlık ardışık
//! bir bozulma her kod sözcüğünde yalnızca ~`B / D` sembolü etkiler.

use std::io::{self, Read, Seek, SeekFrom, Write};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use crate::error::FormatViolation;
use crate::rs;

/// Magic.
pub const MAGIC: [u8; 8] = *b"LPHYRS1\0";
/// Kod sözcüğü başına veri baytı.
pub const K: usize = 239;
/// Kod sözcüğü başına parite baytı (8 bayta kadar hata düzeltir).
pub const NSYM: usize = 16;
/// Kod sözcüğü uzunluğu.
pub const N: usize = K + NSYM;
/// Serpiştirme derinliği (blok başına kod sözcüğü).
pub const D: usize = 128;
/// Tek başlık kopyası.
pub const HEADER_COPY: usize = 64;
/// Başlık alanı (üç kopya).
pub const HEADER_AREA: usize = 3 * HEADER_COPY;
const BLOCK_DATA: usize = D * K;
/// Birlikte okunup paralel çözülen blok sayısı.
const BATCH: usize = 16;
const BLOCK_DISK: usize = D * N;

fn violation(d: &str) -> io::Error {
    FormatViolation::io_at("hata düzeltme", d)
}

fn header_copy(payload_len: u64) -> [u8; HEADER_COPY] {
    let mut h = [0u8; HEADER_COPY];
    h[0..8].copy_from_slice(&MAGIC);
    h[8..10].copy_from_slice(&1u16.to_le_bytes());
    h[10..12].copy_from_slice(&u16::try_from(K).unwrap_or(0).to_le_bytes());
    h[12..14].copy_from_slice(&u16::try_from(NSYM).unwrap_or(0).to_le_bytes());
    h[14..16].copy_from_slice(&u16::try_from(D).unwrap_or(0).to_le_bytes());
    h[16..24].copy_from_slice(&payload_len.to_le_bytes());
    let sum = blake3::hash(&h[..32]);
    h[32..64].copy_from_slice(sum.as_bytes());
    h
}

/// Geçerli bir başlık kopyasından `payload_len`.
fn parse_copy(h: &[u8]) -> Option<u64> {
    if h[0..8] != MAGIC || blake3::hash(&h[..32]).as_bytes() != &h[32..64] {
        return None;
    }
    let ok = u16::from_le_bytes([h[8], h[9]]) == 1
        && usize::from(u16::from_le_bytes([h[10], h[11]])) == K
        && usize::from(u16::from_le_bytes([h[12], h[13]])) == NSYM
        && usize::from(u16::from_le_bytes([h[14], h[15]])) == D
        && h[24..32].iter().all(|&b| b == 0);
    ok.then(|| u64::from_le_bytes(h[16..24].try_into().unwrap_or([0; 8])))
}

/// Üç kopyadan payload uzunluğu: önce sağlaması tutan ilk kopya, olmazsa bayt bayt çoğunluk.
fn parse_area(area: &[u8; HEADER_AREA]) -> Option<u64> {
    let copies = [
        &area[..HEADER_COPY],
        &area[HEADER_COPY..2 * HEADER_COPY],
        &area[2 * HEADER_COPY..],
    ];
    if let Some(l) = copies.iter().find_map(|c| parse_copy(c)) {
        return Some(l);
    }
    let mut vote = [0u8; HEADER_COPY];
    for (i, v) in vote.iter_mut().enumerate() {
        let (a, b, c) = (copies[0][i], copies[1][i], copies[2][i]);
        *v = if a == b || a == c { a } else { b };
    }
    parse_copy(&vote)
}

/// Bayt dizisi bir zarf başlık alanıyla mı başlıyor (en az bir kopyanın magic'i).
#[must_use]
pub fn looks_like_envelope(prefix: &[u8]) -> bool {
    prefix.len() >= 8 && prefix[..8] == MAGIC
}

fn encode_block(data: &[u8], out: &mut [u8]) {
    let mut msg = [0u8; K];
    for c in 0..D {
        for (j, m) in msg.iter_mut().enumerate() {
            *m = data[c + D * j];
        }
        let parity = rs::encode(&msg, NSYM);
        for (s, &b) in msg.iter().chain(parity.iter()).enumerate() {
            out[c + D * s] = b;
        }
    }
}

/// Yazılanları zarfa sarar. Başlık en sonda (`finish`) yazılır; bu yüzden `Seek` gerekir.
pub struct EncodeWriter<W: Write + Seek> {
    inner: W,
    buf: Vec<u8>,
    out: Vec<u8>,
    total: u64,
}

impl<W: Write + Seek> EncodeWriter<W> {
    /// Başlık alanı için yer ayırır.
    ///
    /// # Errors
    /// G/Ç.
    pub fn new(mut inner: W) -> io::Result<Self> {
        inner.write_all(&[0u8; HEADER_AREA])?;
        Ok(Self {
            inner,
            buf: Vec::with_capacity(BATCH * BLOCK_DATA),
            out: vec![0u8; BATCH * BLOCK_DISK],
            total: 0,
        })
    }

    /// Tamponu blok sınırına sıfırla tamamlar ve blokları paralel kodlar.
    fn flush_block(&mut self) -> io::Result<()> {
        let blocks = self.buf.len().div_ceil(BLOCK_DATA).max(1);
        self.buf.resize(blocks * BLOCK_DATA, 0);
        let out = &mut self.out[..blocks * BLOCK_DISK];
        std::thread::scope(|sc| {
            for (data, disk) in self.buf.chunks(BLOCK_DATA).zip(out.chunks_mut(BLOCK_DISK)) {
                sc.spawn(move || encode_block(data, disk));
            }
        });
        self.inner.write_all(out)?;
        self.buf.clear();
        Ok(())
    }

    /// Son bloğu ve başlığı yazar.
    ///
    /// # Errors
    /// G/Ç.
    pub fn finish(mut self) -> io::Result<W> {
        if !self.buf.is_empty() || self.total == 0 {
            self.flush_block()?;
        }
        let end = self.inner.stream_position()?;
        self.inner.seek(SeekFrom::Start(0))?;
        let h = header_copy(self.total);
        for _ in 0..3 {
            self.inner.write_all(&h)?;
        }
        self.inner.seek(SeekFrom::Start(end))?;
        self.inner.flush()?;
        Ok(self.inner)
    }
}

impl<W: Write + Seek> Write for EncodeWriter<W> {
    fn write(&mut self, data: &[u8]) -> io::Result<usize> {
        let mut rest = data;
        while !rest.is_empty() {
            let take = (BATCH * BLOCK_DATA - self.buf.len()).min(rest.len());
            self.buf.extend_from_slice(&rest[..take]);
            rest = &rest[take..];
            if self.buf.len() == BATCH * BLOCK_DATA {
                self.flush_block()?;
            }
        }
        self.total += data.len() as u64;
        Ok(data.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        self.inner.flush()
    }
}

/// Onarım istatistikleri (paylaşımlı; okuyucu düştükten sonra da okunabilir).
#[derive(Debug, Default)]
pub struct Stats {
    /// Düzeltilen bayt sayısı.
    pub corrected: AtomicU64,
    /// Onarılamayan kod sözcüğü sayısı.
    pub failed: AtomicU64,
}

/// Zarfı açıp içteki `.lphy` baytlarını verir; okurken onarır.
pub struct DecodeReader<R: Read> {
    inner: R,
    remaining: u64,
    disk: Vec<u8>,
    data: Vec<u8>,
    pos: usize,
    len: usize,
    lenient: bool,
    stats: Arc<Stats>,
}

impl<R: Read> DecodeReader<R> {
    /// Başlık alanı zaten okunmuşsa (`area`) gövdeden devam eder. `lenient`: onarılamayan kod
    /// sözcüğünde hata vermek yerine veriyi olduğu gibi aktar (kurtarma modu).
    ///
    /// # Errors
    /// Üç başlık kopyası da okunamazsa biçim ihlali (kod 4).
    pub fn with_header(
        area: &[u8; HEADER_AREA],
        inner: R,
        lenient: bool,
        stats: Arc<Stats>,
    ) -> io::Result<Self> {
        let remaining = parse_area(area).ok_or_else(|| violation("zarf başlığı okunamadı"))?;
        Ok(Self {
            inner,
            remaining,
            disk: vec![0u8; BATCH * BLOCK_DISK],
            data: vec![0u8; BATCH * BLOCK_DATA],
            pos: 0,
            len: 0,
            lenient,
            stats,
        })
    }

    fn next_block(&mut self) -> io::Result<()> {
        // Toplu oku: en fazla BATCH blok; bloklar paralel çözülür.
        let mut n = 0;
        while n < self.disk.len() {
            match self.inner.read(&mut self.disk[n..]) {
                Ok(0) => break,
                Ok(k) => n += k,
                Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
                Err(e) => return Err(e),
            }
        }
        let need = usize::try_from(self.remaining.div_ceil(BLOCK_DATA as u64))
            .unwrap_or(BATCH)
            .min(BATCH);
        let full = need * BLOCK_DISK;
        if n < full {
            if !self.lenient {
                return Err(violation("zarf gövdesi kesilmiş"));
            }
            self.disk[n..full].fill(0);
        }
        let lenient = self.lenient;
        let stats = &self.stats;
        let results: Vec<io::Result<()>> = std::thread::scope(|sc| {
            let handles: Vec<_> = self.disk[..full]
                .chunks(BLOCK_DISK)
                .zip(self.data.chunks_mut(BLOCK_DATA))
                .map(|(disk, data)| sc.spawn(move || decode_block(disk, data, lenient, stats)))
                .collect();
            handles
                .into_iter()
                .map(|h| {
                    h.join()
                        .unwrap_or_else(|_| Err(io::Error::other("çözücü panikledi")))
                })
                .collect()
        });
        for r in results {
            r?;
        }
        let take = usize::try_from(self.remaining.min((need * BLOCK_DATA) as u64))
            .unwrap_or(need * BLOCK_DATA);
        self.pos = 0;
        self.len = take;
        self.remaining -= take as u64;
        Ok(())
    }
}

fn decode_block(disk: &[u8], data: &mut [u8], lenient: bool, stats: &Stats) -> io::Result<()> {
    let mut cw = [0u8; N];
    for c in 0..D {
        for (s, b) in cw.iter_mut().enumerate() {
            *b = disk[c + D * s];
        }
        if !rs::is_valid(&cw, NSYM) {
            if let Some(fixed) = rs::decode(&mut cw, NSYM) {
                stats.corrected.fetch_add(fixed as u64, Ordering::Relaxed);
            } else {
                stats.failed.fetch_add(1, Ordering::Relaxed);
                if !lenient {
                    return Err(violation(
                        "bozulma hata düzeltme kapasitesini aşıyor (kurtarma modunu deneyin)",
                    ));
                }
            }
        }
        for (j, &b) in cw[..K].iter().enumerate() {
            data[c + D * j] = b;
        }
    }
    Ok(())
}

impl<R: Read> Read for DecodeReader<R> {
    fn read(&mut self, out: &mut [u8]) -> io::Result<usize> {
        if self.pos == self.len {
            if self.remaining == 0 {
                return Ok(0);
            }
            self.next_block()?;
        }
        let n = (self.len - self.pos).min(out.len());
        out[..n].copy_from_slice(&self.data[self.pos..self.pos + n]);
        self.pos += n;
        Ok(n)
    }
}

/// Zarflı dosyanın diskteki boyutu (`payload` bayt için).
#[must_use]
pub fn disk_size(payload: u64) -> u64 {
    let blocks = payload.div_ceil(BLOCK_DATA as u64).max(1);
    HEADER_AREA as u64 + blocks * BLOCK_DISK as u64
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::cast_possible_truncation)]
mod tests {
    use super::*;
    use std::io::Cursor;

    fn wrap(data: &[u8]) -> Vec<u8> {
        let mut w = EncodeWriter::new(Cursor::new(Vec::new())).unwrap();
        for c in data.chunks(10_007) {
            w.write_all(c).unwrap();
        }
        w.finish().unwrap().into_inner()
    }

    fn unwrap_env(disk: &[u8], lenient: bool) -> (io::Result<Vec<u8>>, Arc<Stats>) {
        let stats = Arc::new(Stats::default());
        let area: [u8; HEADER_AREA] = disk[..HEADER_AREA].try_into().unwrap();
        let r = DecodeReader::with_header(&area, &disk[HEADER_AREA..], lenient, Arc::clone(&stats))
            .and_then(|mut r| {
                let mut out = Vec::new();
                r.read_to_end(&mut out).map(|_| out)
            });
        (r, stats)
    }

    #[test]
    fn roundtrip_sizes() {
        for len in [
            0usize,
            1,
            BLOCK_DATA - 1,
            BLOCK_DATA,
            BLOCK_DATA + 1,
            3 * BLOCK_DATA + 77,
        ] {
            let data: Vec<u8> = (0..len).map(|i| (i % 251) as u8).collect();
            let disk = wrap(&data);
            assert_eq!(disk.len() as u64, disk_size(len as u64));
            assert!(looks_like_envelope(&disk));
            let (out, st) = unwrap_env(&disk, false);
            assert_eq!(out.unwrap(), data);
            assert_eq!(st.corrected.load(Ordering::Relaxed), 0);
        }
    }

    #[test]
    fn repairs_bursts_and_damaged_header_copies() {
        let data: Vec<u8> = (0..(2 * BLOCK_DATA + 500))
            .map(|i| (i * 7 % 256) as u8)
            .collect();
        let mut disk = wrap(&data);
        // İki başlık kopyası bozuk: üçüncüsü yeter.
        disk[3] ^= 0xff;
        disk[HEADER_COPY + 20] ^= 0xff;
        // Her blokta 1 KiB ardışık bozulma (D × nsym/2 = 1024 sembol).
        for b in 0..3 {
            let start = HEADER_AREA + b * BLOCK_DISK + 5000;
            for x in &mut disk[start..start + 1024] {
                *x ^= 0x5a;
            }
        }
        let (out, st) = unwrap_env(&disk, false);
        assert_eq!(out.unwrap(), data);
        assert_eq!(st.corrected.load(Ordering::Relaxed), 3 * 1024);
    }

    #[test]
    fn too_much_damage_is_an_error_unless_lenient() {
        let data = vec![9u8; BLOCK_DATA];
        let mut disk = wrap(&data);
        for x in &mut disk[HEADER_AREA..HEADER_AREA + 4000] {
            *x ^= 0xff;
        }
        let (out, _) = unwrap_env(&disk, false);
        assert!(out.is_err());
        let (out, st) = unwrap_env(&disk, true);
        assert_eq!(out.unwrap().len(), data.len());
        assert!(st.failed.load(Ordering::Relaxed) > 0);
        // Kesilmiş gövde.
        let short = &disk[..disk.len() - 10];
        assert!(unwrap_env(short, false).0.is_err());
    }
}
