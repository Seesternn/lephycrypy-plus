//! PADMÉ dolgu (PLAN B3, R4-O5; FORMAT.md › PADMÉ).
//!
//! `P(L)`: `E = floor(log2 L)`, `S = floor(log2 E) + 1`, `z = E − S`, `m = 2^z − 1`,
//! `P(L) = (L + m) & !m` (L < 2 → L).
//! - Ham akış (`content_type = 0`, padded): düz metin `[u64 LE L][veri][sıfır]`, toplam
//!   `P(L + 8)`; L baştan bilinmelidir. Okuma sırasında dosya L'den farklı bayt verirse → kod 1.
//! - Arşiv: END sonrası sıfır dolgu, toplam `P(END'e kadar yazılan)`.
//! - Okuyucu: sıfır olmayan dolgu baytı ya da toplam uzunluk uyuşmazlığı → kod 4.

use std::io::{self, Read, Write};

use crate::error::FormatViolation;

/// PADMÉ hedef uzunluğu.
#[must_use]
pub const fn padme(len: u64) -> u64 {
    if len < 2 {
        return len;
    }
    let e = len.ilog2(); // floor(log2 len), len ≥ 2 → e ≥ 1
    let s = e.ilog2() + 1; // floor(log2 e) + 1
    let z = e.saturating_sub(s);
    let m = (1u64 << z) - 1;
    (len + m) & !m
}

/// Ham akış dolgulayıcı: `[u64 LE L][veri][sıfır]`; `inner` tam `len` bayt vermezse hata (kod 1).
pub struct RawPadReader<R: Read> {
    inner: R,
    len: u64,
    total: u64,
    header: [u8; 8],
    header_pos: usize,
    body_read: u64,
    emitted: u64,
}

impl<R: Read> RawPadReader<R> {
    /// `len`: kaynağın baştan bilinen uzunluğu.
    #[must_use]
    pub fn new(inner: R, len: u64) -> Self {
        Self {
            inner,
            len,
            total: padme(len + 8),
            header: len.to_le_bytes(),
            header_pos: 0,
            body_read: 0,
            emitted: 0,
        }
    }

    /// Toplam düz metin uzunluğu `P(L + 8)`.
    #[must_use]
    pub const fn padded_len(&self) -> u64 {
        self.total
    }
}

impl<R: Read> Read for RawPadReader<R> {
    fn read(&mut self, out: &mut [u8]) -> io::Result<usize> {
        if out.is_empty() {
            return Ok(0);
        }
        if self.header_pos < 8 {
            let n = (8 - self.header_pos).min(out.len());
            out[..n].copy_from_slice(&self.header[self.header_pos..self.header_pos + n]);
            self.header_pos += n;
            self.emitted += n as u64;
            return Ok(n);
        }
        if self.body_read < self.len {
            let want = usize::try_from((self.len - self.body_read).min(out.len() as u64))
                .unwrap_or(out.len());
            let n = self.inner.read(&mut out[..want])?;
            if n == 0 {
                return Err(io::Error::other(
                    "kaynak dosya okuma sırasında küçüldü (PADMÉ uzunluğu baştan sabit)",
                ));
            }
            self.body_read += n as u64;
            self.emitted += n as u64;
            return Ok(n);
        }
        // Kaynak büyüdü mü? Bir bayt daha okumayı dene.
        if self.body_read == self.len {
            let mut probe = [0u8; 1];
            if self.inner.read(&mut probe)? != 0 {
                return Err(io::Error::other(
                    "kaynak dosya okuma sırasında büyüdü (PADMÉ uzunluğu baştan sabit)",
                ));
            }
            self.body_read += 1; // probe yapıldı işareti
        }
        let remaining = self.total - self.emitted;
        if remaining == 0 {
            return Ok(0);
        }
        let n = usize::try_from(remaining.min(out.len() as u64)).unwrap_or(out.len());
        out[..n].fill(0);
        self.emitted += n as u64;
        Ok(n)
    }
}

/// Ham akış dolgu çözücü (`Write` adaptörü): `[u64 LE L]` okur, `L` baytı `inner`'a yazar, kalan
/// baytların sıfır olduğunu ve toplamın `P(L + 8)` olduğunu doğrular ([`finish`](Self::finish)).
pub struct RawPadWriter<W: Write> {
    inner: W,
    header: [u8; 8],
    header_pos: usize,
    len: u64,
    written: u64,
    total_seen: u64,
}

impl<W: Write> RawPadWriter<W> {
    /// Kurar.
    pub fn new(inner: W) -> Self {
        Self {
            inner,
            header: [0; 8],
            header_pos: 0,
            len: 0,
            written: 0,
            total_seen: 0,
        }
    }

    /// Akış bitince: toplam uzunluk `P(L + 8)` olmalı. Döner: düz metin uzunluğu `L`.
    ///
    /// # Errors
    /// Biçim ihlali (kod 4) ya da `L` okunmadı.
    pub fn finish(mut self) -> io::Result<(W, u64)> {
        if self.header_pos < 8 {
            return Err(FormatViolation::io("PADMÉ uzunluk öneki eksik"));
        }
        if self.total_seen != padme(self.len + 8) {
            return Err(FormatViolation::io("PADMÉ toplam uzunluk uyuşmuyor"));
        }
        self.inner.flush()?;
        Ok((self.inner, self.len))
    }
}

impl<W: Write> Write for RawPadWriter<W> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        let mut rest = buf;
        if self.header_pos < 8 {
            let n = (8 - self.header_pos).min(rest.len());
            self.header[self.header_pos..self.header_pos + n].copy_from_slice(&rest[..n]);
            self.header_pos += n;
            self.total_seen += n as u64;
            rest = &rest[n..];
            if self.header_pos == 8 {
                self.len = u64::from_le_bytes(self.header);
            }
            if rest.is_empty() {
                return Ok(buf.len());
            }
        }
        if self.written < self.len {
            let n = usize::try_from((self.len - self.written).min(rest.len() as u64))
                .unwrap_or(rest.len());
            self.inner.write_all(&rest[..n])?;
            self.written += n as u64;
            self.total_seen += n as u64;
            rest = &rest[n..];
        }
        if !rest.is_empty() {
            if rest.iter().any(|&b| b != 0) {
                return Err(FormatViolation::io("PADMÉ dolgusunda sıfır olmayan bayt"));
            }
            self.total_seen += rest.len() as u64;
            if self.total_seen > padme(self.len + 8) {
                return Err(FormatViolation::io("PADMÉ dolgusu beklenenden uzun"));
            }
        }
        Ok(buf.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        self.inner.flush()
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn padme_values() {
        // PADMÉ makalesi: 1024 → 1024, 1000 → 1024? (E=9,S=4,z=5,m=31 → 1024); 100 → 104 (E=6,S=3,z=3,m=7)
        assert_eq!(padme(0), 0);
        assert_eq!(padme(1), 1);
        assert_eq!(padme(8), 8);
        assert_eq!(padme(100), 104);
        assert_eq!(padme(1000), 1024);
        assert_eq!(padme(1024), 1024);
        assert_eq!(padme(1025), 1088);
        assert_eq!(padme(1_000_000), 1_015_808);
        for l in 2..5000u64 {
            let p = padme(l);
            assert!(p >= l && p < l + l / 8 + 64, "{l} → {p}");
        }
    }

    #[test]
    fn raw_roundtrip_and_size_change_detection() {
        let data = vec![7u8; 1000];
        let mut r = RawPadReader::new(&data[..], 1000);
        let mut padded = Vec::new();
        r.read_to_end(&mut padded).unwrap();
        assert_eq!(padded.len() as u64, padme(1008));
        assert_eq!(&padded[..8], &1000u64.to_le_bytes());
        assert!(padded[1008..].iter().all(|&b| b == 0));
        let mut out = Vec::new();
        let mut w = RawPadWriter::new(&mut out);
        for chunk in padded.chunks(7) {
            w.write_all(chunk).unwrap();
        }
        let (_, l) = w.finish().unwrap();
        assert_eq!(l, 1000);
        assert_eq!(out, data);
        // küçülen kaynak → hata
        let mut r = RawPadReader::new(&data[..500], 1000);
        assert!(r.read_to_end(&mut Vec::new()).is_err());
        // büyüyen kaynak → hata
        let mut r = RawPadReader::new(&data[..], 900);
        assert!(r.read_to_end(&mut Vec::new()).is_err());
        // sıfır olmayan dolgu → biçim ihlali
        let mut bad = padded.clone();
        bad[1010] = 1;
        let mut w = RawPadWriter::new(Vec::new());
        let e = w.write_all(&bad).unwrap_err();
        assert!(FormatViolation::is(&e));
        // kısa dolgu → finish hatası
        let mut w = RawPadWriter::new(Vec::new());
        w.write_all(&padded[..padded.len() - 1]).unwrap();
        assert!(FormatViolation::is(&w.finish().unwrap_err()));
    }
}
