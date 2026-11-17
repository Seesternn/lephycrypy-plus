//! İsteğe bağlı sıkıştırma (biçim v2, `feature_flags.bit0`): ham DEFLATE (RFC 1951),
//! şifrelemeden **önce**.
//!
//! Sıra: kaynak (arşiv ya da ham akış) → DEFLATE → [PADMÉ sıfır dolgusu] → STREAM AEAD.
//! Dolgu açıksa sıkıştırılmış akışın uzunluğu `L` ise ardından `padme(L) − L` sıfır bayt gelir;
//! DEFLATE akışı kendi sonunu işaretlediği için uzunluk öneki gerekmez.
//!
//! Yan kanal uyarısı: sıkıştırılmış boyut içerik hakkında bilgi verir (bir saldırgan girdinin bir
//! kısmını seçebiliyorsa CRIME/BREACH türü saldırılar). PADMÉ bunu azaltır ama ortadan
//! kaldırmaz. Sıkıştırma bu yüzden varsayılan olarak kapalıdır.
//!
//! Açma tarafında çıktı boyutu sınırlanmaz (DEFLATE en fazla ~1032:1 genişler); arşiv çıkarmanın
//! kendi sınırları ve disk alanı denetimi geçerlidir.

use std::io::{self, Read, Write};

use miniz_oxide::deflate::core::{CompressorOxide, create_comp_flags_from_zip_params};
use miniz_oxide::inflate::stream::InflateState;
use miniz_oxide::{DataFormat, MZError, MZFlush, MZStatus};
use zeroize::Zeroizing;

use crate::error::FormatViolation;

const BUF: usize = 64 * 1024;
/// Sıkıştırma düzeyi (zlib ölçeği; 6 = varsayılan denge).
const LEVEL: i32 = 6;

fn violation(d: &str) -> io::Error {
    FormatViolation::io_at("sıkıştırma", d)
}

fn padme(len: u64) -> io::Result<u64> {
    crate::pad::padme_checked(len).ok_or_else(|| violation("dolgu uzunluğu taşıyor"))
}

/// Kaynağı okurken sıkıştırır; istenirse PADMÉ sıfır dolgusu ekler.
pub struct DeflateReader<R: Read> {
    inner: R,
    comp: Box<CompressorOxide>,
    inbuf: Zeroizing<Vec<u8>>,
    in_pos: usize,
    in_len: usize,
    inner_eof: bool,
    finished: bool,
    written: u64,
    pad: bool,
    pad_left: u64,
}

impl<R: Read> DeflateReader<R> {
    /// Yeni sıkıştırıcı.
    pub fn new(inner: R, pad: bool) -> Self {
        let flags = create_comp_flags_from_zip_params(LEVEL, -15, 0); // ham DEFLATE
        Self {
            inner,
            comp: Box::new(CompressorOxide::new(flags)),
            inbuf: Zeroizing::new(vec![0u8; BUF]),
            in_pos: 0,
            in_len: 0,
            inner_eof: false,
            finished: false,
            written: 0,
            pad,
            pad_left: 0,
        }
    }

    /// İç okuyucuyu döndürür (ör. arşiv raporu için).
    pub fn into_inner(self) -> R {
        self.inner
    }
}

impl<R: Read> Read for DeflateReader<R> {
    fn read(&mut self, out: &mut [u8]) -> io::Result<usize> {
        if out.is_empty() {
            return Ok(0);
        }
        loop {
            if self.finished {
                let n = usize::try_from(self.pad_left.min(out.len() as u64)).unwrap_or(0);
                out[..n].fill(0);
                self.pad_left -= n as u64;
                return Ok(n);
            }
            if self.in_pos == self.in_len && !self.inner_eof {
                let n = self.inner.read(&mut self.inbuf[..])?;
                self.in_pos = 0;
                self.in_len = n;
                self.inner_eof = n == 0;
            }
            let flush = if self.inner_eof && self.in_pos == self.in_len {
                MZFlush::Finish
            } else {
                MZFlush::None
            };
            let r = miniz_oxide::deflate::stream::deflate(
                &mut self.comp,
                &self.inbuf[self.in_pos..self.in_len],
                out,
                flush,
            );
            self.in_pos += r.bytes_consumed;
            self.written += r.bytes_written as u64;
            match r.status {
                Ok(MZStatus::StreamEnd) => {
                    self.finished = true;
                    if self.pad {
                        self.pad_left = padme(self.written)? - self.written;
                    }
                    if r.bytes_written > 0 {
                        return Ok(r.bytes_written);
                    }
                }
                Ok(_) | Err(MZError::Buf) => {
                    if r.bytes_written > 0 {
                        return Ok(r.bytes_written);
                    }
                    if r.bytes_consumed == 0 && flush == MZFlush::Finish {
                        return Err(io::Error::other("sıkıştırma ilerlemiyor"));
                    }
                }
                Err(e) => return Err(io::Error::other(format!("sıkıştırma: {e:?}"))),
            }
        }
    }
}

/// Çözülmüş (sıkıştırılmış) akışı açıp `inner`'a yazar. Akışın sonunu ve dolguyu denetler.
pub struct InflateWriter<W: Write> {
    inner: W,
    state: Box<InflateState>,
    outbuf: Zeroizing<Vec<u8>>,
    done: bool,
    consumed: u64,
    trailing: u64,
    padded: bool,
    produced: u64,
}

impl<W: Write> InflateWriter<W> {
    /// Yeni açıcı. `padded`: başlıktaki dolgu bayrağı.
    pub fn new(inner: W, padded: bool) -> Self {
        Self {
            inner,
            state: InflateState::new_boxed(DataFormat::Raw),
            outbuf: Zeroizing::new(vec![0u8; BUF]),
            done: false,
            consumed: 0,
            trailing: 0,
            padded,
            produced: 0,
        }
    }

    /// Akış bitti: sıkıştırılmış akış tam olmalı, dolgu (varsa) tam PADMÉ uzunluğunda olmalı.
    /// Döner: iç yazıcı ve açılmış bayt sayısı.
    ///
    /// # Errors
    /// Biçim ihlali (kod 4).
    pub fn finish(mut self) -> io::Result<(W, u64)> {
        if !self.done {
            return Err(violation("sıkıştırılmış akış eksik"));
        }
        let total = self.consumed + self.trailing;
        let expect = if self.padded {
            padme(self.consumed)?
        } else {
            self.consumed
        };
        if total != expect {
            return Err(violation("dolgu uzunluğu uyuşmuyor"));
        }
        self.inner.flush()?;
        Ok((self.inner, self.produced))
    }

    fn trailer(&mut self, rest: &[u8]) -> io::Result<()> {
        if !self.padded && !rest.is_empty() {
            return Err(violation("sıkıştırılmış akıştan sonra veri"));
        }
        if rest.iter().any(|&b| b != 0) {
            return Err(violation("dolgu sıfır değil"));
        }
        self.trailing += rest.len() as u64;
        Ok(())
    }
}

impl<W: Write> Write for InflateWriter<W> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        if self.done {
            self.trailer(buf)?;
            return Ok(buf.len());
        }
        let mut input = buf;
        loop {
            let r = miniz_oxide::inflate::stream::inflate(
                &mut self.state,
                input,
                &mut self.outbuf,
                MZFlush::None,
            );
            self.consumed += r.bytes_consumed as u64;
            input = &input[r.bytes_consumed..];
            self.inner.write_all(&self.outbuf[..r.bytes_written])?;
            self.produced += r.bytes_written as u64;
            match r.status {
                Ok(MZStatus::StreamEnd) => {
                    self.done = true;
                    self.trailer(input)?;
                    return Ok(buf.len());
                }
                Ok(_) | Err(MZError::Buf) => {
                    let drained = r.bytes_written < self.outbuf.len();
                    if input.is_empty() && drained {
                        return Ok(buf.len());
                    }
                    if r.bytes_consumed == 0 && r.bytes_written == 0 {
                        return Err(violation("bozuk sıkıştırılmış veri"));
                    }
                }
                Err(_) => return Err(violation("bozuk sıkıştırılmış veri")),
            }
        }
    }

    fn flush(&mut self) -> io::Result<()> {
        self.inner.flush()
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    fn roundtrip(data: &[u8], pad: bool, chunk: usize) -> Vec<u8> {
        let mut comp = Vec::new();
        DeflateReader::new(data, pad)
            .read_to_end(&mut comp)
            .unwrap();
        if pad {
            let n = comp.len() as u64;
            assert_eq!(
                crate::pad::padme_checked(n).unwrap(),
                n,
                "dolgulu uzunluk PADMÉ olmalı"
            );
        }
        let mut w = InflateWriter::new(Vec::new(), pad);
        for c in comp.chunks(chunk) {
            w.write_all(c).unwrap();
        }
        let (out, n) = w.finish().unwrap();
        assert_eq!(n, out.len() as u64);
        out
    }

    #[test]
    fn roundtrips_and_compresses() {
        let text: Vec<u8> = b"lephycrypy sikistirma testi "
            .iter()
            .copied()
            .cycle()
            .take(500_000)
            .collect();
        for pad in [false, true] {
            for chunk in [1, 7, 4096, 1 << 20] {
                assert_eq!(roundtrip(&text, pad, chunk), text);
            }
        }
        let mut comp = Vec::new();
        DeflateReader::new(&text[..], false)
            .read_to_end(&mut comp)
            .unwrap();
        assert!(comp.len() < text.len() / 20, "tekrarlı metin sıkışmalı");
        assert_eq!(roundtrip(b"", false, 3), b"");
        assert_eq!(roundtrip(b"", true, 3), b"");
    }

    #[test]
    fn rejects_truncation_garbage_and_bad_padding() {
        let data = vec![7u8; 100_000];
        let mut comp = Vec::new();
        DeflateReader::new(&data[..], true)
            .read_to_end(&mut comp)
            .unwrap();
        // Kesilmiş akış.
        let mut w = InflateWriter::new(Vec::new(), true);
        w.write_all(&comp[..comp.len() / 2]).unwrap_or(());
        assert!(w.finish().is_err());
        // Sıfır olmayan dolgu.
        let mut bad = comp.clone();
        let last = bad.len() - 1;
        if bad.len() > 12 {
            bad[last] = 1;
            let mut w = InflateWriter::new(Vec::new(), true);
            assert!(w.write_all(&bad).is_err() || w.finish().is_err());
        }
        // Dolgusuz akışın sonuna ek veri.
        let mut plain = Vec::new();
        DeflateReader::new(&data[..], false)
            .read_to_end(&mut plain)
            .unwrap();
        plain.push(0);
        let mut w = InflateWriter::new(Vec::new(), false);
        assert!(w.write_all(&plain).is_err());
        // Rastgele bayt.
        let mut w = InflateWriter::new(Vec::new(), false);
        let junk: Vec<u8> = (0..5000u32)
            .map(|i| (i.wrapping_mul(2_654_435_761) >> 24) as u8)
            .collect();
        assert!(w.write_all(&junk).is_err() || w.finish().is_err());
    }
}
