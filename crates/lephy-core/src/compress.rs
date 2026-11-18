//! Optional compression (format v2, `feature_flags.bit0`): raw DEFLATE (RFC 1951), **before**
//! encryption.
//!
//! Order: source (archive or raw stream) → DEFLATE → [PADMÉ zero padding] → STREAM AEAD.
//! With padding, a compressed stream of length `L` is followed by `padme(L) − L` zero bytes; no
//! length prefix is needed because DEFLATE marks its own end.
//!
//! Side-channel warning: the compressed size reveals information about the content (CRIME/BREACH
//! style attacks if an attacker can choose part of the input). PADMÉ reduces this but does not
//! remove it. Compression is therefore off by default.
//!
//! The inflated size is not limited (DEFLATE expands at most ~1032:1); archive extraction has its
//! own limits and the disk-space check applies.

use std::io::{self, Read, Write};

use miniz_oxide::deflate::core::{CompressorOxide, create_comp_flags_from_zip_params};
use miniz_oxide::inflate::stream::InflateState;
use miniz_oxide::{DataFormat, MZError, MZFlush, MZStatus};
use zeroize::Zeroizing;

use crate::error::FormatViolation;

const BUF: usize = 64 * 1024;
/// Compression level (zlib scale; 6 = default balance).
const LEVEL: i32 = 6;

fn violation(d: &str) -> io::Error {
    FormatViolation::io_at("compression", d)
}

fn padme(len: u64) -> io::Result<u64> {
    crate::pad::padme_checked(len).ok_or_else(|| violation("padding length overflows"))
}

/// Compresses while reading the source; optionally adds PADMÉ zero padding.
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
    /// New compressor.
    pub fn new(inner: R, pad: bool) -> Self {
        let flags = create_comp_flags_from_zip_params(LEVEL, -15, 0); // raw DEFLATE
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

    /// Returns the inner reader (e.g. for the archive report).
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
                        return Err(io::Error::other("compression makes no progress"));
                    }
                }
                Err(e) => return Err(io::Error::other(format!("compression: {e:?}"))),
            }
        }
    }
}

/// Inflates the decrypted (compressed) stream into `inner`. Checks the end of the stream and the padding.
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
    /// New inflater. `padded`: the padding flag from the header.
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

    /// End of the stream: the compressed stream must be complete and the padding (if any) exactly
    /// the PADMÉ length. Returns the inner writer and the number of inflated bytes.
    ///
    /// # Errors
    /// Format violation (code 4).
    pub fn finish(mut self) -> io::Result<(W, u64)> {
        if !self.done {
            return Err(violation("compressed stream incomplete"));
        }
        let total = self.consumed + self.trailing;
        let expect = if self.padded {
            padme(self.consumed)?
        } else {
            self.consumed
        };
        if total != expect {
            return Err(violation("padding length mismatch"));
        }
        self.inner.flush()?;
        Ok((self.inner, self.produced))
    }

    /// Returns the inner writer without checks (recovery: the stream may be cut short).
    pub fn into_inner(self) -> W {
        self.inner
    }

    fn trailer(&mut self, rest: &[u8]) -> io::Result<()> {
        if !self.padded && !rest.is_empty() {
            return Err(violation("data after the compressed stream"));
        }
        if rest.iter().any(|&b| b != 0) {
            return Err(violation("padding is not zero"));
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
                        return Err(violation("corrupt compressed data"));
                    }
                }
                Err(_) => return Err(violation("corrupt compressed data")),
            }
        }
    }

    fn flush(&mut self) -> io::Result<()> {
        self.inner.flush()
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::cast_possible_truncation)]
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
                "padded length must be PADMÉ"
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
        let text: Vec<u8> = b"lephycrypy compression test "
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
        assert!(
            comp.len() < text.len() / 20,
            "repetitive text must compress"
        );
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
        // Truncated stream.
        let mut w = InflateWriter::new(Vec::new(), true);
        w.write_all(&comp[..comp.len() / 2]).unwrap_or(());
        assert!(w.finish().is_err());
        // Non-zero padding.
        let mut bad = comp.clone();
        let last = bad.len() - 1;
        if bad.len() > 12 {
            bad[last] = 1;
            let mut w = InflateWriter::new(Vec::new(), true);
            assert!(w.write_all(&bad).is_err() || w.finish().is_err());
        }
        // Extra data after an unpadded stream.
        let mut plain = Vec::new();
        DeflateReader::new(&data[..], false)
            .read_to_end(&mut plain)
            .unwrap();
        plain.push(0);
        let mut w = InflateWriter::new(Vec::new(), false);
        assert!(w.write_all(&plain).is_err());
        // Random bytes.
        let mut w = InflateWriter::new(Vec::new(), false);
        let junk: Vec<u8> = (0..5000u32)
            .map(|i| (i.wrapping_mul(2_654_435_761) >> 24) as u8)
            .collect();
        assert!(w.write_all(&junk).is_err() || w.finish().is_err());
    }
}
