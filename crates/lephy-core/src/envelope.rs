//! Error-correction envelope: a Reed–Solomon layer wrapped **around** an encrypted `.lphy` file.
//!
//! The envelope is independent of encryption: the inner `.lphy` stays byte for byte the same and
//! is only protected against disk/USB damage. Integrity still comes from STREAM authentication;
//! the envelope only **repairs** small damage.
//!
//! Layout:
//! ```text
//! [header 64 B] × 3            (each copy with its own BLAKE3 checksum)
//! [block]…                     block = D codewords × N bytes, interleaved
//! ```
//! Header: `magic "LPHYRS1\0"` ‖ `version u16 = 1` ‖ `k u16` ‖ `nsym u16` ‖ `d u16` ‖
//! `payload_len u64` ‖ 8 zero bytes ‖ `BLAKE3(first 32 B)`. Each block carries `D × k` data bytes
//! (the last block is zero-padded); data byte `j` is symbol `j / D` of codeword `j mod D`; on
//! disk, byte `t` is symbol `t / D` of codeword `t mod D`. A burst of `B` consecutive bytes thus
//! affects only ~`B / D` symbols of each codeword.

use std::io::{self, Read, Seek, SeekFrom, Write};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use crate::error::FormatViolation;
use crate::rs;

/// Magic.
pub const MAGIC: [u8; 8] = *b"LPHYRS1\0";
/// Data bytes per codeword.
pub const K: usize = 239;
/// Parity bytes per codeword (corrects up to 8 byte errors).
pub const NSYM: usize = 16;
/// Codeword length.
pub const N: usize = K + NSYM;
/// Interleaving depth (codewords per block).
pub const D: usize = 128;
/// One header copy.
pub const HEADER_COPY: usize = 64;
/// Header area (three copies).
pub const HEADER_AREA: usize = 3 * HEADER_COPY;
const BLOCK_DATA: usize = D * K;
/// Number of blocks read together and decoded in parallel.
const BATCH: usize = 16;
const BLOCK_DISK: usize = D * N;

fn violation(d: &str) -> io::Error {
    FormatViolation::io_at("error correction", d)
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

/// `payload_len` from a valid header copy.
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

/// Payload length from the three copies: the first copy whose checksum matches, else a byte-wise majority.
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

/// Whether the bytes start with an envelope header area (the magic of at least one copy).
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

/// Wraps what is written into the envelope. The header is written last (`finish`), hence `Seek`.
pub struct EncodeWriter<W: Write + Seek> {
    inner: W,
    buf: Vec<u8>,
    out: Vec<u8>,
    total: u64,
}

impl<W: Write + Seek> EncodeWriter<W> {
    /// Reserves space for the header area.
    ///
    /// # Errors
    /// I/O.
    pub fn new(mut inner: W) -> io::Result<Self> {
        inner.write_all(&[0u8; HEADER_AREA])?;
        Ok(Self {
            inner,
            buf: Vec::with_capacity(BATCH * BLOCK_DATA),
            out: vec![0u8; BATCH * BLOCK_DISK],
            total: 0,
        })
    }

    /// Zero-pads the buffer to a block boundary and encodes the blocks in parallel.
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

    /// Writes the last block and the header.
    ///
    /// # Errors
    /// I/O.
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

/// Repair statistics (shared; readable after the reader is dropped).
#[derive(Debug, Default)]
pub struct Stats {
    /// Number of corrected bytes.
    pub corrected: AtomicU64,
    /// Number of codewords that could not be repaired.
    pub failed: AtomicU64,
}

/// Opens the envelope and yields the inner `.lphy` bytes, repairing while reading.
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
    /// Continues from the body when the header area (`area`) has already been read. `lenient`: pass
    /// an unrepairable codeword through unchanged instead of failing (recovery mode).
    ///
    /// # Errors
    /// Format violation (code 4) if none of the three header copies can be read.
    pub fn with_header(
        area: &[u8; HEADER_AREA],
        inner: R,
        lenient: bool,
        stats: Arc<Stats>,
    ) -> io::Result<Self> {
        let remaining = parse_area(area).ok_or_else(|| violation("envelope header unreadable"))?;
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
        // Batched read: at most BATCH blocks; blocks are decoded in parallel.
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
                return Err(violation("envelope body truncated"));
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
                        .unwrap_or_else(|_| Err(io::Error::other("decoder panicked")))
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
                        "damage exceeds the error-correction capacity (try recovery mode)",
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

/// On-disk size of an enveloped file (for `payload` bytes).
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
        // Two header copies damaged: the third is enough.
        disk[3] ^= 0xff;
        disk[HEADER_COPY + 20] ^= 0xff;
        // A 1 KiB burst in every block (D × nsym/2 = 1024 symbols).
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
        // Truncated body.
        let short = &disk[..disk.len() - 10];
        assert!(unwrap_env(short, false).0.is_err());
    }
}
