//! QR codes for the paper backup and for public keys, drawn as squares (no image files), and a
//! one-page PDF of the paper backup built in memory for printing.
//!
//! The encoder (`qrcodegen`) keeps its own working buffers, which are not wiped when freed; the
//! module grid kept here is.

use zeroize::Zeroizing;

/// A QR code: `size` × `size` modules, row by row (1 = dark).
pub struct Qr {
    /// Modules per side.
    pub size: usize,
    modules: Zeroizing<Vec<u8>>,
}

impl Qr {
    /// Encodes `data` (bytes mode, medium error correction; low if it does not fit).
    #[must_use]
    pub fn encode(data: &[u8]) -> Option<Self> {
        use qrcodegen::{QrCode, QrCodeEcc};
        let code = QrCode::encode_binary(data, QrCodeEcc::Medium)
            .or_else(|_| QrCode::encode_binary(data, QrCodeEcc::Low))
            .ok()?;
        let n = code.size();
        let size = usize::try_from(n).ok()?;
        let mut modules = Zeroizing::new(Vec::with_capacity(size * size));
        for y in 0..n {
            for x in 0..n {
                modules.push(u8::from(code.get_module(x, y)));
            }
        }
        Some(Self { size, modules })
    }

    /// Module at column `x`, row `y`.
    #[must_use]
    pub fn dark(&self, x: usize, y: usize) -> bool {
        self.modules.get(y * self.size + x).is_some_and(|m| *m == 1)
    }

    /// Horizontal runs of dark modules per row: `(row, first column, length)`, for drawing
    /// with few rectangles.
    #[must_use]
    pub fn runs(&self) -> Vec<(usize, usize, usize)> {
        let mut out = Vec::new();
        for y in 0..self.size {
            let mut x = 0;
            while x < self.size {
                if self.dark(x, y) {
                    let start = x;
                    while x < self.size && self.dark(x, y) {
                        x += 1;
                    }
                    out.push((y, start, x - start));
                } else {
                    x += 1;
                }
            }
        }
        out
    }
}

/// Lines of the paper-backup words, six per line.
fn word_lines(words: &[u8]) -> Vec<String> {
    let text = String::from_utf8_lossy(words);
    let all: Vec<&str> = text.split_whitespace().collect();
    all.chunks(6).map(|c| c.join(" ")).collect()
}

/// Text safe inside a PDF string literal (ASCII printable; others become `?`).
fn pdf_text(s: &str) -> String {
    s.chars()
        .map(|c| match c {
            '(' | ')' | '\\' => format!("\\{c}"),
            ' '..='~' => c.to_string(),
            _ => "?".into(),
        })
        .collect()
}

/// A one-page A4 PDF: title, the words, the QR code and a note. Built in memory (wiped when
/// dropped); nothing is written to disk here.
#[must_use]
pub fn paper_pdf(title: &str, words: &[u8], qr: &Qr, note: &str) -> Zeroizing<Vec<u8>> {
    use std::fmt::Write as _;
    let mut content = Zeroizing::new(String::new());
    let _ = writeln!(
        content,
        "BT /F1 18 Tf 56 780 Td ({}) Tj ET",
        pdf_text(title)
    );
    let mut y = 740;
    for line in word_lines(words) {
        let line = Zeroizing::new(line);
        let _ = writeln!(
            content,
            "BT /F2 13 Tf 56 {y} Td ({}) Tj ET",
            pdf_text(&line)
        );
        y -= 22;
    }
    // QR: 4-module quiet zone is the white page; 4 pt per module, below the words.
    #[allow(
        clippy::cast_precision_loss,
        clippy::cast_possible_truncation,
        reason = "small page coordinates"
    )]
    {
        let m = 4.0_f32;
        let top = (y - 30) as f32;
        let left = 56.0_f32;
        content.push_str("0 0 0 rg\n");
        for (row, col, len) in qr.runs() {
            let x = left + col as f32 * m;
            let yy = top - (row as f32 + 1.0) * m;
            let _ = writeln!(content, "{x:.1} {yy:.1} {:.1} {m:.1} re f", len as f32 * m);
        }
        y = (top - qr.size as f32 * m) as i32 - 30;
    }
    for (i, line) in note.split('\n').enumerate() {
        let _ = writeln!(
            content,
            "BT /F1 10 Tf 56 {} Td ({}) Tj ET",
            y - i32::try_from(i).unwrap_or(0) * 14,
            pdf_text(line)
        );
    }
    let objects = [
        "<< /Type /Catalog /Pages 2 0 R >>".to_owned(),
        "<< /Type /Pages /Kids [3 0 R] /Count 1 >>".to_owned(),
        "<< /Type /Page /Parent 2 0 R /MediaBox [0 0 595 842] /Resources << /Font << /F1 4 0 R /F2 5 0 R >> >> /Contents 6 0 R >>".to_owned(),
        "<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>".to_owned(),
        "<< /Type /Font /Subtype /Type1 /BaseFont /Courier >>".to_owned(),
    ];
    let mut out = Zeroizing::new(Vec::new());
    out.extend_from_slice(b"%PDF-1.4\n");
    let mut offsets = Vec::new();
    for (i, o) in objects.iter().enumerate() {
        offsets.push(out.len());
        out.extend_from_slice(format!("{} 0 obj\n{o}\nendobj\n", i + 1).as_bytes());
    }
    offsets.push(out.len());
    out.extend_from_slice(format!("6 0 obj\n<< /Length {} >>\nstream\n", content.len()).as_bytes());
    out.extend_from_slice(content.as_bytes());
    out.extend_from_slice(b"\nendstream\nendobj\n");
    let xref = out.len();
    out.extend_from_slice(
        format!("xref\n0 {}\n0000000000 65535 f \n", offsets.len() + 1).as_bytes(),
    );
    for o in &offsets {
        out.extend_from_slice(format!("{o:010} 00000 n \n").as_bytes());
    }
    out.extend_from_slice(
        format!(
            "trailer\n<< /Size {} /Root 1 0 R >>\nstartxref\n{xref}\n%%EOF\n",
            offsets.len() + 1
        )
        .as_bytes(),
    );
    out
}

/// Sends a PDF to the default printer through `lp`'s standard input (macOS). The print system
/// may keep a copy in its queue until the job is printed.
///
/// # Errors
/// No printing tool, or it failed.
pub fn print_pdf(pdf: &[u8]) -> std::io::Result<()> {
    #[cfg(target_os = "macos")]
    {
        use std::io::Write as _;
        use std::process::{Command, Stdio};
        let mut child = Command::new("/usr/bin/lp")
            .args(["-t", "lephycrypy+ paper backup", "-"])
            .stdin(Stdio::piped())
            .stdout(Stdio::null())
            .stderr(Stdio::piped())
            .spawn()?;
        if let Some(mut stdin) = child.stdin.take() {
            stdin.write_all(pdf)?;
        }
        let out = child.wait_with_output()?;
        if out.status.success() {
            Ok(())
        } else {
            Err(std::io::Error::other(
                String::from_utf8_lossy(&out.stderr).trim().to_owned(),
            ))
        }
    }
    #[cfg(not(target_os = "macos"))]
    {
        let _ = pdf;
        Err(std::io::Error::other("printing is available on macOS only"))
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn same_text_same_code() {
        let a = Qr::encode(b"lphy1qqqexample").unwrap();
        let b = Qr::encode(b"lphy1qqqexample").unwrap();
        assert_eq!(a.size, b.size);
        assert_eq!(*a.modules, *b.modules);
        assert!(a.size >= 21 && (a.size - 17).is_multiple_of(4), "a QR size");
        // Finder pattern corner is dark.
        assert!(a.dark(0, 0) && a.dark(6, 6) && !a.dark(7, 7));
        let runs: usize = a.runs().iter().map(|r| r.2).sum();
        let dark = (0..a.size * a.size)
            .filter(|i| a.dark(i % a.size, i / a.size))
            .count();
        assert_eq!(runs, dark);
    }

    #[test]
    fn long_keys_fit() {
        // A post-quantum public key is about 2 000 characters.
        let key = "lphypq1".to_owned() + &"q".repeat(1960);
        assert!(Qr::encode(key.as_bytes()).is_some());
        assert!(Qr::encode(&vec![b'a'; 4000]).is_none(), "too long");
    }

    #[test]
    fn pdf_shape() {
        let words = b"one two three four five six seven eight nine ten eleven twelve";
        let qr = Qr::encode(words).unwrap();
        let pdf = paper_pdf("Paper backup", words, &qr, "Keep apart (safe).");
        let s = String::from_utf8_lossy(&pdf);
        assert!(s.starts_with("%PDF-1.4"));
        assert!(s.contains("/Type /Page "));
        assert!(s.contains("(one two three four five six) Tj"));
        assert!(s.contains("(Keep apart \\(safe\\).) Tj"));
        assert!(s.trim_end().ends_with("%%EOF"));
        // The xref offset points at the xref table.
        let start: usize = s
            .rsplit("startxref\n")
            .next()
            .unwrap()
            .lines()
            .next()
            .unwrap()
            .parse()
            .unwrap();
        assert!(s[start..].starts_with("xref"));
    }
}
