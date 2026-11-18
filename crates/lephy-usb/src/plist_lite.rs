//! A small XML plist parser for `diskutil -plist` output.
//!
//! Used instead of the `plist` crate: only `dict`, `array`, `key`, `string`, `integer`, `true`
//! and `false` are needed; the `plist` tree brought in 15+ unaudited crates (to keep
//! `cargo vet` exemptions small). The input is `/usr/sbin/diskutil` output. Depth is limited
//! (64); unknown elements (`real`, `date`, `data`) are skipped as [`Value::Other`].
//! Entities: `&amp; &lt; &gt; &quot; &apos; &#N; &#xH;`.

/// Plist value.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Value {
    /// Dictionary (order preserved).
    Dict(Vec<(String, Value)>),
    /// Array.
    Array(Vec<Value>),
    /// String.
    String(String),
    /// Integer.
    Integer(i128),
    /// Boolean.
    Bool(bool),
    /// Unsupported type (`real`, `date`, `data`).
    Other,
}

impl Value {
    /// Key in a dictionary.
    #[must_use]
    pub fn get(&self, key: &str) -> Option<&Value> {
        match self {
            Value::Dict(items) => items.iter().find(|(k, _)| k == key).map(|(_, v)| v),
            _ => None,
        }
    }
    /// String.
    #[must_use]
    pub fn as_str(&self) -> Option<&str> {
        match self {
            Value::String(s) => Some(s),
            _ => None,
        }
    }
    /// Boolean.
    #[must_use]
    pub const fn as_bool(&self) -> Option<bool> {
        match self {
            Value::Bool(b) => Some(*b),
            _ => None,
        }
    }
    /// Unsigned integer.
    #[must_use]
    pub fn as_u64(&self) -> Option<u64> {
        match self {
            Value::Integer(i) => u64::try_from(*i).ok(),
            _ => None,
        }
    }
    /// Array.
    #[must_use]
    pub fn as_array(&self) -> Option<&[Value]> {
        match self {
            Value::Array(a) => Some(a),
            _ => None,
        }
    }
    /// Whether it is a dictionary.
    #[must_use]
    pub const fn is_dict(&self) -> bool {
        matches!(self, Value::Dict(_))
    }
}

const MAX_DEPTH: usize = 64;

struct P<'a> {
    s: &'a str,
    i: usize,
}

impl<'a> P<'a> {
    fn rest(&self) -> &'a str {
        &self.s[self.i..]
    }

    fn skip_misc(&mut self) {
        loop {
            let r = self.rest();
            let t = r.trim_start();
            self.i += r.len() - t.len();
            let r = self.rest();
            let end = if r.starts_with("<?") {
                r.find("?>").map(|p| p + 2)
            } else if r.starts_with("<!--") {
                r.find("-->").map(|p| p + 3)
            } else if r.starts_with("<!") {
                r.find('>').map(|p| p + 1)
            } else {
                return;
            };
            let Some(n) = end else {
                self.i = self.s.len();
                return;
            };
            self.i += n;
        }
    }

    /// Reads `<name ...>` or `<name .../>`: (name, self-closing).
    fn open_tag(&mut self) -> Option<(&'a str, bool)> {
        self.skip_misc();
        let r = self.rest();
        if !r.starts_with('<') || r.starts_with("</") {
            return None;
        }
        let end = r.find('>')?;
        let inner = &r[1..end];
        let self_closing = inner.ends_with('/');
        let inner = inner.trim_end_matches('/');
        let name = inner.split_whitespace().next()?;
        self.i += end + 1;
        Some((name, self_closing))
    }

    fn close_tag(&mut self, name: &str) -> Option<()> {
        self.skip_misc();
        let want = format!("</{name}>");
        if self.rest().starts_with(&want) {
            self.i += want.len();
            Some(())
        } else {
            None
        }
    }

    fn text_until(&mut self, name: &str) -> Option<String> {
        let want = format!("</{name}>");
        let r = self.rest();
        let end = r.find(&want)?;
        let raw = &r[..end];
        self.i += end + want.len();
        unescape(raw)
    }

    fn peek_close(&mut self, name: &str) -> bool {
        self.skip_misc();
        self.rest().starts_with(&format!("</{name}>"))
    }

    fn value(&mut self, depth: usize) -> Option<Value> {
        if depth > MAX_DEPTH {
            return None;
        }
        let (name, self_closing) = self.open_tag()?;
        Some(match (name, self_closing) {
            ("dict", true) => Value::Dict(Vec::new()),
            ("dict", false) => {
                let mut items = Vec::new();
                while !self.peek_close("dict") {
                    let (k, kc) = self.open_tag()?;
                    if k != "key" || kc {
                        return None;
                    }
                    let key = self.text_until("key")?;
                    let v = self.value(depth + 1)?;
                    items.push((key, v));
                }
                self.close_tag("dict")?;
                Value::Dict(items)
            }
            ("array", true) => Value::Array(Vec::new()),
            ("array", false) => {
                let mut items = Vec::new();
                while !self.peek_close("array") {
                    items.push(self.value(depth + 1)?);
                }
                self.close_tag("array")?;
                Value::Array(items)
            }
            ("string", true) => Value::String(String::new()),
            ("string", false) => Value::String(self.text_until("string")?),
            ("integer", false) => Value::Integer(self.text_until("integer")?.trim().parse().ok()?),
            ("true", true) => Value::Bool(true),
            ("false", true) => Value::Bool(false),
            ("real" | "date" | "data", false) => {
                let _ = self.text_until(name)?;
                Value::Other
            }
            ("real" | "date" | "data", true) => Value::Other,
            _ => return None,
        })
    }
}

fn unescape(raw: &str) -> Option<String> {
    if !raw.contains('&') {
        return Some(raw.to_string());
    }
    let mut out = String::with_capacity(raw.len());
    let mut rest = raw;
    while let Some(p) = rest.find('&') {
        out.push_str(&rest[..p]);
        let after = &rest[p + 1..];
        let semi = after.find(';')?;
        let ent = &after[..semi];
        let ch = match ent {
            "amp" => '&',
            "lt" => '<',
            "gt" => '>',
            "quot" => '"',
            "apos" => '\'',
            _ if ent.starts_with("#x") || ent.starts_with("#X") => {
                char::from_u32(u32::from_str_radix(&ent[2..], 16).ok()?)?
            }
            _ if ent.starts_with('#') => char::from_u32(ent[1..].parse().ok()?)?,
            _ => return None,
        };
        out.push(ch);
        rest = &after[semi + 1..];
    }
    out.push_str(rest);
    Some(out)
}

/// Parses an XML plist. Invalid/unexpected structure → `None`.
#[must_use]
pub fn parse(input: &[u8]) -> Option<Value> {
    let s = std::str::from_utf8(input).ok()?;
    let mut p = P { s, i: 0 };
    let (name, sc) = p.open_tag()?;
    if name == "plist" && !sc {
        let v = p.value(0)?;
        p.close_tag("plist")?;
        Some(v)
    } else {
        // A value without the plist wrapper.
        let mut p = P { s, i: 0 };
        p.value(0)
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    #[test]
    fn parses_subset_and_entities() {
        let x = br#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <!-- yorum -->
  <key>Ad</key><string>A &amp; B &lt;x&gt; &#351;&#x011F;</string>
  <key>Bos</key><string/>
  <key>Sayi</key><integer> 32017047552 </integer>
  <key>Evet</key><true/>
  <key>Hayir</key><false/>
  <key>Real</key><real>1.5</real>
  <key>Dizi</key><array><string>a</string><dict/><array/></array>
</dict>
</plist>"#;
        let v = parse(x).unwrap();
        assert!(v.is_dict());
        assert_eq!(v.get("Ad").unwrap().as_str(), Some("A & B <x> şğ"));
        assert_eq!(v.get("Bos").unwrap().as_str(), Some(""));
        assert_eq!(v.get("Sayi").unwrap().as_u64(), Some(32_017_047_552));
        assert_eq!(v.get("Evet").unwrap().as_bool(), Some(true));
        assert_eq!(v.get("Hayir").unwrap().as_bool(), Some(false));
        assert_eq!(v.get("Real"), Some(&Value::Other));
        assert_eq!(v.get("Dizi").unwrap().as_array().unwrap().len(), 3);
    }

    #[test]
    fn rejects_malformed_and_deep_input() {
        assert!(parse(b"<plist><dict><key>a</key></dict></plist>").is_none());
        assert!(parse(b"<plist><dict><string>x</string></dict></plist>").is_none());
        assert!(parse(b"<plist><integer>abc</integer></plist>").is_none());
        assert!(parse(b"<plist><string>&bogus;</string></plist>").is_none());
        assert!(parse(&[0xff, 0xfe]).is_none());
        let deep = "<array>".repeat(200) + &"</array>".repeat(200);
        assert!(parse(deep.as_bytes()).is_none());
        let ok = "<array>".repeat(10) + &"</array>".repeat(10);
        assert!(parse(ok.as_bytes()).is_some());
    }

    /// With real `diskutil` output (read only; machine data is not written to the repository).
    #[cfg(target_os = "macos")]
    #[test]
    fn parses_live_diskutil_output() {
        let out = std::process::Command::new("/usr/sbin/diskutil")
            .args(["info", "-plist", "/"])
            .output()
            .unwrap();
        assert!(out.status.success());
        let v = parse(&out.stdout).expect("real diskutil plist must parse");
        assert_eq!(v.get("MountPoint").and_then(Value::as_str), Some("/"));
        assert!(v.get("BusProtocol").and_then(Value::as_str).is_some());
        assert!(v.get("TotalSize").and_then(Value::as_u64).unwrap_or(0) > 0);
        assert!(v.get("Internal").and_then(Value::as_bool).is_some());
        let out = std::process::Command::new("/usr/sbin/diskutil")
            .args(["list", "-plist"])
            .output()
            .unwrap();
        let v = parse(&out.stdout).expect("diskutil list -plist must parse");
        assert!(
            v.get("AllDisksAndPartitions")
                .and_then(Value::as_array)
                .is_some()
        );
    }
}
