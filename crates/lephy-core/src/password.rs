//! Parola okuma ve politika (PLAN D2, D3, R4-D2, R4-D6, R5-12, R5-13). Aşama 1.
//!
//! Terminal raw-mode (`lephy_sys::term`), `--password-stdin`/`--password-fd` (unix)/
//! `--password-file`; ham ≤ 1024 B, NFC tamponu 4× önceden ayrılmış `SecretBytes`; sondaki
//! `\n`/`\r\n` yalnızca fd/stdin/dosya kaynağında kırpılır; şifrelemede < 8 Unicode scalar → red;
//! zxcvbn yalnızca `strength` feature'ı; `--generate-passphrase` 6 kelime EFF.
