//! Çerçeveli arşiv konteyneri (PLAN › Arşiv; C1–C8, R4-Y3/Y4/Y5, R5-11). Aşama 2.
//!
//! Giriş: `[u8 tür 0/1/2/255][u16 len][yol NFC][u32 mode][i64 mtime]`; dosya/symlink verisi
//! `[u32 len][bytes]…[u32 0]`. Sınırlar FORMAT.md'de. Çıkarma cap-std kök handle'ı ile
//! `hedef.lphy-tmp-<rand>` dizininde; sıra: dizin+dosya → symlink (END sonrası) → mtime/izin.
//! Yürüyüş özyinelemesizdir.
