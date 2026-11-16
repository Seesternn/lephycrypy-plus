//! Atomik yazma ve tmp yönetimi (PLAN F1–F5, R4-Y3, R5-04, R5-05). Aşama 1.
//!
//! `.lphy-tmp-<16 hex>` (macOS'ta `.noindex` sonekli; Windows'ta `NOT_CONTENT_INDEXED`), 0600/0700,
//! `sync_all` → noclobber rename (`lephy_sys::fs`). `TmpGuard` global kayıt (panik hook'u (2)
//! adımı için önceden kodlanmış yollar). `cleanup <dizin>`; disk alanı / FAT32 ön kontrolü.
