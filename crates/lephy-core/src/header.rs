//! 256 baytlık başlık (FORMAT.md › Başlık; R4-O2, R5-09). Aşama 1.
//!
//! `parse` sırası: sabit alanlar → reserved (ofs 12, 15, 28..32, 192..224) sıfır → bilinmeyen
//! bayrak bitleri (`stream_flags` bit1..7, `kdf_flags` bit1..7) → nonce kuyrukları (AES) →
//! sınırlar; ihlal → `Error::Corrupt { at: "başlık" }`, KDF'den önce. Değişmez-alan hash'i
//! `chunk_aad = BLAKE3(header[0..13] || header[64..88])`.
