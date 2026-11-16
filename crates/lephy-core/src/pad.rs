//! PADMÉ dolgu (PLAN B3, R4-O5). Aşama 2.
//!
//! `content_type=0`: `[u64 LE L][veri][sıfır]`, toplam P(L+8); `content_type=1`: END sonrası sıfır
//! dolgu, toplam P(END'e kadar yazılan). Okuyucu sıfır olmayan dolgu → kod 4.
