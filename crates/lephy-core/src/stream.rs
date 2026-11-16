//! STREAM çerçeveleme (FORMAT.md › STREAM; B1). Aşama 1.
//!
//! Nonce = prefix || BE32(i) || last; kanonik son chunk (tam katta ek boş chunk yok; yalnızca
//! 0 baytlık içerikte tek boş son chunk); okuyucu `chunk_size + 17` bayt okur; son chunk'tan sonra
//! veri / ortada `last=1` / `i ≥ 2^32` → kod 4. Varsayılan `chunk_code = 2` (1 MiB).
