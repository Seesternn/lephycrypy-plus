# lephycrypy+ dosya biçimi — v1 (normatif taslak)

Bu belge normatiftir. Python referans uygulaması (`tests/ref/`) yalnızca bu belgeden yazılır.
Tüm çok baytlı tamsayılar **little-endian**'dır; STREAM nonce sayacı istisnadır (BE32).
Kaynaklar: RFC 9106 (Argon2), RFC 5869 (HKDF), draft-irtf-cfrg-xchacha-03, NIST SP 800-38D.

## Başlık (256 bayt)

| ofs | boyut | alan | değişmez? |
|---|---|---|---|
| 0 | 6 | magic `"LPHY+\0"` | ✓ |
| 6 | 2 | version u16 = 1 | ✓ |
| 8 | 1 | alg_id: 1=XChaCha20-Poly1305, 2=AES-256-GCM | ✓ |
| 9 | 1 | content_type: 0=ham akış, 1=arşiv | ✓ |
| 10 | 1 | stream_flags: bit0 padded; bit1..7 rezerve (0) | ✓ |
| 11 | 1 | chunk_code: 0=64KiB 1=256KiB 2=1MiB(vars.) 3=4MiB 4=16MiB | ✓ |
| 12 | 1 | reserved (0) | ✓ |
| 13 | 1 | kdf_id: 1=Argon2id v0x13 | |
| 14 | 1 | kdf_flags: bit0 keyfile; bit1 v2 rezerve; bit2..7 rezerve (0) | |
| 15 | 1 | reserved (0) | |
| 16 | 4 | argon2 m_kib u32 | |
| 20 | 4 | argon2 t u32 | |
| 24 | 4 | argon2 p u32 | |
| 28 | 4 | reserved (0) | |
| 32 | 32 | salt | |
| 64 | 24 | stream_nonce_prefix (XChaCha 19 B; AES 7 B, [7..24] = 0) | ✓ |
| 88 | 24 | wrap_nonce (XChaCha 24 B; AES 12 B, [12..24] = 0) | |
| 112 | 32 | commit_tag | |
| 144 | 48 | wrapped_fk = AEAD_{wrap_key}(wrap_nonce, FK, AAD=header[0..144]) | |
| 192 | 32 | reserved (0, MAC'e dahil) | |
| 224 | 32 | header_mac = BLAKE3-keyed(header_mac_key, header[0..224]) | |
| **256** | | toplam | |

Ofset kontrolü: 0+6=6, +2=8, +1=9, +1=10, +1=11, +1=12, +1=13, +1=14, +1=15, +1=16, +4=20, +4=24, +4=28, +4=32, +32=64, +24=88, +24=112, +32=144, +48=192, +32=224, +32=**256** ✓

"Değişmez" alanlar `rekey` ile değişmez; chunk AAD yalnızca bunlardan türetilir.

**Reserved ve bayrak denetimi (normatif).** Okuyucu ofset 12, 15, 28..32, 192..224 baytlarının `0x00`, `stream_flags` bit1..7 ve `kdf_flags` bit1..7'nin 0 olduğunu doğrular; aksi → "Dosya bozuk (başlık)", kod 4. Bu denetim çözme sırasının 1. adımındadır (KDF'den önce). Yazıcı sıfır yazar.

**Nonce kuyruk kuralı.** alg_id=2 iken `stream_nonce_prefix[7..24]` ve `wrap_nonce[12..24]` sıfırdır; okuyucu doğrular (ihlal → kod 4).

**Sınırlar.** `m_kib`: 65536..=4194304 (64 MiB..4 GiB); `t`: 1..=64; `p`: 1..=64; `8·p ≤ m_kib`; ihlal → kod 4. `m_kib × t > 16 GiB·iter` ya da `m_kib > %75 × RAM` → kod 6 (biçim ihlali değil, politika).

## Anahtar türetme

```
argon2_out     = Argon2id(P=pwd_nfc, S=salt, p, T=32, m=m_kib, t, v=0x13, K=ε, X=ε, y=2)
KEK            = argon2_out                                                          (kdf_flags.bit0 = 0)
KEK            = HKDF-SHA512(ikm=argon2_out || BLAKE3(keyfile_bytes), salt=salt,
                             info="lphy+/v1/kek", L=32)                              (kdf_flags.bit0 = 1)
wrap_key       = HKDF-SHA512(ikm=KEK, salt=salt,                info="lphy+/v1/wrap",   L=32)
commit_tag     = HKDF-SHA512(ikm=KEK, salt=salt,                info="lphy+/v1/commit", L=32)
data_key       = HKDF-SHA512(ikm=FK,  salt=stream_nonce_prefix, info="lphy+/v1/data",   L=32)
header_mac_key = HKDF-SHA512(ikm=FK,  salt=stream_nonce_prefix, info="lphy+/v1/hmac",   L=32)
chunk_aad      = BLAKE3(header[0..13] || header[64..88])
```

- `salt = header[32..64]` (32 B); `stream_nonce_prefix = header[64..88]` (24 B'ın tamamı, AES'te kuyruk sıfır). `||` bitiştirme, `ε` boş.
- **Argon2id (RFC 9106 §3.1):** `v = 0x13`; `K` (secret) ve `X` (associated data) boş (uzunluk alanı 0 kodlanır); `y = 2`; `T = 32`.
- **HKDF (RFC 5869 §2.2–2.3):** SHA-512, HashLen 64; `L = 32`; salt her zaman açıkça verilir; `L=32` çıktısı T(1)'in ilk 32 baytıdır.
- **info dizgileri:** ASCII, NUL yok, uzunluk öneki yok:

| info | uzunluk | hex |
|---|---|---|
| `lphy+/v1/kek` | 12 | `6c7068792b2f76312f6b656b` |
| `lphy+/v1/wrap` | 13 | `6c7068792b2f76312f77726170` |
| `lphy+/v1/commit` | 15 | `6c7068792b2f76312f636f6d6d6974` |
| `lphy+/v1/data` | 13 | `6c7068792b2f76312f64617461` |
| `lphy+/v1/hmac` | 13 | `6c7068792b2f76312f686d6163` |

- `keyfile_bytes`: dosya **içeriği**, bayt bayt; yol/ad/meta veri türetmeye girmez. `BLAKE3` anahtarsız, 32 B. Keyfile 32 B..1 MiB; parola zorunlu (yalnızca-keyfile v1'de yok).
- `FK`: 32 B rastgele. `wrapped_fk` = 32 B şifreli + 16 B tag. Argon2 salt'ı FK alt anahtarlarında **kullanılmaz** (rekey salt'ı değiştirir, `data_key` sabit kalır).
- `commit_tag` sır değildir; `subtle::ConstantTimeEq` ile doğrulanır; taahhüt etmeyen AEAD unwrap'i yalnızca bu geçince çalışır.
- `header_mac = BLAKE3-keyed(header_mac_key, header[0..224])`.

## Parola

UTF-8 → NFC = `pwd_nfc`. Kaynak fd/stdin/dosya ise NFC'den önce sondaki tek `\n` veya `\r\n` kırpılır; terminalde kırpma yok. Ham parola ≤ 1024 B. Biçim, parola uzunluğu için kural koymaz; okuyucu her uzunluğu kabul eder. Minimum uzunluk (8 Unicode scalar value, NFC sonrası) yalnızca şifreleme politikasıdır (CLI politikası).

## Çözme sırası ve hatalar

1. parse: sabit alanlar, reserved ve bayrak sıfır, sınırlar, nonce kuyruğu → "Dosya bozuk (başlık)", kod 4
2. keyfile bayrak/argüman tutarlılığı → kod 3 ("Bu dosya anahtar dosyası gerektiriyor" / "…kullanmıyor"), KDF çalışmaz
3. KDF bütçesi/RAM → kod 6
4. KDF
5. `commit_tag` sabit zamanlı → "Parola veya anahtar dosyası yanlış", kod 3
6. unwrap → kod 4
7. türetme (`data_key`, `header_mac_key`)
8. `header_mac` → kod 4
9. chunk'lar → "Dosya bozuk (chunk N)", kod 4

## STREAM

Başlıktan sonra chunk'lar gelir. `chunk_size = 64 KiB × 4^chunk_code` (0..=4). Ciphertext chunk = `chunk_size + 16` (son hariç).
Nonce = `prefix || BE32(i) || last(u8)`: XChaCha 19 + 4 + 1 = 24 B; AES 7 + 4 + 1 = 12 B. `i` 0'dan başlar; `last` yalnızca son chunk'ta 1. AAD = `chunk_aad` (32 B).
- Son chunk 0..=chunk_size bayt düz metin içerir; içerik tam kat ise son chunk tam boydur ve ek boş chunk **yazılmaz**; yalnızca 0 baytlık içerikte tek boş son chunk (16 B ciphertext).
- Okuyucu `chunk_size + 17` bayt okumayı dener; `chunk_size + 16`'dan az veya eşit geldiyse son chunk'tır.
- Son chunk'tan sonra bayt → 4; `last=1` ortada → 4; son olmayan chunk kısa → 4; `i ≥ 2^32` → 4.
- Varsayılan `chunk_code = 2` (1 MiB).

## Arşiv (content_type = 1)

Düz metin akışının içinde, ardışık girişler:
`[u8 tür: 0 dosya, 1 dizin, 2 symlink, 255 END][u16 yol_len][yol NFC, '/' ayırıcı][u32 mode][i64 mtime]`
- Dosya verisi: `[u32 len][bytes]…[u32 0]` çerçeveleri; `len` 1..=16 MiB.
- Symlink: hedef tek çerçevede `[u32 len][hedef][u32 0]`, 1..=4096 B, NUL yok, `/` ayırıcı, NFC uygulanmaz; `mode`/`mtime` yazıcı 0 yazar, okuyucu yok sayar.
- Dizin: veri yok. END: yol_len 0, mode 0, mtime 0, veri yok.
- Sıra: yazıcı bir dizinin girişini çocuklarından önce yazar; okuyucu üst dizin girişi olmayan
  bir yolu reddeder (kod 4). Çocuklar ad baytlarına göre artan sırada yazılır (tekrarlanabilirlik).
- Kök adı arşive girmez: klasör şifrelenirken girişler klasörün içeriğine görelidir; tek dosya
  şifrelenirken tek giriş dosyanın adıdır.
- `mode`: POSIX; okuyucu setuid/setgid/sticky siler, `& 0o777`. `mtime`: Unix saniye, ∈ [−2^40, 2^40].

Sınırlar (ihlal → kod 4): çerçeve ≤ 16 MiB; bileşen ≤ 255 B; yol ≤ 4096 B; derinlik ≤ 256; giriş ≤ 1 000 000; toplam yol baytı (symlink hedefleri dahil) ≤ 64 MiB; yolda `..`, boş bileşen, `/` ile başlama, `\`, NUL, sürücü harfi (`[A-Za-z]:`) yasak; yinelenen (NFC + harf katlama) yasak.
Symlink hedefinin güvenli/güvensiz sınıflandırması çıkarma politikasıdır, biçim ihlali değildir; okuyucu symlink'leri tüm dosya ve dizinlerden sonra kurar.
END zorunlu; END sonrası: padded ise yalnızca sıfır bayt, değilse hiçbir bayt.

## PADMÉ

`P(L)`: PADMÉ hedefi (Nikitin ve diğ., 2019): `E = floor(log2 L)`, `S = floor(log2 E) + 1`, `z = E − S`, `m = 2^z − 1`, `P(L) = (L + m) & ~m`.
- content_type=0 (`stream_flags.bit0 = 1`): düz metin = `[u64 LE L][veri][sıfır dolgu]`, toplam `P(L+8)`; L baştan bilinmelidir.
- content_type=1: END sonrası sıfır dolgu, toplam = `P(END'e kadar yazılan bayt)`.
- Okuyucu sıfır olmayan dolgu baytı → kod 4.

## Test vektörleri (şablon)

Python referansı yalnızca bu belgeden yazılır; Rust tarafı `test-vectors` feature'ıyla üretir.
Ortak: parola `"test"`, m=64 MiB, t=1, p=1, salt=`00..1f`, stream_nonce_prefix=`20..37` (AES: `20..26`+sıfır), wrap_nonce=`40..57` (AES: `40..4b`+sıfır), FK=`60..7f`.

| # | alg | ct | pad | düz metin | çıktı |
|---|---|---|---|---|---|
| 1 | 1 | 0 | 0 | 0 B | _ |
| 2 | 1 | 0 | 0 | 64 KiB (chunk_code 0, tam kat) | _ |
| 3 | 1 | 0 | 0 | 64 KiB+1 | _ |
| 4 | 2 | 0 | 0 | "hello" | _ |
| 5 | 1 | 1 | 1 | `a.txt`="hi" | _ |
| 6 | 1 | 0 | 1 | "hello" (ham + pad) | _ |
| 7 | — | — | — | NFD "ş ğ İ é" ≡ NFC | KEK eşitliği |
| 8 | — | — | — | fd kaynağı `"test\r\n"` ≡ `"test"` | KEK eşitliği |
| 9 | 1 | 0 | 0 | "hello", keyfile = bayt 00..3f (64 B), kdf_flags=1 | _ |
| 10 | — | — | — | HKDF info baytları (hex tablosu) | wrap_key, commit_tag, data_key, header_mac_key |
| 11 | — | — | — | stdin kaynağı `"test\n"` ≡ `"test"` | KEK eşitliği |

Resmî KAT'lar: Argon2id RFC 9106 §5.3; HKDF RFC 5869 Ek A (SHA-256/SHA-1; SHA-512 Python çapraz kontrol); XChaCha20-Poly1305 draft-irtf-cfrg-xchacha-03 Ek A; AES-256-GCM NIST CAVP `gcmEncryptExtIV256.rsp`; BLAKE3 `test_vectors.json` (hash + keyed).

## Sürüm politikası

v1 okuma ≥ 5 yıl / 3 major. Yazıcı, dosyayı ifade edebilen **en düşük** sürümü yazar (v2 yalnızca bir v2 özelliği açıksa). Bilinmeyen `version` → kod 4. `kdf_flags.bit1` gelecekteki bir yalnızca-keyfile modu için rezerve.

## Format version 2 (compression)

A writer emits version 2 **only** when a v2 feature is used; otherwise it writes version 1, so
v1 files stay byte-for-byte identical. Readers accept both.

| Offset | v1 | v2 |
|---|---|---|
| 6..8 `version` | `1` | `2` |
| 12 | reserved, must be `0` | `feature_flags`; bit0 = compressed; other bits must be `0`; at least one bit set |

Everything else in the header is unchanged. Byte 12 and the version lie inside
`header[0..13]`, so they are bound to every chunk through `chunk_aad`, to the wrapped key through
the wrap AAD (`header[0..144]`) and to `header_mac`. Flipping the flag fails authentication.

**Compressed content (bit0).** The plaintext stream (archive or raw) is compressed with raw
DEFLATE (RFC 1951, no zlib/gzip wrapper) **before** encryption:

```
source (archive | raw bytes) → DEFLATE → [PADMÉ zeros] → STREAM AEAD
```

- With `padded = 1` the compressed stream of length `L` is followed by `padme(L) − L` zero bytes.
  No length prefix is used: DEFLATE marks its own end. The raw-stream `u64 L` prefix of v1 is not
  used for compressed files, and the archive is not padded separately.
- A reader inflates the decrypted stream and rejects: a stream that does not end, non-zero
  padding, padding of the wrong length, and any byte after the end when `padded = 0` (code 4).
- Any valid DEFLATE stream is accepted. Writers may use any compression level.
- Vectors 12 and 13 use only DEFLATE *stored* blocks (deterministic) and are checked in the
  decrypt direction.

**Side channel.** The compressed size reveals information about the content, especially when an
attacker controls part of the input (CRIME/BREACH-style). PADMÉ reduces but does not remove this.
Compression is therefore off by default.

| # | alg | chunk_code | content_type | Input | Note |
|---|---|---|---|---|---|
| 12 | 1 | 0 | 0 | `"lephycrypy v2 "` × 40, compressed, padded | decrypt direction |
| 13 | 2 | 0 | 1 | archive `a.txt = "hi"`, compressed, not padded | decrypt direction |

## Split output (informative)

Splitting is a container below the format and has no header flag. A file `name.lphy` is cut into
`name.lphy.001`, `name.lphy.002`, … (at most 999 parts, at least 1 MiB each); every part except
the last has the same size. Concatenating the parts in order gives the original file. Integrity
comes from STREAM: a missing, truncated or reordered part fails authentication or the end-of-stream
check.

## Error-correction envelope (informative)

Error correction is an outer layer around a complete `.lphy` file and has no header flag; the
inner file is byte-for-byte what would have been written without it. A reader recognises the
envelope by its magic.

```text
[header copy 64 B] × 3
[block]…
```

Header copy (little-endian): `magic "LPHYRS1\0"` ‖ `version u16 = 1` ‖ `k u16 = 239` ‖
`nsym u16 = 16` ‖ `d u16 = 128` ‖ `payload_len u64` ‖ 8 zero bytes ‖ `BLAKE3(first 32 B)`. The
first copy whose checksum matches is used.

Each block carries `d × k` payload bytes (the last block is zero-padded) as `d` Reed–Solomon
RS(255,239) codewords over GF(2^8) (primitive polynomial `0x11d`, generator roots `α^0…α^15`).
Payload byte `j` of a block is symbol `j / d` of codeword `j mod d`; on disk, byte `t` of a block
is symbol `t / d` of codeword `t mod d`. A codeword corrects up to 8 symbol errors, so a burst of
up to `8 × d` = 1024 bytes per block is repaired.

A codeword that cannot be corrected is an error, except in recovery mode, where its bytes are
passed through unchanged and STREAM authentication then marks the affected chunks as damaged.

