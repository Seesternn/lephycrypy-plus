# lephycrypy+ file format — v1 (normative draft)

This document is normative. The Python reference implementation (`tests/ref/`) is written from
this document only. All multi-byte integers are **little-endian**, except the STREAM nonce
counter (BE32). Sources: RFC 9106 (Argon2), RFC 5869 (HKDF), draft-irtf-cfrg-xchacha-03,
NIST SP 800-38D, RFC 7748 (X25519).

## Header (256 bytes)

| Offset | Size | Field | Immutable? |
|---|---|---|---|
| 0 | 6 | magic `"LPHY+\0"` | ✓ |
| 6 | 2 | version u16 = 1 | ✓ |
| 8 | 1 | alg_id: 1 = XChaCha20-Poly1305, 2 = AES-256-GCM | ✓ |
| 9 | 1 | content_type: 0 = raw stream, 1 = archive | ✓ |
| 10 | 1 | stream_flags: bit0 padded; bits 1..7 reserved (0) | ✓ |
| 11 | 1 | chunk_code: 0 = 64 KiB, 1 = 256 KiB, 2 = 1 MiB (default), 3 = 4 MiB, 4 = 16 MiB | ✓ |
| 12 | 1 | reserved (0) — `feature_flags` in v2 | ✓ |
| 13 | 1 | kdf_id: 1 = Argon2id v0x13 | |
| 14 | 1 | kdf_flags: bit0 key file; bit1 reserved for v2; bits 2..7 reserved (0) | |
| 15 | 1 | reserved (0) | |
| 16 | 4 | Argon2 m_kib u32 | |
| 20 | 4 | Argon2 t u32 | |
| 24 | 4 | Argon2 p u32 | |
| 28 | 4 | reserved (0) — recipient count in v2 recipient files | |
| 32 | 32 | salt | |
| 64 | 24 | stream_nonce_prefix (XChaCha 19 B; AES 7 B, [7..24] = 0) | ✓ |
| 88 | 24 | wrap_nonce (XChaCha 24 B; AES 12 B, [12..24] = 0) | |
| 112 | 32 | commit_tag | |
| 144 | 48 | wrapped_fk = AEAD_{wrap_key}(wrap_nonce, FK, AAD = header[0..144]) | |
| 192 | 32 | reserved (0, covered by the MAC) | |
| 224 | 32 | header_mac = BLAKE3-keyed(header_mac_key, header[0..224]) | |
| **256** | | total | |

Offset check: 0+6=6, +2=8, +1=9, +1=10, +1=11, +1=12, +1=13, +1=14, +1=15, +1=16, +4=20, +4=24,
+4=28, +4=32, +32=64, +24=88, +24=112, +32=144, +48=192, +32=224, +32=**256** ✓

"Immutable" fields do not change on `rekey`; the chunk AAD is derived from them only.

**Reserved fields and flags (normative).** In a v1 file the reader checks that bytes 12, 15,
28..32 and 192..224 are `0x00` and that `stream_flags` bits 1..7 and `kdf_flags` bits 1..7 are 0;
otherwise "file is damaged (header)", code 4. This check is step 1 of the decryption order
(before key derivation). Writers write zeros. Version 2 changes bytes 12 and 28..30 only as
described below.

**Nonce tail rule.** With alg_id = 2, `stream_nonce_prefix[7..24]` and `wrap_nonce[12..24]` are
zero; the reader checks this (violation → code 4).

**Limits.** `m_kib`: 65536..=4194304 (64 MiB..4 GiB); `t`: 1..=64; `p`: 1..=64; `8·p ≤ m_kib`;
violation → code 4. `m_kib × t > 16 GiB·iterations` or `m_kib > 75 % of RAM` → code 6 (a policy,
not a format violation). If the amount of RAM cannot be determined, a fixed upper limit applies
(fail closed).

## Key derivation

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

- `salt = header[32..64]` (32 B); `stream_nonce_prefix = header[64..88]` (all 24 bytes; the tail
  is zero for AES). `||` is concatenation, `ε` is empty.
- **Argon2id (RFC 9106 §3.1):** `v = 0x13`; `K` (secret) and `X` (associated data) are empty
  (their length fields encode 0); `y = 2`; `T = 32`.
- **HKDF (RFC 5869 §2.2–2.3):** SHA-512, HashLen 64; `L = 32`; the salt is always given
  explicitly; the `L = 32` output is the first 32 bytes of T(1).
- **info strings:** ASCII, no NUL, no length prefix:

| info | Length | Hex |
|---|---|---|
| `lphy+/v1/kek` | 12 | `6c7068792b2f76312f6b656b` |
| `lphy+/v1/wrap` | 13 | `6c7068792b2f76312f77726170` |
| `lphy+/v1/commit` | 15 | `6c7068792b2f76312f636f6d6d6974` |
| `lphy+/v1/data` | 13 | `6c7068792b2f76312f64617461` |
| `lphy+/v1/hmac` | 13 | `6c7068792b2f76312f686d6163` |

- `keyfile_bytes`: the file's **content**, byte for byte; its path, name and metadata are not
  part of the derivation. `BLAKE3` is unkeyed, 32 B. Key files are 32 B..1 MiB; a password is
  always required (no key-file-only mode in v1).
- `FK`: 32 random bytes. `wrapped_fk` = 32 B ciphertext + 16 B tag. The Argon2 salt is **not**
  used for the FK subkeys (`rekey` changes the salt while `data_key` stays the same).
- `commit_tag` is not secret; it is compared with `subtle::ConstantTimeEq`; the non-committing
  AEAD unwrap runs only after it matches.
- `header_mac = BLAKE3-keyed(header_mac_key, header[0..224])`.

## Password

UTF-8 → NFC = `pwd_nfc`. When the source is an fd, stdin or a file, one trailing `\n` or `\r\n` is
removed before NFC; nothing is removed for terminal input. Raw password ≤ 1024 B. The format
sets no rule for the password length; a reader accepts any length. The minimum length (8 Unicode
scalar values after NFC) is an encryption policy of the tools only.

## Decryption order and errors

1. Parse: fixed fields, reserved fields and flags zero, limits, nonce tails → "file is damaged
   (header)", code 4
2. Key-file flag vs. argument → code 3 ("this file needs a key file" / "…does not use one"); no
   key derivation runs
3. KDF budget / RAM → code 6
4. Key derivation
5. `commit_tag` in constant time → "wrong password or key file", code 3
6. Unwrap → code 4
7. Derivation (`data_key`, `header_mac_key`)
8. `header_mac` → code 4
9. Chunks → "file is damaged (chunk N)", code 4

## STREAM

Chunks follow the header. `chunk_size = 64 KiB × 4^chunk_code` (0..=4). A ciphertext chunk is
`chunk_size + 16` bytes (except the last). Nonce = `prefix || BE32(i) || last (u8)`: XChaCha
19 + 4 + 1 = 24 B; AES 7 + 4 + 1 = 12 B. `i` starts at 0; `last` is 1 only on the last chunk.
AAD = `chunk_aad` (32 B).
- The last chunk holds 0..=chunk_size plaintext bytes; if the content is an exact multiple, the
  last chunk is full size and **no** extra empty chunk is written; only 0-byte content has a
  single empty last chunk (16 B ciphertext).
- The reader tries to read `chunk_size + 17` bytes; if `chunk_size + 16` or fewer arrive, it is
  the last chunk.
- Bytes after the last chunk → 4; `last = 1` in the middle → 4; a short non-last chunk → 4;
  `i ≥ 2^32` → 4.
- Default `chunk_code = 2` (1 MiB).

## Archive (content_type = 1)

Consecutive entries inside the plaintext stream:
`[u8 kind: 0 file, 1 directory, 2 symlink, 255 END][u16 path_len][path NFC, '/' separator][u32 mode][i64 mtime]`
- File data: `[u32 len][bytes]…[u32 0]` frames; `len` 1..=16 MiB.
- Symlink: the target in a single frame `[u32 len][target][u32 0]`, 1..=4096 B, no NUL, `/`
  separator, no NFC; the writer writes 0 for `mode`/`mtime`, the reader ignores them.
- Directory: no data. END: path_len 0, mtime 0, no data; `mode` holds flags: bit 0 (`END_FOLDER`)
  = the source was a folder, every other bit 0 (otherwise code 4).
- Order: the writer writes a directory's entry before its children; the reader rejects a path
  without a parent directory entry (code 4). Children are written in ascending order of their
  name bytes (reproducibility).
- The root name is not stored: when a folder is encrypted, entries are relative to its content
  and END has `END_FOLDER` set; when a single file is encrypted, the only entry is the file's name.
- A reader writes an archive whose only entry is a top-level file straight to the destination as
  that file, unless `END_FOLDER` is set: then the destination is always a folder.
- `mode`: POSIX; the reader clears setuid/setgid/sticky, `& 0o777`. `mtime`: Unix seconds,
  ∈ [−2^40, 2^40].

Limits (violation → code 4): frame ≤ 16 MiB; component ≤ 255 B; path ≤ 4096 B; depth ≤ 256;
entries ≤ 1 000 000; total path bytes (including symlink targets) ≤ 64 MiB; `..`, empty
components, a leading `/`, `\`, NUL and drive letters (`[A-Za-z]:`) are forbidden in paths;
duplicates (NFC + case folding) are forbidden. Classifying a symlink target as safe or unsafe is
an extraction policy, not a format violation; the reader creates symlinks after all files and
directories. END is mandatory; after END: only zero bytes if padded, otherwise no bytes.

## PADMÉ

`P(L)`: the PADMÉ target (Nikitin et al., 2019): `E = floor(log2 L)`, `S = floor(log2 E) + 1`,
`z = E − S`, `m = 2^z − 1`, `P(L) = (L + m) & ~m`.
- content_type = 0 (`stream_flags.bit0 = 1`): plaintext = `[u64 LE L][data][zero padding]`,
  total `P(L+8)`; L must be known in advance.
- content_type = 1: zero padding after END, total = `P(bytes written up to and including END)`.
- A non-zero padding byte → code 4.

## Test vectors

The Python reference is written from this document only; the Rust side produces the same files
with the `test-vectors` feature. Common values: password `"test"`, m = 64 MiB, t = 1, p = 1,
salt = `00..1f`, stream_nonce_prefix = `20..37` (AES: `20..26` + zeros), wrap_nonce = `40..57`
(AES: `40..4b` + zeros), FK = `60..7f`.

| # | alg | ct | pad | Plaintext | Output |
|---|---|---|---|---|---|
| 1 | 1 | 0 | 0 | 0 B | file |
| 2 | 1 | 0 | 0 | 64 KiB (chunk_code 0, exact multiple) | file |
| 3 | 1 | 0 | 0 | 64 KiB + 1 | file |
| 4 | 2 | 0 | 0 | "hello" | file |
| 5 | 1 | 1 | 1 | `a.txt` = "hi" | file |
| 6 | 1 | 0 | 1 | "hello" (raw + padding) | file |
| 7 | — | — | — | NFD "ş ğ İ é" ≡ NFC | equal KEK |
| 8 | — | — | — | fd source `"test\r\n"` ≡ `"test"` | equal KEK |
| 9 | 1 | 0 | 0 | "hello", key file = bytes 00..3f (64 B), kdf_flags = 1 | file |
| 10 | — | — | — | HKDF info bytes (hex table) | wrap_key, commit_tag, data_key, header_mac_key |
| 11 | — | — | — | stdin source `"test\n"` ≡ `"test"` | equal KEK |

Official KATs: Argon2id RFC 9106 §5.3; HKDF RFC 5869 Appendix A (SHA-256/SHA-1; SHA-512 by
Python cross-check); XChaCha20-Poly1305 draft-irtf-cfrg-xchacha-03 Appendix A; AES-256-GCM NIST
CAVP `gcmEncryptExtIV256.rsp`; BLAKE3 `test_vectors.json` (hash + keyed); X25519 RFC 7748 §6.1.

## Version policy

Version 1 files remain readable for at least 5 years / 3 major releases. A writer writes the
**lowest** version that can express the file (version 2 only when a v2 feature is used). An
unknown `version` → code 4. `kdf_flags.bit1` is reserved for a future key-file-only mode.

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

## Format version 2 (recipients)

`feature_flags.bit1` marks a file whose file key `FK` is wrapped for one or more X25519 public
keys (RFC 7748) instead of a password. Such a file has **no password slot**:

| Offset | Value in a recipient file |
|---|---|
| 12 `feature_flags` | bit1 set (bit0 may also be set) |
| 13 `kdf_id` | `0` |
| 14 `kdf_flags`, 16..28 Argon2 parameters, 30..64, 88..192 | all `0` |
| 28..30 | recipient count `n`, u16, `1 ≤ n ≤ 64` |

A reader rejects (code 4) a recipient file with any of these fields non-zero, `n` out of range,
or `kdf_id ≠ 0`, and a password file (bit1 clear) with `kdf_id ≠ 1` or `header[28..32] ≠ 0`.

Right after the 256-byte header come `n` stanzas of 136 bytes each; the STREAM chunks start at
`256 + 136·n`.

```
stanza     = E (32) ‖ wrap_nonce (24; AES: bytes 12..24 zero) ‖ commit (32) ‖ wrapped_fk (48)

E          = X25519(e, 9)                          e: 32 random bytes per recipient
ss         = X25519(e, pk)                         all-zero → reject
kek        = HKDF-SHA512(ikm=ss,  salt=E ‖ pk, info="lphy+/v2/x25519", L=32)
wrap_key   = HKDF-SHA512(ikm=kek, salt=E,      info="lphy+/v1/wrap",   L=32)
commit     = HKDF-SHA512(ikm=kek, salt=E,      info="lphy+/v1/commit", L=32)
wrapped_fk = AEAD_alg(wrap_key, wrap_nonce, FK, AAD = header[0..144] ‖ E)
header_mac = BLAKE3-keyed(header_mac_key, header[0..224] ‖ stanzas)
```

`data_key`, `header_mac_key` and `chunk_aad` are derived exactly as in v1. To open the file, a
reader with secret key `sk` and public key `pk = X25519(sk, 9)` computes `ss = X25519(sk, E)` for
each stanza, derives `commit` and compares it in constant time; on the first match it unwraps
`FK` (failure after a matching commit: code 4) and then checks `header_mac`. No match: code 3.
Public keys are not stored in the file.

**Public key text.** `lphy1` followed by base32 (RFC 4648 alphabet, lowercase, no padding) of
`pk ‖ BLAKE3(pk)[0..4]` — 63 characters. The checksum catches typing mistakes.

**Identity file (`.lphykey`).** An ordinary password-protected v1 file (raw stream, no padding,
no compression) whose 40-byte content is `"LPHYID1\0" ‖ sk`.

**Replacing the recipients.** A current recipient may rewrite the header and stanzas for a new,
complete list (`lephycrypy recipients`): `FK` and `stream_nonce_prefix` are kept, so `data_key`,
`chunk_aad` (it does not cover bytes 28..30) and every chunk stay byte for byte the same; every
stanza is new (fresh `e` and `wrap_nonce`) because the wrap AAD covers the recipient count, and
`header_mac` is recomputed. Because public keys are not stored, recipients cannot be added to or
removed from the existing list individually.

| # | alg | chunk_code | content_type | Input | Note |
|---|---|---|---|---|---|
| 14 | 1 | 0 | 0 | `"to a public key"`, two recipients `sk1 = 80..9f`, `sk2 = a0..bf`; `e1 = c0..df`, `wrap_nonce1 = 40..57`; `e2 = e0..ff`, `wrap_nonce2 = 58..6f`; prefix and FK as above | byte-identical both ways |
| 15 | 1 | 0 | 0 | vector 14 with its recipients replaced by `sk2` only: `e = 10..2f`, `wrap_nonce = 30..47`; same chunks | byte-identical |

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

