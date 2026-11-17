#!/usr/bin/env python3
"""lephycrypy+ v1 Python referans uygulaması (PLAN I1).

YALNIZCA docs/FORMAT.md okunarak yazılmıştır; Rust koduna bakılmamıştır. Amaç: Rust çıktısıyla
bayt bayt karşılaştırılacak test vektörleri üretmek (tests/kat/vectors/). Aşama 1 kapsamı:
content_type=0, dolgusuz. Arşiv ve PADMÉ aşama 2'de eklenecek.

Bağımlılıklar: cryptography, argon2-cffi, blake3. XChaCha20-Poly1305 `cryptography`'de yoktur;
HChaCha20 burada elle uygulanır ve draft-irtf-cfrg-xchacha-03 §2.2.1 vektörüyle doğrulanır.

Kullanım:
    python3 -I lephy_ref.py selftest
    python3 -I lephy_ref.py vectors <çıktı_dizini>
"""
from __future__ import annotations

import json
import os
import struct
import sys
import unicodedata

import blake3
from argon2.low_level import Type, hash_secret_raw
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM, ChaCha20Poly1305
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

MAGIC = b"LPHY+\0"
VERSION = 1
INFO_KEK = b"lphy+/v1/kek"
INFO_WRAP = b"lphy+/v1/wrap"
INFO_COMMIT = b"lphy+/v1/commit"
INFO_DATA = b"lphy+/v1/data"
INFO_HMAC = b"lphy+/v1/hmac"
CHUNK_SIZES = {0: 64 * 1024, 1: 256 * 1024, 2: 1024 * 1024, 3: 4 * 1024 * 1024, 4: 16 * 1024 * 1024}


# ---------------------------------------------------------------------------------------------
# HChaCha20 / XChaCha20-Poly1305 (draft-irtf-cfrg-xchacha-03)
# ---------------------------------------------------------------------------------------------
def _rotl(x, n):
    return ((x << n) | (x >> (32 - n))) & 0xFFFFFFFF


def _qr(s, a, b, c, d):
    s[a] = (s[a] + s[b]) & 0xFFFFFFFF
    s[d] = _rotl(s[d] ^ s[a], 16)
    s[c] = (s[c] + s[d]) & 0xFFFFFFFF
    s[b] = _rotl(s[b] ^ s[c], 12)
    s[a] = (s[a] + s[b]) & 0xFFFFFFFF
    s[d] = _rotl(s[d] ^ s[a], 8)
    s[c] = (s[c] + s[d]) & 0xFFFFFFFF
    s[b] = _rotl(s[b] ^ s[c], 7)


def hchacha20(key: bytes, nonce16: bytes) -> bytes:
    assert len(key) == 32 and len(nonce16) == 16
    s = [0x61707865, 0x3320646E, 0x79622D32, 0x6B206574]
    s += list(struct.unpack("<8I", key))
    s += list(struct.unpack("<4I", nonce16))
    for _ in range(10):
        _qr(s, 0, 4, 8, 12)
        _qr(s, 1, 5, 9, 13)
        _qr(s, 2, 6, 10, 14)
        _qr(s, 3, 7, 11, 15)
        _qr(s, 0, 5, 10, 15)
        _qr(s, 1, 6, 11, 12)
        _qr(s, 2, 7, 8, 13)
        _qr(s, 3, 4, 9, 14)
    return struct.pack("<4I", *s[0:4]) + struct.pack("<4I", *s[12:16])


def xchacha_seal(key: bytes, nonce24: bytes, aad: bytes, pt: bytes) -> bytes:
    """ciphertext || tag (16 B)"""
    assert len(nonce24) == 24
    sub = hchacha20(key, nonce24[:16])
    iv = b"\0\0\0\0" + nonce24[16:]
    return ChaCha20Poly1305(sub).encrypt(iv, pt, aad)


def aesgcm_seal(key: bytes, nonce12: bytes, aad: bytes, pt: bytes) -> bytes:
    assert len(nonce12) == 12
    return AESGCM(key).encrypt(nonce12, pt, aad)


def seal(alg: int, key: bytes, nonce: bytes, aad: bytes, pt: bytes) -> bytes:
    return xchacha_seal(key, nonce, aad, pt) if alg == 1 else aesgcm_seal(key, nonce, aad, pt)


# ---------------------------------------------------------------------------------------------
# Anahtar türetme (FORMAT.md › Anahtar türetme)
# ---------------------------------------------------------------------------------------------
def hkdf32(ikm: bytes, salt: bytes, info: bytes) -> bytes:
    return HKDF(algorithm=hashes.SHA512(), length=32, salt=salt, info=info).derive(ikm)


def argon2_out(pwd_nfc: bytes, salt: bytes, m_kib: int, t: int, p: int) -> bytes:
    return hash_secret_raw(
        secret=pwd_nfc,
        salt=salt,
        time_cost=t,
        memory_cost=m_kib,
        parallelism=p,
        hash_len=32,
        type=Type.ID,
        version=19,
    )


def normalize_password(raw: bytes, source_is_terminal: bool) -> bytes:
    if not source_is_terminal:
        if raw.endswith(b"\r\n"):
            raw = raw[:-2]
        elif raw.endswith(b"\n"):
            raw = raw[:-1]
    return unicodedata.normalize("NFC", raw.decode("utf-8")).encode("utf-8")


def derive_kek(pwd_nfc: bytes, salt: bytes, m_kib: int, t: int, p: int, keyfile: bytes | None) -> bytes:
    a = argon2_out(pwd_nfc, salt, m_kib, t, p)
    if keyfile is None:
        return a
    return hkdf32(a + blake3.blake3(keyfile).digest(), salt, INFO_KEK)


def derive_keys(kek: bytes, salt: bytes, fk: bytes, prefix24: bytes) -> dict:
    return {
        "wrap_key": hkdf32(kek, salt, INFO_WRAP),
        "commit_tag": hkdf32(kek, salt, INFO_COMMIT),
        "data_key": hkdf32(fk, prefix24, INFO_DATA),
        "header_mac_key": hkdf32(fk, prefix24, INFO_HMAC),
    }


# ---------------------------------------------------------------------------------------------
# Başlık ve akış
# ---------------------------------------------------------------------------------------------
def nonce_len(alg):
    return 24 if alg == 1 else 12


def prefix_len(alg):
    return nonce_len(alg) - 5


def build_header(alg, content_type, padded, chunk_code, m_kib, t, p, pwd_nfc, keyfile,
                 salt, prefix, wrap_nonce, fk) -> tuple[bytes, dict]:
    assert len(salt) == 32 and len(fk) == 32
    prefix24 = prefix[: prefix_len(alg)].ljust(24, b"\0")
    wrap24 = wrap_nonce[: nonce_len(alg)].ljust(24, b"\0")
    kek = derive_kek(pwd_nfc, salt, m_kib, t, p, keyfile)
    keys = derive_keys(kek, salt, fk, prefix24)
    h = bytearray(256)
    h[0:6] = MAGIC
    h[6:8] = struct.pack("<H", VERSION)
    h[8] = alg
    h[9] = content_type
    h[10] = 1 if padded else 0
    h[11] = chunk_code
    h[12] = 0
    h[13] = 1
    h[14] = 1 if keyfile is not None else 0
    h[15] = 0
    h[16:20] = struct.pack("<I", m_kib)
    h[20:24] = struct.pack("<I", t)
    h[24:28] = struct.pack("<I", p)
    h[28:32] = b"\0" * 4
    h[32:64] = salt
    h[64:88] = prefix24
    h[88:112] = wrap24
    h[112:144] = keys["commit_tag"]
    h[144:192] = seal(alg, keys["wrap_key"], wrap24[: nonce_len(alg)], bytes(h[0:144]), fk)
    h[192:224] = b"\0" * 32
    h[224:256] = blake3.blake3(bytes(h[0:224]), key=keys["header_mac_key"]).digest()
    return bytes(h), keys


def chunk_aad(header: bytes) -> bytes:
    return blake3.blake3(header[0:13] + header[64:88]).digest()


def encrypt_stream(alg, data_key, prefix24, aad, chunk_size, plaintext: bytes) -> bytes:
    out = bytearray()
    pl = prefix_len(alg)
    n = len(plaintext)
    # Kanonik son chunk: tam katta ek boş chunk yok; yalnızca 0 baytta tek boş son chunk.
    chunks = [plaintext[i:i + chunk_size] for i in range(0, n, chunk_size)] or [b""]
    for i, c in enumerate(chunks):
        last = i == len(chunks) - 1
        nonce = prefix24[:pl] + struct.pack(">I", i) + bytes([1 if last else 0])
        out += seal(alg, data_key, nonce, aad, c)
    return bytes(out)


def encrypt_file(alg, chunk_code, m_kib, t, p, pwd_nfc, keyfile, salt, prefix, wrap_nonce, fk,
                 plaintext: bytes) -> tuple[bytes, dict]:
    header, keys = build_header(alg, 0, False, chunk_code, m_kib, t, p, pwd_nfc, keyfile,
                                salt, prefix, wrap_nonce, fk)
    body = encrypt_stream(alg, keys["data_key"], header[64:88], chunk_aad(header),
                          CHUNK_SIZES[chunk_code], plaintext)
    return header + body, keys


# ---------------------------------------------------------------------------------------------
# PADMÉ ve arşiv (FORMAT.md › PADMÉ, Arşiv)
# ---------------------------------------------------------------------------------------------
def padme(L: int) -> int:
    if L < 2:
        return L
    E = L.bit_length() - 1
    S = E.bit_length()  # floor(log2 E) + 1
    z = max(E - S, 0)
    m = (1 << z) - 1
    return (L + m) & ~m


def raw_padded(data: bytes) -> bytes:
    body = struct.pack("<Q", len(data)) + data
    return body + b"\0" * (padme(len(body)) - len(body))


def archive_entry(kind: int, path: str, mode: int, mtime: int, data: bytes | None = None) -> bytes:
    p = unicodedata.normalize("NFC", path).encode("utf-8")
    out = bytes([kind]) + struct.pack("<H", len(p)) + p + struct.pack("<I", mode) + struct.pack("<q", mtime)
    if kind in (0, 2):
        if data:
            out += struct.pack("<I", len(data)) + data
        out += struct.pack("<I", 0)
    return out


def archive_end() -> bytes:
    return bytes([255]) + struct.pack("<H", 0) + struct.pack("<I", 0) + struct.pack("<q", 0)


def archive_padded(entries: bytes) -> bytes:
    body = entries + archive_end()
    return body + b"\0" * (padme(len(body)) - len(body))


def encrypt_stream_file(alg, content_type, padded, chunk_code, m_kib, t, p, pwd_nfc, keyfile,
                        salt, prefix, wrap_nonce, fk, plaintext: bytes) -> bytes:
    header, keys = build_header(alg, content_type, padded, chunk_code, m_kib, t, p, pwd_nfc, keyfile,
                                salt, prefix, wrap_nonce, fk)
    body = encrypt_stream(alg, keys["data_key"], header[64:88], chunk_aad(header),
                          CHUNK_SIZES[chunk_code], plaintext)
    return header + body


# ---------------------------------------------------------------------------------------------
# Test vektörleri (FORMAT.md › Test vektörleri)
# ---------------------------------------------------------------------------------------------
COMMON = dict(m_kib=64 * 1024, t=1, p=1)
SALT = bytes(range(0x00, 0x20))
PREFIX = bytes(range(0x20, 0x38))
WRAP = bytes(range(0x40, 0x58))
FK = bytes(range(0x60, 0x80))
KEYFILE9 = bytes(range(0x00, 0x40))


def selftest():
    # HChaCha20 §2.2.1
    key = bytes(range(32))
    nonce = bytes.fromhex("000000090000004a0000000031415927")
    assert hchacha20(key, nonce).hex() == "82413b4227b27bfed30e42508a877d73a0f9e4d58a74a853c12ec41326d3ecdc"
    # AEAD A.3.1
    k = bytes.fromhex("808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f")
    n = bytes.fromhex("404142434445464748494a4b4c4d4e4f5051525354555657")
    aad = bytes.fromhex("50515253c0c1c2c3c4c5c6c7")
    pt = (b"Ladies and Gentlemen of the class of '99: If I could offer you only one tip for the future, "
          b"sunscreen would be it.")
    ct = xchacha_seal(k, n, aad, pt)
    assert ct[-16:].hex() == "c0875924c1c7987947deafd8780acf49", ct[-16:].hex()
    assert ct[:32].hex() == "bd6d179d3e83d43b9576579493c0e939572a1700252bfaccbed2902c21396cbb"
    # RFC 9106 §5.3 (secret/ad'li; sadece kütüphane doğrulaması)
    from argon2.low_level import hash_secret_raw as hsr  # noqa
    print("selftest ok")


def vectors(outdir: str):
    os.makedirs(outdir, exist_ok=True)
    pwd = normalize_password(b"test", True)
    meta = {}
    cases = [
        (1, 1, 0, b"", None),
        (2, 1, 0, bytes([(i % 251) for i in range(64 * 1024)]), None),
        (3, 1, 0, bytes([(i % 251) for i in range(64 * 1024 + 1)]), None),
        (4, 2, 0, b"hello", None),
        (9, 1, 0, b"hello", KEYFILE9),
    ]
    for num, alg, chunk_code, pt, kf in cases:
        blob, keys = encrypt_file(alg, chunk_code, COMMON["m_kib"], COMMON["t"], COMMON["p"], pwd, kf,
                                  SALT, PREFIX, WRAP, FK, pt)
        with open(os.path.join(outdir, f"v{num}.lphy"), "wb") as f:
            f.write(blob)
        meta[f"v{num}"] = {"alg": alg, "chunk_code": chunk_code, "plain_len": len(pt),
                           "keyfile": kf.hex() if kf else None, "sha256_blake3": blake3.blake3(blob).hexdigest()}
    # 5: arşiv, a.txt="hi", mode 0644, mtime 0, padded
    pt5 = archive_padded(archive_entry(0, "a.txt", 0o644, 0, b"hi"))
    blob = encrypt_stream_file(1, 1, True, 0, COMMON["m_kib"], COMMON["t"], COMMON["p"], pwd, None,
                               SALT, PREFIX, WRAP, FK, pt5)
    with open(os.path.join(outdir, "v5.lphy"), "wb") as f:
        f.write(blob)
    meta["v5"] = {"alg": 1, "chunk_code": 0, "content_type": 1, "padded": True, "plain_len": len(pt5)}
    # 6: ham + pad, "hello"
    pt6 = raw_padded(b"hello")
    blob = encrypt_stream_file(1, 0, True, 0, COMMON["m_kib"], COMMON["t"], COMMON["p"], pwd, None,
                               SALT, PREFIX, WRAP, FK, pt6)
    with open(os.path.join(outdir, "v6.lphy"), "wb") as f:
        f.write(blob)
    meta["v6"] = {"alg": 1, "chunk_code": 0, "content_type": 0, "padded": True, "plain_len": len(pt6)}
    assert padme(100) == 104 and padme(1000) == 1024 and padme(1_000_000) == 1_015_808
    # 7/8/11: KEK eşitliği
    nfd = "ş ğ İ é".encode("utf-8")
    nfc = "ş ğ İ é".encode("utf-8")
    assert normalize_password(nfd, True) == normalize_password(nfc, True)
    assert normalize_password(b"test\r\n", False) == normalize_password(b"test\n", False) == b"test"
    kek7 = derive_kek(normalize_password(nfd, True), SALT, **COMMON, keyfile=None)
    meta["v7_kek"] = kek7.hex()
    # 10: HKDF çıktıları (parola "test", keyfile yok, XChaCha prefix)
    kek = derive_kek(pwd, SALT, **COMMON, keyfile=None)
    keys = derive_keys(kek, SALT, FK, PREFIX[:19].ljust(24, b"\0"))
    meta["v10"] = {k: v.hex() for k, v in keys.items()}
    meta["v10"]["argon2_out"] = kek.hex()
    # AES prefix ile data/hmac anahtarları (v4 için)
    keys_a = derive_keys(kek, SALT, FK, PREFIX[:7].ljust(24, b"\0"))
    meta["v10_aes"] = {k: v.hex() for k, v in keys_a.items()}
    with open(os.path.join(outdir, "vectors.json"), "w") as f:
        json.dump(meta, f, indent=1, sort_keys=True)
    print("vectors written to", outdir)


if __name__ == "__main__":
    if len(sys.argv) >= 2 and sys.argv[1] == "selftest":
        selftest()
    elif len(sys.argv) >= 3 and sys.argv[1] == "vectors":
        selftest()
        vectors(sys.argv[2])
    else:
        print(__doc__)
        sys.exit(2)
