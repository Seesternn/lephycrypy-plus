#!/usr/bin/env python3
"""lephycrypy+ Python reference implementation.

Written ONLY from docs/FORMAT.md, without looking at the Rust code. Purpose: produce test vectors
compared byte for byte with the Rust output (tests/kat/vectors/). Covers raw streams, archives,
PADMÉ, compression (stored DEFLATE blocks) and X25519 recipients.

Dependencies: cryptography, argon2-cffi, blake3. XChaCha20-Poly1305 is not in `cryptography`;
HChaCha20 is implemented here by hand and checked against the draft-irtf-cfrg-xchacha-03 §2.2.1 vector.

Usage:
    python3 -I lephy_ref.py selftest
    python3 -I lephy_ref.py vectors <output_dir>
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
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

MAGIC = b"LPHY+\0"
VERSION = 1
VERSION_2 = 2
FEATURE_COMPRESSED = 0x01
FEATURE_RECIPIENTS = 0x02
INFO_X25519 = b"lphy+/v2/x25519"
FEATURE_SIGNED = 0x04
INFO_ED25519 = b"lphy+/v2/ed25519"
INFO_SIG_KEY = b"lphy+/v2/sig-key"
SIG_CONTEXT = b"lphy+/v2/sig\0"
FEATURE_PQ = 0x08
INFO_MLKEM_D = b"lphy+/v2/ml-kem-768/d"
INFO_MLKEM_Z = b"lphy+/v2/ml-kem-768/z"
INFO_HYBRID = b"lphy+/v2/hybrid"
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
# Key derivation (FORMAT.md › Key derivation)
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
# Header and stream
# ---------------------------------------------------------------------------------------------
def nonce_len(alg):
    return 24 if alg == 1 else 12


def prefix_len(alg):
    return nonce_len(alg) - 5


def build_header(alg, content_type, padded, chunk_code, m_kib, t, p, pwd_nfc, keyfile,
                 salt, prefix, wrap_nonce, fk, compressed=False) -> tuple[bytes, dict]:
    assert len(salt) == 32 and len(fk) == 32
    prefix24 = prefix[: prefix_len(alg)].ljust(24, b"\0")
    wrap24 = wrap_nonce[: nonce_len(alg)].ljust(24, b"\0")
    kek = derive_kek(pwd_nfc, salt, m_kib, t, p, keyfile)
    keys = derive_keys(kek, salt, fk, prefix24)
    h = bytearray(256)
    h[0:6] = MAGIC
    h[6:8] = struct.pack("<H", VERSION_2 if compressed else VERSION)
    h[8] = alg
    h[9] = content_type
    h[10] = 1 if padded else 0
    h[11] = chunk_code
    h[12] = FEATURE_COMPRESSED if compressed else 0
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


def x25519_public(secret: bytes) -> bytes:
    return X25519PrivateKey.from_private_bytes(secret).public_key().public_bytes_raw()


def build_recipient_header(alg, content_type, padded, chunk_code, prefix, fk, stanzas_in,
                           compressed=False, signed=False) -> tuple[bytes, bytes, dict]:
    """FORMAT.md › Recipients. stanzas_in: [(recipient_pk, eph_secret, wrap_nonce)]."""
    prefix24 = prefix[: prefix_len(alg)].ljust(24, b"\0")
    h = bytearray(256)
    h[0:6] = MAGIC
    h[6:8] = struct.pack("<H", VERSION_2)
    h[8] = alg
    h[9] = content_type
    h[10] = 1 if padded else 0
    h[11] = chunk_code
    h[12] = FEATURE_RECIPIENTS | (FEATURE_COMPRESSED if compressed else 0) | (FEATURE_SIGNED if signed else 0)
    h[13] = 0  # no password slot
    h[28:30] = struct.pack("<H", len(stanzas_in))
    h[64:88] = prefix24
    ext = bytearray()
    for pk, e, wn in stanzas_in:
        eph = x25519_public(e)
        ss = X25519PrivateKey.from_private_bytes(e).exchange(X25519PublicKey.from_public_bytes(pk))
        assert ss != bytes(32)
        kek = hkdf32(ss, eph + pk, INFO_X25519)
        wrap_key = hkdf32(kek, eph, INFO_WRAP)
        commit = hkdf32(kek, eph, INFO_COMMIT)
        wn24 = wn[: nonce_len(alg)].ljust(24, b"\0")
        wrapped = seal(alg, wrap_key, wn24[: nonce_len(alg)], bytes(h[0:144]) + eph, fk)
        ext += eph + wn24 + commit + wrapped
    data_key = hkdf32(fk, prefix24, INFO_DATA)
    mac_key = hkdf32(fk, prefix24, INFO_HMAC)
    h[224:256] = blake3.blake3(bytes(h[0:224]) + bytes(ext), key=mac_key).digest()
    return bytes(h), bytes(ext), {"data_key": data_key}


def mlkem_private(identity_secret: bytes):
    """FORMAT.md › hybrid recipients: ML-KEM-768 key from the identity secret (seed d ‖ z)."""
    from cryptography.hazmat.primitives.asymmetric import mlkem
    seed = hkdf32(identity_secret, b"", INFO_MLKEM_D) + hkdf32(identity_secret, b"", INFO_MLKEM_Z)
    return mlkem.MLKEM768PrivateKey.from_seed_bytes(seed)


def build_hybrid_file(alg, prefix, fk, recipient_secret, e, ct_from, wrap_nonce, plaintext):
    """Rebuilds a one-recipient hybrid raw file. ML-KEM encapsulation is randomized in the
    library, so the ciphertext is taken from `ct_from` (the Rust vector) and checked by
    decapsulation; every other byte is derived here independently."""
    sk = mlkem_private(recipient_secret)
    ek = sk.public_key().public_bytes_raw()
    pk_x = x25519_public(recipient_secret)
    ct = ct_from[256 + 32:256 + 32 + 1088]
    ss_k = sk.decapsulate(ct)
    prefix24 = prefix[: prefix_len(alg)].ljust(24, b"\0")
    h = bytearray(256)
    h[0:6] = MAGIC
    h[6:8] = struct.pack("<H", VERSION_2)
    h[8] = alg
    h[9] = 0
    h[10] = 0
    h[11] = 0
    h[12] = FEATURE_RECIPIENTS | FEATURE_PQ
    h[13] = 0
    h[28:30] = struct.pack("<H", 1)
    h[64:88] = prefix24
    eph = x25519_public(e)
    ss_x = X25519PrivateKey.from_private_bytes(e).exchange(X25519PublicKey.from_public_bytes(pk_x))
    salt = eph + pk_x + blake3.blake3(ek).digest() + blake3.blake3(ct).digest()
    kek = hkdf32(ss_x + ss_k, salt, INFO_HYBRID)
    wrap_key = hkdf32(kek, eph, INFO_WRAP)
    commit = hkdf32(kek, eph, INFO_COMMIT)
    wn24 = wrap_nonce[: nonce_len(alg)].ljust(24, b"\0")
    wrapped = seal(alg, wrap_key, wn24[: nonce_len(alg)], bytes(h[0:144]) + eph, fk)
    ext = eph + ct + wn24 + commit + wrapped
    data_key = hkdf32(fk, prefix24, INFO_DATA)
    mac_key = hkdf32(fk, prefix24, INFO_HMAC)
    h[224:256] = blake3.blake3(bytes(h[0:224]) + ext, key=mac_key).digest()
    body = encrypt_stream(alg, data_key, prefix24, chunk_aad(bytes(h)), CHUNK_SIZES[0], plaintext)
    return bytes(h) + ext + body


def paper_words(secret: bytes) -> str:
    """FORMAT.md › Paper backup: secret ‖ BLAKE3("lphy+/paper/v1" ‖ secret)[0..2] as 22 base-7776 words."""
    path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "..", "crates", "lephy-core",
                        "data", "eff_large_wordlist.txt")
    with open(path, encoding="utf-8") as f:
        words = [line.split("\t")[1].strip() for line in f if "\t" in line]
    assert len(words) == 7776
    n = int.from_bytes(secret + blake3.blake3(b"lphy+/paper/v1" + secret).digest()[:2], "big")
    digits = []
    for _ in range(22):
        n, d = divmod(n, 7776)
        digits.append(d)
    assert n == 0
    return " ".join(words[d] for d in reversed(digits))


def signature_trailer(alg, fk, prefix24, header, body, identity_secret, nonce) -> bytes:
    """FORMAT.md › Format version 2 (signatures)."""
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    from cryptography.hazmat.primitives import serialization
    seed = hkdf32(identity_secret, b"", INFO_ED25519)
    sk = Ed25519PrivateKey.from_private_bytes(seed)
    vk = sk.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    aad = chunk_aad(header)
    sig = sk.sign(SIG_CONTEXT + aad + blake3.blake3(body).digest())
    sig_key = hkdf32(fk, prefix24, INFO_SIG_KEY)
    nl = nonce_len(alg)
    n24 = nonce[:nl].ljust(24, b"\0")
    return n24 + seal(alg, sig_key, n24[:nl], aad, vk + sig)


def chunk_aad(header: bytes) -> bytes:
    return blake3.blake3(header[0:13] + header[64:88]).digest()


def encrypt_stream(alg, data_key, prefix24, aad, chunk_size, plaintext: bytes) -> bytes:
    out = bytearray()
    pl = prefix_len(alg)
    n = len(plaintext)
    # Canonical last chunk: no extra empty chunk at an exact multiple; a single empty last chunk only for 0 bytes.
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
# PADMÉ and archive (FORMAT.md › PADMÉ, Archive)
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


def archive_end(folder: bool = False) -> bytes:
    # mode bit 0 (END_FOLDER): the source was a folder, never flattened to a single file.
    return bytes([255]) + struct.pack("<H", 0) + struct.pack("<I", 1 if folder else 0) + struct.pack("<q", 0)


def archive_padded(entries: bytes) -> bytes:
    body = entries + archive_end()
    return body + b"\0" * (padme(len(body)) - len(body))


def deflate_stored(data: bytes) -> bytes:
    """RFC 1951 raw DEFLATE, "stored" blocks only (≤ 65 535 B; BFINAL on the last block).
    Deterministic; for the FORMAT.md v2 test vectors. Readers accept any valid DEFLATE
    stream."""
    out = bytearray()
    blocks = [data[i:i + 65535] for i in range(0, len(data), 65535)] or [b""]
    for i, b in enumerate(blocks):
        final = 1 if i == len(blocks) - 1 else 0
        out += bytes([final])  # BFINAL + BTYPE=00, aligned to a byte boundary
        out += struct.pack("<HH", len(b), len(b) ^ 0xFFFF)
        out += b
    return bytes(out)


def compressed_stream(inner: bytes, padded: bool) -> bytes:
    """v2 compression: DEFLATE(inner) + (with padding) padme(L) − L zeros."""
    c = deflate_stored(inner)
    return c + (b"\0" * (padme(len(c)) - len(c)) if padded else b"")


def encrypt_stream_file(alg, content_type, padded, chunk_code, m_kib, t, p, pwd_nfc, keyfile,
                        salt, prefix, wrap_nonce, fk, plaintext: bytes, compressed=False) -> bytes:
    header, keys = build_header(alg, content_type, padded, chunk_code, m_kib, t, p, pwd_nfc, keyfile,
                                salt, prefix, wrap_nonce, fk, compressed)
    body = encrypt_stream(alg, keys["data_key"], header[64:88], chunk_aad(header),
                          CHUNK_SIZES[chunk_code], plaintext)
    return header + body


# ---------------------------------------------------------------------------------------------
# Test vectors (FORMAT.md › Test vectors)
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
    # RFC 7748 §6.1 X25519
    a = bytes.fromhex("77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a")
    assert x25519_public(a).hex() == "8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a"
    # RFC 9106 §5.3 (with secret/ad; only a library check)
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
    # 5: archive, a.txt="hi", mode 0644, mtime 0, padded
    pt5 = archive_padded(archive_entry(0, "a.txt", 0o644, 0, b"hi"))
    blob = encrypt_stream_file(1, 1, True, 0, COMMON["m_kib"], COMMON["t"], COMMON["p"], pwd, None,
                               SALT, PREFIX, WRAP, FK, pt5)
    with open(os.path.join(outdir, "v5.lphy"), "wb") as f:
        f.write(blob)
    meta["v5"] = {"alg": 1, "chunk_code": 0, "content_type": 1, "padded": True, "plain_len": len(pt5)}
    # 6: raw + pad, "hello"
    pt6 = raw_padded(b"hello")
    blob = encrypt_stream_file(1, 0, True, 0, COMMON["m_kib"], COMMON["t"], COMMON["p"], pwd, None,
                               SALT, PREFIX, WRAP, FK, pt6)
    with open(os.path.join(outdir, "v6.lphy"), "wb") as f:
        f.write(blob)
    meta["v6"] = {"alg": 1, "chunk_code": 0, "content_type": 0, "padded": True, "plain_len": len(pt6)}
    assert padme(100) == 104 and padme(1000) == 1024 and padme(1_000_000) == 1_015_808
    # 12: v2, raw + compression + padding
    raw12 = b"lephycrypy v2 " * 40
    blob = encrypt_stream_file(1, 0, True, 0, COMMON["m_kib"], COMMON["t"], COMMON["p"], pwd, None,
                               SALT, PREFIX, WRAP, FK, compressed_stream(raw12, True), compressed=True)
    with open(os.path.join(outdir, "v12.lphy"), "wb") as f:
        f.write(blob)
    meta["v12"] = {"alg": 1, "chunk_code": 0, "content_type": 0, "padded": True, "compressed": True,
                   "plaintext": raw12.decode()}
    # 13: v2, archive + compression (no padding), a.txt="hi"
    ar13 = archive_entry(0, "a.txt", 0o644, 0, b"hi") + archive_end()
    blob = encrypt_stream_file(2, 1, False, 0, COMMON["m_kib"], COMMON["t"], COMMON["p"], pwd, None,
                               SALT, PREFIX, WRAP, FK, compressed_stream(ar13, False), compressed=True)
    with open(os.path.join(outdir, "v13.lphy"), "wb") as f:
        f.write(blob)
    meta["v13"] = {"alg": 2, "chunk_code": 0, "content_type": 1, "padded": False, "compressed": True}
    # 14: v2, recipients (X25519), two stanzas, raw stream, no padding
    sk1 = bytes(range(0x80, 0xA0))
    sk2 = bytes(range(0xA0, 0xC0))
    e1 = bytes(range(0xC0, 0xE0))
    e2 = bytes(range(0xE0, 0x100))
    wrap2 = bytes(range(0x58, 0x70))
    pt14 = b"to a public key"
    h14, ext14, k14 = build_recipient_header(
        1, 0, False, 0, PREFIX, FK,
        [(x25519_public(sk1), e1, WRAP), (x25519_public(sk2), e2, wrap2)])
    body = encrypt_stream(1, k14["data_key"], h14[64:88], chunk_aad(h14), CHUNK_SIZES[0], pt14)
    with open(os.path.join(outdir, "v14.lphy"), "wb") as f:
        f.write(h14 + ext14 + body)
    meta["v14"] = {"alg": 1, "chunk_code": 0, "content_type": 0, "padded": False,
                   "recipients": [x25519_public(sk1).hex(), x25519_public(sk2).hex()],
                   "identities": [sk1.hex(), sk2.hex()], "plaintext": pt14.decode()}
    # 15: v14 with its recipient list replaced by the second recipient only (set_recipients):
    # same FK, prefix and chunks; a new stanza.
    e3 = bytes(range(0x10, 0x30))
    wrap3 = bytes(range(0x30, 0x48))
    h15, ext15, _ = build_recipient_header(
        1, 0, False, 0, PREFIX, FK, [(x25519_public(sk2), e3, wrap3)])
    assert chunk_aad(h15) == chunk_aad(h14)
    with open(os.path.join(outdir, "v15.lphy"), "wb") as f:
        f.write(h15 + ext15 + body)
    meta["paper_words"] = paper_words(sk1)
    # 17: post-quantum hybrid recipient (sk2), produced by Rust with fixed ML-KEM randomness and
    # rebuilt here byte for byte from the decapsulated ciphertext.
    here = os.path.dirname(os.path.abspath(__file__))
    with open(os.path.join(here, "..", "kat", "vectors", "v17.lphy"), "rb") as f:
        v17_rust = f.read()
    v17 = build_hybrid_file(1, PREFIX, FK, sk2, e1, v17_rust, WRAP, b"post-quantum hello")
    assert v17 == v17_rust, "vector 17: the reference does not reproduce the Rust file"
    with open(os.path.join(outdir, "v17.lphy"), "wb") as f:
        f.write(v17)
    meta["v17"] = {"identities": [sk2.hex()], "plaintext": "post-quantum hello",
                   "mlkem_ek_blake3": blake3.blake3(mlkem_private(sk2).public_key().public_bytes_raw()).hexdigest()}
    # 16: like 14 but for the second recipient only, signed by identity sk1
    pt16 = b"signed by sk1"
    h16, ext16, k16 = build_recipient_header(
        1, 0, False, 0, PREFIX, FK, [(x25519_public(sk2), e1, WRAP)], signed=True)
    body16 = encrypt_stream(1, k16["data_key"], h16[64:88], chunk_aad(h16), CHUNK_SIZES[0], pt16)
    sig_nonce = bytes(range(0x70, 0x88))
    tr16 = signature_trailer(1, FK, h16[64:88], h16, body16, sk1, sig_nonce)
    with open(os.path.join(outdir, "v16.lphy"), "wb") as f:
        f.write(h16 + ext16 + body16 + tr16)
    meta["v16"] = {"signer_identity": sk1.hex(), "identities": [sk2.hex()],
                   "plaintext": pt16.decode()}
    meta["v15"] = {"from": "v14", "recipients": [x25519_public(sk2).hex()],
                   "identities": [sk2.hex()], "plaintext": pt14.decode()}
    # 7/8/11: equal KEKs
    nfd = "ş ğ İ é".encode("utf-8")
    nfc = "ş ğ İ é".encode("utf-8")
    assert normalize_password(nfd, True) == normalize_password(nfc, True)
    assert normalize_password(b"test\r\n", False) == normalize_password(b"test\n", False) == b"test"
    kek7 = derive_kek(normalize_password(nfd, True), SALT, **COMMON, keyfile=None)
    meta["v7_kek"] = kek7.hex()
    # 10: HKDF outputs (password "test", no key file, XChaCha prefix)
    kek = derive_kek(pwd, SALT, **COMMON, keyfile=None)
    keys = derive_keys(kek, SALT, FK, PREFIX[:19].ljust(24, b"\0"))
    meta["v10"] = {k: v.hex() for k, v in keys.items()}
    meta["v10"]["argon2_out"] = kek.hex()
    # AES-prefix data/hmac keys (for v4)
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
