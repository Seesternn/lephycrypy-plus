//! Official known-answer tests. Data files are in `tests/kat/` (repository root).
//!
//! - Argon2id: RFC 9106 §5.3 (m=32 KiB; outside the format limits, so the argon2 crate directly)
//! - HKDF: RFC 5869 Appendix A (SHA-256; SHA-512 by Python cross-check, `vectors.rs`)
//! - XChaCha20-Poly1305: draft-irtf-cfrg-xchacha-03 Appendix A.3.1 (through lephy-core `SharedCipher`)
//! - AES-256-GCM: a subset of NIST CAVP `gcmEncryptExtIV256.rsp` (through `SharedCipher`)
//! - BLAKE3: the official `test_vectors.json` (hash + keyed; the keyed path through `kdf::header_mac`)

#![allow(
    clippy::unwrap_used,
    clippy::missing_panics_doc,
    clippy::cast_possible_truncation
)]

use lephy_core::cipher::{AlgId, SharedCipher};
use lephy_sys::mem::SecretBytes;
use std::collections::HashMap;

const ARGON2: &str = include_str!("../../../tests/kat/argon2id_rfc9106.txt");
const HKDF: &str = include_str!("../../../tests/kat/hkdf_rfc5869.txt");
const XCHACHA: &str = include_str!("../../../tests/kat/xchacha20poly1305_draft03.txt");
const AESGCM: &str = include_str!("../../../tests/kat/aes256gcm_cavp_subset.txt");
const BLAKE3_JSON: &str = include_str!("../../../tests/kat/blake3_test_vectors.json");

/// Simple format with `[section]` headers and `Key = hex` lines.
fn sections(text: &str) -> Vec<(String, HashMap<String, String>)> {
    let mut out: Vec<(String, HashMap<String, String>)> = Vec::new();
    let mut cur: Option<(String, HashMap<String, String>)> = None;
    for line in text.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        if line.starts_with('[') {
            if let Some(c) = cur.take() {
                out.push(c);
            }
            cur = Some((line.trim_matches(['[', ']']).to_string(), HashMap::new()));
            continue;
        }
        if let Some((k, v)) = line.split_once('=') {
            let (k, v) = (k.trim().to_string(), v.trim().to_string());
            if k == "Count" {
                if let Some(c) = cur.take() {
                    out.push(c);
                    cur = Some((format!("{}#{v}", out.last().unwrap().0), HashMap::new()));
                }
                continue;
            }
            cur.get_or_insert_with(|| (String::from("default"), HashMap::new()))
                .1
                .insert(k, v);
        }
    }
    if let Some(c) = cur.take() {
        out.push(c);
    }
    out
}

fn h(s: &str) -> Vec<u8> {
    hex::decode(s).unwrap()
}

#[test]
fn argon2id_rfc9106_section_5_3() {
    use argon2::{Algorithm, Argon2, AssociatedData, Block, ParamsBuilder, Version};
    let m = &sections(ARGON2)[0].1;
    let pwd = h(&m["Password"]);
    let salt = h(&m["Salt"]);
    let secret = h(&m["Secret"]);
    let ad = h(&m["AD"]);
    let tag = h(&m["Tag"]);
    let mut b = ParamsBuilder::new();
    b.m_cost(32).t_cost(3).p_cost(4).output_len(32);
    b.data(AssociatedData::new(&ad).unwrap());
    let params = b.build().unwrap();
    let a = Argon2::new_with_secret(&secret, Algorithm::Argon2id, Version::V0x13, params).unwrap();
    let mut mem = vec![Block::new(); 32];
    let mut out = [0u8; 32];
    a.hash_password_into_with_memory(&pwd, &salt, &mut out, mem.as_mut_slice())
        .unwrap();
    assert_eq!(out.to_vec(), tag, "RFC 9106 Argon2id tag");
}

#[test]
fn hkdf_rfc5869_appendix_a_sha256() {
    use hkdf::Hkdf;
    use sha2::Sha256;
    for (name, m) in sections(HKDF) {
        let ikm = h(&m["IKM"]);
        let salt = h(&m["salt"]);
        let info = h(&m["info"]);
        let l: usize = m["L"].parse().unwrap();
        let (prk, hk) = Hkdf::<Sha256>::extract(Some(&salt), &ikm);
        assert_eq!(prk.to_vec(), h(&m["PRK"]), "{name} PRK");
        let mut okm = vec![0u8; l];
        hk.expand(&info, &mut okm).unwrap();
        assert_eq!(okm, h(&m["OKM"]), "{name} OKM");
    }
}

#[test]
fn xchacha20poly1305_draft03_aead() {
    let secs = sections(XCHACHA);
    let m = &secs.iter().find(|(n, _)| n == "AEAD").unwrap().1;
    let key: [u8; 32] = h(&m["Key"]).try_into().unwrap();
    let nonce = h(&m["Nonce"]);
    let aad = h(&m["AAD"]);
    let mut buf = h(&m["Plaintext"]);
    let c = SharedCipher::new(AlgId::XChaCha20Poly1305, &key).unwrap();
    let tag = c.seal_in_place(&nonce, &aad, &mut buf).unwrap();
    assert_eq!(buf, h(&m["Ciphertext"]));
    assert_eq!(tag.to_vec(), h(&m["Tag"]));
    let t: [u8; 16] = h(&m["Tag"]).try_into().unwrap();
    c.open_in_place(&nonce, &aad, &mut buf, &t)
        .unwrap()
        .unwrap();
    assert_eq!(buf, h(&m["Plaintext"]));
}

#[test]
fn aes256gcm_nist_cavp_subset() {
    let secs = sections(AESGCM);
    let mut n = 0;
    for (name, m) in &secs {
        if !m.contains_key("Key") {
            continue;
        }
        let key: [u8; 32] = h(&m["Key"]).try_into().unwrap();
        let iv = h(&m["IV"]);
        let aad = h(&m["AAD"]);
        let mut buf = h(&m["PT"]);
        let c = SharedCipher::new(AlgId::Aes256Gcm, &key).unwrap();
        let tag = c.seal_in_place(&iv, &aad, &mut buf).unwrap();
        assert_eq!(buf, h(&m["CT"]), "{name} CT");
        assert_eq!(tag.to_vec(), h(&m["Tag"]), "{name} Tag");
        n += 1;
    }
    assert!(n >= 40, "expected at least 40 CAVP vectors, {n}");
}

#[test]
fn blake3_official_vectors_hash_and_keyed() {
    // Official JSON: {"key": "...", "context_string": "...", "cases": [{"input_len", "hash", "keyed_hash", "derive_key"}]}
    // Input: byte i = i % 251. `hash`/`keyed_hash` are 131-byte extended outputs; the first 32 bytes are compared.
    let key_str = BLAKE3_JSON
        .split("\"key\": \"")
        .nth(1)
        .unwrap()
        .split('"')
        .next()
        .unwrap();
    let key: [u8; 32] = key_str.as_bytes().try_into().unwrap();
    let mut count = 0;
    for case in BLAKE3_JSON.split("\"input_len\": ").skip(1) {
        let len: usize = case.split(',').next().unwrap().trim().parse().unwrap();
        let hash_hex = case
            .split("\"hash\": \"")
            .nth(1)
            .unwrap()
            .split('"')
            .next()
            .unwrap();
        let keyed_hex = case
            .split("\"keyed_hash\": \"")
            .nth(1)
            .unwrap()
            .split('"')
            .next()
            .unwrap();
        let input: Vec<u8> = (0..len).map(|i| (i % 251) as u8).collect();
        let hash = blake3::Hasher::new().update(&input).finalize();
        assert_eq!(
            hex::encode(hash.as_bytes()),
            &hash_hex[..64],
            "hash len={len}"
        );
        let k = SecretBytes::from_slice(&key).unwrap();
        let keyed = lephy_core::kdf::header_mac(&k, &input).unwrap();
        assert_eq!(hex::encode(keyed), &keyed_hex[..64], "keyed len={len}");
        count += 1;
    }
    assert!(count >= 30, "{count}");
}
