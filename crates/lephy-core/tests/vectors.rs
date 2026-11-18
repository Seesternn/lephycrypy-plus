//! FORMAT.md test vectors: the Rust output must equal, byte for byte, the `tests/kat/vectors/*.lphy`
//! produced by the Python reference written only from FORMAT.md (`tests/ref/lephy_ref.py`).
//! `cargo test -p lephy-core --features test-vectors`.

#![allow(
    clippy::unwrap_used,
    clippy::missing_panics_doc,
    clippy::cast_possible_truncation
)]

use lephy_core::cipher::AlgId;
use lephy_core::header::{ContentType, NewHeaderParams};
use lephy_core::kdf::{self, KdfParams};
use lephy_core::ops::{self, DecryptOptions, EncryptOptions, Input, Reuse};
use lephy_core::password;
use lephy_core::testvec::FixedEntropy;
use lephy_sys::mem::SecretBytes;
use std::path::PathBuf;

const V1: &[u8] = include_bytes!("../../../tests/kat/vectors/v1.lphy");
const V2: &[u8] = include_bytes!("../../../tests/kat/vectors/v2.lphy");
const V3: &[u8] = include_bytes!("../../../tests/kat/vectors/v3.lphy");
const V4: &[u8] = include_bytes!("../../../tests/kat/vectors/v4.lphy");
const V5: &[u8] = include_bytes!("../../../tests/kat/vectors/v5.lphy");
const V6: &[u8] = include_bytes!("../../../tests/kat/vectors/v6.lphy");
const V9: &[u8] = include_bytes!("../../../tests/kat/vectors/v9.lphy");
/// v2 (compression) vectors: the Python reference produces "stored" DEFLATE blocks. DEFLATE output
/// is not deterministic across implementations, so these vectors are compared in the
/// **decrypt** direction only.
const V12: &[u8] = include_bytes!("../../../tests/kat/vectors/v12.lphy");
const V13: &[u8] = include_bytes!("../../../tests/kat/vectors/v13.lphy");
/// v2 recipient vector (X25519, two stanzas): byte-identical in both directions.
const V14: &[u8] = include_bytes!("../../../tests/kat/vectors/v14.lphy");
const META: &str = include_str!("../../../tests/kat/vectors/vectors.json");

fn common_kdf() -> KdfParams {
    KdfParams {
        m_kib: 64 * 1024,
        t: 1,
        p: 1,
    }
}

fn pwd(s: &str) -> SecretBytes {
    password::normalize_nfc(&SecretBytes::from_slice(s.as_bytes()).unwrap()).unwrap()
}

fn json_hex(key: &str) -> Vec<u8> {
    let v = META
        .split(&format!("\"{key}\": \""))
        .nth(1)
        .unwrap()
        .split('"')
        .next()
        .unwrap();
    hex::decode(v).unwrap()
}

fn opts(alg: AlgId, chunk_code: u8, raw: bool, pad: Option<bool>) -> EncryptOptions {
    EncryptOptions {
        alg,
        chunk_code,
        kdf: common_kdf(),
        force: false,
        strict_memory: false,
        raw,
        pad,
        strict: false,
        compress: false,
        ecc: false,
    }
}

fn tmp(num: u32) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("lphy-vec-{num}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

/// Raw-stream vector: encrypt (fixed entropy), compare with the Python output, decrypt.
fn run_raw(num: u32, alg: AlgId, plain: &[u8], keyfile: Option<&[u8]>, pad: bool, expected: &[u8]) {
    let dir = tmp(num);
    let src = dir.join("in");
    std::fs::write(&src, plain).unwrap();
    let out = dir.join("out.lphy");
    let kf = keyfile.map(kdf::keyfile_digest);
    let mut ent = FixedEntropy::format_defaults(alg);
    let p = pwd("test");
    let o = opts(alg, 0, true, Some(pad));
    ops::encrypt(
        &Input::Path(&src),
        &out,
        &p,
        kf.as_ref(),
        &o,
        &mut ent,
        &mut |_| {},
    )
    .unwrap();
    let got = std::fs::read(&out).unwrap();
    assert_eq!(got.len(), expected.len(), "v{num} length");
    assert_eq!(&got[..256], &expected[..256], "v{num} header");
    assert_eq!(got, expected, "v{num} body");
    let dec = dir.join("dec");
    let r = ops::decrypt(
        &out,
        &ops::Output::Path(&dec, false),
        &p,
        kf.as_ref(),
        DecryptOptions::default(),
        &mut |_| {},
    )
    .unwrap();
    assert_eq!(r.plain_len, plain.len() as u64);
    assert_eq!(std::fs::read(&dec).unwrap(), plain);
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn v1_empty() {
    run_raw(1, AlgId::XChaCha20Poly1305, b"", None, false, V1);
}

#[test]
fn v2_exact_multiple() {
    let plain: Vec<u8> = (0..64 * 1024usize).map(|i| (i % 251) as u8).collect();
    run_raw(2, AlgId::XChaCha20Poly1305, &plain, None, false, V2);
}

#[test]
fn v3_exact_multiple_plus_one() {
    let plain: Vec<u8> = (0..=64 * 1024usize).map(|i| (i % 251) as u8).collect();
    run_raw(3, AlgId::XChaCha20Poly1305, &plain, None, false, V3);
}

#[test]
fn v4_aes_hello() {
    run_raw(4, AlgId::Aes256Gcm, b"hello", None, false, V4);
}

#[test]
fn v5_archive_single_file_padded() {
    // a.txt="hi", mode 0644, mtime 0: the source file's mode/mtime are set (Unix).
    let dir = tmp(5);
    let src = dir.join("a.txt");
    std::fs::write(&src, b"hi").unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&src, std::fs::Permissions::from_mode(0o644)).unwrap();
    }
    std::fs::File::options()
        .write(true)
        .open(&src)
        .unwrap()
        .set_modified(std::time::UNIX_EPOCH)
        .unwrap();
    let out = dir.join("out.lphy");
    let mut ent = FixedEntropy::format_defaults(AlgId::XChaCha20Poly1305);
    let p = pwd("test");
    let o = opts(AlgId::XChaCha20Poly1305, 0, false, None);
    let rep = ops::encrypt(
        &Input::Path(&src),
        &out,
        &p,
        None,
        &o,
        &mut ent,
        &mut |_| {},
    )
    .unwrap();
    assert_eq!(rep.content_type, ContentType::Archive);
    let got = std::fs::read(&out).unwrap();
    if cfg!(unix) {
        assert_eq!(got, V5, "v5 (archive + PADMÉ) must match Python");
    } else {
        assert_eq!(got.len(), V5.len());
    }
    // The Python output is decrypted and flattened by Rust.
    let py = dir.join("py.lphy");
    std::fs::write(&py, V5).unwrap();
    let dec = dir.join("dec.txt");
    ops::decrypt(
        &py,
        &ops::Output::Path(&dec, false),
        &p,
        None,
        DecryptOptions::default(),
        &mut |_| {},
    )
    .unwrap();
    assert!(dec.is_file());
    assert_eq!(std::fs::read(&dec).unwrap(), b"hi");
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn v6_raw_padded_hello() {
    run_raw(6, AlgId::XChaCha20Poly1305, b"hello", None, true, V6);
}

#[test]
fn v9_keyfile() {
    let kf: Vec<u8> = (0u8..0x40).collect();
    run_raw(9, AlgId::XChaCha20Poly1305, b"hello", Some(&kf), false, V9);
}

#[test]
fn v10_hkdf_outputs_match_python() {
    let salt: [u8; 32] = (0u8..0x20).collect::<Vec<_>>().try_into().unwrap();
    let p = pwd("test");
    let a = kdf::argon2_out(p.expose(), &salt, &common_kdf()).unwrap();
    assert_eq!(a.expose(), &json_hex("argon2_out")[..]);
    let kek = kdf::derive_kek(a, None, &salt).unwrap();
    let (wrap, commit) = kdf::derive_wrap_and_commit(&kek, &salt).unwrap();
    assert_eq!(wrap.expose(), &json_hex("wrap_key")[..]);
    assert_eq!(&commit[..], &json_hex("commit_tag")[..]);
    let fk = SecretBytes::from_slice(&(0x60u8..0x80).collect::<Vec<_>>()).unwrap();
    let mut prefix = [0u8; 24];
    prefix[..19].copy_from_slice(&(0x20u8..0x33).collect::<Vec<_>>());
    let (data, mac) = kdf::derive_fk_subkeys(&fk, &prefix).unwrap();
    assert_eq!(data.expose(), &json_hex("data_key")[..]);
    assert_eq!(mac.expose(), &json_hex("header_mac_key")[..]);
}

#[test]
fn v7_nfd_password_kek_matches_python() {
    let salt: [u8; 32] = (0u8..0x20).collect::<Vec<_>>().try_into().unwrap();
    let nfd = pwd("s\u{0327} g\u{0306} I\u{0307} e\u{0301}");
    let nfc = pwd("ş ğ İ é");
    assert_eq!(nfd.expose(), nfc.expose());
    let a = kdf::argon2_out(nfd.expose(), &salt, &common_kdf()).unwrap();
    assert_eq!(a.expose(), &json_hex("v7_kek")[..]);
}

#[test]
fn marker_present_in_test_vectors_build() {
    assert_eq!(lephy_core::testvec::MARKER, "LPHY-TEST-VECTORS-BUILD");
    const { assert!(lephy_core::TEST_VECTORS_ENABLED) };
    // Entropy-order contract: salt, prefix, wrap_nonce, FK (build_header).
    let mut e = FixedEntropy::format_defaults(AlgId::Aes256Gcm);
    let p = pwd("test");
    let params = NewHeaderParams {
        alg: AlgId::Aes256Gcm,
        content_type: ContentType::Raw,
        padded: false,
        chunk_code: 0,
        kdf: common_kdf(),
        keyfile: false,
        compressed: false,
    };
    let u = ops::build_header(
        &params,
        &p,
        None,
        Reuse::default(),
        &mut e,
        false,
        &mut |_| {},
    )
    .unwrap();
    assert_eq!(&u.bytes[32..64], &(0u8..0x20).collect::<Vec<_>>()[..]);
    assert_eq!(&u.bytes[64..71], &(0x20u8..0x27).collect::<Vec<_>>()[..]);
    assert_eq!(&u.bytes[71..88], &[0u8; 17]);
    assert_eq!(&u.bytes[88..100], &(0x40u8..0x4c).collect::<Vec<_>>()[..]);
    assert_eq!(u.fk.expose(), &(0x60u8..0x80).collect::<Vec<_>>()[..]);
}

#[test]
fn v2_compressed_vectors_from_reference_decrypt() {
    let d = std::env::temp_dir().join(format!("lphy-v2vec-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&d);
    std::fs::create_dir_all(&d).unwrap();
    std::fs::write(d.join("v12.lphy"), V12).unwrap();
    std::fs::write(d.join("v13.lphy"), V13).unwrap();
    let p = pwd("test");
    let h12 = ops::info(&d.join("v12.lphy")).unwrap();
    assert!(h12.compressed && h12.padded && h12.content_type == ContentType::Raw);
    ops::decrypt(
        &d.join("v12.lphy"),
        &ops::Output::Path(&d.join("v12.out"), false),
        &p,
        None,
        DecryptOptions::default(),
        &mut |_| {},
    )
    .unwrap();
    assert_eq!(
        std::fs::read(d.join("v12.out")).unwrap(),
        b"lephycrypy v2 ".repeat(40)
    );
    let h13 = ops::info(&d.join("v13.lphy")).unwrap();
    assert!(h13.compressed && h13.content_type == ContentType::Archive);
    ops::decrypt(
        &d.join("v13.lphy"),
        &ops::Output::Path(&d.join("v13.out"), false),
        &p,
        None,
        DecryptOptions::default(),
        &mut |_| {},
    )
    .unwrap();
    assert_eq!(std::fs::read(d.join("v13.out")).unwrap(), b"hi");
    let _ = std::fs::remove_dir_all(&d);
}

#[test]
fn v14_recipients_match_reference_both_ways() {
    use lephy_core::ops::{Identity, PublicKey, UnlockOptions};
    let d = std::env::temp_dir().join(format!("lphy-v14-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&d);
    std::fs::create_dir_all(&d).unwrap();
    let range = |a: u16, b: u16| -> Vec<u8> { (a..b).map(|x| x as u8).collect() };
    let (sk1, sk2) = (range(0x80, 0xA0), range(0xA0, 0xC0));
    let ids: Vec<Identity> = [&sk1, &sk2]
        .iter()
        .map(|s| Identity::from_secret(SecretBytes::from_slice(s).unwrap()).unwrap())
        .collect();
    let pks: Vec<PublicKey> = ids.iter().map(Identity::public).collect();
    // Rust → same bytes as the reference (entropy order: prefix, FK, then e and wrap_nonce
    // per recipient).
    let src = d.join("pt");
    std::fs::write(&src, b"to a public key").unwrap();
    let mut e = FixedEntropy::new(vec![
        range(0x20, 0x20 + 19),
        range(0x60, 0x80),
        range(0xC0, 0xE0),
        range(0x40, 0x58),
        range(0xE0, 0x100),
        range(0x58, 0x70),
    ]);
    let out = d.join("v14.lphy");
    ops::encrypt_to_recipients(
        &Input::Path(&src),
        &out,
        &pks,
        &opts(AlgId::XChaCha20Poly1305, 0, true, Some(false)),
        &mut e,
        &mut |_| {},
    )
    .unwrap();
    assert_eq!(std::fs::read(&out).unwrap(), V14);
    // Reference → Rust: each identity opens it.
    std::fs::write(d.join("ref.lphy"), V14).unwrap();
    for (i, id) in ids.iter().enumerate() {
        let target = d.join(format!("out{i}"));
        ops::decrypt(
            &d.join("ref.lphy"),
            &ops::Output::Path(&target, false),
            &pwd(""),
            None,
            DecryptOptions {
                unlock: UnlockOptions {
                    identity: Some(id),
                    ..UnlockOptions::default()
                },
                ..DecryptOptions::default()
            },
            &mut |_| {},
        )
        .unwrap();
        assert_eq!(std::fs::read(&target).unwrap(), b"to a public key");
    }
    let _ = std::fs::remove_dir_all(&d);
}
