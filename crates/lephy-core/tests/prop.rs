//! Özellik tabanlı testler: STREAM sınırları, bozulma/kesme tespiti, PADMÉ, arşiv
//! round-trip (boş dizin, Unicode/NFD ad), ayrıştırıcıların panik yokluğu.
//!
//! Vaka sayıları CI süresi için küçüktür; `PROPTEST_CASES` ile artırılabilir.

#![allow(
    clippy::unwrap_used,
    clippy::missing_panics_doc,
    clippy::cast_possible_truncation
)]

use std::collections::BTreeMap;
use std::io::{Read, Write};
use std::path::{Path, PathBuf};

use lephy_core::archive::{ArchivePadReader, ArchiveWriter, ExtractOptions, Extractor};
use lephy_core::cipher::{AlgId, SharedCipher, TAG_LEN};
use lephy_core::error::Error;
use lephy_core::header::{HEADER_LEN, Header};
use lephy_core::names;
use lephy_core::pad::padme;
use lephy_core::pipeline::{StreamParams, decrypt_stream, encrypt_stream, verify_stream};
use proptest::prelude::*;

/// Varsayılan vaka sayısı `cases`; `PROPTEST_CASES` ayarlıysa (proptest varsayılanı 256'dan
/// farklıysa) o kullanılır — ortam değişkeni proptest'in kendisi tarafından okunur.
fn cfg(cases: u32) -> ProptestConfig {
    let d = ProptestConfig::default();
    ProptestConfig {
        cases: if d.cases == 256 { cases } else { d.cases },
        failure_persistence: None,
        ..d
    }
}

fn alg_strategy() -> impl Strategy<Value = AlgId> {
    prop_oneof![Just(AlgId::XChaCha20Poly1305), Just(AlgId::Aes256Gcm)]
}

/// Chunk sınırı çevresinde uzunluk: k·chunk + {−1, 0, +1} ya da rastgele.
fn len_strategy(chunk: usize) -> impl Strategy<Value = usize> {
    prop_oneof![
        (0usize..6, 0usize..=2).prop_map(move |(k, d)| (k * chunk + d).saturating_sub(1)),
        0usize..(6 * chunk),
    ]
}

fn seal(alg: AlgId, chunk: usize, data: &[u8]) -> (SharedCipher, Vec<u8>) {
    let c = SharedCipher::new(alg, &[0x5a; 32]).unwrap();
    let mut ct = Vec::new();
    {
        let p = StreamParams {
            cipher: &c,
            prefix: &[7u8; 24],
            aad: &[3u8; 32],
            chunk_size: chunk,
        };
        let mut inp: &[u8] = data;
        encrypt_stream(&p, &mut inp, &mut ct).unwrap();
    }
    (c, ct)
}

fn params(c: &SharedCipher, chunk: usize) -> StreamParams<'_> {
    StreamParams {
        cipher: c,
        prefix: &[7u8; 24],
        aad: &[3u8; 32],
        chunk_size: chunk,
    }
}

proptest! {
    #![proptest_config(cfg(48))]

    /// B1: kanonik son chunk; boyut formülü; round-trip.
    #[test]
    fn stream_roundtrip_and_size(
        alg in alg_strategy(),
        (chunk, len) in prop_oneof![Just(16usize), Just(64), Just(1000)]
            .prop_flat_map(|c| (Just(c), len_strategy(c))),
        seed in any::<u8>(),
    ) {
        let data: Vec<u8> = (0..len).map(|i| (i as u8).wrapping_mul(31).wrapping_add(seed)).collect();
        let (c, ct) = seal(alg, chunk, &data);
        let chunks = if len == 0 { 1 } else { len.div_ceil(chunk) };
        prop_assert_eq!(ct.len(), len + chunks * TAG_LEN);
        let mut out = Vec::new();
        let mut inp: &[u8] = &ct;
        let n = decrypt_stream(&params(&c, chunk), &mut inp, &mut out).unwrap();
        prop_assert_eq!(n as usize, len);
        prop_assert_eq!(out, data);
    }

    /// Herhangi bir bit çevirmesi, kesme ya da ek bayt kod 4 verir.
    #[test]
    fn stream_tamper_is_detected(alg in alg_strategy(), len in 0usize..400, pos in any::<usize>(), bit in 0u8..8, cut in 1usize..40, extra in any::<u8>()) {
        let chunk = 64;
        let data = vec![0xA5u8; len];
        let (c, ct) = seal(alg, chunk, &data);
        let p = params(&c, chunk);

        let mut flipped = ct.clone();
        let i = pos % flipped.len();
        flipped[i] ^= 1 << bit;
        let mut inp: &[u8] = &flipped;
        let corrupt = matches!(verify_stream(&p, &mut inp), Err(Error::Corrupt { .. }));
        prop_assert!(corrupt);

        let keep = ct.len().saturating_sub(cut);
        let mut inp: &[u8] = &ct[..keep];
        let corrupt = matches!(verify_stream(&p, &mut inp), Err(Error::Corrupt { .. }));
        prop_assert!(corrupt);

        let mut longer = ct.clone();
        longer.push(extra);
        let mut inp: &[u8] = &longer;
        let corrupt = matches!(verify_stream(&p, &mut inp), Err(Error::Corrupt { .. }));
        prop_assert!(corrupt);
    }

    /// PADMÉ: P(L) ≥ L, idempotent, monoton, sızıntı sınırı.
    #[test]
    fn padme_properties(l in 0u64..(1u64 << 40), d in 0u64..1000) {
        let p = padme(l);
        prop_assert!(p >= l);
        prop_assert_eq!(padme(p), p);
        prop_assert!(padme(l + d) >= p);
        if l >= 2 {
            // Yük ≤ ~%12 (E − S bitlik yuvarlama): P(L) − L < L / 2^(S−1) ≤ L/4, pratikte çok daha az.
            prop_assert!(p - l <= l / 4 + 1);
        }
    }

    /// Ayrıştırıcılar keyfi girdide panik yapmaz.
    #[test]
    fn parsers_never_panic(h in proptest::collection::vec(any::<u8>(), HEADER_LEN), path in proptest::collection::vec(any::<u8>(), 0..300)) {
        let arr: [u8; HEADER_LEN] = h.try_into().unwrap();
        let _ = Header::parse(&arr);
        let _ = names::validate_archive_path(&path);
        let _ = names::classify_symlink_target(&path);
        let _ = names::validate_symlink_target(&path);
        if let Ok(s) = std::str::from_utf8(&path) {
            let _ = names::fold_key(s);
            let _ = names::escape_display(s);
            let _ = names::windows_sanitize(s);
        }
    }

    /// `..` bileşeni içeren her hedef güvensizdir; doğrulanmış arşiv yolu `..` içermez.
    #[test]
    fn path_and_symlink_invariants(comps in proptest::collection::vec(prop_oneof![Just("..".to_string()), Just(".".to_string()), "[a-zş]{1,4}"], 1..6)) {
        let joined = comps.join("/");
        if comps.iter().any(|c| c == "..") {
            prop_assert_eq!(names::classify_symlink_target(joined.as_bytes()), names::SymlinkClass::Unsafe);
        }
        if let Ok(p) = names::validate_archive_path(joined.as_bytes()) {
            prop_assert!(!p.split('/').any(|c| c == ".." || c == "." || c.is_empty()));
        }
    }
}

// ---------------------------------------------------------------------------------------------
// Arşiv round-trip
// ---------------------------------------------------------------------------------------------

#[derive(Debug, Clone)]
enum Node {
    File(Vec<u8>),
    Dir,
}

/// Benzersiz adlı rastgele ağaç: göreli yol → düğüm. Adlar NFC/katlama sonrası da benzersizdir
/// (sıra numarası soneki), böylece yinelenen-ad reddi testin konusu olmaz.
fn tree_strategy() -> impl Strategy<Value = BTreeMap<String, Node>> {
    let name = prop_oneof![
        "[a-z]{1,6}",
        Just("ş".to_string()),
        Just("s\u{0327}x".to_string()), // NFD; yazıcı NFC'ye çevirir
        Just("çok uzun ad".to_string()),
        Just("ı".to_string()),
    ];
    let entry = (
        proptest::collection::vec(name, 1..4),
        prop_oneof![
            3 => proptest::collection::vec(any::<u8>(), 0..3000).prop_map(Node::File),
            1 => Just(Node::Dir),
        ],
    );
    proptest::collection::vec(entry, 0..12).prop_map(|entries| {
        let mut out = BTreeMap::new();
        for (i, (comps, node)) in entries.into_iter().enumerate() {
            let comps: Vec<String> = comps
                .into_iter()
                .enumerate()
                .map(|(j, c)| format!("{c}{i}_{j}"))
                .collect();
            out.insert(comps.join("/"), node);
        }
        out
    })
}

fn tmp(tag: &str) -> PathBuf {
    use std::sync::atomic::{AtomicU64, Ordering};
    static N: AtomicU64 = AtomicU64::new(0);
    let d = std::env::temp_dir().join(format!(
        "lphy-prop-{tag}-{}-{}",
        std::process::id(),
        N.fetch_add(1, Ordering::Relaxed)
    ));
    let _ = std::fs::remove_dir_all(&d);
    std::fs::create_dir_all(&d).unwrap();
    d
}

fn materialize(root: &Path, tree: &BTreeMap<String, Node>) {
    for (rel, node) in tree {
        let p = root.join(rel);
        match node {
            Node::Dir => std::fs::create_dir_all(&p).unwrap(),
            Node::File(data) => {
                std::fs::create_dir_all(p.parent().unwrap()).unwrap();
                std::fs::write(&p, data).unwrap();
            }
        }
    }
}

/// NFC'ye çevrilmiş göreli yol → (dizin mi, içerik).
fn snapshot(root: &Path) -> BTreeMap<String, (bool, Vec<u8>)> {
    use unicode_normalization::UnicodeNormalization;
    let mut out = BTreeMap::new();
    let mut stack = vec![root.to_path_buf()];
    while let Some(d) = stack.pop() {
        for e in std::fs::read_dir(&d).unwrap() {
            let e = e.unwrap();
            let p = e.path();
            let rel: String = p
                .strip_prefix(root)
                .unwrap()
                .to_string_lossy()
                .replace('\\', "/")
                .nfc()
                .collect();
            if e.file_type().unwrap().is_dir() {
                out.insert(rel, (true, Vec::new()));
                stack.push(p);
            } else {
                out.insert(rel, (false, std::fs::read(&p).unwrap()));
            }
        }
    }
    out
}

fn roundtrip(
    tree: &BTreeMap<String, Node>,
    padded: bool,
) -> std::result::Result<(), TestCaseError> {
    let base = tmp("arc");
    let src = base.join("src");
    std::fs::create_dir(&src).unwrap();
    materialize(&src, tree);
    let mut bytes = Vec::new();
    let w = ArchiveWriter::new(&src, false).unwrap();
    if padded {
        let mut r = ArchivePadReader::new(w);
        r.read_to_end(&mut bytes).unwrap();
        prop_assert_eq!(bytes.len() as u64, padme(bytes.len() as u64));
    } else {
        let mut r = w;
        r.read_to_end(&mut bytes).unwrap();
        prop_assert!(r.report.skipped.is_empty());
        prop_assert!(r.report.warnings.is_empty(), "{:?}", r.report.warnings);
    }
    let dst = base.join("dst");
    std::fs::create_dir(&dst).unwrap();
    let mut ex = Extractor::new(
        &dst,
        ExtractOptions {
            padded,
            ..ExtractOptions::default()
        },
    )
    .unwrap();
    for part in bytes.chunks(997) {
        ex.write_all(part).unwrap();
    }
    ex.finish().unwrap();
    let a = snapshot(&src);
    let b = snapshot(&dst);
    let _ = std::fs::remove_dir_all(&base);
    prop_assert_eq!(a, b);
    Ok(())
}

proptest! {
    #![proptest_config(cfg(32))]

    #[test]
    fn archive_roundtrip(tree in tree_strategy(), padded in any::<bool>()) {
        roundtrip(&tree, padded)?;
    }

    /// Arşiv akışındaki keyfi bozulma ya panik yapmadan hata verir ya da (veri baytına denk
    /// gelirse) başarılı olur; hiçbir dosya çıkarma kökünün dışına yazılmaz.
    #[test]
    fn archive_mutation_never_escapes(tree in tree_strategy(), pos in any::<usize>(), val in any::<u8>()) {
        let base = tmp("mut");
        let src = base.join("src");
        std::fs::create_dir(&src).unwrap();
        materialize(&src, &tree);
        let mut bytes = Vec::new();
        ArchiveWriter::new(&src, false).unwrap().read_to_end(&mut bytes).unwrap();
        if !bytes.is_empty() {
            let i = pos % bytes.len();
            bytes[i] = val;
        }
        let dst = base.join("dst");
        std::fs::create_dir(&dst).unwrap();
        let mut ex = Extractor::new(&dst, ExtractOptions::default()).unwrap();
        let ok = ex.write_all(&bytes).is_ok();
        if ok {
            let _ = ex.finish();
        }
        let outside: Vec<_> = std::fs::read_dir(&base)
            .unwrap()
            .filter_map(Result::ok)
            .map(|e| e.file_name().to_string_lossy().into_owned())
            .filter(|n| n != "src" && n != "dst")
            .collect();
        let _ = std::fs::remove_dir_all(&base);
        prop_assert!(outside.is_empty(), "kök dışına yazıldı: {outside:?}");
    }
}
