//! Fuzz regresyonları: `tests/regress/<hedef>/*` altındaki her girdi, fuzz hedefiyle
//! aynı mantıkla (`fuzz/fuzz_targets/logic.rs`) yeniden oynatılır. Panik = test hatası.
//! Ayrıca `fuzz/seeds/` girdileri de oynatılır (fuzz kurulu olmasa da mantık sınanır).

#[allow(
    dead_code,
    unreachable_pub,
    missing_docs,
    clippy::all,
    clippy::pedantic,
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic
)]
#[path = "../../../fuzz/fuzz_targets/logic.rs"]
mod logic;

use std::path::Path;

fn replay(dir: &Path, f: fn(&[u8])) -> usize {
    let Ok(rd) = std::fs::read_dir(dir) else {
        return 0;
    };
    let mut n = 0;
    let mut files: Vec<_> = rd.filter_map(Result::ok).map(|e| e.path()).collect();
    files.sort();
    for p in files {
        if p.is_file() {
            let data = std::fs::read(&p).unwrap_or_default();
            eprintln!("oynatılıyor: {}", p.display());
            f(&data);
            n += 1;
        }
    }
    n
}

fn root() -> &'static Path {
    Path::new(concat!(env!("CARGO_MANIFEST_DIR"), "/../.."))
}

#[test]
fn regress_and_seeds_replay_without_panic() {
    type Target = (&'static str, fn(&[u8]));
    let targets: [Target; 4] = [
        ("header", logic::header),
        ("archive_entry", logic::archive_entry),
        ("names", logic::names),
        ("decrypt_known_key", logic::decrypt_known_key),
    ];
    let mut total = 0;
    for (name, f) in targets {
        total += replay(&root().join("tests/regress").join(name), f);
        total += replay(&root().join("fuzz/seeds").join(name), f);
    }
    assert!(total >= 15, "beklenenden az girdi oynatıldı: {total}");
}
