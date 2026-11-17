//! Sinyal testleri — yalnızca Unix. Windows `CTRL_BREAK_EVENT` testi Windows
//! CI'da ayrı adımdır (henüz yazılmadı).
//!
//! 1. Parola isteminde SIGINT (pty): yankı geri açılır, çıkış kodu 130.
//! 2. Akış ortasında SIGINT/SIGTERM (bitmeyen stdin): çıkış 130, tmp kalmaz, gecikme küçük.
//! 3. KDF sırasında çift SIGINT: ikinci sinyalde hemen `_exit(130)`.
//!
//! pty için `python3` (stdlib `pty`/`termios`) kullanılır: lephy-cli `unsafe` içeremez ve libc'ye
//! doğrudan bağımlı olamaz (deny.toml).

#![cfg(unix)]
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::missing_panics_doc
)]

use std::io::Read;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

const BIN: &str = env!("CARGO_BIN_EXE_lephycrypy");

fn tmpdir(tag: &str) -> PathBuf {
    let d = std::env::temp_dir().join(format!("lphy-sig-{tag}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&d);
    std::fs::create_dir_all(&d).unwrap();
    std::fs::write(d.join("pw.txt"), "sinyal parola 123\n").unwrap();
    d
}

fn kill(pid: u32, sig: &str) {
    let st = Command::new("kill")
        .args([sig, &pid.to_string()])
        .status()
        .unwrap();
    assert!(st.success(), "kill {sig} {pid}");
}

fn wait_timeout(child: &mut Child, limit: Duration) -> Option<std::process::ExitStatus> {
    let start = Instant::now();
    loop {
        if let Some(st) = child.try_wait().unwrap() {
            return Some(st);
        }
        if start.elapsed() > limit {
            let _ = child.kill();
            return None;
        }
        std::thread::sleep(Duration::from_millis(10));
    }
}

fn stale_tmp(dir: &Path) -> Vec<String> {
    std::fs::read_dir(dir)
        .unwrap()
        .filter_map(Result::ok)
        .map(|e| e.file_name().to_string_lossy().into_owned())
        .filter(|n| n.starts_with(".lphy-tmp-"))
        .collect()
}

fn have_python() -> bool {
    Command::new("python3")
        .arg("-c")
        .arg("import pty, termios")
        .status()
        .is_ok_and(|s| s.success())
}

/// Parola istemindeyken SIGINT: istem sırasında yankı kapalı, sinyalden sonra açık; kod 130.
#[test]
fn sigint_at_password_prompt_restores_echo_and_exits_130() {
    assert!(have_python(), "python3 (pty, termios) gerekli");
    // Her adım zaman aşımlıdır: test hiçbir koşulda takılmaz (select + WNOHANG + üst süre).
    let script = r#"
import os, pty, sys, termios, signal, time, select
binp = sys.argv[1]
pid, fd = pty.fork()
if pid == 0:
    os.execv(binp, [binp, "decrypt", "yok.lphy", "-o", "x"])
def pump(timeout):
    out = b""
    r, _, _ = select.select([fd], [], [], timeout)
    if r:
        try:
            out = os.read(fd, 1024)
        except OSError:
            pass
    return out
buf = b""
deadline = time.time() + 15
while b"Parola" not in buf and time.time() < deadline:
    buf += pump(0.1)
time.sleep(0.2)
echo_during = bool(termios.tcgetattr(fd)[3] & termios.ECHO)
os.kill(pid, signal.SIGINT)
status = None
deadline = time.time() + 10
while time.time() < deadline:
    p, st = os.waitpid(pid, os.WNOHANG)
    if p:
        status = st
        break
    buf += pump(0.05)
if status is None:
    os.kill(pid, signal.SIGKILL)
    os.waitpid(pid, 0)
    print("code=timeout")
    sys.exit(0)
try:
    echo_after = bool(termios.tcgetattr(fd)[3] & termios.ECHO)
except termios.error:
    echo_after = "unknown"
code = os.WEXITSTATUS(status) if os.WIFEXITED(status) else -os.WTERMSIG(status)
print(f"prompt={b'Parola' in buf} echo_during={echo_during} echo_after={echo_after} code={code}")
"#;
    let mut child = Command::new("python3")
        .args(["-c", script, BIN])
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let st = wait_timeout(&mut child, Duration::from_mins(1))
        .expect("pty yardımcısı 60 sn içinde bitmedi");
    let mut s = String::new();
    child.stdout.take().unwrap().read_to_string(&mut s).unwrap();
    let mut e = String::new();
    child.stderr.take().unwrap().read_to_string(&mut e).unwrap();
    eprintln!("{s}{e}");
    assert!(st.success(), "pty yardımcısı başarısız: {e}");
    assert!(s.contains("prompt=True"), "istem görülmedi: {s}");
    assert!(
        s.contains("echo_during=False"),
        "istem sırasında yankı kapalı olmalı: {s}"
    );
    assert!(s.contains("echo_after=True"), "yankı geri açılmalı: {s}");
    assert!(s.contains("code=130"), "çıkış kodu 130 olmalı: {s}");
}

/// Bitmeyen stdin akışını şifrelerken sinyal: kod 130, tmp yok, gecikme ≤ 2 s.
fn interrupt_streaming(sig: &str, tag: &str) {
    let d = tmpdir(tag);
    let mut child = Command::new(BIN)
        .current_dir(&d)
        .args([
            "--verbose",
            "encrypt",
            "-",
            "-o",
            "out.lphy",
            "--kdf-memory",
            "64",
            "--kdf-time",
            "1",
            "--kdf-parallelism",
            "1",
            "--chunk-size",
            "64k",
            "--password-file",
            "pw.txt",
        ])
        .stdin(Stdio::piped())
        .stderr(Stdio::piped())
        .stdout(Stdio::null())
        .spawn()
        .unwrap();
    // Sonsuz üretici: ayrı iş parçacığı stdin'e yazar (boru kırılınca durur).
    let mut stdin = child.stdin.take().unwrap();
    let feeder = std::thread::spawn(move || {
        use std::io::Write;
        let block = vec![0x5Au8; 1 << 16];
        while stdin.write_all(&block).is_ok() {}
    });
    // KDF bitip akış başlayana kadar bekle: tmp dosyası görünür.
    let start = Instant::now();
    while stale_tmp(&d).is_empty() {
        assert!(start.elapsed() < Duration::from_secs(20), "akış başlamadı");
        std::thread::sleep(Duration::from_millis(20));
    }
    std::thread::sleep(Duration::from_millis(300));
    let t0 = Instant::now();
    kill(child.id(), sig);
    let st =
        wait_timeout(&mut child, Duration::from_secs(10)).expect("süreç sinyalden sonra bitmedi");
    let latency = t0.elapsed();
    let mut err = String::new();
    child
        .stderr
        .take()
        .unwrap()
        .read_to_string(&mut err)
        .unwrap();
    let _ = feeder.join();
    eprintln!("{sig}: gecikme {latency:?}, stderr:\n{err}");
    assert_eq!(st.code(), Some(130), "çıkış kodu 130 olmalı ({sig})");
    assert!(
        stale_tmp(&d).is_empty(),
        "tmp kalmamalı: {:?}",
        stale_tmp(&d)
    );
    assert!(!d.join("out.lphy").exists(), "yarım hedef oluşmamalı");
    assert!(
        latency < Duration::from_secs(2),
        "gecikme ≤ 1 chunk + 1 s olmalı: {latency:?}"
    );
    let _ = std::fs::remove_dir_all(&d);
}

#[test]
fn sigint_mid_stream_cleans_tmp_and_exits_130() {
    interrupt_streaming("-INT", "int");
}

#[test]
fn sigterm_mid_stream_cleans_tmp_and_exits_130() {
    interrupt_streaming("-TERM", "term");
}

/// KDF (kesilemez) sırasında ilk SIGINT bekletilir, ikincisi `_exit(130)` ile hemen çıkar.
#[test]
fn double_sigint_during_kdf_exits_immediately() {
    let d = tmpdir("kdf");
    std::fs::write(d.join("in.bin"), b"x").unwrap();
    let mut child = Command::new(BIN)
        .current_dir(&d)
        .args([
            "--verbose",
            "encrypt",
            "in.bin",
            "-o",
            "out.lphy",
            // Az bellek, çok yineleme: KDF uzun sürer ama büyük bellek ayırma/kilitleme
            // (sinyal teslimini geciktiren uzun çekirdek çağrısı) küçük CI makinelerinde ölçümü
            // bozmaz.
            "--kdf-memory",
            "128",
            "--kdf-time",
            "60",
            "--kdf-parallelism",
            "1",
            "--password-file",
            "pw.txt",
        ])
        .stderr(Stdio::piped())
        .stdout(Stdio::null())
        .spawn()
        .unwrap();
    // "KDF:" satırını bekle (stderr'i ayrı iş parçacığında oku).
    let mut stderr = child.stderr.take().unwrap();
    let (tx, rx) = std::sync::mpsc::channel::<String>();
    let reader = std::thread::spawn(move || {
        let mut all = String::new();
        let mut buf = [0u8; 256];
        loop {
            match stderr.read(&mut buf) {
                Ok(0) | Err(_) => break,
                Ok(n) => {
                    all.push_str(&String::from_utf8_lossy(&buf[..n]));
                    let _ = tx.send(all.clone());
                }
            }
        }
        all
    });
    let start = Instant::now();
    loop {
        let s = rx
            .recv_timeout(Duration::from_secs(10))
            .expect("KDF satırı gelmedi");
        if s.contains("KDF:") {
            break;
        }
        assert!(start.elapsed() < Duration::from_secs(10));
    }
    std::thread::sleep(Duration::from_millis(150));
    kill(child.id(), "-INT");
    std::thread::sleep(Duration::from_millis(200));
    assert!(
        child.try_wait().unwrap().is_none(),
        "ilk SIGINT KDF'i kesmemeli (kesilemez)"
    );
    let t0 = Instant::now();
    kill(child.id(), "-INT");
    let st = wait_timeout(&mut child, Duration::from_secs(5)).expect("ikinci SIGINT ile çıkmadı");
    let latency = t0.elapsed();
    let err = reader.join().unwrap();
    eprintln!("çift SIGINT gecikmesi {latency:?}\n{err}");
    assert_eq!(st.code(), Some(130));
    assert!(
        latency < Duration::from_millis(500),
        "ikinci sinyal hemen çıkmalı: {latency:?}"
    );
    assert!(!err.contains("KDF tamamlandı"), "KDF bitmeden çıkılmalıydı");
    assert!(stale_tmp(&d).is_empty());
    let _ = std::fs::remove_dir_all(&d);
}
