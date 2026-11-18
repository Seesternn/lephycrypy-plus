//! Signal tests — Unix only. A Windows `CTRL_BREAK_EVENT` test would be a separate Windows
//! CI step (not written yet).
//!
//! 1. SIGINT at the password prompt (pty): echo comes back, exit code 130.
//! 2. SIGINT/SIGTERM in the middle of a stream (endless stdin): exit 130, no temp file left, small delay.
//! 3. Double SIGINT during key derivation: `_exit(130)` at once on the second signal.
//!
//! `python3` (stdlib `pty`/`termios`) is used for the pty: lephy-cli cannot contain `unsafe` and
//! cannot depend on libc directly (deny.toml).

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

/// SIGINT at the password prompt: echo off during the prompt, back on after the signal; code 130.
#[test]
fn sigint_at_password_prompt_restores_echo_and_exits_130() {
    assert!(have_python(), "python3 (pty, termios) required");
    // Every step has a timeout: the test never hangs (select + WNOHANG + an upper limit).
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
while b"Password" not in buf and time.time() < deadline:
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
print(f"prompt={b'Password' in buf} echo_during={echo_during} echo_after={echo_after} code={code}")
"#;
    let mut child = Command::new("python3")
        .args(["-c", script, BIN])
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let st = wait_timeout(&mut child, Duration::from_mins(1))
        .expect("the pty helper did not finish within 60 s");
    let mut s = String::new();
    child.stdout.take().unwrap().read_to_string(&mut s).unwrap();
    let mut e = String::new();
    child.stderr.take().unwrap().read_to_string(&mut e).unwrap();
    eprintln!("{s}{e}");
    assert!(st.success(), "the pty helper failed: {e}");
    assert!(s.contains("prompt=True"), "prompt not seen: {s}");
    assert!(
        s.contains("echo_during=False"),
        "echo must be off during the prompt: {s}"
    );
    assert!(s.contains("echo_after=True"), "echo must come back: {s}");
    assert!(s.contains("code=130"), "exit code must be 130: {s}");
}

/// Signal while encrypting an endless stdin stream: code 130, no temp file, delay ≤ 2 s.
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
    // Endless producer: a separate thread writes to stdin (stops when the pipe breaks).
    let mut stdin = child.stdin.take().unwrap();
    let feeder = std::thread::spawn(move || {
        use std::io::Write;
        let block = vec![0x5Au8; 1 << 16];
        while stdin.write_all(&block).is_ok() {}
    });
    // Wait until key derivation ends and the stream starts: the temp file appears.
    let start = Instant::now();
    while stale_tmp(&d).is_empty() {
        assert!(
            start.elapsed() < Duration::from_secs(20),
            "the stream did not start"
        );
        std::thread::sleep(Duration::from_millis(20));
    }
    std::thread::sleep(Duration::from_millis(300));
    let t0 = Instant::now();
    kill(child.id(), sig);
    let st = wait_timeout(&mut child, Duration::from_secs(10))
        .expect("the process did not end after the signal");
    let latency = t0.elapsed();
    let mut err = String::new();
    child
        .stderr
        .take()
        .unwrap()
        .read_to_string(&mut err)
        .unwrap();
    let _ = feeder.join();
    eprintln!("{sig}: delay {latency:?}, stderr:\n{err}");
    assert_eq!(st.code(), Some(130), "exit code must be 130 ({sig})");
    assert!(
        stale_tmp(&d).is_empty(),
        "no temp file may remain: {:?}",
        stale_tmp(&d)
    );
    assert!(
        !d.join("out.lphy").exists(),
        "no partial output may be created"
    );
    assert!(
        latency < Duration::from_secs(2),
        "the delay must be ≤ 1 chunk + 1 s: {latency:?}"
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

/// During key derivation (not interruptible) the first SIGINT is held back; the second exits at once with `_exit(130)`.
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
            // Little memory, many iterations: key derivation takes long, but no large allocation/lock
            // (a long kernel call that delays signal delivery) disturbs the measurement on small CI
            // machines.
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
    // Wait for the "KDF:" line (stderr is read on a separate thread).
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
            .expect("no KDF line arrived");
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
        "the first SIGINT must not interrupt key derivation (not interruptible)"
    );
    let t0 = Instant::now();
    kill(child.id(), "-INT");
    let st = wait_timeout(&mut child, Duration::from_secs(5))
        .expect("did not exit on the second SIGINT");
    let latency = t0.elapsed();
    let err = reader.join().unwrap();
    eprintln!("double SIGINT delay {latency:?}\n{err}");
    assert_eq!(st.code(), Some(130));
    assert!(
        latency < Duration::from_millis(500),
        "the second signal must exit at once: {latency:?}"
    );
    assert!(
        !err.contains("KDF done"),
        "should have exited before the KDF finished"
    );
    assert!(stale_tmp(&d).is_empty());
    let _ = std::fs::remove_dir_all(&d);
}
