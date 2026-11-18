#!/bin/bash
# Panic-hook test: a `fault-injection` + release (panic=abort) build panics in the middle of
# the pipeline (chunk 4). Expected: the hook runs ("arena=0" line), the temp file is deleted, the process ends with SIGABRT
# (134 in the shell), terminal echo stays on (in a pty), the output file is not created.
# Usage: tests/fault/panic_hook.sh   (macOS/Linux; needs python3)
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
TGT="${CARGO_TARGET_DIR:-$ROOT/target}/fault"
cargo build --release --locked -p lephy-cli --features fault-injection --target-dir "$TGT" >/dev/null 2>&1 \
  || cargo build --release -p lephy-cli --features fault-injection --target-dir "$TGT"
BIN="$TGT/release/lephycrypy"
W="$(mktemp -d)"; trap 'rm -rf "$W"' EXIT
umask 077
printf 'fault password 123\n' > "$W/pw.txt"
head -c $((512 * 1024)) /dev/urandom > "$W/in.bin"   # 64 KiB chunks → 8 chunks; panic at the 4th
python3 - "$BIN" "$W" <<'PY'
import os, pty, sys, termios, signal, time
binp, w = sys.argv[1], sys.argv[2]
pid, fd = pty.fork()
if pid == 0:
    os.chdir(w)
    os.execv(binp, [binp, "encrypt", "in.bin", "-o", "out.lphy", "--raw", "--kdf-memory", "64",
                    "--kdf-time", "1", "--kdf-parallelism", "1", "--chunk-size", "64k",
                    "--password-file", "pw.txt"])
out = b""
while True:
    try:
        chunk = os.read(fd, 4096)
    except OSError:
        break
    if not chunk:
        break
    out += chunk
_, status = os.waitpid(pid, 0)
text = out.decode("utf-8", "replace")
print(text)
echo_on = bool(termios.tcgetattr(fd)[3] & termios.ECHO) if os.isatty(fd) else True
ok = True
def check(cond, msg):
    global ok
    print(("OK   " if cond else "FAIL ") + msg)
    ok &= cond
check(os.WIFSIGNALED(status) and os.WTERMSIG(status) == signal.SIGABRT, f"ended with SIGABRT (status={status})")
check("at=crates/lephy-core/src/pipeline.rs" in text, "panic in the middle of the pipeline (injected)")
check("arena=0" in text, "the hook zeroized the arena (arena=0)")
check("tmp=1" in text, "the hook deleted 1 temp file (tmp=1)")
left = [n for n in os.listdir(w) if n.startswith(".lphy-tmp-")]
check(not left, f"no temp file left {left}")
check(not os.path.exists(os.path.join(w, "out.lphy")), "output not created")
check(echo_on, "terminal echo is on")
sys.exit(0 if ok else 1)
PY
