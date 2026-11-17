#!/usr/bin/env bash
# Refuses a commit that would add private data to the repository.
#
# Checks the lines added in the staged diff (and, if given, the commit message file) for:
#   - the local user name and host name (read at runtime, never stored in the repo),
#   - home-directory paths (/Users/<name>, C:\Users\<name>, /home/<name>),
#   - assistant/tool attribution markers,
#   - common token and private-key patterns,
#   - extra patterns from the untracked file .local/private-patterns (one ERE per line).
#
# Usage: scripts/check-private.sh [commit-message-file]
set -euo pipefail
cd "$(git rev-parse --show-toplevel)"

patterns=(
  '/Users/[A-Za-z0-9._-]+'
  '[Cc]:\\\\?Users\\\\?[A-Za-z0-9._-]+'
  '/home/[a-z][a-z0-9._-]*/'
  '[Cc]laude|[Aa]nthropic|Co-Authored-By'
  'gh[pousr]_[A-Za-z0-9]{20,}'
  'github_pat_[A-Za-z0-9_]{20,}'
  '-----BEGIN [A-Z ]*PRIVATE KEY-----'
  'AKIA[0-9A-Z]{16}'
)
user="$(id -un 2>/dev/null || true)"
host="$(hostname -s 2>/dev/null || true)"
[ -n "$user" ] && [ "${#user}" -ge 4 ] && patterns+=("$user")
[ -n "$host" ] && [ "${#host}" -ge 4 ] && patterns+=("$host")
if [ -f .local/private-patterns ]; then
  while IFS= read -r p; do
    [ -n "$p" ] && [ "${p:0:1}" != "#" ] && patterns+=("$p")
  done < .local/private-patterns
fi

# Lines that legitimately contain a pattern (third-party auditor records, CI runner paths).
allow='^\+\+\+ |/home/runner/'

added="$(git diff --cached -U0 --no-color -- . ':(exclude)scripts/check-private.sh' ':(exclude)supply-chain/imports.lock' | grep -E '^\+' | grep -vE "$allow" || true)"
msg=""
[ $# -ge 1 ] && [ -f "$1" ] && msg="$(cat "$1")"

fail=0
for p in "${patterns[@]}"; do
  if hits="$(printf '%s\n' "$added" | grep -inE -e "$p" | head -n 3)" && [ -n "$hits" ]; then
    echo "private-data check: pattern matched in staged changes:" >&2
    printf '%s\n' "$hits" | cut -c1-160 >&2
    fail=1
  fi
  if [ -n "$msg" ] && printf '%s\n' "$msg" | grep -iqE -e "$p"; then
    echo "private-data check: pattern matched in commit message" >&2
    fail=1
  fi
done

if git diff --cached --name-only --diff-filter=AM | grep -qiE '\.(png|jpe?g|gif|bmp|pdf)$'; then
  echo "private-data check: images are staged; text inside them cannot be scanned. Review them by eye:" >&2
  git diff --cached --name-only --diff-filter=AM | grep -iE '\.(png|jpe?g|gif|bmp|pdf)$' >&2
fi
if git diff --cached --name-only | grep -qE '^\.local/|\.env'; then
  echo "private-data check: local or environment files are staged" >&2
  fail=1
fi

exit "$fail"
