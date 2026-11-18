## What and why

## How it was tested

## Checklist

- [ ] `cargo fmt --all --check` and `cargo clippy --workspace --all-targets -- -D warnings`
- [ ] `cargo test --workspace` (and `--features test-vectors` for format changes)
- [ ] Tests added for the change; fuzz target for new parsing code
- [ ] `unsafe` only in `lephy-sys`, each block with a `// SAFETY:` comment
- [ ] New dependencies justified and passing `cargo deny` / `cargo vet`
- [ ] CHANGELOG, FORMAT.md and THREAT-MODEL.md updated where needed
- [ ] No personal data, local paths, keys or real encrypted files in the diff
