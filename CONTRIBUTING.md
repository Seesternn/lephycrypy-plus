# Contributing to lephycrypy+

Thank you for helping. This is security software, so changes are reviewed carefully and some
rules are stricter than usual. Please read this page before opening a pull request.

## Before you start

- **Security problems:** do not open an issue; follow [SECURITY.md](SECURITY.md).
- **Bugs:** open an issue with the version, platform, exact command or steps, what you expected
  and what happened. Never attach real encrypted files, passwords, key files or identities.
- **Features and format changes:** open an issue first. Anything that changes the file format
  needs an update to [docs/FORMAT.md](docs/FORMAT.md), the Python reference and new test vectors.

## Development setup

The toolchain is pinned in `rust-toolchain.toml` (Rust 1.95.0).

```bash
cargo build --locked
```

```bash
cargo test --locked --workspace
```

```bash
cargo test --locked -p lephy-core --features test-vectors
```

Lints must pass on all three targets with warnings as errors:

```bash
cargo clippy --locked --workspace --all-targets -- -D warnings
```

```bash
cargo fmt --all --check
```

Fuzz targets live in `fuzz/` (separate workspace, nightly and `cargo-fuzz`):

```bash
cd fuzz && cargo +nightly fuzz run envelope -- -max_total_time=60
```

Supply-chain checks run in CI: `cargo deny` (two tiers: `deny.toml` for the core with
`--exclude lephy-gui`, `deny-gui.toml` for the app), `cargo audit` and `cargo vet --locked`.

## Rules for code

- `unsafe` code is allowed **only** in `crates/lephy-sys`. Every `unsafe` block holds exactly one
  operation and has a `// SAFETY:` comment; every public function there is safe and checks its
  own contract. All other crates use `#![forbid(unsafe_code)]`.
- `lephy-sys` may depend only on `libc`, `windows-sys` and `zeroize` (checked in CI).
- New dependencies need a reason in the pull request, must pass both `cargo deny` tiers and need
  `cargo vet` audits or a justified exemption. GUI crates must not reach the core.
- Secrets live in `SecretBytes` (locked, zeroized memory). Do not copy them into `String`/`Vec`,
  do not log them, never read them from argv or environment variables.
- Errors map to the documented exit codes. Messages say what happened and what to do.
- Add a regression test for every bug fix and tests for every feature. Fuzz targets for new
  parsers.
- Keep the user-facing text of the desktop app in both English and Turkish (`tr("…", "…")`).

## Commits and pull requests

- One logical change per pull request; describe what changed and why, and how you tested it.
- Commit messages in English, imperative mood ("Add …", "Fix …").
- Update [CHANGELOG.md](CHANGELOG.md) under "Unreleased" for user-visible changes, and the
  threat model when security properties change.
- Do not commit personal data, local paths, screenshots showing private folders, `.env` files,
  keys or tokens. `scripts/check-private.sh` and the CI privacy job (gitleaks) check this.

## License

By contributing you agree that your contribution is licensed under MIT or Apache-2.0, at the
user's option, like the rest of the project.
