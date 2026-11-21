# Contributing to lephycrypy+

Thank you for helping. Bug reports, documentation, translations and code are all welcome.
Discussion in issues and pull requests can be in English or Turkish; code, comments, commit
messages and documentation are written in English (the Turkish README, `README.tr.md`, is the
exception).

Please read the [code of conduct](CODE_OF_CONDUCT.md) first.

## Security problems

Do **not** open a public issue for a vulnerability. Follow [SECURITY.md](SECURITY.md) and use
**Security › Report a vulnerability** on this repository.

## Reporting a bug or asking for a feature

Use the issue templates. For a bug, include the version (`lephycrypy --version`), the operating
system, what you did, what you expected and what happened. Never attach real encrypted files,
passwords, key files, identity files or paper-backup words; make a small example with test data
instead.

## Before you write code

- Small fixes (typos, clear bugs, tests, documentation) can go straight to a pull request.
- For anything larger, open an issue first so we can agree on the approach.
- **Changes to cryptography, the file format ([docs/FORMAT.md](docs/FORMAT.md)) or the security
  boundaries ([docs/THREAT-MODEL.md](docs/THREAT-MODEL.md)) must be discussed in an issue
  before any code.** They need a design note and usually test vectors.

## Project layout

| Crate | What it is |
|---|---|
| `lephy-sys` | The only crate with `unsafe` code: locked memory and operating-system calls. Its dependencies are limited to `libc`, `windows-sys` and `zeroize`. |
| `lephy-core` | File format, cryptography, streaming and archives. |
| `lephy-cli` | The `lephycrypy` command-line tool. |
| `lephy-usb` | Writing to and preparing USB sticks. |
| `lephy-gui` | The desktop app (macOS and Windows, egui). |

## Building and testing

The toolchain is pinned in `rust-toolchain.toml`. Run what CI runs before you open a pull
request:

```bash
cargo fmt --all --check
```

```bash
cargo clippy --locked --workspace --all-targets -- -D warnings
```

```bash
cargo test --locked --workspace
```

```bash
cargo test --locked -p lephy-core --features test-vectors
```

```bash
bash tests/fault/panic_hook.sh
```

If you change `lephy-sys`, also run Miri (it uses a dated nightly, see `.github/workflows/ci.yml`):

```bash
cargo +nightly-2026-11-01 miri test --target x86_64-unknown-linux-gnu -p lephy-sys
```

If you add or change a dependency:

```bash
cargo deny --all-features --exclude lephy-gui check
```

```bash
cargo deny --all-features --config deny-gui.toml check
```

```bash
cargo vet --locked
```

## Rules for code

- `unsafe` code goes only in `lephy-sys`, and every `unsafe` block has a `// SAFETY:` comment.
- No warnings: clippy runs with `-D warnings` (pedantic lints are on).
- Secrets live in locked memory (`lephy_sys::mem::SecretBytes`) and are wiped; do not copy them
  into ordinary `String`s or `Vec`s.
- Every change comes with tests. New parsing code gets a fuzz target in `fuzz/`.
- New dependencies need a reason in the pull request and must pass `cargo deny` and `cargo vet`.
- Update `CHANGELOG.md`, and `docs/FORMAT.md` / `docs/THREAT-MODEL.md` where they are affected.
  User-facing changes to the desktop app also update both READMEs.
- Text shown in the desktop app is written in both English and Turkish.

## Commits and pull requests

- Commit messages are in English: a short summary line, a blank line, then what changed and why.
- Keep a pull request to one topic and fill in the template checklist.
- No personal data, local paths, keys or real encrypted files in the diff or the history.
- By contributing you agree that your contribution is licensed under the project's
  [Apache License 2.0](LICENSE).

## AI-assisted contributions

Contributions written with the help of AI tools are welcome, on two conditions:

1. Say so in the pull request description, and name the tool.
2. You understand every line you submit, you have run the tests yourself, and you can answer
   questions about the change in review. The person who opens the pull request is responsible
   for it, not the tool.
