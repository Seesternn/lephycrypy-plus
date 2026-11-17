# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project uses
[Semantic Versioning](https://semver.org/). Nothing has been released yet.

## [Unreleased]

### Security
Fixes from the November 2026 internal review (not an independent audit):

- `--delete-original` now deletes only the entries that were actually archived. If any entry was
  skipped (unreadable file, special file, over-long symlink) nothing is deleted. Files added or
  replaced after archiving are left in place.
- Source folders are read through a directory handle, so a file swapped for a symlink while
  encrypting can no longer pull data from outside the folder.
- The temporary folder used while extracting is named `.lphy-tmp-*`, created with mode `0700`,
  and found by `cleanup`. It no longer reveals the output name.
- `decrypt --force` moves the existing target aside and restores it if the new output cannot be
  put in place, instead of deleting it first.
- `rekey` and `reencrypt` refuse symlinks and files with several hard links (the old header would
  otherwise survive under another name) and keep the original file permissions. `reencrypt`
  also closes the source before replacing it, which Windows requires.
- `reencrypt` keeps plaintext inside the locked buffer pool instead of passing it through
  ordinary heap memory.
- Extracted files and folders never get group- or world-writable permissions.
- When the amount of physical RAM cannot be determined, key-derivation settings above 1 GiB need
  explicit confirmation.
- Keys are no longer copied to unwiped stack memory; key-file digests are wiped after use.
- A symlink target spread over several frames is rejected, as the format requires.
- `verify` now checks the archive structure and padding as well, without writing anything.
- USB wipe also empties `.Trashes`, `.Spotlight-V100`, `.fseventsd` and `System Volume
  Information` (old deleted files and indexed text lived there); the dry run lists them.
- USB wipe checks the device identity on the opened folder handle, so another device mounted at
  the same place after the check is never touched; macOS formatting targets the volume UUID.
- Windows USB targets must be a drive root such as `E:\`; relative paths are rejected.
- The desktop app's Cancel uses its own flag: a later Ctrl+C or SIGTERM still cleans up instead of
  exiting at once, and Cancel pressed while the size is being measured is no longer lost.
- The panic hook can no longer write into a buffer that another thread is unmapping.
- The signal handler preserves `errno`.
- `--password-fd` duplicates the descriptor instead of taking ownership, and refuses the
  program's own internal descriptors.
- macOS: secure keyboard input is on while a password field has focus, so processes with input
  monitoring permission cannot read the keystrokes.
- An archive entry with an extreme modification time no longer crashes extraction on Windows,
  whose time range is narrower; the time is simply not applied.

### Changed
- Supply chain: audits imported from more sources (ISRG, Zcash, Embark, Ariel OS); unnecessary
  `cargo-vet` exemptions pruned (339 to 326); CI fails a pull request that exempts a new crate.
- Release: SBOM tool pinned. `cargo-audit` ignores carry a review date.

### Added
- Passphrase generator using the EFF large wordlist (`lephycrypy passphrase`, and "Generate a
  strong password" in the app; shown once so it can be written down).
- Password strength estimate while typing (rough, dependency-free; labelled as an estimate).
- Key-file generator (`lephycrypy keyfile-gen`, and "Create new" in the app): random bytes,
  mode `0600`, never overwrites.
- The app shows an encrypted file's algorithm, key-derivation memory and content type before
  asking for the password.
- Desktop app in English and Turkish, chosen from the system language and switchable in the
  window.
- Internal security review report: `docs/SECURITY-REVIEW-2026-11.md`.
- Private-data guard (`scripts/check-private.sh`) run before every commit, and a CI job that
  scans the whole history with gitleaks and checks that every commit uses a noreply address.
- macOS app bundle script with hardened runtime; local paths are stripped from the binary.
- Desktop app: password-derivation presets, explanations of the advanced settings, optional key
  file, batch-ready layout, real progress based on bytes written.
