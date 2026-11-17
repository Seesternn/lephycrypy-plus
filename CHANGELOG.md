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

### Added
- Private-data guard (`scripts/check-private.sh`) run before every commit, and a CI job that
  scans the whole history with gitleaks and checks that every commit uses a noreply address.
- macOS app bundle script with hardened runtime; local paths are stripped from the binary.
- Desktop app: password-derivation presets, explanations of the advanced settings, optional key
  file, batch-ready layout, real progress based on bytes written.
