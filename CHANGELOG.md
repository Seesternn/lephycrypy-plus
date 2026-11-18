# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project uses
[Semantic Versioning](https://semver.org/). Nothing has been released yet.

## [Unreleased]

### Security
- Decrypted files keep the download mark of the `.lphy` file they came from (macOS quarantine,
  Windows Mark of the Web), so Gatekeeper and SmartScreen still check programs inside an
  encrypted file. Restored names have bidirectional and control characters replaced, and the app
  warns when the output contains programs.
- Identity files (`.lphykey`) are refused as decryption input in the app and the CLI; decrypting
  one would have written the secret key to disk unprotected.
- Desktop app: an encrypted file with error correction (`--error-correction`) was offered for
  encryption again instead of decryption, because only the bare `.lphy` header was recognised.
  Files are now recognised through the envelope and split sets as well; any part of a set opens the
  set, and a damaged `.lphy` file goes to decryption (with recovery) instead of being encrypted
  again. Key-file and identity detection use the same path.
- macOS: interactive password prompts no longer hang. `poll()` reports POLLNVAL for `/dev/tty`
  on macOS; the reader now falls through to the blocking read.
- Desktop app: a request from the operating system to open items (double-click, Quick Action,
  Explorer, `open`) no longer replaces an item that is already chosen; the app asks first, so
  another program cannot swap the file after a password was typed.
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
- Arena-based memory tests no longer starve each other when run in parallel (flaky CI failure).
- macOS: secure keyboard input is on while a password field has focus, so processes with input
  monitoring permission cannot read the keystrokes.
- An archive entry with an extreme modification time no longer crashes extraction on Windows,
  whose time range is narrower; the time is simply not applied.

### Changed
- Decrypting a single file now restores the name stored inside the encrypted file, next to the
  default destination: `7f3a9c2e.lphy` comes back as `photo.png`, not as `7f3a9c2e`. A taken name
  gets ` (2)`, ` (3)`… and nothing is overwritten. Applies in the desktop app (unless a
  destination was chosen with "Change") and in the CLI when no `-o` is given
  (`DecryptOptions::restore_name`). A folder has no stored name and keeps the destination's name.
- Desktop app: Encrypt and Decrypt open their own pages from the home screen, and the first-launch
  welcome is a short three-step introduction.
- Desktop app: fold-out "?" help boxes next to identity files, public keys and signatures (what an
  identity file is, how to create and share keys, how to back them up), and a Help page from the
  home screen with all of them.
- Touch ID / Windows Hello unlock of identities was evaluated and not added: without a signed
  release the biometric check is not enforced (macOS legacy keychain) or not bound to the data
  (Windows DPAPI). See the threat model.
- A folder that is encrypted now always comes back as a folder, even when it holds a single file
  (it used to be written out as that file). The archive's END entry records that the source was a
  folder (`END_FOLDER`, docs/FORMAT.md); files encrypted from a single file are unchanged.
- The desktop app's password generator shows the new password as dots until the pointer rests on
  it, so it is not readable over the shoulder or in a screen recording.
- License: Apache License 2.0 only (MIT removed). NOTICE now states the attribution required
  when copies, modified versions or derivative works are distributed.
- The command line, error messages, code comments, build and CI configuration are now in English
  (the desktop app stays bilingual). Confirmation prompts ask for `yes` (`evet` is still accepted).
- The "Copy" link next to a new public key now really copies it (through the system tool); the
  app's own clipboard access stays disabled.
- New dependency for recipient encryption: `curve25519-dalek` 5.0 (pure Rust, BSD-3-Clause), with
  `fiat-crypto` and `curve25519-dalek-derive`. All three are `cargo vet` exemptions until audits
  can be imported; `syn` 2 is allowed next to `syn` 3 because of the derive crate.
- Supply chain: audits imported from more sources (ISRG, Zcash, Embark, Ariel OS); unnecessary
  `cargo-vet` exemptions pruned (339 to 326); CI fails a pull request that exempts a new crate.
- Release: SBOM tool pinned. `cargo-audit` ignores carry a review date.

### Added
- Desktop app: leftover `.lphy-tmp-*` items from a decryption that was cut short are found at
  start (home, Desktop, Downloads, Documents) and can be deleted after confirmation; Settings ›
  Maintenance searches any folder.
- Desktop app start screen: a welcome on first launch, then cards for Encrypt, Decrypt, My keys
  and Settings. "My keys" creates key pairs, shows an identity's public, signer and post-quantum
  keys with copy links, and its paper backup. Settings are laid out in sections.
- Optional app lock (off by default): a password asked at every start; only its Argon2id verifier
  is saved. The app now saves a small settings file (language, welcome seen, lock verifier).
- Closing the window no longer stops a job: on macOS the app hides and the Dock icon brings it
  back; Cmd+Q / Dock → Quit asks first while a job runs. On Windows closing while a job runs
  minimises the window.
- Post-quantum hybrid recipients (ML-KEM-768 + X25519): `encrypt --pq`, "Post-quantum" in the
  app. Breaking a file needs breaking both. The ML-KEM key is derived from the identity, so
  existing identities and paper backups cover it; `keygen` writes the `lphypq1…` key as the third
  line of the `.pub` file. Vector 17 is made by Rust and rebuilt byte for byte by the Python
  reference from the decapsulated ciphertext. New dependency `ml-kem` 0.3 (RustCrypto, with
  `kem`, `module-lattice`, `sha3`, `shake`, `keccak`, `sponge-cursor`), `cargo vet` exemptions.
- Sender signatures (Ed25519): `encrypt --sign ID`, `decrypt/verify/list --expect-signer KEY|FILE`,
  "Sign with my identity" in the app and the signer on its result screen. The signature and the
  signer's `lphysig1…` key are encrypted in a trailer, checked before anything is written, and
  survive `rekey` and replacing recipients. Vector 16 from the Python reference (signed with
  `cryptography`'s Ed25519) is reproduced byte for byte. New dependency `ed25519-dalek` 3.0 (with
  `ed25519` and `signature`), `cargo vet` exemptions until audits can be imported.
- Paper backup of an identity (also shown once, masked until hovered, after the app creates a
  key pair): `lephycrypy identity backup ID` shows 22 words (EFF wordlist,
  2-byte checksum; the first word is always `abacus` or `abdomen`), `identity restore OUT`
  recreates the identity file from them. The Python reference produces the same words.
- Change who can open a file encrypted to public keys (`lephycrypy recipients FILE -i ID -r KEY…`,
  and "Change the recipient list…" in the app). A current recipient replaces the whole list; the
  content is not re-encrypted. Vector 15 from the Python reference is reproduced byte for byte.
- List an archive without extracting it (`lephycrypy list`, and "List contents" in the app) and
  extract only some paths (`decrypt --only PATH`, or check boxes in the app). Listing decrypts and
  checks the whole file but writes nothing; selected folders bring everything below them.
- Settings page in the desktop app (gear button on the start screen): language, and the optional
  system integration. The language switch no longer sits on every screen.
- macOS Finder Quick Action ("Encrypt or open with lephycrypy+" under Quick Actions in the
  right-click menu), added and removed from Settings after confirmation, for the current user only.
- New README screenshots in English and Turkish, including the public-key screen.
- Documentation in English: README (Turkish version in README.tr.md), SECURITY, the file format
  and the threat model; issue and pull-request templates, and a sourced comparison with age, Picocrypt,
  VeraCrypt and Cryptomator (docs/COMPARISON.md).
- Opening files from the system. macOS: double-clicking a `.lphy` file opens it in the app, any
  file or folder can be opened with "Open With → lephycrypy+" in Finder, and files can be dropped
  on the Dock icon (the app bundle declares the `.lphy` type). Windows: an optional Explorer
  integration for the current user only — `.lphy` opens with a double-click and every file and
  folder gets a right-click entry; added and removed from the app after confirmation.
- Encryption to public keys (X25519), for one or more recipients
  (`lephycrypy keygen`, `encrypt --recipient`, `decrypt/verify --identity`; "With public keys" and
  "Create my own key pair" in the app). Only the holders of the matching identity files can open
  the file; no shared password is needed. Identities are stored password-protected (`.lphykey`),
  public keys are short `lphy1…` strings with a checksum. Format version 2, documented in
  `docs/FORMAT.md`; vector 14 from the Python reference is reproduced byte for byte.
- Optional error correction (`--error-correction`, and an option in the app). The encrypted file
  is wrapped in a Reed–Solomon RS(255,239) envelope with byte interleaving (about 6.7 % larger):
  any burst of up to 1 KiB per 30 KiB block is repaired on decryption. The inner `.lphy` file is
  unchanged, so integrity still comes from authenticated encryption; the envelope only repairs.
  Three header copies with checksums survive damage to the start of the file.
- Recovery mode for damaged files (`decrypt --recover`, and "Recover a damaged file" in the app).
  Chunks that fail authentication are replaced with zeros and listed; the result is always
  written to a new `.recovered` path and never replaces anything. Archives keep every entry that
  can still be read.
- Fuzz target for the error-correction envelope and Reed–Solomon decoder.
- Optional compression before encryption (`--compress`, and an option in the app). Files that use
  it are written as format version 2; all other files stay version 1. Documented in
  `docs/FORMAT.md` with a side-channel warning; the Python reference implementation produces new
  vectors 12 and 13 that the Rust code decrypts.
- Split output into parts (`--split-size 100m|1g|…`, and "Split into parts" in the app, including
  a FAT32-friendly size). Parts are named `.001`, `.002`, …; decrypting the `.001` file joins them.
  A missing, truncated or reordered part is detected. Splitting needs at most one extra part of
  free space.
- Batch encryption: several files or folders become separate `.lphy` files
  (`lephycrypy encrypt a b c --out-dir DIR`; drop or choose several items in the app). The
  password is asked once; each file still gets its own salt and key. One failing item does not
  stop the others.
- Secure deletion of the originals after encryption has been verified (`--secure-delete`, and an
  option in the app). It asks for explicit confirmation, overwrites each file once with random
  data and is honest about its limits on SSDs, copy-on-write file systems and snapshots. Files
  with other hard links are only unlinked.
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
