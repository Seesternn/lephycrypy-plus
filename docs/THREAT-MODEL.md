# lephycrypy+ threat model (draft)

The goal is to keep secret residue to a minimum on a **best effort** basis; leaving "no trace at
all" is not promised. Every "no mitigation" / "out of scope" item is a deliberate limit. Claims
marked "UNVERIFIED" are assumptions until a source is found.

## Protected
Content, names and structure, optionally the size (PADMÉ); header and chunk integrity;
truncation, reordering and splicing; key commitment (`commit_tag` — invisible salamanders /
partitioning oracles); small secrets held in locked, zeroized memory (best effort); no partial
output (atomic writes).

## Unencrypted metadata
Version, algorithm, KDF parameters, key-file / padding / compression flags, number of recipients,
chunk size, salts and nonces, `commit_tag`, total encrypted size (± one chunk without padding),
number of chunks; file-system timestamps. File and key-file **paths** appear in argv (`ps`,
Windows Event Log 4688 command-line field — depends on the audit policy, default UNVERIFIED).
Passwords are never in argv. The desktop app receives paths in argv only from the optional
Windows Explorer integration (`--open`); the optional macOS Quick Action passes them briefly in
the argv of `/usr/bin/open`.

## Rekey limit
`rekey` does not change the file key: the old password plus a copy of the old header (256 B)
still opens the new file. Real rotation is `reencrypt`.

## Memory
Drops do not run on panic (`panic=abort`); the panic hook (1) zeroizes the arena and registered
large regions, (2) deletes temporary files, (3) restores the terminal, then aborts (core dumps
disabled). Not locked or not zeroized:
- Internal buffers of the Unicode normalisation iterator; Argon2 H0 / Blake2b internal state
  (UNVERIFIED).
- Per-call AEAD state on worker stacks (ChaCha20 stream state, XChaCha subkey, Poly1305 one-time
  key, GHASH copy, tag mask); Poly1305 has no zeroize. These are chunk specific and do not reveal
  `data_key` directly.
- HKDF/HMAC/BLAKE3 move copies and register spills; round-key zeroization in the AES `ni`/`armv8`
  back ends is UNVERIFIED.
- X25519 scalars are copied by value into the curve library for each multiplication; those copies
  are wrapped in `Zeroizing` on our side, internal temporaries are not (UNVERIFIED).
- The plaintext chunk pool (≤ 64 MiB) is not locked; it can reach swap/pagefile (it is zeroized
  after use).
- File and directory names are not zeroized on the heap; name secrecy is about the output on
  disk.
- Kernel page cache, tty line buffer and kernel buffers of a password file or pipe are out of
  scope.
- Desktop app: the egui/winit event queue and IME composition; OS keyboard logging is out of
  scope.
- Hibernation (locked memory can be written to sleepimage/hiberfil); swap (encrypted by default
  on macOS, pagefile not on Windows); `mlock` failure (RLIMIT_MEMLOCK, working set) → warning;
  MADV_DONTDUMP / PR_SET_DUMPABLE on Linux only (best effort); on macOS/Windows there is no dump
  exclusion for Argon2 memory, only RLIMIT_CORE=0 / WER disabled; WER dumps can be taken from
  outside the process with `LocalDumps` (the hook zeroizes the arena first, other copies may be
  found); `PT_DENY_ATTACH` / `PR_SET_DUMPABLE` deter, they are not a security boundary;
  `--allow-debugger` does not allow attaching to a notarized, hardened-runtime binary.
- Side channels: the AES-GCM software back end is bitsliced/constant time; cache and timing
  attacks from the same machine are out of scope.

**When the panic hook does not run:** out of memory (`handle_alloc_error` aborts without the
hook), double panic or a panic inside the hook, stack overflow, SIGKILL / `TerminateProcess`,
SIGSEGV/SIGBUS from `unsafe` code, power loss. Temporary files may then remain (`cleanup`), the
arena is not zeroized (it is locked and so not written to disk, except on hibernation). The hook
cannot reach stack, register or heap copies; other threads keep running during the hook (damaged
chunks do not reach the destination); deleting temporary files can block on a hung file system;
the extraction temp tree is not deleted by the hook.

**Signals:** an interruption during key derivation waits until it finishes; a second signal
calls `_exit(130)` without cleaning up; the delay is at most one chunk of I/O; Windows console
close cleanup is limited to about 5 s; log-off events do not reach interactive apps; SIGKILL
cannot be caught.

## File system
The decryption temp tree is plaintext; SSD/APFS remnants remain. `--delete-original` leaves
remnants. `--secure-delete` overwrites each file once with random data before unlinking it, but
on SSDs (wear levelling, TRIM), copy-on-write file systems (APFS, Btrfs, ReFS) and with snapshots
the old content can survive; files with other hard links are only unlinked. Originals can remain
in APFS / Time Machine snapshots, VSS and cloud version history. No directory fsync on Windows.
No-clobber: FAT/exFAT/network file systems may not support `RENAME_NOREPLACE`/`RENAME_EXCL` →
without the `link` fallback a check-then-rename race window remains (warning). Restricting the
Windows temp ACL is UNVERIFIED. `--password-file` leaves a plaintext password file; prefer
tmpfs, a RAM disk or a pipe. Windows named-pipe squatting: an attacker who opens a pipe with the
same name first could supply their own password → only local pipes owned by the same user SID are
accepted.

A decryption that is cut short (crash, power loss, forced quit) can leave a hidden
`.lphy-tmp-*` item with decrypted data next to the destination. `lephycrypy cleanup DIR` finds
and deletes them; the desktop app checks the home folder, Desktop, Downloads and Documents (top
level) at start, offers to delete what it finds (with confirmation), and can search any folder
from Settings › Maintenance. Items younger than ten minutes are skipped (a job may still use
them). Deleting does not overwrite the data, so the limits above apply.

## Operating-system leaks
Even though the tool keeps plaintext only in its own memory and temporary files, OS background
services may copy, index or upload temporary or final plaintext, names or the fact that a file
exists, outside the tool's control. The temp-file measures only protect files the tool creates
while running; the final plaintext output follows the normal OS behaviour of its location.

| Source | What leaks | Platform | Mitigation / status |
|---|---|---|---|
| Spotlight (`.Spotlight-V100`) | content + name | macOS | temp directory/file names end in `.noindex` (suffix mechanism UNVERIFIED); final output is indexed normally |
| QuickLook thumbnail cache | content (preview) + name | macOS | the tool does not use QuickLook; previews by the user may be cached; DataVault protected on 10.14+; location UNVERIFIED |
| APFS snapshots / Time Machine local snapshots | content + name (original) | macOS | no mitigation; may remain after deleting the original |
| iCloud Drive / OneDrive / Dropbox / Google Drive | content (plaintext to the cloud) + name | macOS, Windows | cloud-root detection → confirmation and `--allow-cloud-dir`; the list is heuristic and may be incomplete |
| Screenshots, screen recording, screen sharing | paper-backup words, generated password | macOS, Windows | the desktop app hides its window from capture while they (or the lock screen) are shown (`NSWindowSharingNone`; `WDA_EXCLUDEFROMCAPTURE`, Windows 10 2004+); no protection against a camera or malware with administrator rights |
| Windows Search index | content + name | Windows | temp files get `FILE_ATTRIBUTE_NOT_CONTENT_INDEXED` (VERIFIED); final output follows the folder setting |
| VSS shadow copies | content + name (original) | Windows | no mitigation; documented |
| Microsoft Defender automatic sample submission | content (file to the cloud) + name | Windows | no mitigation; if cloud analysis is inconclusive the file may be sent to Microsoft (VERIFIED: https://learn.microsoft.com/en-us/defender-endpoint/cloud-protection-microsoft-antivirus-sample-submission); `SubmitSamplesConsent` is a user setting |
| Recent items / jump lists / Finder Recents | name + existence | macOS, Windows | no mitigation (recorded by the shell/OS) |
| File paths in argv | name + existence | macOS (`ps`), Windows (Event Log 4688) | passwords never in argv; paths visible; desktop app only via the Explorer integration |

## USB
FAT/exFAT deleted directory entries, NTFS resident files, system folders and wear levelling →
no physical guarantee; `--format` gives no controller-level guarantee; read-back is labelled
"verified from cache" if unmounting failed; `is_removable` is inconsistent across systems;
external USB SSDs/HDDs reporting as "fixed" are not supported; a TOCTOU window remains between
re-checking the identity and the call; system, boot and Time Machine volumes are excluded.
- macOS `diskutil` does not report serial numbers: a serial is required only on Windows. The
  macOS physical identity is `MediaName|DiskUUID|ParentWholeDisk` + size + `st_dev`, and erasing
  is done by volume UUID.
- Windows remount (`FSCTL_DISMOUNT_VOLUME`) is not implemented: read-back is always labelled
  "verified from cache".
- `diskutil` key names were checked against internal-disk output; their values on a USB stick,
  Windows `STORAGE_DEVICE_DESCRIPTOR` fields on a USB stick, and the end-to-end behaviour of
  `diskutil eraseVolume` and `Format-Volume -Path` are **not verified on real hardware**.
- PowerShell `Format-Volume` values are not embedded in the command string; they are read from
  the child process's environment. The `powershell.exe` signature (`WinVerifyTrust`) is not
  checked.
- Free-space filling uses a ChaCha20 key stream (a separate nonce per file, ≤ 64 GiB per file).

## Desktop app
- The egui/winit event queue (`Event::Text`) and IME composition create heap copies of the
  password text; the zeroizing global allocator wipes them when freed, but nothing is guaranteed
  before they are freed or for stack/register copies. OS keyboard logging and accessibility
  tools are out of scope. On macOS the password field enables Secure Event Input while focused.
- The clipboard is disabled (no `clipboard` feature; the password field swallows copy, cut and
  paste events).
- No persistent settings (`persistence`); window position and recent paths are not written to
  disk.
- Opening files from the operating system: on macOS through the open-documents event
  (double-click on `.lphy`, Finder "Open With", drop on the Dock icon, and the optional Finder
  Quick Action), handled by a method that `lephy-sys` adds to the window library's application
  delegate. The Quick Action is a workflow in `~/Library/Services/lephycrypy+.workflow` that runs
  only `/usr/bin/open -b <bundle id>` with the selected paths; the app removes it only while it
  still carries the app's marker, and never touches another workflow of the same name. On Windows the optional
  Explorer integration (added and removed from the app, after confirmation, in `HKCU` only)
  starts the app with `--open "<absolute path>"`; this is the only argument the app accepts. The
  path is then visible to other processes of the same user in the process list. A received path
  is only shown as the selected source; nothing is encrypted or decrypted without the user's
  password and click.
  When an item is already chosen in the desktop app, a request from the operating system does
  not replace it: the app shows the request and waits for **Replace** or **Ignore**, so another
  program of the same user cannot swap the item after a password was typed.
- The "Copy" link for a public key uses the system tool (`pbcopy`, `clip.exe`) with an empty
  environment; the app itself still has no clipboard access, so a password cannot reach it.
- The app does not offer `--strict`, restoring symbolic links or `--rename-conflicts` (safe
  defaults); use the command line for these.
- Supply chain: the egui/eframe tree adds about 400 crates (most `cargo vet` exemptions); the
  core is checked separately in the strict tier (deny.toml with `--exclude lephy-gui`).

## Archive
The early case-folding warning uses `char::to_lowercase` (full equivalence with CaseFolding.txt
C+S is UNVERIFIED); the file system is the authority. The writer passes frame data through a
zeroized intermediate buffer of at most 1 MiB. Applying mtime and permissions is best effort
(failures are silent). There is no temp-directory ACL restriction on Windows. Extended
attributes, ACLs, resource forks, ownership, hard links (stored as copies), FIFOs, sockets and
devices are not supported; `--stdout` can leave partial output. Symbolic links are not restored
by default; `--restore-symlinks` restores only relative targets without `..`; links restored with
`--restore-symlinks=unsafe` can point outside the destination for other programs after
extraction (warning); on Windows without privilege or Developer Mode they cannot be created and
the tree is incomplete.

## Downloaded-file marks and stored names
A `.lphy` file downloaded from the internet carries the operating system's download mark (macOS
`com.apple.quarantine`, Windows `Zone.Identifier`, "Mark of the Web"). When such a file is
decrypted to a path, the same mark is copied to every file (and, on macOS, every folder) that
comes out of it, so Gatekeeper and SmartScreen still check a program before it runs. Before this,
an encrypted file was a way to strip the mark. Limits: an unmarked `.lphy` file (made locally,
copied from a USB stick, or received through a program that does not mark downloads) produces
unmarked output; `--stdout` output is not marked; a failure to set the mark is reported as a
warning, not an error.

When a single file comes back under its stored name, the name was chosen by whoever encrypted
it. Characters that reorder or hide text (bidirectional controls such as U+202E, zero-width
marks) and control characters are replaced with `_`, so a name cannot pose as a different
extension. The app warns when the output contains programs (by name, such as `.app`, `.command`,
`.exe`, `.ps1`, or by the executable bit).

## Recipient (public-key) encryption
A file encrypted to public keys can be opened by the holder of any listed identity; there is no
password to guess, but the identity file is only as strong as its own password. Encryption is
anonymous to an observer: recipients' public keys are not stored, though the number of
recipients is visible in the header. Unless the file is signed, the sender is not
authenticated — anyone who knows a recipient's public key can create a file for them, so an
unsigned file proves nothing about who made it. A signed file (`encrypt --sign`) proves that the
holder of the signing identity produced exactly this content; check the signer with
`--expect-signer` (or compare the `lphysig1…` key shown) rather than trusting any valid signature.
A signature does not hide that a file is signed from someone who can open it, and it cannot be
revoked: a stolen identity can sign anything. A recipient who can open the file can also learn the file key and could re-encrypt different
content for the other recipients. `rekey`/`reencrypt` do not apply to these files; instead any
recipient can replace the recipient list (`recipients`). That keeps the file key, so removing a
recipient only stops access to the new file: a removed recipient who kept a copy of the old file,
or noted its file key, can still read the content.
The paper backup (22 words) is the identity secret itself, without a password: whoever reads it can
open every file encrypted to that key. It is shown only on request (the CLI refuses to print it
into a pipe or file without `--force`; the app shows it masked until hovered, once). Identity
files are refused as decryption input, so the secret key is never written to disk unprotected. Classic recipient files
have no post-quantum protection: a future quantum computer that records the file could recover the file
key from the stanzas.
Files encrypted with `--pq` (or "Post-quantum" in the app) use hybrid ML-KEM-768 + X25519
stanzas: recovering the file key needs breaking both, so a recorded file stays safe against a
quantum computer as long as ML-KEM-768 holds, and against classical attacks as long as X25519
holds. Password files are not affected by quantum computers beyond Grover's square-root speed-up
on the password guessing, which the 256-bit keys absorb. Signatures (Ed25519) are not
post-quantum: they would only let a future attacker forge new signed files, not read old ones.

## Error correction and recovery
The Reed–Solomon envelope protects against accidental damage only; it adds no secrecy or
authenticity. An attacker can rewrite it at will, and every repaired byte is still checked by
STREAM authentication. Recovery mode deliberately writes output that failed authentication
(damaged chunks replaced with zeros) to a new `.recovered` path and lists the damaged chunks; its
output must be treated as untrusted and possibly incomplete.

## Compression
The compressed size reveals information about the content, especially when an attacker controls
part of the input (CRIME/BREACH style). PADMÉ reduces but does not remove this. Compression is
off by default.

## App settings and app lock

The desktop app saves a small settings file (`~/Library/Application Support/lephycrypy+/settings`,
mode `0600`; Windows `%APPDATA%\lephycrypy+`): the language, whether the welcome screen was seen
and, only if the user turns the lock on, `salt ‖ HKDF(Argon2id(password, salt, 64 MiB, t = 3))`.
No file names, paths or passwords are written. The lock verifier is also stored in the system
credential store (macOS login keychain, generic password "app-lock" / account "lephycrypy+";
Windows Credential Manager, "lephycrypy+/app-lock"), and that copy wins over the file: deleting
the settings file does not remove the lock, and writing another verifier into it does not replace
it. Password checks run off the UI thread, and each wrong password doubles the wait before the
next try (1 s up to 30 s; the counter resets when the app restarts).

The app lock is a convenience against casual use of an unlocked computer, not protection for
data. A program running as the same user can still delete the keychain or Credential Manager item
(on macOS possibly after a keychain prompt) together with the file, and the encrypted files never
depend on the lock. An attacker with the verifier can try to guess the lock password offline at
the Argon2id cost; use a password that is not used elsewhere. If the password is forgotten,
deleting both the credential-store item and the settings file removes the lock.

Closing the window hides the app (macOS) or minimises it while a job runs (Windows); a job keeps
running. Quitting with Cmd+Q or Dock → Quit asks first while a job runs and then cancels it, so
the partial output is deleted as with Cancel.

## Not implemented: Touch ID / Windows Hello unlock

Unlocking an identity with Touch ID or Windows Hello was evaluated (November 2026) and left out,
because without a signed release it would only look secure:

- macOS: a keychain item whose access control requires biometry needs the Data Protection
  keychain, which refuses apps without a Developer ID team entitlement (`errSecMissingEntitlement`,
  −34018). In the legacy file keychain the same access control is accepted but not enforced: the
  item was read back without any Touch ID prompt.
- Windows: DPAPI protects data for the user account, not for Windows Hello; a Hello consent dialog
  in front of it would not stop another process of the same user from decrypting it. Binding to
  Hello needs `KeyCredentialManager` (WinRT), which the project does not use.

It can be revisited together with signed releases. Until then the identity file's password is the
only protection, and the paper backup is the recovery path.

## Other
Weak passwords; a key file is only an additional factor. Linux is best effort: it is not tested,
and Linux-specific protections (MADV_DONTDUMP, PR_SET_DUMPABLE, renameat2) are considered
unverified. **No independent cryptographic audit has been done yet.**
