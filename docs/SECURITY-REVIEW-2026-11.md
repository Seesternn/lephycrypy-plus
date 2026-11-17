# Internal security review — November 2026

> **This is an internal review, not an independent audit.** It was carried out by the project
> itself before the first release. It does not replace a third-party cryptographic audit, which
> is still planned before 1.0.

## Scope

- `lephy-core`: key derivation, header, STREAM pipeline, archive writer and extractor, padding,
  password and key-file handling, atomic writes, `rekey` / `reencrypt`.
- `lephy-sys`: every `unsafe` block (locked memory, zeroizing allocator, signals, terminal,
  file system, volume identity).
- `lephy-usb`: device eligibility, identity checks, wipe, format, fill, write and read-back.
- `lephy-gui`: password field, background job, cancellation, process spawning.
- Supply chain and CI: dependency policy, `cargo-vet`, `cargo-deny`, `cargo-audit`, workflows,
  release and packaging scripts.

## Summary

No critical or high-severity issue was found. The cryptographic core held up:

- nonces never repeat and the chunk counter cannot wrap;
- truncation, reordering and extension are detected;
- header tampering and key-derivation downgrades are rejected before any plaintext is produced;
- key commitment and MAC comparisons are constant-time;
- extraction is confined to its folder through `cap-std`.

The issues below were all in file handling, platform integration and process hygiene. Every
finding listed here is fixed in the commits named in the table.

## Findings

| ID | Severity | Area | Finding | Fix |
|---|---|---|---|---|
| C1 | Medium | CLI / core | `--delete-original` removed the whole source tree, including entries that had been skipped and never encrypted. | Only archived entries are deleted, each re-checked by device and inode; nothing is deleted when anything was skipped. |
| C2 | Medium | core | The extraction temp folder was named `<output>.lphy-tmp-*`, so `cleanup` never found plaintext left after a crash, and the name leaked the output name. | Named `.lphy-tmp-*`, created with mode `0700`. |
| M1 | Medium | USB | Wipe skipped `.Trashes`, `.Spotlight-V100`, `.fseventsd` and `System Volume Information`, which can hold deleted files and indexed text. | Their contents are removed and listed in the dry run. |
| M2 | Medium | USB | The identity check and the destructive step resolved the device by path, leaving a window for another device to appear at the same mount point. | Identity is compared on the opened root handle; macOS formatting targets the volume UUID. |
| M3 | Medium | supply chain | Most dependencies, including all cryptographic crates, were covered only by `cargo-vet` exemptions, and CI compared only the count. | More audit sources imported and exemptions pruned; CI now diffs exempted crate names. |
| C3 | Low | core | `rekey` / `reencrypt` on a symlink or hard link replaced the link and left the old header under the real name. | Symlinks and multiply linked files are refused; permissions are preserved. |
| C4 | Low | core | `decrypt --force` deleted the existing target before moving the new one in. | Backup-swap with rollback. |
| C5 | Low | core | Extracted modes could be `0777`. | Masked to `0755`. |
| C6 | Low | core | The source tree was read by path; an entry swapped for a symlink mid-run could pull data from outside the folder. | Walked through a directory handle; metadata from the opened file. |
| C7 | Low | core | When physical RAM could not be measured, the KDF memory check was skipped. | Fails closed above 1 GiB. |
| C8 | Low | core | Copies of keys and the key-file digest stayed in unwiped memory. | Borrowed without copying; digest wrapped in `Zeroizing`. |
| C9 | Low | core | `reencrypt` moved plaintext chunks through ordinary heap memory. | Runs inside the locked pipeline pool. |
| C10 | Low | core | The temp folder was created with the umask and only then restricted. | Created directly with mode `0700`. |
| C11 | Info | core | The "symlink target is one frame" rule was not enforced. | Enforced. |
| C12 | Info | core | `verify` checked only the authentication tags. | Also validates archive structure and padding, without writing. |
| P1 | Low | GUI | Cancel pressed while the source size was measured was lost. | The flag is reset before the job starts. |
| P2 | Low | GUI / sys | In-app cancel shared the signal flag, so the next signal exited without cleanup. | Separate cancel flag. |
| P3 | Low | sys | The panic hook could zero a buffer another thread was unmapping. | Per-slot state machine. |
| P4 | Low | sys | The signal handler did not preserve `errno`. | Saved and restored. |
| P5 | Low | sys | A safe function took ownership of an arbitrary file descriptor. | Duplicates instead; internal descriptors refused. |
| P6 | Low | USB | Windows mapped a relative target to a drive by its first letter. | Only drive roots accepted. |
| P7 | Low | GUI / sys | The custom password field did not enable macOS secure keyboard input. | Enabled while focused. |
| P8 | Low | release | The SBOM tool was installed unpinned. | Pinned. |
| P9 | Low | packaging | The macOS bundle lacked the hardened runtime and embedded local paths. | Hardened runtime; paths remapped. |
| I1 | Info | GUI | "Show in folder" on Windows inherited the environment. | Environment cleared. |
| I2 | Info | config | Garbled text in `deny-gui.toml`; no review date on `cargo-audit` ignores. | Fixed; review date added. |

## Known limitations (unchanged)

These are documented in [THREAT-MODEL.md](THREAT-MODEL.md) and are not treated as findings:

- Hibernation, swap and OS indexing may keep plaintext.
- Physical deletion from SSDs and USB flash cannot be guaranteed.
- `--stdout` writes plaintext before the end-of-stream check.
- Text drawn by the GUI toolkit passes through ordinary heap memory; it is wiped on free by the
  zeroizing allocator.

## Not covered

- An independent review of the format and the cryptographic construction.
- Testing on real USB hardware and hands-on testing on Windows.
- Side channels below the level of constant-time comparisons (cache timing in third-party
  primitives).
