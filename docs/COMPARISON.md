# How lephycrypy+ compares

This page compares lephycrypy+ with other open-source tools so you can choose the right one. It
tries to be fair: each tool is good at different things, and several are more mature than
lephycrypy+. Facts about other projects were checked against the sources listed at the end in
November 2026; features change, so check the projects themselves before deciding.

## At a glance

| | lephycrypy+ | age / rage | Picocrypt | VeraCrypt | Cryptomator |
|---|---|---|---|---|---|
| What it encrypts | files and folders → one file | a byte stream (folders via `tar`) | files and folders → one file | containers and whole disks | a folder ("vault"), file by file |
| Typical use | archives, backups, sending files | pipelines, sending files | archives | disks, mounted volumes | cloud-synced folders |
| Password KDF | Argon2id (512 MiB default) | scrypt | Argon2id | PBKDF2 (newer releases add options; see the project) | scrypt |
| Public-key recipients | X25519 | X25519, SSH keys, post-quantum hybrid, plugins | no | no | no |
| Key files | yes (plus password) | — | yes (also alone) | yes | no |
| Names and structure hidden | always | needs `tar` | yes | yes (inside the container) | yes |
| Size hiding | PADMÉ by default | no | no | fixed container size | no |
| Error correction | Reed–Solomon (optional) | no | Reed–Solomon (optional) | no | no |
| Recover from damaged file | yes | no | yes (forced decryption) | no | no |
| Split into parts | yes | no | yes | no | — |
| Compression | optional | no | optional | no | no |
| Mount as a drive | no | no | no | yes | yes |
| Desktop app | macOS, Windows | no (CLI) | yes | yes | yes, plus mobile |
| Independent audit | **no** | not stated in the README | yes | yes (2016) | yes (crypto libraries) |
| Status | pre-1.0 | stable | archived (read-only since Sep 2025) | stable | stable |

"—" means not applicable.

## When to use something else

- **You need a mounted drive or full-disk encryption:** VeraCrypt (or your OS's built-in disk
  encryption). lephycrypy+ produces files; it does not mount anything.
- **You keep working files in a cloud folder:** Cryptomator encrypts each file separately so sync
  stays efficient; lephycrypy+ re-creates the whole archive.
- **You need a widely implemented, stable format with SSH keys, hardware keys or post-quantum
  recipients:** age/rage. The age format has several independent implementations and a published
  specification.
- **You need an audited tool today:** lephycrypy+ has not been audited by an independent party.

## Where lephycrypy+ is different

- **Passwords and folders first.** Names and folder structure are always encrypted inside the
  archive, the size is padded by default (PADMÉ) and the default output name is random.
- **Memory-hard key derivation by default.** Argon2id with 512 MiB; the parameters are checked
  against the machine's memory before use.
- **Damage tolerance and recovery** without giving up authentication: the Reed–Solomon layer only
  repairs, every byte is still authenticated, and recovery output always goes to a new file.
- **USB mode.** Wipe a removable USB stick and write only the encrypted file, with identity checks
  before each destructive step.
- **Engineering.** All `unsafe` code in one small crate; the format is specified in
  [FORMAT.md](FORMAT.md) and checked byte for byte against an independent Python implementation;
  fuzzing; supply-chain checks (`cargo deny`, `cargo audit`, `cargo vet`) in CI.
- **Picocrypt's successor niche.** Picocrypt was archived in September 2025. lephycrypy+ offers
  a similar feature set (Argon2id, key files, Reed–Solomon, splitting, compression, recovery) in a
  maintained project, but with its own file format — it cannot open Picocrypt volumes.

## Sources

- age: <https://github.com/FiloSottile/age> and the specification
  <https://github.com/C2SP/C2SP/blob/main/age.md>
- Picocrypt: <https://github.com/Picocrypt/Picocrypt> (archived notice, features, audit link)
- VeraCrypt audit by Quarkslab, funded by OSTIF (VeraCrypt 1.18, 2016):
  <https://blog.quarkslab.com/security-assessment-of-veracrypt-fixes-and-evolutions-from-truecrypt.html>
- Cryptomator audit by Cure53 (scope: the cryptographic libraries), as summarised by Privacy
  Guides: <https://www.privacyguides.org/en/encryption/>
