# Security policy

lephycrypy+ has not yet had an independent cryptographic audit (see docs/THREAT-MODEL.md › Other).
No pre-1.0 release is recommended for production data. The November 2026 internal review is
summarised in [docs/SECURITY-REVIEW-2026-11.md](docs/SECURITY-REVIEW-2026-11.md).

## Reporting a vulnerability

- Please **do not** open a public issue for a vulnerability.
- Use GitHub's "Report a vulnerability" (private security advisories) on this repository.
- Target: first response within 7 days, coordinated disclosure within 90 days.

## In scope

- Format (docs/FORMAT.md) and key-derivation flaws, including recipient (public-key) encryption
- Secret residue in memory
- Archive extraction (zip-slip, symbolic links, duplicate names) and atomic-write violations
- USB mode erasing or writing the wrong device
- Operating-system integration (file associations, `--open` handling)
- Supply chain (deny.toml, supply-chain/)

Out of scope: items that docs/THREAT-MODEL.md explicitly marks as out of scope or "no
mitigation" (hibernation, swap, OS indexing, cloud sync, SIGKILL, and so on).

## Supported versions

| Version | Support |
|---|---|
| 0.x | development only; no support |
