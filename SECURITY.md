# Security model

## Current boundary

This repository implements an experimental, read-only reader for a narrow
VeraCrypt profile: AES-256-XTS, PBKDF2-HMAC-SHA-512 with 500,000 iterations,
and FAT32 or exFAT. Creation, mutation, NTFS, keyfiles, custom PIM, hidden
volumes and root/FUSE mounting are not security-reviewed capabilities and are
not exposed by the Android API or UI.

## Protected assets

- Container passwords and derived/header master keys
- Decrypted filesystem metadata and file contents
- The integrity and availability of the original container
- Release signing material

Passwords are passed as mutable UTF-8 byte arrays and cleared by the caller.
Native derived keys and session keys are wiped on every failure and close path.
The native layer owns a duplicated read-only descriptor per opaque session.

## Trust assumptions

- Android, the app sandbox, kernel, device firmware and selected document
  provider are trusted.
- A rooted, debug-compromised or physically compromised unlocked device is
  outside the confidentiality boundary.
- An external viewer is trusted by the user only after the plaintext warning.
- CI administrators and GitHub release-secret maintainers are trusted.

## Important limitations

- XTS encrypts sectors but does not authenticate them. A modified container can
  produce modified plaintext; parser bounds checks reduce memory-safety risk but
  do not create cryptographic integrity.
- Decrypted bytes necessarily exist in process and pipe buffers. Android may
  schedule or snapshot process memory outside this app's control.
- External preview transfers plaintext to another application, which may retain
  or upload it. Grants are read-only and scoped to the selected content URI.
- A process restart expires the in-memory mount. The provider fails closed and
  requires the user to reopen the container.
- No independent cryptography/native-code audit has been completed. Production
  release is blocked until that review and all P0/P1 findings are closed.

## Parser and provider controls

- Header, sector and filesystem arithmetic uses checked bounds before I/O.
- FAT32/exFAT cluster chains have cycle and maximum-length guards.
- FAT32 LFN and exFAT entry-set checksums and UTF-16 are validated.
- exFAT boot regions, allocation bitmap metadata and upcase checksum are
  validated before data is exposed.
- Document IDs are normalized and resolved from the active session for every
  metadata or open request; cache contents are never authoritative.
- Unmount cancels reliable-pipe streams before closing and wiping the session.
- Release native logging is disabled; passwords, keys and private paths must
  never be logged in any build.

## Release and reporting

Release signing reads only `VERACRYPT_*` environment variables. CI actions are
pinned to immutable commits and CI performs secret, dependency/license and SBOM
checks. Report suspected vulnerabilities privately to the repository owner;
do not include real containers, passwords, keys or decrypted user data.
