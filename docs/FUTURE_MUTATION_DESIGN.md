# Gated design for creation, writes, NTFS and FUSE

This is a design gate, not a supported feature specification. None of these
interfaces may be reintroduced until the read-only milestone has passed an
independent audit and the relevant design has a separate approval record.

## Container creation

Use a maintained, license-compatible formatter with a documented security and
interoperability history. Do not revive the removed boot-signature-only code.
The implementation must build a complete image in app-private temporary
storage, obtain all key material from Android `SecureRandom` without fallback,
write a complete VeraCrypt header and filesystem, `fsync`, close, reopen, list,
perform a write/reopen verification, and only then copy/commit to the target
SAF URI. Failure injection is required at every write, flush, close and publish
boundary. NTFS is excluded.

## Filesystem mutation

Define create/overwrite/append/truncate/delete/rename and collision semantics
before an API exists. FAT32 must update every FAT copy, FSInfo and directory
metadata transactionally. exFAT must update the allocation bitmap, FAT or
NoFatChain state, stream extension, entry-set checksums and free-space metadata.
An interruption-recovery protocol and full-disk/power-loss test matrix are
mandatory. Read-only SAF flags remain unchanged until all acceptance tests pass.

## NTFS

Only a separately audited, license-compatible read-only library integration may
be proposed. A handwritten extension of the current parser is rejected.
Writing requires full journal/recovery semantics and is outside this roadmap.

## Root/FUSE

Any future daemon uses an argument-vector or binder protocol, never a shell
command. It must expose decrypted filesystem contents, enforce an allowlisted
mount root and least-privilege plaintext permissions, bind sessions to caller
identity, and reliably unmount/erase state after crash or process death. A bind
mount of the encrypted container is not a VeraCrypt mount and is forbidden.
