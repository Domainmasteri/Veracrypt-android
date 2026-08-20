# Supported features

This file is the authoritative capability boundary for the current build.
Anything not explicitly listed as supported must fail closed as unsupported.

## Supported and enabled

| Area | Scope | Mode |
|---|---|---|
| Header | VeraCrypt `VERA` version 5 header | Read-only |
| Cipher | AES-256-XTS | Read-only |
| KDF/PRF | PBKDF2-HMAC-SHA-512, 500,000 iterations | Read-only |
| Filesystem | FAT32 | Read-only, under active hardening |
| Filesystem | exFAT | Read-only, under active hardening |
| Android SAF | Listing and streaming existing files | Read-only |
| Preview | Pipe-based plaintext stream to a selected viewer | Read-only |

The FAT32 and exFAT readers are experimental until the interoperability,
corruption and fuzz test matrices in `veracrypt_roadmap.md` are complete.

## Explicitly unsupported

- Creating or formatting containers
- Writing, importing, deleting, renaming or truncating files
- NTFS listing, reading, writing or formatting
- Root or FUSE mounting
- Keyfiles, custom PIM values and hidden volumes
- TrueCrypt headers, non-AES ciphers and cipher cascades
- PRFs other than HMAC-SHA-512
- Recovery from a damaged header or filesystem

Unsupported mutation and mount operations are absent from the public Kotlin/JNI
API. Unsupported readable formats fail closed and never modify the selected
container.

## Security boundary

- File data encrypted with XTS is not authenticated; deliberate modification
  may not be detected.
- The application decrypts data in process memory.
- External preview grants another application access to the plaintext stream.
- Rooted or compromised devices are outside the trust boundary.
- The implementation has not yet completed an independent security audit.
