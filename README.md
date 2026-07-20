# VeraCrypt Android

Android multi-module implementation for opening, creating, and modifying VeraCrypt-compatible containers with native cryptography and SAF integration.

[![Android CI](https://github.com/Domainmasteri/Veracrypt-android/actions/workflows/ci.yml/badge.svg)](https://github.com/Domainmasteri/Veracrypt-android/actions/workflows/ci.yml)

## Current capabilities

- Header parsing and key derivation in native C++ (PBKDF2-HMAC-SHA512 + AES-XTS)
- Read/list support for FAT32 and exFAT container filesystems
- Write pipeline for existing files (FAT32 full path writes, exFAT in-place writes)
- Cluster allocation primitives for FAT32/exFAT volumes
- Directory timestamp update support for FAT32 root entries
- Container creation flow in Android UI and JNI (entropy mixing, master key generation, encrypted header write)
- Filesystem selection at creation time: FAT32, exFAT, NTFS signatures
- Root/FUSE mount preparation hook for advanced rooted-device workflows
- SAF `DocumentsProvider` integration for read and write streaming
- CI pipeline for debug and signed release APK artifacts

## Modules

| Module | Responsibility |
|---|---|
| `:app` | Android UI flows (open/create container, root mount preparation) |
| `:core-api` | Shared Kotlin models and contracts |
| `:core-native` | Native C++ engine (crypto, filesystem parsing, write/create JNI) |
| `:provider-saf` | SAF provider for file browsing/streaming into mounted containers |

## Local build

Requirements:
- JDK 17
- Android SDK (API 35)
- Android NDK 27+

```bash
./gradlew :app:assembleDebug
./gradlew :core-api:test :app:testDebugUnitTest
```

## Signed release build (local)

Create `signing.properties` in the repository root:

```properties
KEYSTORE_PATH=/absolute/path/to/keystore.jks
KEYSTORE_PASSWORD=...
KEY_ALIAS=...
KEY_PASSWORD=...
```

Then run:

```bash
./gradlew :app:assembleRelease
```

## CI release pipeline

`.github/workflows/ci.yml` now includes a signed release APK job (non-PR events).  
Configure repository secrets:

- `KEYSTORE_BASE64`
- `KEYSTORE_PASSWORD`
- `KEY_ALIAS`
- `KEY_PASSWORD`

The workflow decodes the keystore and publishes `veracrypt-android-release` artifact.

## Root & FUSE integration

The app now includes a root/FUSE mount preparation action that validates mount metadata in native code.  
For production deployment, pair this hook with device-side root scripts or a dedicated FUSE daemon process.

## Security notes

- Passphrases are sent to JNI only for immediate derivation and not persisted intentionally.
- Header generation uses mixed entropy (`/dev/urandom` + caller entropy).
- Secret values for release signing are consumed from environment/secrets.

## Credits and licensing

- VeraCrypt project and cryptographic/container format design: **VeraCrypt Team**
- Current VeraCrypt maintainer/developer reference: **AMCrypto**
- NTFS ecosystem references: ntfs-3g project and public NTFS documentation

This repository is an independent Android implementation effort and is not an official VeraCrypt distribution.  
Review upstream VeraCrypt licensing terms and attribution requirements when redistributing derivatives.
