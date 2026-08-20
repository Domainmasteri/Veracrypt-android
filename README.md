# VeraCrypt Android

Experimental, read-only Android client for a deliberately limited subset of
VeraCrypt containers. This is an independent project and is not an official
VeraCrypt distribution.

## Supported scope

- Header decryption: AES-256-XTS with PBKDF2-HMAC-SHA-512 (500,000 iterations)
- Filesystems: FAT32 and exFAT, read-only
- Access: in-app browser, read-only SAF `DocumentsProvider`, and read-only
  streaming to an external viewer
- Android: minSdk 26, target/compileSdk 35

Container creation, all filesystem writes, NTFS access, keyfiles, custom PIM,
hidden volumes, cipher cascades, and root/FUSE mounting are not supported.
See [SUPPORTED_FEATURES.md](SUPPORTED_FEATURES.md) for the authoritative matrix
and security limitations.

## Modules

| Module | Responsibility |
|---|---|
| `:app` | Read-only container selection and file browser |
| `:core-api` | Shared models and contracts |
| `:core-native` | Native header, crypto and read-only filesystem engine |
| `:provider-saf` | Read-only SAF provider |

## Local build

Requirements:

- JDK 17
- Android SDK API 35
- Android NDK 27+

```bash
./gradlew :app:assembleDebug
./gradlew :core-api:test :app:testDebugUnitTest
./gradlew :core-native:connectedAndroidTest :app:connectedDebugAndroidTest
./gradlew :core-native:assembleDebug -PveracryptSanitizers=true
```

## Release signing

Release signing is configured exclusively through environment variables. No
signing secret is read from `local.properties` or another properties file.

```bash
export VERACRYPT_KEYSTORE_PATH=/absolute/path/to/keystore.jks
export VERACRYPT_KEYSTORE_PASSWORD='...'
export VERACRYPT_KEY_ALIAS='...'
export VERACRYPT_KEY_PASSWORD='...'
./gradlew :app:assembleRelease
```

## Security status

This code has not completed an independent cryptographic or native-code audit.
VeraCrypt's XTS data encryption does not authenticate file contents. Opening a
file in an external viewer discloses its plaintext to that application. Do not
use this build as the only means of accessing irreplaceable data.
See [SECURITY.md](SECURITY.md) for the full threat model and reporting guidance.

## Credits and licensing

The VeraCrypt format and cryptographic design belong to the VeraCrypt project.
Review all upstream and dependency licenses before redistribution.
