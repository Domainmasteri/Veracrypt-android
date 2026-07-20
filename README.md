# VeraCrypt Android (Read-Only MVP)

A multi-module Android proof-of-concept for opening and reading VeraCrypt/TrueCrypt containers in **read-only** mode.

[![Android CI](https://github.com/Domainmasteri/Veracrypt-android/actions/workflows/ci.yml/badge.svg)](https://github.com/Domainmasteri/Veracrypt-android/actions/workflows/ci.yml)

## Modules

| Module | Description |
|---|---|
| `:app` | Android application shell – file picker UI using SAF |
| `:core-api` | Kotlin interfaces and data models (`VolumeHeader`, `ContainerReader`) |
| `:core-native` | C++17/JNI bridge – NDK library for header parsing (`veracrypt-native.so`) |
| `:provider-saf` | `DocumentsProvider` skeleton exposing container contents via SAF |

## Requirements

| Tool | Version |
|---|---|
| JDK | 17 |
| Android SDK | API 35 |
| Android NDK | 27.x |
| Gradle | 8.11.1 (via wrapper) |
| AGP | 8.7.3 |
| Kotlin | 2.0.21 |

## Build locally

```bash
# Clone
git clone https://github.com/Domainmasteri/Veracrypt-android.git
cd Veracrypt-android

# Build debug APK (compiles C++ via NDK automatically)
./gradlew :app:assembleDebug

# Run unit tests
./gradlew :core-api:test :app:testDebugUnitTest

# Install on a connected device/emulator
./gradlew :app:installDebug
```

The compiled APK is written to `app/build/outputs/apk/debug/`.

## CI Artifacts

Every push to `main` or a `feat/**` / `fix/**` branch triggers the **Android CI** workflow.
The debug APK is uploaded as an Actions artifact (`veracrypt-android-debug`) with a 14-day
retention period and can be downloaded directly from the **Actions** tab for on-device testing.

## Architecture

```
:app  ──depends──►  :core-native  ──depends──►  :core-api
 │                                                  ▲
 └──depends──►  :provider-saf  ──depends──────────┘
                      │
                      └──depends──►  :core-native
```

## Roadmap

- [ ] Wire real PBKDF2 + AES-XTS decryption in `core-native`
- [ ] Implement FAT/exFAT filesystem traversal via NDK
- [ ] Complete `ContainerReader` implementation
- [ ] Full `DocumentsProvider` cursor and read-stream support
- [ ] Password/keyfile entry UI
- [ ] Keystore-backed passphrase storage
