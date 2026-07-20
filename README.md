# VeraCrypt Android (Read-Only MVP)

This repository contains an Android proof-of-concept project for opening and reading VeraCrypt/TrueCrypt containers in **read-only** mode.

## Status

Initial repository bootstrap. Full project scaffold (multi-module Android + NDK/JNI + GitHub Actions CI) will be added next.

## Planned Modules

- `:app` — Android app UI shell
- `:core-api` — Kotlin interfaces and data models
- `:core-native` — C++/JNI bridge and NDK build
- `:provider-saf` — Storage Access Framework provider

## Planned CI

A GitHub Actions workflow will build the debug APK in the cloud (including native code) and upload it as an artifact for direct installation testing.
