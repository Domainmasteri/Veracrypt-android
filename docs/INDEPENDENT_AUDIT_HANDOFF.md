# Independent read-only security audit handoff

This document defines the evidence required to unlock roadmap phase 8. It does
not claim that an independent audit has happened.

## Frozen product boundary

Only VeraCrypt version-5 headers using AES-256-XTS and
PBKDF2-HMAC-SHA-512/500,000 iterations are in scope. FAT32 and exFAT are
read-only. Create, write, NTFS, keyfiles, custom PIM, hidden volumes and
root/FUSE are absent from the public Kotlin/JNI API. Any finding that exposes a
mutation path or advertises one through SAF is release-blocking.

## Reviewer focus

1. Verify SHA-512, HMAC, PBKDF2, AES-256 and XTS implementation, vectors,
   constant-time comparisons, key lifetime and compiler-resistant wiping.
2. Review header version/CRC/geometry/error classification and all checked
   arithmetic before `pread64`.
3. Review opaque session handles, descriptor duplication, concurrent close,
   handle lookup/removal and thread-local parser context.
4. Review FAT32 BPB/FSInfo/backup boot, FAT values/cycles, LFN sequencing and
   UTF-16 conversion.
5. Review exFAT boot regions, flags, bitmap/upcase metadata, FAT/NoFatChain,
   entry-set checksums and 64-bit sizes.
6. Review DocumentsProvider IDs, URI grants, modes, cancellation, unmount,
   process-state loss and plaintext preview disclosure.
7. Review release manifest/logging/signing and pinned CI supply-chain controls.

## Reproduction commands

```bash
./gradlew :app:assembleDebug :core-api:test :app:testDebugUnitTest
./gradlew :core-native:assembleAndroidTest :app:assembleDebugAndroidTest
./gradlew :core-native:assembleDebug -PveracryptSanitizers=true
cmake -S core-native/fuzz -B build/fuzz -DCMAKE_CXX_COMPILER=clang++
cmake --build build/fuzz --parallel
ctest --test-dir build/fuzz --output-on-failure
build/fuzz/bpb_fuzzer -runs=50000 -max_len=4096 -dict=core-native/fuzz/bpb.dict
build/fuzz/fat_fuzzer -runs=50000 -max_len=4096
build/fuzz/directory_fuzzer -runs=50000 -max_len=4096 -dict=core-native/fuzz/directory.dict
```

Instrumented tests must additionally pass on both configured ABIs. Release
signing tests use only the four documented `VERACRYPT_*` environment variables.

## Exit criteria

The auditor must identify the reviewed commit, toolchain and corpus digests.
Every P0/P1 finding needs a regression test, a reviewed correction and explicit
closure by the auditor. CI must be a required branch-protection check. Until
those external facts are recorded, production publication and roadmap phases
9–11 remain blocked regardless of local build success.
