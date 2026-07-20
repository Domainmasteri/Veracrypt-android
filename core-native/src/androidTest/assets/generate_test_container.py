#!/usr/bin/env python3
"""
generate_test_container.py
──────────────────────────
Generates a minimal 512-byte VeraCrypt header (single sector) that is used
as a test fixture for NativeBridgeParseHeaderTest.

Requirements:
    pip install cryptography

Output:
    core-native/src/androidTest/assets/test.vc  (512 bytes)

Container parameters
──────────────────────
  Cipher     : AES-256-XTS
  PRF        : PBKDF2-HMAC-SHA512
  Iterations : 500 000
  Password   : "test"
  Salt       : fixed 64-byte value (see SALT below) – reproducible builds
  SHA-256    : b71651db848746d13e2b64c2f6d628b34ab74ca7f723006ef380a5e02212687a
"""

import hashlib, struct, time, zlib
from pathlib import Path
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend

PASSWORD   = b"test"
ITERATIONS = 500_000

# Fixed 64-byte salt (reproducible across runs)
SALT = bytes.fromhex(
    "a3b4c5d6e7f80102030405060708090a0b0c0d0e0f101112131415161718191a"
    "1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a"
)
assert len(SALT) == 64

# ── Key derivation ──────────────────────────────────────────────────────────
print(f"Deriving key (PBKDF2-HMAC-SHA512, {ITERATIONS:,} iterations)…")
t0  = time.time()
key = hashlib.pbkdf2_hmac("sha512", PASSWORD, SALT, ITERATIONS, dklen=64)
print(f"Done in {time.time()-t0:.2f}s")
key1, key2 = key[:32], key[32:]

# ── Build plaintext header (448 bytes) ─────────────────────────────────────
p = bytearray(448)
p[0:4]  = b"VERA"
struct.pack_into(">H", p, 4,  5)          # format version
struct.pack_into(">H", p, 6,  0x010b)     # min program version (1.11)
# bytes  8-11: CRC32 of master-keys area (p[192:448]) – computed below
# bytes 12-27: reserved (zeros)
# bytes 28-35: hidden volume size = 0
struct.pack_into(">Q", p, 36, 1 * 1024 * 1024)  # volume size 1 MiB
struct.pack_into(">Q", p, 44, 0)                 # key-scope offset
struct.pack_into(">Q", p, 52, 1 * 1024 * 1024)  # encrypted-area size
# bytes 60-63: flags = 0
struct.pack_into(">I", p, 64, 512)               # sector size

# bytes 68-187: reserved (zeros)
# bytes 192-447: master keys = zeros (test container, not used for decryption)

crc_keys = zlib.crc32(bytes(p[192:448])) & 0xFFFFFFFF
struct.pack_into(">I", p, 8, crc_keys)            # store at offset 8

crc_hdr = zlib.crc32(bytes(p[0:188])) & 0xFFFFFFFF
struct.pack_into(">I", p, 188, crc_hdr)           # store at offset 188

# ── Encrypt with AES-256-XTS (data unit 0, tweak = 16 zero bytes) ──────────
tweak  = bytes(16)
cipher = Cipher(
    algorithms.AES(key1 + key2),
    modes.XTS(tweak),
    backend=default_backend()
)
ciphertext = cipher.encryptor().update(bytes(p))
assert len(ciphertext) == 448

# ── Assemble 512-byte header ─────────────────────────────────────────────────
header = SALT + ciphertext
assert len(header) == 512

out = Path(__file__).parent / "test.vc"
out.write_bytes(header)

sha256 = hashlib.sha256(header).hexdigest()
print(f"Written {out}  ({len(header)} bytes)")
print(f"SHA-256: {sha256}")
expected = "b71651db848746d13e2b64c2f6d628b34ab74ca7f723006ef380a5e02212687a"
assert sha256 == expected, f"SHA-256 mismatch!\n  got      {sha256}\n  expected {expected}"
print("SHA-256 matches ✓")
