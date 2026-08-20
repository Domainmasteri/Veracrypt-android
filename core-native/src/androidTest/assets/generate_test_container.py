#!/usr/bin/env python3
"""
generate_test_container.py
──────────────────────────
Generates a minimal header plus one encrypted-area sector that is used
as a test fixture for NativeBridgeParseHeaderTest.

Requirements:
    pip install cryptography

Outputs:
    test.vc         Minimal header-only negative filesystem fixture
    fat32_test.vc   Deterministic nested FAT32 read-only fixture

Container parameters
──────────────────────
  Cipher     : AES-256-XTS
  PRF        : PBKDF2-HMAC-SHA512
  Iterations : 500 000
  Password   : "test"
  Salt       : fixed 64-byte value (see SALT below) – reproducible builds
  SHA-256    : updated by this script's reproducibility assertion
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
struct.pack_into(">Q", p, 36, 512)  # volume size
struct.pack_into(">Q", p, 44, 512)  # encrypted-area offset
struct.pack_into(">Q", p, 52, 512)  # encrypted-area size
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
container = header + bytes(512)

out = Path(__file__).parent / "test.vc"
out.write_bytes(container)

sha256 = hashlib.sha256(container).hexdigest()
print(f"Written {out}  ({len(container)} bytes)")
print(f"SHA-256: {sha256}")
expected = "b030a4c46cdad4393bc6f946c594c715441c27303c2b3220374ca33648d735f1"
assert sha256 == expected, f"SHA-256 mismatch!\n  got      {sha256}\n  expected {expected}"
print("SHA-256 matches ✓")


def make_lfn_entry(sequence, units, checksum, is_last):
    entry = bytearray(b"\xff" * 32)
    entry[0] = sequence | (0x40 if is_last else 0)
    entry[11] = 0x0F
    entry[12] = 0
    entry[13] = checksum
    entry[26:28] = b"\x00\x00"
    positions = [1, 3, 5, 7, 9, 14, 16, 18, 20, 22, 24, 28, 30]
    padded = list(units)
    if len(padded) < 13:
        padded.append(0)
        padded.extend([0xFFFF] * (13 - len(padded)))
    for position, unit in zip(positions, padded):
        struct.pack_into("<H", entry, position, unit)
    return entry


def short_name_checksum(name11):
    checksum = 0
    for value in name11:
        checksum = (((checksum & 1) << 7) + (checksum >> 1) + value) & 0xFF
    return checksum


def build_fat32_plaintext():
    sector_size = 512
    total_sectors = 512
    sectors_per_fat = 4
    first_data_sector = 32 + 2 * sectors_per_fat
    payload_size = 192 * 1024
    image = bytearray(total_sectors * sector_size)

    boot = memoryview(image)[0:sector_size]
    boot[0:3] = b"\xeb\x58\x90"
    boot[3:11] = b"MSWIN4.1"
    struct.pack_into("<H", boot, 11, sector_size)
    boot[13] = 1
    struct.pack_into("<H", boot, 14, 32)
    boot[16] = 2
    struct.pack_into("<H", boot, 17, 0)
    struct.pack_into("<H", boot, 19, 0)
    boot[21] = 0xF8
    struct.pack_into("<H", boot, 22, 0)
    struct.pack_into("<I", boot, 32, total_sectors)
    struct.pack_into("<I", boot, 36, sectors_per_fat)
    struct.pack_into("<I", boot, 44, 2)
    struct.pack_into("<H", boot, 48, 1)
    struct.pack_into("<H", boot, 50, 6)
    boot[510:512] = b"\x55\xaa"

    fsinfo = memoryview(image)[sector_size:2 * sector_size]
    struct.pack_into("<I", fsinfo, 0, 0x41615252)
    struct.pack_into("<I", fsinfo, 484, 0x61417272)
    cluster_count = total_sectors - first_data_sector
    payload_clusters = payload_size // sector_size
    struct.pack_into("<I", fsinfo, 488, cluster_count - payload_clusters - 2)
    struct.pack_into("<I", fsinfo, 492, 4 + payload_clusters)
    struct.pack_into("<I", fsinfo, 508, 0xAA550000)
    image[6 * sector_size:7 * sector_size] = image[0:sector_size]

    fat = bytearray(sectors_per_fat * sector_size)
    for cluster, value in enumerate([0x0FFFFFF8, 0x0FFFFFFF, 0x0FFFFFFF,
                                     0x0FFFFFFF]):
        struct.pack_into("<I", fat, cluster * 4, value)
    for cluster in range(4, 4 + payload_clusters):
        next_cluster = 0x0FFFFFFF if cluster == 3 + payload_clusters else cluster + 1
        struct.pack_into("<I", fat, cluster * 4, next_cluster)
    image[32 * sector_size:(32 + sectors_per_fat) * sector_size] = fat
    image[(32 + sectors_per_fat) * sector_size:first_data_sector * sector_size] = fat

    root = memoryview(image)[first_data_sector * sector_size:(first_data_sector + 1) * sector_size]
    root[0:11] = b"NESTED     "
    root[11] = 0x10
    struct.pack_into("<H", root, 26, 3)

    nested = memoryview(image)[(first_data_sector + 1) * sector_size:
                               (first_data_sector + 2) * sector_size]
    long_name = "hello-long-\U0001f600.txt"
    units = list(struct.unpack("<" + "H" * (len(long_name.encode("utf-16le")) // 2),
                               long_name.encode("utf-16le")))
    short_name = b"HELLO~1 TXT"
    checksum = short_name_checksum(short_name)
    chunks = [units[i:i + 13] for i in range(0, len(units), 13)]
    offset = 0
    for sequence in range(len(chunks), 0, -1):
        nested[offset:offset + 32] = make_lfn_entry(
            sequence, chunks[sequence - 1], checksum, sequence == len(chunks)
        )
        offset += 32
    nested[offset:offset + 11] = short_name
    nested[offset + 11] = 0x20
    struct.pack_into("<H", nested, offset + 26, 4)
    struct.pack_into("<I", nested, offset + 28, payload_size)

    payload = bytes((index * 17 + 3) & 0xFF for index in range(payload_size))
    payload_offset = (first_data_sector + 2) * sector_size
    image[payload_offset:payload_offset + payload_size] = payload
    return bytes(image), long_name, payload


def build_container(plaintext, master_keys, salt):
    derived = hashlib.pbkdf2_hmac("sha512", PASSWORD, salt, ITERATIONS, dklen=64)
    header_plain = bytearray(448)
    header_plain[0:4] = b"VERA"
    struct.pack_into(">H", header_plain, 4, 5)
    struct.pack_into(">H", header_plain, 6, 0x010B)
    struct.pack_into(">Q", header_plain, 36, len(plaintext))
    struct.pack_into(">Q", header_plain, 44, 512)
    struct.pack_into(">Q", header_plain, 52, len(plaintext))
    struct.pack_into(">I", header_plain, 64, 512)
    header_plain[192:192 + len(master_keys)] = master_keys
    struct.pack_into(">I", header_plain, 8,
                     zlib.crc32(header_plain[192:448]) & 0xFFFFFFFF)
    struct.pack_into(">I", header_plain, 188,
                     zlib.crc32(header_plain[0:188]) & 0xFFFFFFFF)
    header_cipher = Cipher(algorithms.AES(derived), modes.XTS(bytes(16)),
                           backend=default_backend()).encryptor().update(bytes(header_plain))

    encrypted_sectors = bytearray()
    for sector_number in range(len(plaintext) // 512):
        sector = plaintext[sector_number * 512:(sector_number + 1) * 512]
        tweak = sector_number.to_bytes(16, "little")
        encrypted_sectors.extend(
            Cipher(algorithms.AES(master_keys), modes.XTS(tweak),
                   backend=default_backend()).encryptor().update(sector)
        )
    return salt + header_cipher + bytes(encrypted_sectors)


fat_plaintext, fat_long_name, fat_payload = build_fat32_plaintext()
fat_master_keys = bytes(range(64))
fat_salt = bytes(range(64, 128))
fat_container = build_container(fat_plaintext, fat_master_keys, fat_salt)
fat_out = Path(__file__).parent / "fat32_test.vc"
fat_out.write_bytes(fat_container)
fat_sha256 = hashlib.sha256(fat_container).hexdigest()
print(f"Written {fat_out} ({len(fat_container)} bytes)")
print(f"FAT32 fixture SHA-256: {fat_sha256}")
assert fat_sha256 == "cf1e00580f843269cc7480a079a43fdc23c0416741e6591c20a86b15e5de8a20"
assert fat_long_name == "hello-long-\U0001f600.txt"
assert len(fat_payload) == 192 * 1024


def exfat_checksum32(data):
    checksum = 0
    for value in data:
        checksum = (((checksum << 31) | (checksum >> 1)) + value) & 0xFFFFFFFF
    return checksum


def exfat_set_checksum(entries):
    checksum = 0
    for entry_index, entry in enumerate(entries):
        for index, value in enumerate(entry):
            if entry_index == 0 and index in (2, 3):
                continue
            checksum = (((checksum << 15) | (checksum >> 1)) + value) & 0xFFFF
    return checksum


def make_exfat_file_set(name, is_directory, first_cluster, data_length, no_fat_chain):
    encoded = name.encode("utf-16le")
    units = list(struct.unpack("<" + "H" * (len(encoded) // 2), encoded))
    name_entries = (len(units) + 14) // 15
    primary = bytearray(32)
    primary[0] = 0x85
    primary[1] = 1 + name_entries
    struct.pack_into("<H", primary, 4, 0x10 if is_directory else 0x20)
    stream = bytearray(32)
    stream[0] = 0xC0
    stream[1] = 0x02 if no_fat_chain else 0
    stream[3] = len(units)
    struct.pack_into("<Q", stream, 8, data_length)
    struct.pack_into("<I", stream, 20, first_cluster)
    struct.pack_into("<Q", stream, 24, data_length)
    entries = [primary, stream]
    for start in range(0, len(units), 15):
        name_entry = bytearray(32)
        name_entry[0] = 0xC1
        for index, unit in enumerate(units[start:start + 15]):
            struct.pack_into("<H", name_entry, 2 + index * 2, unit)
        entries.append(name_entry)
    struct.pack_into("<H", primary, 2, exfat_set_checksum(entries))
    return b"".join(entries)


def build_exfat_plaintext():
    sector_size = 512
    total_sectors = 128
    cluster_count = total_sectors - 25
    image = bytearray(total_sectors * sector_size)
    boot = memoryview(image)[0:sector_size]
    boot[0:3] = b"\xeb\x76\x90"
    boot[3:11] = b"EXFAT   "
    struct.pack_into("<Q", boot, 72, total_sectors)
    struct.pack_into("<I", boot, 80, 24)
    struct.pack_into("<I", boot, 84, 1)
    struct.pack_into("<I", boot, 88, 25)
    struct.pack_into("<I", boot, 92, cluster_count)
    struct.pack_into("<I", boot, 96, 2)
    struct.pack_into("<I", boot, 100, 0x12345678)
    struct.pack_into("<H", boot, 104, 0x0100)
    boot[108] = 9
    boot[109] = 0
    boot[110] = 1
    boot[111] = 0x80
    boot[112] = 5
    boot[510:512] = b"\x55\xaa"
    for sector in range(1, 9):
        image[(sector + 1) * sector_size - 2:(sector + 1) * sector_size] = b"\x55\xaa"

    checksum = 0
    for sector in range(11):
        data = image[sector * sector_size:(sector + 1) * sector_size]
        for index, value in enumerate(data):
            if sector == 0 and index in (106, 107, 112):
                continue
            checksum = (((checksum << 31) | (checksum >> 1)) + value) & 0xFFFFFFFF
    for offset in range(11 * sector_size, 12 * sector_size, 4):
        struct.pack_into("<I", image, offset, checksum)
    image[12 * sector_size:24 * sector_size] = image[0:12 * sector_size]

    fat = memoryview(image)[24 * sector_size:25 * sector_size]
    struct.pack_into("<I", fat, 0, 0xFFFFFFF8)
    struct.pack_into("<I", fat, 4, 0xFFFFFFFF)
    struct.pack_into("<I", fat, 8, 0xFFFFFFFF)
    # File data is deliberately fragmented: cluster 6 -> cluster 8 -> EOC.
    struct.pack_into("<I", fat, 6 * 4, 8)
    struct.pack_into("<I", fat, 8 * 4, 0xFFFFFFFF)

    bitmap = memoryview(image)[26 * sector_size:27 * sector_size]
    bitmap[0] = 0x5F
    upcase_data = b"\x00\x00"
    image[27 * sector_size:27 * sector_size + len(upcase_data)] = upcase_data
    upcase_checksum = exfat_checksum32(upcase_data)

    root = memoryview(image)[25 * sector_size:26 * sector_size]
    root[0] = 0x81
    struct.pack_into("<I", root, 20, 3)
    struct.pack_into("<Q", root, 24, (cluster_count + 7) // 8)
    root[32] = 0x82
    struct.pack_into("<I", root, 36, upcase_checksum)
    struct.pack_into("<I", root, 52, 4)
    struct.pack_into("<Q", root, 56, len(upcase_data))
    root_set = make_exfat_file_set("NESTED", True, 5, 512, True)
    root[64:64 + len(root_set)] = root_set

    nested = memoryview(image)[28 * sector_size:29 * sector_size]
    file_set = make_exfat_file_set("fragmented.bin", False, 6, 700, False)
    nested[0:len(file_set)] = file_set
    payload = bytes((index * 29 + 11) & 0xFF for index in range(700))
    image[29 * sector_size:29 * sector_size + 512] = payload[:512]
    image[31 * sector_size:31 * sector_size + 188] = payload[512:]
    return bytes(image), payload


exfat_plaintext, exfat_payload = build_exfat_plaintext()
exfat_container = build_container(exfat_plaintext, bytes(range(128, 192)), bytes(range(192, 256)))
exfat_out = Path(__file__).parent / "exfat_test.vc"
exfat_out.write_bytes(exfat_container)
exfat_sha256 = hashlib.sha256(exfat_container).hexdigest()
print(f"Written {exfat_out} ({len(exfat_container)} bytes)")
print(f"exFAT fixture SHA-256: {exfat_sha256}")
assert exfat_sha256 == "cc1f6a4527a465c5c7e0e6f34775ef53c92921042e2f8999a06c4a2e0cd94648"
