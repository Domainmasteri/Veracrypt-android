/*
 * veracrypt_jni.cpp
 *
 * JNI bridge for VeraCrypt volume-header parsing, sector decryption, and
 * FAT32 directory listing.
 *
 * Implements PBKDF2-HMAC-SHA512 key derivation and AES-256-XTS header
 * decryption entirely in self-contained C++17 without external crypto
 * libraries, so the code runs on all supported Android ABI targets
 * (arm64-v8a, x86_64).
 *
 * VeraCrypt header sector layout (512 bytes):
 *   [  0 ..  63] Salt (64 bytes)
 *   [ 64 .. 511] Encrypted part – 448 bytes, AES-256-XTS, data unit 0
 *
 * Decrypted-block field offsets (relative to start of decrypted 448-byte block):
 *    0 –  3  Magic "VERA"
 *    4 –  5  Format version (uint16 BE) = 5
 *    6 –  7  Min program version (uint16 BE)
 *    8 – 11  CRC32 of decrypted[192..447]  (keys area)
 *   12 – 27  Reserved
 *   28 – 35  Hidden-volume size (uint64 BE)
 *   36 – 43  Volume size (uint64 BE)
 *   44 – 51  Key-scope offset (uint64 BE)  = byte offset of first data sector
 *   52 – 59  Encrypted-area size (uint64 BE)
 *   60 – 63  Flags (uint32 BE)
 *   64 – 67  Sector size (uint32 BE)
 *   68 –187  Reserved
 *  188 –191  CRC32 of decrypted[0..187] (header fields)
 *  192 –447  Master keys (256 bytes)
 */

#include <jni.h>
#include <android/log.h>
#include <array>
#include <cstring>
#include <cstdint>
#include <unistd.h>
#include <fcntl.h>
#include <vector>
#include <string>
#include <algorithm>
#include <time.h>
#include <errno.h>
#include <mutex>
#include <memory>
#include <atomic>
#include <unordered_map>
#include <unordered_set>
#include <sys/stat.h>

#include "checked_math.h"
#include "filesystem_validation.h"
#include "secure_memory.h"

#define LOG_TAG "VeraCrypt-Native"
#ifdef NDEBUG
#define LOGI(...) do { if (false) __android_log_print(ANDROID_LOG_INFO, LOG_TAG, __VA_ARGS__); } while (0)
#define LOGE(...) do { if (false) __android_log_print(ANDROID_LOG_ERROR, LOG_TAG, __VA_ARGS__); } while (0)
#else
#define LOGI(...) __android_log_print(ANDROID_LOG_INFO,  LOG_TAG, __VA_ARGS__)
#define LOGE(...) __android_log_print(ANDROID_LOG_ERROR, LOG_TAG, __VA_ARGS__)
#endif


// ============================================================
// SHA-512
// ============================================================

static const uint64_t SHA512_K[80] = {
    UINT64_C(0x428a2f98d728ae22), UINT64_C(0x7137449123ef65cd),
    UINT64_C(0xb5c0fbcfec4d3b2f), UINT64_C(0xe9b5dba58189dbbc),
    UINT64_C(0x3956c25bf348b538), UINT64_C(0x59f111f1b605d019),
    UINT64_C(0x923f82a4af194f9b), UINT64_C(0xab1c5ed5da6d8118),
    UINT64_C(0xd807aa98a3030242), UINT64_C(0x12835b0145706fbe),
    UINT64_C(0x243185be4ee4b28c), UINT64_C(0x550c7dc3d5ffb4e2),
    UINT64_C(0x72be5d74f27b896f), UINT64_C(0x80deb1fe3b1696b1),
    UINT64_C(0x9bdc06a725c71235), UINT64_C(0xc19bf174cf692694),
    UINT64_C(0xe49b69c19ef14ad2), UINT64_C(0xefbe4786384f25e3),
    UINT64_C(0x0fc19dc68b8cd5b5), UINT64_C(0x240ca1cc77ac9c65),
    UINT64_C(0x2de92c6f592b0275), UINT64_C(0x4a7484aa6ea6e483),
    UINT64_C(0x5cb0a9dcbd41fbd4), UINT64_C(0x76f988da831153b5),
    UINT64_C(0x983e5152ee66dfab), UINT64_C(0xa831c66d2db43210),
    UINT64_C(0xb00327c898fb213f), UINT64_C(0xbf597fc7beef0ee4),
    UINT64_C(0xc6e00bf33da88fc2), UINT64_C(0xd5a79147930aa725),
    UINT64_C(0x06ca6351e003826f), UINT64_C(0x142929670a0e6e70),
    UINT64_C(0x27b70a8546d22ffc), UINT64_C(0x2e1b21385c26c926),
    UINT64_C(0x4d2c6dfc5ac42aed), UINT64_C(0x53380d139d95b3df),
    UINT64_C(0x650a73548baf63de), UINT64_C(0x766a0abb3c77b2a8),
    UINT64_C(0x81c2c92e47edaee6), UINT64_C(0x92722c851482353b),
    UINT64_C(0xa2bfe8a14cf10364), UINT64_C(0xa81a664bbc423001),
    UINT64_C(0xc24b8b70d0f89791), UINT64_C(0xc76c51a30654be30),
    UINT64_C(0xd192e819d6ef5218), UINT64_C(0xd69906245565a910),
    UINT64_C(0xf40e35855771202a), UINT64_C(0x106aa07032bbd1b8),
    UINT64_C(0x19a4c116b8d2d0c8), UINT64_C(0x1e376c085141ab53),
    UINT64_C(0x2748774cdf8eeb99), UINT64_C(0x34b0bcb5e19b48a8),
    UINT64_C(0x391c0cb3c5c95a63), UINT64_C(0x4ed8aa4ae3418acb),
    UINT64_C(0x5b9cca4f7763e373), UINT64_C(0x682e6ff3d6b2b8a3),
    UINT64_C(0x748f82ee5defb2fc), UINT64_C(0x78a5636f43172f60),
    UINT64_C(0x84c87814a1f0ab72), UINT64_C(0x8cc702081a6439ec),
    UINT64_C(0x90befffa23631e28), UINT64_C(0xa4506cebde82bde9),
    UINT64_C(0xbef9a3f7b2c67915), UINT64_C(0xc67178f2e372532b),
    UINT64_C(0xca273eceea26619c), UINT64_C(0xd186b8c721c0c207),
    UINT64_C(0xeada7dd6cde0eb1e), UINT64_C(0xf57d4f7fee6ed178),
    UINT64_C(0x06f067aa72176fba), UINT64_C(0x0a637dc5a2c898a6),
    UINT64_C(0x113f9804bef90dae), UINT64_C(0x1b710b35131c471b),
    UINT64_C(0x28db77f523047d84), UINT64_C(0x32caab7b40c72493),
    UINT64_C(0x3c9ebe0a15c9bebc), UINT64_C(0x431d67c49c100d4c),
    UINT64_C(0x4cc5d4becb3e42b6), UINT64_C(0x597f299cfc657e2a),
    UINT64_C(0x5fcb6fab3ad6faec), UINT64_C(0x6c44198c4a475817),
};

static const uint64_t SHA512_H0[8] = {
    UINT64_C(0x6a09e667f3bcc908), UINT64_C(0xbb67ae8584caa73b),
    UINT64_C(0x3c6ef372fe94f82b), UINT64_C(0xa54ff53a5f1d36f1),
    UINT64_C(0x510e527fade682d1), UINT64_C(0x9b05688c2b3e6c1f),
    UINT64_C(0x1f83d9abfb41bd6b), UINT64_C(0x5be0cd19137e2179),
};

struct SHA512Ctx {
    uint64_t state[8];
    uint64_t byte_count;
    uint8_t  buf[128];
    size_t   buf_pos;
};

static inline uint64_t be64_read(const uint8_t *p) {
    return ((uint64_t)p[0]<<56)|((uint64_t)p[1]<<48)|((uint64_t)p[2]<<40)|
           ((uint64_t)p[3]<<32)|((uint64_t)p[4]<<24)|((uint64_t)p[5]<<16)|
           ((uint64_t)p[6]<< 8)| (uint64_t)p[7];
}

#define ROTR64(x,n) (((x)>>(n))|((x)<<(64-(n))))
#define SHA_S0(x) (ROTR64(x,28)^ROTR64(x,34)^ROTR64(x,39))
#define SHA_S1(x) (ROTR64(x,14)^ROTR64(x,18)^ROTR64(x,41))
#define SHA_s0(x) (ROTR64(x,1) ^ROTR64(x,8) ^((x)>>7))
#define SHA_s1(x) (ROTR64(x,19)^ROTR64(x,61)^((x)>>6))
#define SHA_Ch(x,y,z) (((x)&(y))^(~(x)&(z)))
#define SHA_Maj(x,y,z)(((x)&(y))^((x)&(z))^((y)&(z)))

static void sha512_compress(uint64_t st[8], const uint8_t blk[128]) {
    uint64_t W[80];
    for (int i = 0; i < 16; i++) W[i] = be64_read(blk + 8*i);
    for (int i = 16; i < 80; i++)
        W[i] = SHA_s1(W[i-2]) + W[i-7] + SHA_s0(W[i-15]) + W[i-16];
    uint64_t a=st[0],b=st[1],c=st[2],d=st[3],e=st[4],f=st[5],g=st[6],h=st[7];
    for (int i = 0; i < 80; i++) {
        uint64_t t1 = h + SHA_S1(e) + SHA_Ch(e,f,g) + SHA512_K[i] + W[i];
        uint64_t t2 = SHA_S0(a) + SHA_Maj(a,b,c);
        h=g; g=f; f=e; e=d+t1; d=c; c=b; b=a; a=t1+t2;
    }
    st[0]+=a; st[1]+=b; st[2]+=c; st[3]+=d;
    st[4]+=e; st[5]+=f; st[6]+=g; st[7]+=h;
}

static void sha512_init(SHA512Ctx *ctx) {
    memcpy(ctx->state, SHA512_H0, sizeof(SHA512_H0));
    ctx->byte_count = 0;
    ctx->buf_pos    = 0;
}

static void sha512_update(SHA512Ctx *ctx, const uint8_t *data, size_t len) {
    while (len) {
        size_t room = 128 - ctx->buf_pos;
        size_t take = (len < room) ? len : room;
        memcpy(ctx->buf + ctx->buf_pos, data, take);
        ctx->buf_pos  += take;
        ctx->byte_count += take;
        data += take;
        len  -= take;
        if (ctx->buf_pos == 128) {
            sha512_compress(ctx->state, ctx->buf);
            ctx->buf_pos = 0;
        }
    }
}

static void sha512_final(SHA512Ctx *ctx, uint8_t digest[64]) {
    ctx->buf[ctx->buf_pos++] = 0x80;
    if (ctx->buf_pos > 112) {
        memset(ctx->buf + ctx->buf_pos, 0, 128 - ctx->buf_pos);
        sha512_compress(ctx->state, ctx->buf);
        ctx->buf_pos = 0;
    }
    memset(ctx->buf + ctx->buf_pos, 0, 112 - ctx->buf_pos);
    uint64_t bits_low  = ctx->byte_count << 3;
    uint64_t bits_high = ctx->byte_count >> 61;
    for (int i = 7; i >= 0; i--) ctx->buf[112 + (7-i)] = (bits_high >> (8*i)) & 0xff;
    for (int i = 7; i >= 0; i--) ctx->buf[120 + (7-i)] = (bits_low  >> (8*i)) & 0xff;
    sha512_compress(ctx->state, ctx->buf);
    for (int i = 0; i < 8; i++) {
        uint64_t v = ctx->state[i];
        for (int j = 7; j >= 0; j--) { digest[8*i + (7-j)] = (v >> (8*j)) & 0xff; }
    }
}

static void sha512_hash(const uint8_t *data, size_t len, uint8_t digest[64]) {
    SHA512Ctx ctx;
    sha512_init(&ctx);
    sha512_update(&ctx, data, len);
    sha512_final(&ctx, digest);
    secure_zero(&ctx, sizeof(ctx));
}

// ============================================================
// HMAC-SHA-512
// ============================================================

static void hmac_sha512(const uint8_t *key, size_t klen,
                        const uint8_t *msg, size_t mlen,
                        uint8_t mac[64]) {
    uint8_t k0[128];
    if (klen > 128) {
        sha512_hash(key, klen, k0);
        memset(k0 + 64, 0, 64);
    } else {
        memcpy(k0, key, klen);
        memset(k0 + klen, 0, 128 - klen);
    }
    uint8_t ipad[128], opad[128];
    for (int i = 0; i < 128; i++) { ipad[i] = k0[i] ^ 0x36; opad[i] = k0[i] ^ 0x5c; }
    uint8_t inner[64];
    SHA512Ctx ctx;
    sha512_init(&ctx); sha512_update(&ctx, ipad, 128); sha512_update(&ctx, msg, mlen);  sha512_final(&ctx, inner);
    sha512_init(&ctx); sha512_update(&ctx, opad, 128); sha512_update(&ctx, inner, 64); sha512_final(&ctx, mac);
    secure_zero(&ctx, sizeof(ctx));
    secure_zero(inner, sizeof(inner));
    secure_zero(ipad, sizeof(ipad));
    secure_zero(opad, sizeof(opad));
    secure_zero(k0, sizeof(k0));
}

// ============================================================
// PBKDF2-HMAC-SHA512  (dkLen must be <= 64)
// ============================================================

static void pbkdf2_sha512(const uint8_t *pwd, size_t plen,
                          const uint8_t *salt, size_t slen,
                          uint32_t iter,
                          uint8_t *dk, size_t dklen) {
    // Single PRF block (block index 1); sufficient for dkLen <= 64.
    // Use a fixed-size stack buffer large enough for a 64-byte VC salt + 4-byte counter.
    uint8_t s1[68];
    if (slen > 64) slen = 64; // guard; VC salt is always 64 bytes
    memcpy(s1, salt, slen);
    s1[slen]   = 0; s1[slen+1] = 0; s1[slen+2] = 0; s1[slen+3] = 1;

    uint8_t U[64], T[64];
    hmac_sha512(pwd, plen, s1, slen+4, U);
    memcpy(T, U, 64);

    for (uint32_t i = 1; i < iter; i++) {
        hmac_sha512(pwd, plen, U, 64, U);
        for (int j = 0; j < 64; j++) T[j] ^= U[j];
    }
    memcpy(dk, T, dklen <= 64 ? dklen : 64);
    secure_zero(s1, sizeof(s1));
    secure_zero(U, sizeof(U));
    secure_zero(T, sizeof(T));
}

// ============================================================
// AES-256
// ============================================================

static const uint8_t AES_SBOX[256] = {
    0x63,0x7c,0x77,0x7b,0xf2,0x6b,0x6f,0xc5,0x30,0x01,0x67,0x2b,0xfe,0xd7,0xab,0x76,
    0xca,0x82,0xc9,0x7d,0xfa,0x59,0x47,0xf0,0xad,0xd4,0xa2,0xaf,0x9c,0xa4,0x72,0xc0,
    0xb7,0xfd,0x93,0x26,0x36,0x3f,0xf7,0xcc,0x34,0xa5,0xe5,0xf1,0x71,0xd8,0x31,0x15,
    0x04,0xc7,0x23,0xc3,0x18,0x96,0x05,0x9a,0x07,0x12,0x80,0xe2,0xeb,0x27,0xb2,0x75,
    0x09,0x83,0x2c,0x1a,0x1b,0x6e,0x5a,0xa0,0x52,0x3b,0xd6,0xb3,0x29,0xe3,0x2f,0x84,
    0x53,0xd1,0x00,0xed,0x20,0xfc,0xb1,0x5b,0x6a,0xcb,0xbe,0x39,0x4a,0x4c,0x58,0xcf,
    0xd0,0xef,0xaa,0xfb,0x43,0x4d,0x33,0x85,0x45,0xf9,0x02,0x7f,0x50,0x3c,0x9f,0xa8,
    0x51,0xa3,0x40,0x8f,0x92,0x9d,0x38,0xf5,0xbc,0xb6,0xda,0x21,0x10,0xff,0xf3,0xd2,
    0xcd,0x0c,0x13,0xec,0x5f,0x97,0x44,0x17,0xc4,0xa7,0x7e,0x3d,0x64,0x5d,0x19,0x73,
    0x60,0x81,0x4f,0xdc,0x22,0x2a,0x90,0x88,0x46,0xee,0xb8,0x14,0xde,0x5e,0x0b,0xdb,
    0xe0,0x32,0x3a,0x0a,0x49,0x06,0x24,0x5c,0xc2,0xd3,0xac,0x62,0x91,0x95,0xe4,0x79,
    0xe7,0xc8,0x37,0x6d,0x8d,0xd5,0x4e,0xa9,0x6c,0x56,0xf4,0xea,0x65,0x7a,0xae,0x08,
    0xba,0x78,0x25,0x2e,0x1c,0xa6,0xb4,0xc6,0xe8,0xdd,0x74,0x1f,0x4b,0xbd,0x8b,0x8a,
    0x70,0x3e,0xb5,0x66,0x48,0x03,0xf6,0x0e,0x61,0x35,0x57,0xb9,0x86,0xc1,0x1d,0x9e,
    0xe1,0xf8,0x98,0x11,0x69,0xd9,0x8e,0x94,0x9b,0x1e,0x87,0xe9,0xce,0x55,0x28,0xdf,
    0x8c,0xa1,0x89,0x0d,0xbf,0xe6,0x42,0x68,0x41,0x99,0x2d,0x0f,0xb0,0x54,0xbb,0x16
};

static const uint8_t AES_SBOX_INV[256] = {
    0x52,0x09,0x6a,0xd5,0x30,0x36,0xa5,0x38,0xbf,0x40,0xa3,0x9e,0x81,0xf3,0xd7,0xfb,
    0x7c,0xe3,0x39,0x82,0x9b,0x2f,0xff,0x87,0x34,0x8e,0x43,0x44,0xc4,0xde,0xe9,0xcb,
    0x54,0x7b,0x94,0x32,0xa6,0xc2,0x23,0x3d,0xee,0x4c,0x95,0x0b,0x42,0xfa,0xc3,0x4e,
    0x08,0x2e,0xa1,0x66,0x28,0xd9,0x24,0xb2,0x76,0x5b,0xa2,0x49,0x6d,0x8b,0xd1,0x25,
    0x72,0xf8,0xf6,0x64,0x86,0x68,0x98,0x16,0xd4,0xa4,0x5c,0xcc,0x5d,0x65,0xb6,0x92,
    0x6c,0x70,0x48,0x50,0xfd,0xed,0xb9,0xda,0x5e,0x15,0x46,0x57,0xa7,0x8d,0x9d,0x84,
    0x90,0xd8,0xab,0x00,0x8c,0xbc,0xd3,0x0a,0xf7,0xe4,0x58,0x05,0xb8,0xb3,0x45,0x06,
    0xd0,0x2c,0x1e,0x8f,0xca,0x3f,0x0f,0x02,0xc1,0xaf,0xbd,0x03,0x01,0x13,0x8a,0x6b,
    0x3a,0x91,0x11,0x41,0x4f,0x67,0xdc,0xea,0x97,0xf2,0xcf,0xce,0xf0,0xb4,0xe6,0x73,
    0x96,0xac,0x74,0x22,0xe7,0xad,0x35,0x85,0xe2,0xf9,0x37,0xe8,0x1c,0x75,0xdf,0x6e,
    0x47,0xf1,0x1a,0x71,0x1d,0x29,0xc5,0x89,0x6f,0xb7,0x62,0x0e,0xaa,0x18,0xbe,0x1b,
    0xfc,0x56,0x3e,0x4b,0xc6,0xd2,0x79,0x20,0x9a,0xdb,0xc0,0xfe,0x78,0xcd,0x5a,0xf4,
    0x1f,0xdd,0xa8,0x33,0x88,0x07,0xc7,0x31,0xb1,0x12,0x10,0x59,0x27,0x80,0xec,0x5f,
    0x60,0x51,0x7f,0xa9,0x19,0xb5,0x4a,0x0d,0x2d,0xe5,0x7a,0x9f,0x93,0xc9,0x9c,0xef,
    0xa0,0xe0,0x3b,0x4d,0xae,0x2a,0xf5,0xb0,0xc8,0xeb,0xbb,0x3c,0x83,0x53,0x99,0x61,
    0x17,0x2b,0x04,0x7e,0xba,0x77,0xd6,0x26,0xe1,0x69,0x14,0x63,0x55,0x21,0x0c,0x7d
};

static const uint8_t AES_RCON[7] = {0x01,0x02,0x04,0x08,0x10,0x20,0x40};

// AES-256 key schedule: 15 round keys × 16 bytes = 240 bytes
typedef uint8_t AES256_KS[240];

static void aes256_expand(const uint8_t key[32], AES256_KS ks) {
    memcpy(ks, key, 32);
    for (int i = 8; i < 60; i++) {
        uint8_t tmp[4];
        memcpy(tmp, ks + 4*(i-1), 4);
        if (i % 8 == 0) {
            uint8_t t = tmp[0];
            tmp[0] = AES_SBOX[tmp[1]] ^ AES_RCON[i/8-1];
            tmp[1] = AES_SBOX[tmp[2]];
            tmp[2] = AES_SBOX[tmp[3]];
            tmp[3] = AES_SBOX[t];
        } else if (i % 8 == 4) {
            for (int j = 0; j < 4; j++) tmp[j] = AES_SBOX[tmp[j]];
        }
        for (int j = 0; j < 4; j++) ks[4*i+j] = ks[4*(i-8)+j] ^ tmp[j];
    }
}

static inline uint8_t xtime(uint8_t a) {
    return (uint8_t)((a << 1) ^ ((a >> 7) * 0x1Bu));
}

static void aes256_encrypt_block(const AES256_KS ks, const uint8_t in[16], uint8_t out[16]) {
    uint8_t s[16];
    // AddRoundKey r0
    for (int i = 0; i < 16; i++) s[i] = in[i] ^ ks[i];
    for (int r = 1; r <= 14; r++) {
        // SubBytes
        for (int i = 0; i < 16; i++) s[i] = AES_SBOX[s[i]];
        // ShiftRows
        uint8_t tmp;
        tmp=s[1]; s[1]=s[5]; s[5]=s[9];  s[9]=s[13]; s[13]=tmp;
        tmp=s[2]; s[2]=s[10]; s[10]=tmp; tmp=s[6]; s[6]=s[14]; s[14]=tmp;
        tmp=s[15]; s[15]=s[11]; s[11]=s[7]; s[7]=s[3]; s[3]=tmp;
        // MixColumns (skip round 14)
        if (r < 14) {
            for (int c = 0; c < 4; c++) {
                uint8_t a0=s[c*4],a1=s[c*4+1],a2=s[c*4+2],a3=s[c*4+3];
                uint8_t t0=xtime(a0),t1=xtime(a1),t2=xtime(a2),t3=xtime(a3);
                s[c*4+0] = t0^t1^a1^a2^a3;
                s[c*4+1] = a0^t1^t2^a2^a3;
                s[c*4+2] = a0^a1^t2^t3^a3;
                s[c*4+3] = t0^a0^a1^a2^t3;
            }
        }
        // AddRoundKey
        for (int i = 0; i < 16; i++) s[i] ^= ks[r*16+i];
    }
    memcpy(out, s, 16);
    secure_zero(s, sizeof(s));
}

// InvMixColumns helper for one 4-byte column
static void inv_mix_col(uint8_t *s) {
    uint8_t a0=s[0],a1=s[1],a2=s[2],a3=s[3];
    uint8_t x2_0=xtime(a0),x4_0=xtime(x2_0),x8_0=xtime(x4_0);
    uint8_t x2_1=xtime(a1),x4_1=xtime(x2_1),x8_1=xtime(x4_1);
    uint8_t x2_2=xtime(a2),x4_2=xtime(x2_2),x8_2=xtime(x4_2);
    uint8_t x2_3=xtime(a3),x4_3=xtime(x2_3),x8_3=xtime(x4_3);
    s[0]=(uint8_t)((x8_0^x4_0^x2_0)^(x8_1^x2_1^a1)^(x8_2^x4_2^a2)^(x8_3^a3));
    s[1]=(uint8_t)((x8_0^a0)^(x8_1^x4_1^x2_1)^(x8_2^x2_2^a2)^(x8_3^x4_3^a3));
    s[2]=(uint8_t)((x8_0^x4_0^a0)^(x8_1^a1)^(x8_2^x4_2^x2_2)^(x8_3^x2_3^a3));
    s[3]=(uint8_t)((x8_0^x2_0^a0)^(x8_1^x4_1^a1)^(x8_2^a2)^(x8_3^x4_3^x2_3));
}

static void aes256_decrypt_block(const AES256_KS ks, const uint8_t in[16], uint8_t out[16]) {
    uint8_t s[16];
    // AddRoundKey r14
    for (int i = 0; i < 16; i++) s[i] = in[i] ^ ks[14*16+i];
    for (int r = 13; r >= 0; r--) {
        // InvShiftRows
        uint8_t tmp;
        tmp=s[13]; s[13]=s[9]; s[9]=s[5]; s[5]=s[1]; s[1]=tmp;
        tmp=s[2]; s[2]=s[10]; s[10]=tmp; tmp=s[6]; s[6]=s[14]; s[14]=tmp;
        tmp=s[3]; s[3]=s[7]; s[7]=s[11]; s[11]=s[15]; s[15]=tmp;
        // InvSubBytes
        for (int i = 0; i < 16; i++) s[i] = AES_SBOX_INV[s[i]];
        // AddRoundKey
        for (int i = 0; i < 16; i++) s[i] ^= ks[r*16+i];
        // InvMixColumns (skip round 0)
        if (r > 0) {
            for (int c = 0; c < 4; c++) inv_mix_col(s + c*4);
        }
    }
    memcpy(out, s, 16);
    secure_zero(s, sizeof(s));
}

// ============================================================
// AES-256-XTS decrypt
// Decrypts `len` bytes (must be a multiple of 16, >= 16).
// unit_no is the 64-bit data-unit (sector) number (little-endian).
// key1 = first 32 bytes of derived key (data encryption key).
// key2 = next  32 bytes of derived key (tweak encryption key).
// ============================================================

static void aes256_xts_decrypt(const uint8_t key1[32], const uint8_t key2[32],
                                uint64_t unit_no,
                                const uint8_t *ct, uint8_t *pt, size_t len) {
    AES256_KS ks1, ks2;
    aes256_expand(key1, ks1);
    aes256_expand(key2, ks2);

    // Compute initial tweak: T = AES_Encrypt(key2, unit_no_LE || 0…0)
    uint8_t tweak_in[16] = {};
    for (int i = 0; i < 8; i++) tweak_in[i] = (unit_no >> (8*i)) & 0xff;
    uint8_t T[16];
    aes256_encrypt_block(ks2, tweak_in, T);

    for (size_t pos = 0; pos + 16 <= len; pos += 16) {
        uint8_t tmp[16];
        // tmp = C[pos..pos+15] XOR T
        for (int i = 0; i < 16; i++) tmp[i] = ct[pos+i] ^ T[i];
        // tmp = AES_Decrypt(key1, tmp)
        aes256_decrypt_block(ks1, tmp, tmp);
        // P[pos..pos+15] = tmp XOR T
        for (int i = 0; i < 16; i++) pt[pos+i] = tmp[i] ^ T[i];
        // T = GF_mult(T, alpha): shift left, XOR 0x87 if carry
        uint8_t carry = T[15] >> 7;
        for (int i = 15; i > 0; i--) T[i] = (uint8_t)((T[i]<<1)|(T[i-1]>>7));
        T[0] = (uint8_t)((T[0]<<1) ^ (carry ? 0x87u : 0u));
    }
    secure_zero(ks1, sizeof(ks1));
    secure_zero(ks2, sizeof(ks2));
    secure_zero(tweak_in, sizeof(tweak_in));
    secure_zero(T, sizeof(T));
}

static void aes256_xts_encrypt(const uint8_t key1[32], const uint8_t key2[32],
                               uint64_t unit_no,
                               const uint8_t *pt, uint8_t *ct, size_t len) {
    AES256_KS ks1, ks2;
    aes256_expand(key1, ks1);
    aes256_expand(key2, ks2);

    uint8_t tweak_in[16] = {};
    for (int i = 0; i < 8; i++) tweak_in[i] = (unit_no >> (8 * i)) & 0xff;
    uint8_t T[16];
    aes256_encrypt_block(ks2, tweak_in, T);

    for (size_t pos = 0; pos + 16 <= len; pos += 16) {
        uint8_t tmp[16];
        for (int i = 0; i < 16; i++) tmp[i] = pt[pos + i] ^ T[i];
        aes256_encrypt_block(ks1, tmp, tmp);
        for (int i = 0; i < 16; i++) ct[pos + i] = tmp[i] ^ T[i];
        uint8_t carry = T[15] >> 7;
        for (int i = 15; i > 0; i--) T[i] = (uint8_t)((T[i] << 1) | (T[i - 1] >> 7));
        T[0] = (uint8_t)((T[0] << 1) ^ (carry ? 0x87u : 0u));
    }
    secure_zero(ks1, sizeof(ks1));
    secure_zero(ks2, sizeof(ks2));
    secure_zero(tweak_in, sizeof(tweak_in));
    secure_zero(T, sizeof(T));
}

// ============================================================
// CRC-32 (IEEE 802.3 / zlib polynomial 0xEDB88320)
// ============================================================

static uint32_t crc32_compute(const uint8_t *data, size_t len) {
    static const uint32_t TABLE[16] = {
        0x00000000u,0x1db71064u,0x3b6e20c8u,0x26d930acu,
        0x76dc4190u,0x6b6b51f4u,0x4db26158u,0x5005713cu,
        0xedb88320u,0xf00f9344u,0xd6d6a3e8u,0xcb61b38cu,
        0x9b64c2b0u,0x86d3d2d4u,0xa00ae278u,0xbdbdf21cu
    };
    uint32_t crc = 0xFFFFFFFFu;
    for (size_t i = 0; i < len; i++) {
        crc = (crc >> 4) ^ TABLE[(crc ^ data[i])       & 0xf];
        crc = (crc >> 4) ^ TABLE[(crc ^ (data[i] >> 4)) & 0xf];
    }
    return crc ^ 0xFFFFFFFFu;
}

// ============================================================
// Session state
// Each opened container owns a duplicated descriptor and independent key set.
// A short-lived thread-local copy lets the existing parser helpers operate on
// the session selected by the JNI entry point without sharing keys globally.
// ============================================================

#define VC_MAX_SECTOR_SIZE 4096

struct VCSession {
    bool     valid;
    uint8_t  masterKey1[32];  // AES-256 data encryption key
    uint8_t  masterKey2[32];  // AES-256 tweak key
    uint64_t dataOffset;      // byte offset of the first data sector in the file
    uint64_t encryptedAreaSize;
    uint32_t sectorSize;      // bytes per logical sector (from volume header)
    int      fd;
    dev_t    device;
    ino_t    inode;
    uint64_t fileSize;
};

struct ManagedSession {
    VCSession state{};
    std::mutex operationMutex;
    int validatedFsType = 0;
};

static thread_local VCSession g_session = {};
static std::mutex g_sessions_mutex;
static std::unordered_map<uint64_t, std::shared_ptr<ManagedSession>> g_sessions;
static std::atomic<uint64_t> g_next_session_handle{1};

static void clear_session_state(VCSession& session) {
    secure_zero(session.masterKey1, sizeof(session.masterKey1));
    secure_zero(session.masterKey2, sizeof(session.masterKey2));
    session = {};
    session.fd = -1;
}

class ScopedSessionContext {
public:
    explicit ScopedSessionContext(const VCSession& state) {
        g_session = state;
    }

    ~ScopedSessionContext() {
        clear_session_state(g_session);
    }

    ScopedSessionContext(const ScopedSessionContext&) = delete;
    ScopedSessionContext& operator=(const ScopedSessionContext&) = delete;
};

class ScopedFd {
public:
    explicit ScopedFd(int fd) : fd_(fd) {}
    ~ScopedFd() { if (fd_ >= 0) close(fd_); }
    int get() const { return fd_; }
    int release() { int value = fd_; fd_ = -1; return value; }
    ScopedFd(const ScopedFd&) = delete;
    ScopedFd& operator=(const ScopedFd&) = delete;

private:
    int fd_;
};

static std::shared_ptr<ManagedSession> find_session(uint64_t handle) {
    if (handle == 0) return nullptr;
    std::lock_guard<std::mutex> lock(g_sessions_mutex);
    auto it = g_sessions.find(handle);
    return it == g_sessions.end() ? nullptr : it->second;
}

static uint64_t store_session(const std::shared_ptr<ManagedSession>& session) {
    std::lock_guard<std::mutex> lock(g_sessions_mutex);
    for (;;) {
        uint64_t handle = g_next_session_handle.fetch_add(1, std::memory_order_relaxed);
        handle &= INT64_MAX;
        if (handle != 0 && g_sessions.emplace(handle, session).second) return handle;
    }
}

// ============================================================
// Little-endian helpers
// ============================================================

static inline uint16_t le16r(const uint8_t* p) {
    return (uint16_t)(p[0] | ((uint16_t)p[1] << 8));
}
static inline uint32_t le32r(const uint8_t* p) {
    return (uint32_t)(p[0] | ((uint32_t)p[1]<<8) | ((uint32_t)p[2]<<16) | ((uint32_t)p[3]<<24));
}
static inline uint64_t le64r(const uint8_t* p) {
    return ((uint64_t)p[0])       | ((uint64_t)p[1] <<  8) |
           ((uint64_t)p[2] << 16) | ((uint64_t)p[3] << 24) |
           ((uint64_t)p[4] << 32) | ((uint64_t)p[5] << 40) |
           ((uint64_t)p[6] << 48) | ((uint64_t)p[7] << 56);
}
static inline uint16_t be16r(const uint8_t* p) {
    return (uint16_t)(((uint16_t)p[0] << 8) | p[1]);
}
static inline uint32_t be32r(const uint8_t* p) {
    return ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) |
           ((uint32_t)p[2] << 8) | (uint32_t)p[3];
}
static inline uint64_t be64r(const uint8_t* p) {
    return ((uint64_t)p[0] << 56) | ((uint64_t)p[1] << 48) |
           ((uint64_t)p[2] << 40) | ((uint64_t)p[3] << 32) |
           ((uint64_t)p[4] << 24) | ((uint64_t)p[5] << 16) |
           ((uint64_t)p[6] << 8) | (uint64_t)p[7];
}
static bool read_full_at(int fd, void* buffer, size_t len, off64_t offset) {
    uint8_t* out = reinterpret_cast<uint8_t*>(buffer);
    size_t done = 0;
    while (done < len) {
        ssize_t n = pread64(fd, out + done, len - done, offset + (off64_t)done);
        if (n > 0) { done += (size_t)n; continue; }
        if (n < 0 && errno == EINTR) continue;
        return false;
    }
    return true;
}

static bool current_fd_matches_session(int fd) {
    if (!g_session.valid || fd < 0 || fd != g_session.fd) return false;
    struct stat st{};
    if (fstat(fd, &st) < 0) return false;
    return st.st_dev == g_session.device && st.st_ino == g_session.inode;
}

static bool safe_absolute_path(const char* path) {
    if (!path || path[0] != '/') return false;
    if (path[1] == '\0') return true;
    if (path[1] == '/') return false;
    std::string value(path);
    if (value.size() > 4096 || value.find('\0') != std::string::npos) return false;
    size_t start = 1;
    while (start < value.size()) {
        size_t end = value.find('/', start);
        if (end == std::string::npos) end = value.size();
        std::string part = value.substr(start, end - start);
        if (part.empty() || part == "." || part == "..") return false;
        start = end + 1;
    }
    return true;
}

// ============================================================
// Sector reader
// Reads one logical sector from fd, decrypts it with AES-256-XTS,
// and writes the plaintext to outBuf (must be at least sectorSize bytes).
// sectorNo is the logical data-sector index starting at 0.
// ============================================================

static bool vc_read_sector(int fd, uint64_t sectorNo, uint8_t outBuf[VC_MAX_SECTOR_SIZE]) {
    if (!current_fd_matches_session(fd)) return false;

    uint32_t sz = g_session.sectorSize;
    if (sz == 0 || sz > VC_MAX_SECTOR_SIZE) {
        LOGE("vc_read_sector: unexpected sector size %u", sz);
        return false;
    }

    uint64_t relative = 0;
    uint64_t fileOff = 0;
    if (!checked_mul_u64(sectorNo, (uint64_t)sz, &relative) ||
        !checked_add_u64(g_session.dataOffset, relative, &fileOff)) {
        LOGE("vc_read_sector: sector offset overflow");
        return false;
    }
    if (fileOff > g_session.fileSize || (uint64_t)sz > g_session.fileSize - fileOff) {
        LOGE("vc_read_sector: sector is outside file bounds");
        return false;
    }
    if (g_session.encryptedAreaSize != 0 &&
        (relative > g_session.encryptedAreaSize ||
         (uint64_t)sz > g_session.encryptedAreaSize - relative)) {
        LOGE("vc_read_sector: sector is outside encrypted area");
        return false;
    }

    uint8_t enc[VC_MAX_SECTOR_SIZE];
    if (!read_full_at(fd, enc, sz, (off64_t)fileOff)) {
        LOGE("vc_read_sector: read failed for sector %llu", (unsigned long long)sectorNo);
        return false;
    }

    aes256_xts_decrypt(g_session.masterKey1, g_session.masterKey2, sectorNo, enc, outBuf, sz);
    return true;
}

// ============================================================
// FAT32 parser (read-only)
// ============================================================

struct DirEntry {
    std::string name;
    bool        isDir;
    uint64_t    sizeBytes;
    uint16_t    modDate;      // FAT date encoding
    uint16_t    modTime;      // FAT time encoding
    uint32_t    firstCluster; // starting FAT cluster of this entry's data
    uint64_t    recordSector; // logical sector where primary entry starts
    uint32_t    recordOffset; // byte offset within recordSector (0..sectorSize-32)
    bool        noFatChain;   // exFAT contiguous allocation flag; false for FAT32
};

static constexpr size_t MAX_DIRECTORY_ENTRIES = 100000u;

// Convert a FAT 8.3 directory-entry name field to a trimmed string.
static std::string fat_83_to_string(const uint8_t* name11) {
    std::string base, ext;
    for (int i = 0; i < 8; i++) {
        if (name11[i] == ' ') break;
        base += (char)name11[i];
    }
    for (int i = 8; i < 11; i++) {
        if (name11[i] == ' ') break;
        ext += (char)name11[i];
    }
    return ext.empty() ? base : base + "." + ext;
}

// Convert FAT date+time to milliseconds since the Unix epoch (UTC).
static uint64_t fat_datetime_to_ms(uint16_t date, uint16_t time) {
    int year  = ((date >> 9) & 0x7F) + 1980;
    int month = (date >> 5) & 0x0F;
    int day   = date & 0x1F;
    int hour  = (time >> 11) & 0x1F;
    int min   = (time >> 5)  & 0x3F;
    int sec   = (time & 0x1F) * 2;

    if (month < 1 || month > 12 || day < 1 || day > 31) return 0;

    struct tm t = {};
    t.tm_year = year - 1900;
    t.tm_mon  = month - 1;
    t.tm_mday = day;
    t.tm_hour = hour;
    t.tm_min  = min;
    t.tm_sec  = sec;
    t.tm_isdst = 0;
    time_t ts = timegm(&t);
    return (ts == (time_t)-1) ? 0 : (uint64_t)ts * 1000u;
}

struct Fat32Info {
    uint16_t bytesPerSector;
    uint8_t  sectorsPerCluster;
    uint32_t firstFATSector;   // logical sector index of the first FAT
    uint32_t firstDataSector;  // logical sector index of cluster 2
    uint32_t rootCluster;
    uint32_t sectorsPerFat;
    uint8_t  numFATs;
    uint32_t clusterCount;
};

// Read and parse the FAT32 BIOS Parameter Block (sector 0 of the data area).
static bool fat32_read_bpb(int fd, Fat32Info* fi) {
    uint8_t sec[VC_MAX_SECTOR_SIZE];
    if (!vc_read_sector(fd, 0, sec)) {
        LOGE("fat32_read_bpb: could not read sector 0");
        return false;
    }

    vc::Fat32BootFields fields{};
    const uint64_t availableSectors = g_session.encryptedAreaSize / g_session.sectorSize;
    if (!vc::validate_fat32_boot_sector(sec, sizeof(sec), g_session.sectorSize,
                                        availableSectors, &fields)) {
        LOGE("fat32_read_bpb: invalid BPB");
        return false;
    }
    uint8_t fsInfo[VC_MAX_SECTOR_SIZE];
    uint8_t backupBoot[VC_MAX_SECTOR_SIZE];
    if (!vc_read_sector(fd, fields.fsInfoSector, fsInfo) ||
        le32r(fsInfo) != 0x41615252u || le32r(fsInfo + 484) != 0x61417272u ||
        le32r(fsInfo + 508) != 0xAA550000u ||
        (le32r(fsInfo + 488) != 0xFFFFFFFFu && le32r(fsInfo + 488) > fields.clusterCount) ||
        (le32r(fsInfo + 492) != 0xFFFFFFFFu &&
         (le32r(fsInfo + 492) < 2u || le32r(fsInfo + 492) > fields.clusterCount + 1u)) ||
        !vc_read_sector(fd, fields.backupBootSector, backupBoot) ||
        memcmp(sec + 11, backupBoot + 11, 79u) != 0 ||
        backupBoot[510] != 0x55u || backupBoot[511] != 0xAAu) {
        LOGE("fat32_read_bpb: invalid FSInfo or backup boot sector");
        return false;
    }

    fi->bytesPerSector    = fields.bytesPerSector;
    fi->sectorsPerCluster = fields.sectorsPerCluster;
    fi->firstFATSector    = fields.reservedSectors;
    fi->firstDataSector   = fields.firstDataSector;
    fi->rootCluster       = fields.rootCluster;
    fi->sectorsPerFat     = fields.sectorsPerFat;
    fi->numFATs           = fields.numberOfFats;
    fi->clusterCount      = fields.clusterCount;

    LOGI("fat32_read_bpb: bps=%u spc=%u firstFAT=%u firstData=%u rootClus=%u",
         fi->bytesPerSector, fi->sectorsPerCluster, fi->firstFATSector,
         fi->firstDataSector, fi->rootCluster);
    return true;
}

// Return the logical sector index for the start of a given cluster (>= 2).
static bool fat32_cluster_to_sector(const Fat32Info& fi, uint32_t cluster, uint64_t* sector) {
    if (cluster < 2u || cluster > fi.clusterCount + 1u) return false;
    uint64_t relative = 0;
    return checked_mul_u64((uint64_t)cluster - 2u, fi.sectorsPerCluster, &relative) &&
           checked_add_u64(fi.firstDataSector, relative, sector);
}

// Follow the FAT chain: return the cluster that follows `cluster`.
// Returns 0x0FFFFFFF (end-of-chain marker) on error or EOF.
static uint32_t fat32_next_cluster(int fd, const Fat32Info& fi, uint32_t cluster) {
    if (cluster < 2u || cluster > fi.clusterCount + 1u) return 0x0FFFFFFFu;
    uint64_t fatByteOff  = (uint64_t)cluster * 4u;
    uint64_t fatSector64 = (uint64_t)fi.firstFATSector + fatByteOff / g_session.sectorSize;
    uint32_t entryOff    = (uint32_t)(fatByteOff % g_session.sectorSize);
    if (fatSector64 >= (uint64_t)fi.firstFATSector + fi.sectorsPerFat) return 0x0FFFFFFFu;

    uint8_t sec[VC_MAX_SECTOR_SIZE];
    if (!vc_read_sector(fd, fatSector64, sec)) return 0x0FFFFFFFu;
    if (entryOff + 4u > g_session.sectorSize) return 0x0FFFFFFFu;

    uint32_t nextCluster = 0;
    if (!vc::decode_fat32_chain_entry(sec + entryOff, 4u, fi.clusterCount,
                                      &nextCluster)) {
        LOGE("fat32_next_cluster: invalid chain value for cluster=%u", cluster);
        return 0x0FFFFFFFu;
    }
    return nextCluster;
}

// List all (non-deleted, non-dot) entries in the directory starting at startCluster.
static std::vector<DirEntry> fat32_list_cluster(int fd, const Fat32Info& fi,
                                                 uint32_t startCluster,
                                                 bool* outValid = nullptr) {
    std::vector<DirEntry> results;
    if (outValid) *outValid = true;

    // LFN accumulation: seq → piece (seq 1 = first chars, highest seq = last chars on disk)
    // We accumulate piece strings indexed by (seq-1) then concatenate in order.
    static const int LFN_MAX_SEQ = 20; // 20 × 13 chars = 260 > MAX_PATH
    std::u16string lfnParts[LFN_MAX_SEQ];
    int         lfnMaxSeq = 0;
    int         lfnExpectedSeq = 0;
    uint8_t     lfnChecksum = 0;
    bool        haveLFN   = false;

    uint32_t cluster = startCluster;
    bool endOfDir = false;
    std::unordered_set<uint32_t> visited;

    while (!endOfDir && cluster >= 2u && cluster < 0x0FFFFFF8u) {
        if (!visited.insert(cluster).second || visited.size() > fi.clusterCount) {
            LOGE("fat32_list_cluster: cyclic or overlong FAT chain");
            if (outValid) *outValid = false;
            results.clear();
            return results;
        }
        uint64_t firstSec = 0;
        if (!fat32_cluster_to_sector(fi, cluster, &firstSec)) {
            if (outValid) *outValid = false;
            results.clear();
            return results;
        }

        for (uint8_t s = 0; !endOfDir && s < fi.sectorsPerCluster; s++) {
            uint8_t sec[VC_MAX_SECTOR_SIZE];
            if (!vc_read_sector(fd, firstSec + s, sec)) {
                if (outValid) *outValid = false;
                results.clear();
                return results;
            }

            uint32_t sectorBytes     = g_session.sectorSize;
            uint32_t entriesPerSector = sectorBytes / 32u;

            for (uint32_t e = 0; e < entriesPerSector; e++) {
                const uint8_t* ent = sec + e * 32u;

                if (ent[0] == 0x00u) { endOfDir = true; break; } // end of directory
                if (ent[0] == 0xE5u) {                            // deleted entry
                    haveLFN = false; lfnMaxSeq = 0; lfnExpectedSeq = 0;
                    continue;
                }

                uint8_t attr = ent[11];

                if (attr == 0x0Fu) {
                    vc::FatLfnEntryFields lfnEntry{};
                    if (!vc::parse_fat_lfn_entry(ent, 32u, &lfnEntry)) {
                        haveLFN = false; lfnMaxSeq = 0; lfnExpectedSeq = 0;
                        continue;
                    }
                    const uint8_t seq = lfnEntry.sequence;

                    if (lfnEntry.isLast) {
                        // Reset accumulator for a new LFN sequence
                        for (int i = 0; i < LFN_MAX_SEQ; i++) lfnParts[i].clear();
                        lfnMaxSeq = (int)seq;
                        lfnExpectedSeq = (int)seq;
                        lfnChecksum = lfnEntry.checksum;
                        haveLFN = seq >= 1u && seq <= (uint8_t)LFN_MAX_SEQ;
                    }

                    if (haveLFN && seq == (uint8_t)lfnExpectedSeq &&
                        lfnEntry.checksum == lfnChecksum) {
                        lfnParts[seq - 1] = std::move(lfnEntry.characters);
                        --lfnExpectedSeq;
                    } else {
                        haveLFN = false;
                    }
                    continue;
                }

                // Skip volume-ID and pure-system entries
                if (attr & 0x08u) {
                    haveLFN = false; lfnMaxSeq = 0; lfnExpectedSeq = 0;
                    continue;
                }

                // Ordinary file or sub-directory entry
                std::string name;
                if (haveLFN && lfnMaxSeq > 0 && lfnExpectedSeq == 0 &&
                    vc::fat_lfn_checksum(ent) == lfnChecksum) {
                    std::u16string utf16Name;
                    for (int i = 0; i < lfnMaxSeq && i < LFN_MAX_SEQ; i++) {
                        utf16Name += lfnParts[i];
                    }
                    if (!vc::utf16_to_utf8_strict(utf16Name.data(), utf16Name.size(), &name)) {
                        name.clear();
                    }
                }
                if (name.empty()) {
                    name = fat_83_to_string(ent);
                }
                haveLFN = false; lfnMaxSeq = 0; lfnExpectedSeq = 0;

                if (name == "." || name == "..") continue;
                if (name.empty()) continue;

                bool     isDir        = (attr & 0x10u) != 0u;
                uint32_t fsize        = le32r(ent + 28);
                uint16_t mdate        = le16r(ent + 24);
                uint16_t mtime        = le16r(ent + 22);
                uint32_t firstCluster = ((uint32_t)le16r(ent + 20) << 16) | (uint32_t)le16r(ent + 26);

                if (results.size() >= MAX_DIRECTORY_ENTRIES) {
                    LOGE("fat32_list_cluster: directory entry limit exceeded");
                    if (outValid) *outValid = false;
                    results.clear();
                    return results;
                }
                results.push_back({name, isDir, fsize, mdate, mtime, firstCluster,
                                   firstSec + s, e * 32u, false});
            }
        }

        if (!endOfDir) cluster = fat32_next_cluster(fd, fi, cluster);
    }

    return results;
}

// Split an absolute path like "/dir/sub/file.txt" into ["dir", "sub", "file.txt"].
static std::vector<std::string> split_path(const std::string& path) {
    std::vector<std::string> parts;
    size_t start = (!path.empty() && path[0] == '/') ? 1u : 0u;
    while (start < path.size()) {
        size_t end = path.find('/', start);
        if (end == std::string::npos) end = path.size();
        if (end > start) parts.push_back(path.substr(start, end - start));
        start = end + 1;
    }
    return parts;
}

// Resolve `path` to a cluster number.  Only root ("/") is supported in this
// milestone; deeper paths always return 0 (not found).
static uint32_t fat32_find_dir(int fd, const Fat32Info& fi, const char* path) {
    if (path == nullptr || path[0] == '\0') return fi.rootCluster;
    // Any path whose non-empty components are zero (e.g. "/", "//") maps to root.
    if (split_path(std::string(path)).empty()) {
        LOGI("fat32_find_dir: resolved root cluster");
        return fi.rootCluster;
    }
    uint32_t cluster = fi.rootCluster;
    for (const std::string& part : split_path(std::string(path))) {
        auto entries = fat32_list_cluster(fd, fi, cluster);
        auto match = std::find_if(entries.begin(), entries.end(), [&](const DirEntry& entry) {
            return entry.isDir && entry.name == part;
        });
        if (match == entries.end() || match->firstCluster < 2u) return 0u;
        cluster = match->firstCluster;
    }
    return cluster;
}

// ============================================================
// Filesystem detection
// ============================================================

enum FsType { FS_UNKNOWN, FS_FAT32, FS_EXFAT, FS_NTFS };

static FsType detect_filesystem(int fd) {
    uint8_t sec[VC_MAX_SECTOR_SIZE];
    if (!vc_read_sector(fd, 0, sec)) {
        LOGE("detect_filesystem: vc_read_sector(sector 0) failed");
        return FS_UNKNOWN;
    }

    // exFAT: OEM name at bytes 3-10 is "EXFAT   " (with 3 trailing spaces)
    if (memcmp(sec + 3, "EXFAT   ", 8) == 0) return FS_EXFAT;
    if (memcmp(sec + 3, "NTFS    ", 8) == 0) return FS_NTFS;

    // FAT32: BPB_BytsPerSec (offset 11) != 0 and BPB_FATSz32 (offset 36) != 0
    uint16_t bps   = le16r(sec + 11);
    uint32_t spf32 = le32r(sec + 36);
    if (bps != 0 && spf32 != 0) return FS_FAT32;

    // None of the known signatures matched – log the raw bytes so we can debug.
    LOGE("detect_filesystem: unrecognised FS – OEM=[%02x%02x%02x%02x%02x%02x%02x%02x]"
         " bps=%u spf32=%u sec0byte0=%02x",
         sec[3], sec[4], sec[5], sec[6], sec[7], sec[8], sec[9], sec[10],
         (unsigned)bps, (unsigned)spf32, (unsigned)sec[0]);
    return FS_UNKNOWN;
}

// ============================================================
// exFAT parser (read-only)
//
// Microsoft exFAT BPB layout (sector 0 of the data area):
//   [  3 .. 10] OEM Name "EXFAT   "
//   [ 11 .. 63] MustBeZero
//   [ 64 .. 71] PartitionOffset (uint64 LE)
//   [ 72 .. 79] VolumeLength    (uint64 LE)
//   [ 80 .. 83] FatOffset       (uint32 LE) – in sectors from vol start
//   [ 84 .. 87] FatLength       (uint32 LE) – in sectors
//   [ 88 .. 91] ClusterHeapOffset (uint32 LE)
//   [ 92 .. 95] ClusterCount    (uint32 LE)
//   [ 96 .. 99] FirstClusterOfRootDirectory (uint32 LE)
//   [108]       BytesPerSectorShift  (uint8)
//   [109]       SectorsPerClusterShift (uint8)
//
// Directory entry types used here:
//   0x85  File (primary)  – attributes + timestamps
//   0xC0  Stream Extension (secondary) – name length + data length
//   0xC1  File Name (secondary) – up to 15 × UCS-2LE chars each
// ============================================================

struct ExFatInfo {
    uint64_t volumeLength;
    uint32_t bitmapCluster;
    uint64_t bitmapLength;
    uint32_t fatOffset;           // first FAT sector (from start of data area)
    uint32_t fatLength;           // FAT length in sectors
    uint32_t clusterHeapOffset;   // first cluster-heap sector
    uint32_t clusterCount;        // total cluster count
    uint32_t rootCluster;         // first cluster of root directory
    uint8_t  bytesPerSectorShift;
    uint8_t  sectorsPerClusterShift;
    uint32_t sectorsPerCluster;   // 1 << sectorsPerClusterShift (precomputed)
    uint16_t bytesPerSector;      // 1 << bytesPerSectorShift   (precomputed)
};

static uint32_t exfat_boot_checksum_update(uint32_t checksum, uint8_t value) {
    return ((checksum << 31u) | (checksum >> 1u)) + value;
}

static bool exfat_validate_boot_region(int fd, uint64_t startSector, uint16_t bytesPerSector) {
    uint32_t checksum = 0;
    uint8_t sector[VC_MAX_SECTOR_SIZE];
    for (uint32_t s = 0; s < 11u; ++s) {
        if (!vc_read_sector(fd, startSector + s, sector)) return false;
        for (uint32_t i = 0; i < bytesPerSector; ++i) {
            if (s == 0u && (i == 106u || i == 107u || i == 112u)) continue;
            checksum = exfat_boot_checksum_update(checksum, sector[i]);
        }
    }
    if (!vc_read_sector(fd, startSector + 11u, sector)) return false;
    for (uint32_t i = 0; i + 4u <= bytesPerSector; i += 4u) {
        if (le32r(sector + i) != checksum) return false;
    }
    return true;
}

static bool exfat_read_bpb(int fd, ExFatInfo* ei, bool validateBootRegions = true) {
    uint8_t sec[VC_MAX_SECTOR_SIZE];
    if (!vc_read_sector(fd, 0, sec)) {
        LOGE("exfat_read_bpb: could not read sector 0");
        return false;
    }
    vc::ExFatBootFields fields{};
    const uint64_t totalSectors = g_session.encryptedAreaSize / g_session.sectorSize;
    if (!vc::validate_exfat_boot_sector(sec, sizeof(sec), g_session.sectorSize,
                                        totalSectors, &fields)) {
        LOGE("exfat_read_bpb: invalid boot sector");
        return false;
    }
    if (validateBootRegions &&
        (!exfat_validate_boot_region(fd, 0u, fields.bytesPerSector) ||
         !exfat_validate_boot_region(fd, 12u, fields.bytesPerSector))) {
        LOGE("exfat_read_bpb: invalid main or backup boot-region checksum");
        return false;
    }

    ei->volumeLength           = fields.volumeLength;
    ei->bitmapCluster          = 0u;
    ei->bitmapLength           = 0u;
    ei->fatOffset              = fields.fatOffset;
    ei->fatLength              = fields.fatLength;
    ei->clusterHeapOffset      = fields.clusterHeapOffset;
    ei->clusterCount           = fields.clusterCount;
    ei->rootCluster            = fields.rootCluster;
    ei->bytesPerSectorShift    = fields.bytesPerSectorShift;
    ei->sectorsPerClusterShift = fields.sectorsPerClusterShift;
    ei->sectorsPerCluster      = fields.sectorsPerCluster;
    ei->bytesPerSector         = fields.bytesPerSector;

    LOGI("exfat_read_bpb: fatOff=%u heapOff=%u rootClus=%u bps=%u spc=%u",
         ei->fatOffset, ei->clusterHeapOffset, ei->rootCluster,
         ei->bytesPerSector, ei->sectorsPerCluster);
    return true;
}

// Return the logical sector (in vc_read_sector numbering) of a given cluster.
static uint64_t exfat_cluster_to_sector(const ExFatInfo& ei, uint32_t cluster) {
    if (cluster < 2u) return ei.clusterHeapOffset;
    return (uint64_t)ei.clusterHeapOffset + (uint64_t)(cluster - 2u) * ei.sectorsPerCluster;
}

// Follow the exFAT FAT chain; returns next cluster value (>= 0xFFFFFFF8 = end/bad).
static uint32_t exfat_next_cluster(int fd, const ExFatInfo& ei, uint32_t cluster) {
    if (cluster < 2u || cluster > ei.clusterCount + 1u) return 0xFFFFFFFFu;
    uint64_t fatByteOff = (uint64_t)cluster * 4u;
    uint64_t fatSector  = (uint64_t)ei.fatOffset + fatByteOff / ei.bytesPerSector;
    uint32_t entryOff   = (uint32_t)(fatByteOff % ei.bytesPerSector);
    if (fatSector >= (uint64_t)ei.fatOffset + ei.fatLength) return 0xFFFFFFFFu;

    uint8_t sec[VC_MAX_SECTOR_SIZE];
    if (!vc_read_sector(fd, fatSector, sec)) {
        LOGE("exfat_next_cluster: sector read failed for cluster=%u fatSector=%llu",
             cluster, (unsigned long long)fatSector);
        return 0xFFFFFFFFu;  // end-of-chain sentinel; 0xFFFFFFFu (7 F's) is not >= 0xFFFFFFF8 and would cause looping
    }
    if (entryOff + 4u > (uint32_t)ei.bytesPerSector) {
        LOGE("exfat_next_cluster: entryOff=%u out of range for bytesPerSector=%u cluster=%u",
             entryOff, ei.bytesPerSector, cluster);
        return 0xFFFFFFFFu;
    }

    return le32r(sec + entryOff);
}

static bool exfat_cluster_is_allocated(int fd, const ExFatInfo& ei, uint32_t cluster);

static bool exfat_stream_extent_is_plausible(const ExFatInfo& ei, uint32_t firstCluster,
                                             uint64_t dataLength, bool noFatChain) {
    if (dataLength == 0u) return firstCluster == 0u ||
                                  (firstCluster >= 2u && firstCluster <= ei.clusterCount + 1u);
    if (firstCluster < 2u || firstCluster > ei.clusterCount + 1u) return false;
    uint64_t clusterBytes = (uint64_t)ei.sectorsPerCluster * ei.bytesPerSector;
    uint64_t maxDataLength = (uint64_t)ei.clusterCount * clusterBytes;
    if (dataLength > maxDataLength) return false;
    if (!noFatChain) return true;
    uint64_t requiredClusters = (dataLength + clusterBytes - 1u) / clusterBytes;
    return (uint64_t)firstCluster - 2u + requiredClusters <= ei.clusterCount;
}

// List all non-deleted entries in the exFAT directory starting at startCluster.
// Handles File (0x85) + Stream Extension (0xC0) + File Name (0xC1) record groups.
static std::vector<DirEntry> exfat_list_cluster(int fd, const ExFatInfo& ei,
                                                 uint32_t startCluster,
                                                 bool noFatChain = false,
                                                 uint64_t directoryDataLength = 0u,
                                                 bool* outValid = nullptr) {
    std::vector<DirEntry> results;
    if (outValid) *outValid = true;

    if (startCluster < 2u) {
        LOGE("exfat_list_cluster: invalid startCluster=%u", startCluster);
        if (outValid) *outValid = false;
        return results;
    }

    // At most 1 primary + 18 secondary entries per exFAT file entry set.
    std::array<uint8_t, 19u * 32u> pendingRecord{};
    uint8_t pendingExpectedEntries = 0u;
    uint8_t pendingEntryCount = 0u;
    uint64_t primarySector = 0;
    uint32_t primaryOffset = 0;

    uint32_t cluster  = startCluster;
    uint32_t clusterSteps = 0;
    bool     endOfDir = false;
    std::unordered_set<uint32_t> visited;

    while (!endOfDir && cluster >= 2u && cluster < 0xFFFFFFF8u &&
           clusterSteps++ <= ei.clusterCount) {
        if (noFatChain && directoryDataLength != 0u &&
            (uint64_t)(clusterSteps - 1u) * ei.sectorsPerCluster * ei.bytesPerSector >=
                directoryDataLength) break;
        if (cluster > ei.clusterCount + 1u ||
            (!noFatChain && !visited.insert(cluster).second)) {
            LOGE("exfat_list_cluster: cyclic or out-of-range cluster chain");
            if (outValid) *outValid = false;
            results.clear();
            return results;
        }
        if (ei.bitmapCluster >= 2u && !exfat_cluster_is_allocated(fd, ei, cluster)) {
            LOGE("exfat_list_cluster: directory cluster is not allocated");
            if (outValid) *outValid = false;
            results.clear();
            return results;
        }
        uint64_t firstSec = exfat_cluster_to_sector(ei, cluster);
        LOGI("exfat_list_cluster: scanning cluster=%u firstSec=%llu", cluster, (unsigned long long)firstSec);

        for (uint32_t s = 0; !endOfDir && s < ei.sectorsPerCluster; s++) {
            uint8_t sec[VC_MAX_SECTOR_SIZE];
            if (!vc_read_sector(fd, firstSec + s, sec)) {
                LOGE("exfat_list_cluster: sector read failed cluster=%u sector=%llu",
                     cluster, (unsigned long long)(firstSec + s));
                if (outValid) *outValid = false;
                results.clear();
                return results;
            }

            uint32_t entriesPerSector = (uint32_t)ei.bytesPerSector / 32u;

            for (uint32_t e = 0; e < entriesPerSector; e++) {
                const uint8_t* ent  = sec + e * 32u;
                uint8_t        type = ent[0];

                // End-of-directory marker
                if (type == 0x00u) { endOfDir = true; break; }

                // Not-in-use (bit 7 clear = deleted / free); reset any pending record
                if ((type & 0x80u) == 0u) {
                    pendingExpectedEntries = 0u;
                    pendingEntryCount = 0u;
                    continue;
                }

                if (type == 0x85u) {
                    const uint8_t secondaryCount = ent[1];
                    if (secondaryCount < 2u || secondaryCount > 18u) {
                        pendingExpectedEntries = 0u;
                        pendingEntryCount = 0u;
                        continue;
                    }
                    pendingExpectedEntries = (uint8_t)(secondaryCount + 1u);
                    pendingEntryCount = 1u;
                    memcpy(pendingRecord.data(), ent, 32u);
                    primarySector = firstSec + s;
                    primaryOffset = e * 32u;
                    continue;
                }

                if (pendingEntryCount == 0u ||
                    pendingEntryCount >= pendingExpectedEntries) continue;
                memcpy(pendingRecord.data() + (std::size_t)pendingEntryCount * 32u,
                       ent, 32u);
                ++pendingEntryCount;

                if (pendingEntryCount == pendingExpectedEntries) {
                    vc::ExFatFileEntryFields fields{};
                    const bool parsed = vc::parse_exfat_file_entry_set(
                        pendingRecord.data(), (std::size_t)pendingEntryCount * 32u, &fields);
                    if (parsed &&
                        exfat_stream_extent_is_plausible(ei, fields.firstCluster,
                                                         fields.dataLength,
                                                         fields.noFatChain)) {
                        if (results.size() >= MAX_DIRECTORY_ENTRIES) {
                            LOGE("exfat_list_cluster: directory entry limit exceeded");
                            if (outValid) *outValid = false;
                            results.clear();
                            return results;
                        }
                        results.push_back({std::move(fields.name), fields.isDirectory,
                                           fields.dataLength, fields.modifiedDate,
                                           fields.modifiedTime, fields.firstCluster,
                                           primarySector, primaryOffset, fields.noFatChain});
                    }
                    pendingExpectedEntries = 0u;
                    pendingEntryCount = 0u;
                }
            }
        }

        if (!endOfDir) {
            uint32_t next = noFatChain ? cluster + 1u : exfat_next_cluster(fd, ei, cluster);
            if (next >= 0xFFFFFFF8u) break;
            cluster = next;
        }
    }

    if (!endOfDir && clusterSteps > ei.clusterCount) {
        LOGE("exfat_list_cluster: FAT chain exceeded cluster count (cycle or corrupt BPB)");
        if (outValid) *outValid = false;
        results.clear();
    }
    LOGI("exfat_list_cluster: startCluster=%u returned %zu entries", startCluster, results.size());
    return results;
}

struct ExFatRootMetadata {
    uint32_t bitmapCluster = 0;
    uint64_t bitmapLength = 0;
    uint32_t upcaseCluster = 0;
    uint64_t upcaseLength = 0;
    uint32_t upcaseChecksum = 0;
};

static bool exfat_read_contiguous_byte(int fd, const ExFatInfo& ei, uint32_t firstCluster,
                                       uint64_t offset, uint8_t* value) {
    uint64_t clusterBytes = (uint64_t)ei.sectorsPerCluster * ei.bytesPerSector;
    uint64_t clusterIndex = offset / clusterBytes;
    if (clusterIndex >= ei.clusterCount ||
        (uint64_t)firstCluster + clusterIndex > (uint64_t)ei.clusterCount + 1u) return false;
    uint64_t sector = exfat_cluster_to_sector(ei, firstCluster + (uint32_t)clusterIndex) +
                      (offset % clusterBytes) / ei.bytesPerSector;
    uint8_t data[VC_MAX_SECTOR_SIZE];
    if (!vc_read_sector(fd, sector, data)) return false;
    *value = data[offset % ei.bytesPerSector];
    return true;
}

static bool exfat_validate_root_metadata(int fd, ExFatInfo* ei, bool validateUpcaseChecksum) {
    ExFatRootMetadata metadata;
    uint32_t cluster = ei->rootCluster;
    std::unordered_set<uint32_t> visited;
    bool endOfDirectory = false;
    while (!endOfDirectory && cluster >= 2u && cluster <= ei->clusterCount + 1u) {
        if (!visited.insert(cluster).second || visited.size() > ei->clusterCount) return false;
        uint64_t firstSector = exfat_cluster_to_sector(*ei, cluster);
        for (uint32_t s = 0; !endOfDirectory && s < ei->sectorsPerCluster; ++s) {
            uint8_t sector[VC_MAX_SECTOR_SIZE];
            if (!vc_read_sector(fd, firstSector + s, sector)) return false;
            for (uint32_t off = 0; off + 32u <= ei->bytesPerSector; off += 32u) {
                const uint8_t* entry = sector + off;
                if (entry[0] == 0x00u) {
                    endOfDirectory = true;
                    break;
                }
                if (entry[0] == 0x81u && (entry[1] & 1u) == 0u) {
                    metadata.bitmapCluster = le32r(entry + 20);
                    metadata.bitmapLength = le64r(entry + 24);
                } else if (entry[0] == 0x82u) {
                    metadata.upcaseChecksum = le32r(entry + 4);
                    metadata.upcaseCluster = le32r(entry + 20);
                    metadata.upcaseLength = le64r(entry + 24);
                }
            }
        }
        if (!endOfDirectory) {
            uint32_t next = exfat_next_cluster(fd, *ei, cluster);
            if (next >= 0xFFFFFFF8u) break;
            cluster = next;
        }
    }
    uint64_t minimumBitmapLength = ((uint64_t)ei->clusterCount + 7u) / 8u;
    if (metadata.bitmapCluster < 2u || metadata.bitmapCluster > ei->clusterCount + 1u ||
        metadata.bitmapLength < minimumBitmapLength ||
        metadata.upcaseCluster < 2u || metadata.upcaseCluster > ei->clusterCount + 1u ||
        metadata.upcaseLength == 0u || metadata.upcaseLength > 2u * 1024u * 1024u) {
        LOGE("exfat: required allocation bitmap or upcase metadata is invalid");
        return false;
    }

    uint8_t allocationByte = 0;
    uint64_t rootBit = (uint64_t)ei->rootCluster - 2u;
    if (!exfat_read_contiguous_byte(fd, *ei, metadata.bitmapCluster, rootBit / 8u,
                                    &allocationByte) ||
        (allocationByte & (uint8_t)(1u << (rootBit % 8u))) == 0u) {
        LOGE("exfat: root cluster is not allocated in allocation bitmap");
        return false;
    }
    ei->bitmapCluster = metadata.bitmapCluster;
    ei->bitmapLength = metadata.bitmapLength;

    if (!validateUpcaseChecksum) return true;

    uint32_t checksum = 0;
    uint64_t upcaseSectors = (metadata.upcaseLength + ei->bytesPerSector - 1u) /
                             ei->bytesPerSector;
    uint64_t upcaseStartSector = exfat_cluster_to_sector(*ei, metadata.upcaseCluster);
    uint64_t availableClusterSectors =
        ((uint64_t)ei->clusterCount + 2u - metadata.upcaseCluster) * ei->sectorsPerCluster;
    if (upcaseSectors > availableClusterSectors) return false;
    uint64_t remaining = metadata.upcaseLength;
    for (uint64_t s = 0; s < upcaseSectors; ++s) {
        uint8_t sector[VC_MAX_SECTOR_SIZE];
        if (!vc_read_sector(fd, upcaseStartSector + s, sector)) return false;
        uint32_t count = (uint32_t)std::min<uint64_t>(remaining, ei->bytesPerSector);
        for (uint32_t i = 0; i < count; ++i) {
            checksum = ((checksum << 31u) | (checksum >> 1u)) + sector[i];
        }
        remaining -= count;
    }
    if (checksum != metadata.upcaseChecksum) {
        LOGE("exfat: invalid upcase-table checksum");
        return false;
    }
    return true;
}

static bool exfat_cluster_is_allocated(int fd, const ExFatInfo& ei, uint32_t cluster) {
    if (cluster < 2u || cluster > ei.clusterCount + 1u || ei.bitmapCluster < 2u) return false;
    uint64_t bit = (uint64_t)cluster - 2u;
    if (bit / 8u >= ei.bitmapLength) return false;
    uint8_t value = 0;
    return exfat_read_contiguous_byte(fd, ei, ei.bitmapCluster, bit / 8u, &value) &&
           (value & (uint8_t)(1u << (bit % 8u))) != 0u;
}

// Resolve `path` to a cluster number for exFAT.  Only root ("/") is supported.
static bool exfat_find_dir(int fd, const ExFatInfo& ei, const char* path,
                           uint32_t* outCluster, bool* outNoFatChain,
                           uint64_t* outDataLength) {
    if (path == nullptr || path[0] == '\0') {
        *outCluster = ei.rootCluster;
        *outNoFatChain = false;
        *outDataLength = 0u;
        return true;
    }
    // Any path whose non-empty components are zero (e.g. "/", "//") maps to root.
    if (split_path(std::string(path)).empty()) {
        LOGI("exfat_find_dir: resolved root cluster");
        *outCluster = ei.rootCluster;
        *outNoFatChain = false;
        *outDataLength = 0u;
        return true;
    }
    uint32_t cluster = ei.rootCluster;
    bool noFatChain = false;
    uint64_t directoryLength = 0u;
    for (const std::string& part : split_path(std::string(path))) {
        auto entries = exfat_list_cluster(fd, ei, cluster, noFatChain, directoryLength);
        auto match = std::find_if(entries.begin(), entries.end(), [&](const DirEntry& entry) {
            return entry.isDir && entry.name == part;
        });
        if (match == entries.end() || match->firstCluster < 2u) return false;
        cluster = match->firstCluster;
        noFatChain = match->noFatChain;
        directoryLength = match->sizeBytes;
    }
    *outCluster = cluster;
    *outNoFatChain = noFatChain;
    *outDataLength = directoryLength;
    return true;
}

// ============================================================
// Path utilities and file-reading helpers
// ============================================================


// Find the DirEntry for the file at `path` inside a FAT32 filesystem.
// Returns true and fills `out` on success; false if not found or path is a directory.
static bool fat32_find_file(int fd, const Fat32Info& fi,
                             const char* path, DirEntry& out) {
    if (!path || path[0] == '\0') return false;
    auto parts = split_path(std::string(path));
    if (parts.empty()) return false;

    uint32_t cluster = fi.rootCluster;
    for (size_t i = 0; i < parts.size(); i++) {
        auto entries = fat32_list_cluster(fd, fi, cluster);
        bool found = false;
        for (auto& e : entries) {
            if (e.name == parts[i]) {
                if (i == parts.size() - 1) {
                    if (e.isDir) return false; // path points to a directory
                    out = e;
                    return true;
                }
                if (!e.isDir) return false; // expected a directory
                cluster = e.firstCluster;
                found = true;
                break;
            }
        }
        if (!found) return false;
    }
    return false;
}

// Read up to `length` bytes from a FAT32 file starting at byte `offset`.
// Returns the number of bytes actually read, 0 at EOF, or -1 on I/O error.
static ssize_t fat32_read_file_data(int fd, const Fat32Info& fi,
                                     const DirEntry& entry,
                                     uint64_t offset, uint8_t* buf, int length) {
    if (length <= 0 || entry.firstCluster < 2u || offset >= (uint64_t)entry.sizeBytes)
        return 0;

    int64_t toRead = (int64_t)std::min((uint64_t)length,
                                        (uint64_t)entry.sizeBytes - offset);
    uint32_t clusterBytes = (uint32_t)fi.sectorsPerCluster * g_session.sectorSize;

    // Advance to the cluster that contains `offset`
    uint64_t clusterIdx = offset / clusterBytes;
    if (clusterIdx >= fi.clusterCount) return -1;
    uint32_t cluster    = entry.firstCluster;
    std::unordered_set<uint32_t> visited;
    for (uint64_t i = 0; i < clusterIdx; i++) {
        if (!visited.insert(cluster).second) return -1;
        cluster = fat32_next_cluster(fd, fi, cluster);
        if (cluster >= 0x0FFFFFF8u) return 0;
    }

    uint64_t offsetInCluster = offset % clusterBytes;
    ssize_t  totalRead       = 0;

    while (toRead > 0 && cluster >= 2u && cluster < 0x0FFFFFF8u) {
        if (!visited.insert(cluster).second) return -1;
        uint64_t firstSec = 0;
        if (!fat32_cluster_to_sector(fi, cluster, &firstSec)) return -1;
        uint32_t secIdx   = (uint32_t)(offsetInCluster / g_session.sectorSize);
        uint32_t offInSec = (uint32_t)(offsetInCluster % g_session.sectorSize);

        while (toRead > 0 && secIdx < (uint32_t)fi.sectorsPerCluster) {
            uint8_t sec[VC_MAX_SECTOR_SIZE];
            if (!vc_read_sector(fd, firstSec + secIdx, sec)) {
                return totalRead > 0 ? totalRead : -1;
            }
            int32_t copyLen = (int32_t)std::min((int64_t)(g_session.sectorSize - offInSec), toRead);
            memcpy(buf + totalRead, sec + offInSec, (size_t)copyLen);
            totalRead += copyLen;
            toRead    -= copyLen;
            offInSec   = 0;
            secIdx++;
        }

        offsetInCluster = 0;
        if (toRead > 0) cluster = fat32_next_cluster(fd, fi, cluster);
    }

    // A chain shorter than the directory-advertised size is corruption, not a
    // successful short read. Fail closed so callers never mistake truncation
    // for a clean EOF.
    return toRead == 0 ? totalRead : -1;
}

// Find the DirEntry for the file at `path` inside an exFAT filesystem.
// Returns true and fills `out` on success; false if not found or path is a directory.
static bool exfat_find_file(int fd, const ExFatInfo& ei,
                              const char* path, DirEntry& out) {
    if (!path || path[0] == '\0') {
        LOGE("exfat_find_file: null or empty path");
        return false;
    }
    auto parts = split_path(std::string(path));
    if (parts.empty()) {
        // path is "/" or equivalent – that is a directory, not a file
        LOGI("exfat_find_file: path resolves to a directory");
        return false;
    }

    LOGI("exfat_find_file: resolving %zu path components", parts.size());

    uint32_t cluster = ei.rootCluster;
    bool noFatChain = false;
    uint64_t directoryLength = 0u;
    for (size_t i = 0; i < parts.size(); i++) {
        auto entries = exfat_list_cluster(fd, ei, cluster, noFatChain, directoryLength);
        LOGI("exfat_find_file: searching directory with %zu entries", entries.size());
        bool found = false;
        for (auto& e : entries) {
            if (e.name == parts[i]) {
                if (i == parts.size() - 1) {
                    if (e.isDir) {
                        LOGE("exfat_find_file: requested entry is a directory");
                        return false;
                    }
                    out = e;
                    LOGI("exfat_find_file: file resolved firstCluster=%u size=%llu",
                         e.firstCluster, (unsigned long long)e.sizeBytes);
                    return true;
                }
                if (!e.isDir) {
                    LOGE("exfat_find_file: path component is not a directory");
                    return false;
                }
                cluster = e.firstCluster;
                noFatChain = e.noFatChain;
                directoryLength = e.sizeBytes;
                found = true;
                break;
            }
        }
        if (!found) {
            LOGI("exfat_find_file: path component not found");
            return false;
        }
    }
    return false;
}

// Read up to `length` bytes from an exFAT file starting at byte `offset`.
// Returns the number of bytes actually read, 0 at EOF, or -1 on I/O error.
static ssize_t exfat_read_file_data(int fd, const ExFatInfo& ei,
                                     const DirEntry& entry,
                                     uint64_t offset, uint8_t* buf, int length) {
    if (length <= 0 || entry.firstCluster < 2u || offset >= (uint64_t)entry.sizeBytes)
        return 0;

    int64_t toRead = (int64_t)std::min((uint64_t)length,
                                        (uint64_t)entry.sizeBytes - offset);
    uint32_t clusterBytes = ei.sectorsPerCluster * (uint32_t)ei.bytesPerSector;

    // Advance to the cluster that contains `offset`
    uint64_t clusterIdx = offset / clusterBytes;
    uint32_t cluster    = entry.firstCluster;
    if (clusterIdx >= ei.clusterCount) return -1;
    std::unordered_set<uint32_t> visited;
    for (uint64_t i = 0; i < clusterIdx; i++) {
        if (!entry.noFatChain && !visited.insert(cluster).second) return -1;
        cluster = entry.noFatChain ? cluster + 1u : exfat_next_cluster(fd, ei, cluster);
        if (cluster >= 0xFFFFFFF8u) return 0;
    }

    uint64_t offsetInCluster = offset % clusterBytes;
    ssize_t  totalRead       = 0;

    while (toRead > 0 && cluster >= 2u && cluster < 0xFFFFFFF8u) {
        if (cluster > ei.clusterCount + 1u ||
            (!entry.noFatChain && !visited.insert(cluster).second) ||
            !exfat_cluster_is_allocated(fd, ei, cluster)) return -1;
        uint64_t firstSec = exfat_cluster_to_sector(ei, cluster);
        uint32_t secIdx   = (uint32_t)(offsetInCluster / ei.bytesPerSector);
        uint32_t offInSec = (uint32_t)(offsetInCluster % ei.bytesPerSector);

        while (toRead > 0 && secIdx < ei.sectorsPerCluster) {
            uint8_t sec[VC_MAX_SECTOR_SIZE];
            if (!vc_read_sector(fd, firstSec + secIdx, sec)) {
                return totalRead > 0 ? totalRead : -1;
            }
            int32_t copyLen = (int32_t)std::min((int64_t)((uint32_t)ei.bytesPerSector - offInSec), toRead);
            memcpy(buf + totalRead, sec + offInSec, (size_t)copyLen);
            totalRead += copyLen;
            toRead    -= copyLen;
            offInSec   = 0;
            secIdx++;
        }

        offsetInCluster = 0;
        if (toRead > 0) {
            uint32_t next = entry.noFatChain ? cluster + 1u :
                                               exfat_next_cluster(fd, ei, cluster);
            if (next >= 0xFFFFFFF8u) break;
            cluster = next;
        }
    }

    return toRead == 0 ? totalRead : -1;
}


static bool decode_hex(const char* text, uint8_t* output, size_t outputLength) {
    auto nibble = [](char value) -> int {
        if (value >= '0' && value <= '9') return value - '0';
        if (value >= 'a' && value <= 'f') return value - 'a' + 10;
        if (value >= 'A' && value <= 'F') return value - 'A' + 10;
        return -1;
    };
    for (size_t index = 0; index < outputLength; ++index) {
        int high = nibble(text[index * 2]);
        int low = nibble(text[index * 2 + 1]);
        if (high < 0 || low < 0) return false;
        output[index] = static_cast<uint8_t>((high << 4) | low);
    }
    return text[outputLength * 2] == '\0';
}

static bool run_crypto_self_tests() {
    uint8_t expected[64] = {};
    uint8_t actual[64] = {};
    ScopedWipe expectedWipe(expected, sizeof(expected));
    ScopedWipe actualWipe(actual, sizeof(actual));

    if (!decode_hex(
            "cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce"
            "47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e",
            expected, 64)) return false;
    sha512_hash(nullptr, 0, actual);
    if (!secure_equal(actual, expected, 64)) return false;

    const uint8_t hmacKey[20] = {
        0x0b,0x0b,0x0b,0x0b,0x0b,0x0b,0x0b,0x0b,0x0b,0x0b,
        0x0b,0x0b,0x0b,0x0b,0x0b,0x0b,0x0b,0x0b,0x0b,0x0b
    };
    const uint8_t hmacMessage[] = "Hi There";
    if (!decode_hex(
            "87aa7cdea5ef619d4ff0b4241a1d6cb02379f4e2ce4ec2787ad0b30545e17cd"
            "edaa833b7d6b8a702038b274eaea3f4e4be9d914eeb61f1702e696c203a126854",
            expected, 64)) return false;
    hmac_sha512(hmacKey, sizeof(hmacKey), hmacMessage, sizeof(hmacMessage) - 1, actual);
    if (!secure_equal(actual, expected, 64)) return false;

    if (!decode_hex(
            "867f70cf1ade02cff3752599a3a53dc4af34c7a669815ae5d513554e1c8cf252"
            "c02d470a285a0501bad999bfe943c08f050235d7d68b1da55e63f73b60a57fce",
            expected, 64)) return false;
    const uint8_t password[] = "password";
    const uint8_t salt[] = "salt";
    pbkdf2_sha512(password, sizeof(password) - 1, salt, sizeof(salt) - 1, 1, actual, 64);
    if (!secure_equal(actual, expected, 64)) return false;

    uint8_t aesKey[32];
    uint8_t aesPlain[16];
    uint8_t aesCipher[16];
    uint8_t aesExpected[16];
    AES256_KS schedule;
    ScopedWipe scheduleWipe(schedule, sizeof(schedule));
    for (int index = 0; index < 32; ++index) aesKey[index] = static_cast<uint8_t>(index);
    if (!decode_hex("00112233445566778899aabbccddeeff", aesPlain, 16) ||
        !decode_hex("8ea2b7ca516745bfeafc49904b496089", aesExpected, 16)) return false;
    aes256_expand(aesKey, schedule);
    aes256_encrypt_block(schedule, aesPlain, aesCipher);
    if (!secure_equal(aesCipher, aesExpected, 16)) return false;

    uint8_t xtsKey[64];
    uint8_t xtsPlain[32];
    uint8_t xtsCipher[32];
    uint8_t xtsExpected[32];
    uint8_t xtsRoundTrip[32];
    for (int index = 0; index < 64; ++index) xtsKey[index] = static_cast<uint8_t>(index);
    for (int index = 0; index < 32; ++index) xtsPlain[index] = static_cast<uint8_t>(index);
    if (!decode_hex("249bbf23bb2097d1a5a3d89a542629c8a8fc9175ae92e03c83ea8133d82a0fb9",
                    xtsExpected, 32)) return false;
    aes256_xts_encrypt(xtsKey, xtsKey + 32, 42, xtsPlain, xtsCipher, 32);
    if (!secure_equal(xtsCipher, xtsExpected, 32)) return false;
    aes256_xts_decrypt(xtsKey, xtsKey + 32, 42, xtsCipher, xtsRoundTrip, 32);
    return secure_equal(xtsRoundTrip, xtsPlain, 32);
}

static bool run_filesystem_self_tests() {
    std::string utf8;
    const std::u16string validName = u"nested-\U0001F600.txt";
    if (!vc::utf16_to_utf8_strict(validName.data(), validName.size(), &utf8) ||
        utf8 != "nested-\xF0\x9F\x98\x80.txt") return false;
    const std::u16string invalidName = {u'a', (char16_t)0xD800u, u'b'};
    if (vc::utf16_to_utf8_strict(invalidName.data(), invalidName.size(), &utf8)) return false;

    const uint8_t shortName[11] = {'H','E','L','L','O','~','1',' ','T','X','T'};
    if (vc::fat_lfn_checksum(shortName) != 0xEDu) return false;

    ExFatInfo largeVolume{};
    largeVolume.clusterCount = 2'000'000u;
    largeVolume.sectorsPerCluster = 8u;
    largeVolume.bytesPerSector = 512u;
    constexpr uint64_t fiveGiB = 5ull * 1024ull * 1024ull * 1024ull;
    if (!exfat_stream_extent_is_plausible(largeVolume, 2u, fiveGiB, true)) return false;
    DirEntry entry{"large.bin", false, fiveGiB, 0u, 0u, 2u, 0u, 0u, true};
    if (entry.sizeBytes != fiveGiB) return false;

    Fat32Info fat{};
    fat.firstDataSector = UINT32_MAX - 100u;
    fat.clusterCount = 1'000'000u;
    fat.sectorsPerCluster = 128u;
    uint64_t sector = 0;
    return fat32_cluster_to_sector(fat, 1'000'001u, &sector) && sector > UINT32_MAX;
}

// ============================================================
// JNI entry points
// ============================================================

extern "C" {

JNIEXPORT jstring JNICALL
Java_io_veracrypt_android_corenative_NativeBridge_nativeGetVersion(
        JNIEnv *env,
        jclass /* clazz */) {
    return env->NewStringUTF("0.4.0");
}

JNIEXPORT jboolean JNICALL
Java_io_veracrypt_android_corenative_NativeBridge_nativeRunCryptoSelfTests(
        JNIEnv* /* env */,
        jclass /* clazz */) {
    return run_crypto_self_tests() ? JNI_TRUE : JNI_FALSE;
}

JNIEXPORT jboolean JNICALL
Java_io_veracrypt_android_corenative_NativeBridge_nativeRunFilesystemSelfTests(
        JNIEnv* /* env */,
        jclass /* clazz */) {
    return run_filesystem_self_tests() ? JNI_TRUE : JNI_FALSE;
}

/**
 * Attempt to parse and decrypt the VeraCrypt volume header.
 *
 * Reads the first 512 bytes from fd, derives 64 bytes of key material via
 * PBKDF2-HMAC-SHA512 (500,000 iterations), decrypts the header with
 * AES-256-XTS, validates the "VERA" magic and both CRC-32 fields, then
 * stores master keys + volume parameters in g_session for subsequent calls.
 *
 * @param fd       Open, readable file descriptor of the container.
 * @param password UTF-8 passphrase bytes.
 * @return 0 = success, -1 = wrong password / unsupported algorithm, -2 = I/O or format error.
 */
JNIEXPORT jlong JNICALL
Java_io_veracrypt_android_corenative_NativeBridge_nativeOpen(
        JNIEnv *env,
        jclass /* clazz */,
        jint   jfd,
        jbyteArray password) {

    clear_session_state(g_session);

    if (jfd < 0 || password == nullptr) {
        LOGE("nativeOpen: invalid arguments");
        return -2;
    }

    ScopedFd ownedFd(fcntl((int)jfd, F_DUPFD_CLOEXEC, 0));
    if (ownedFd.get() < 0) {
        LOGE("nativeOpen: could not duplicate descriptor");
        return -2;
    }
    const int sessionFd = ownedFd.get();

    struct stat st{};
    if (fstat(sessionFd, &st) < 0) {
        LOGE("nativeOpen: descriptor metadata read failed");
        return -2;
    }
    if (st.st_size < 1024) return -5;
    uint8_t hdr[512];
    ScopedWipe hdrWipe(hdr, sizeof(hdr));
    if (!read_full_at(sessionFd, hdr, sizeof(hdr), 0)) {
        LOGE("nativeOpen: header read failed");
        return -2;
    }

    jsize  pwdLen = env->GetArrayLength(password);
    if (env->ExceptionCheck() || pwdLen <= 0) return -1;
    jbyte* pwd_j  = env->GetByteArrayElements(password, nullptr);
    if (!pwd_j) {
        LOGE("nativeOpen: GetByteArrayElements failed");
        return -2;
    }
    const uint8_t* pwd = reinterpret_cast<const uint8_t*>(pwd_j);

    // Salt: first 64 bytes of the header
    uint8_t dk[64];
    ScopedWipe dkWipe(dk, sizeof(dk));
    LOGI("nativeOpen: deriving configured key");
    pbkdf2_sha512(pwd, (size_t)pwdLen, hdr, 64, 500000u, dk, 64);

    secure_zero(pwd_j, (size_t)pwdLen);
    env->ReleaseByteArrayElements(password, pwd_j, 0);

    // Decrypt the 448-byte encrypted block (header[64..511]) with AES-256-XTS, unit 0
    uint8_t plain[448];
    ScopedWipe plainWipe(plain, sizeof(plain));
    aes256_xts_decrypt(dk, dk + 32, 0u, hdr + 64, plain, 448);

    // Validate magic "VERA"
    if (plain[0]!='V'||plain[1]!='E'||plain[2]!='R'||plain[3]!='A') {
        if (plain[0]=='T' && plain[1]=='R' && plain[2]=='U' && plain[3]=='E') {
            return -4;
        }
        LOGI("nativeOpen: header magic mismatch");
        return -1;
    }

    // Validate CRC32 of header fields (plain[0..187]) stored at plain[188..191]
    uint32_t crc_hdr_stored = ((uint32_t)plain[188]<<24)|((uint32_t)plain[189]<<16)|
                               ((uint32_t)plain[190]<< 8)| (uint32_t)plain[191];
    uint32_t crc_hdr_calc   = crc32_compute(plain, 188);
    if (crc_hdr_calc != crc_hdr_stored) {
        LOGI("nativeOpen: header CRC32 mismatch");
        return -3;
    }

    // Validate CRC32 of master-keys area (plain[192..447]) stored at plain[8..11]
    uint32_t crc_keys_stored = ((uint32_t)plain[8]<<24)|((uint32_t)plain[9]<<16)|
                                ((uint32_t)plain[10]<<8)| (uint32_t)plain[11];
    uint32_t crc_keys_calc   = crc32_compute(plain + 192, 256);
    if (crc_keys_calc != crc_keys_stored) {
        LOGI("nativeOpen: keys CRC32 mismatch");
        return -3;
    }

    // Extract volume parameters from the decrypted header
    uint16_t version = be16r(plain + 4);
    uint64_t hiddenVolumeSize = be64r(plain + 28);
    uint64_t volumeSize = be64r(plain + 36);
    uint64_t dataOffset = be64r(plain + 44);
    uint64_t encryptedAreaSize = be64r(plain + 52);
    uint32_t flags = be32r(plain + 60);
    uint32_t sectorSize = be32r(plain + 64);
    uint64_t encryptedAreaEnd = 0;
    if (version != 5u || sectorSize < 512u || sectorSize > VC_MAX_SECTOR_SIZE ||
        (sectorSize & (sectorSize - 1u)) != 0u || hiddenVolumeSize != 0u ||
        flags != 0u || encryptedAreaSize == 0u || volumeSize != encryptedAreaSize ||
        (dataOffset % sectorSize) != 0u || (encryptedAreaSize % sectorSize) != 0u ||
        !checked_add_u64(dataOffset, encryptedAreaSize, &encryptedAreaEnd) ||
        encryptedAreaEnd > (uint64_t)st.st_size) {
        LOGE("nativeOpen: invalid header geometry");
        return -3;
    }

    // Populate session (master keys are at plain[192..255])
    memcpy(g_session.masterKey1, plain + 192, 32);
    memcpy(g_session.masterKey2, plain + 224, 32);
    g_session.dataOffset = dataOffset;
    g_session.encryptedAreaSize = encryptedAreaSize;
    g_session.sectorSize = sectorSize;
    g_session.fd         = sessionFd;
    g_session.device     = st.st_dev;
    g_session.inode      = st.st_ino;
    g_session.fileSize   = (uint64_t)st.st_size;
    g_session.valid      = true;

    auto managedSession = std::make_shared<ManagedSession>();
    managedSession->state = g_session;
    managedSession->state.fd = ownedFd.release();
    uint64_t handle = store_session(managedSession);

    clear_session_state(g_session);

    LOGI("nativeOpen: session opened");
    return (jlong)handle;
}

JNIEXPORT void JNICALL
Java_io_veracrypt_android_corenative_NativeBridge_nativeClose(
        JNIEnv* /* env */,
        jclass /* clazz */,
        jlong jhandle) {
    if (jhandle <= 0) return;
    std::shared_ptr<ManagedSession> session;
    {
        std::lock_guard<std::mutex> lock(g_sessions_mutex);
        auto it = g_sessions.find((uint64_t)jhandle);
        if (it == g_sessions.end()) return;
        session = it->second;
        g_sessions.erase(it);
    }
    std::lock_guard<std::mutex> operationLock(session->operationMutex);
    if (session->state.fd >= 0) close(session->state.fd);
    clear_session_state(session->state);
}

JNIEXPORT jboolean JNICALL
Java_io_veracrypt_android_corenative_NativeBridge_nativeIsOpen(
        JNIEnv* /* env */,
        jclass /* clazz */,
        jlong jhandle) {
    return find_session((uint64_t)jhandle) ? JNI_TRUE : JNI_FALSE;
}

/**
 * List the files and sub-directories at `path` inside the container.
 *
 * nativeParseHeader must have returned 0 before calling this function.
 * Detects whether the encrypted volume contains a FAT32 or exFAT filesystem
 * and reads structures from fd using the master keys cached in g_session.
 *
 * @param fd    File descriptor of the container (same as passed to nativeParseHeader).
 * @param path  Absolute path inside the container; currently only "/" is supported.
 * @return jobjectArray of io.veracrypt.android.coreapi.VolumeEntry, or null on error.
 */
JNIEXPORT jobjectArray JNICALL
Java_io_veracrypt_android_corenative_NativeBridge_nativeListDir(
        JNIEnv *env,
        jclass /* clazz */,
        jlong  jhandle,
        jstring jpath) {

    auto session = find_session((uint64_t)jhandle);
    if (!session || jpath == nullptr) {
        LOGE("nativeListDir: no valid session");
        return nullptr;
    }
    std::lock_guard<std::mutex> operationLock(session->operationMutex);
    ScopedSessionContext sessionContext(session->state);
    const int sessionFd = session->state.fd;

    const char* path = env->GetStringUTFChars(jpath, nullptr);
    if (!path) {
        LOGE("nativeListDir: GetStringUTFChars returned null");
        return nullptr;
    }
    if (!safe_absolute_path(path)) {
        env->ReleaseStringUTFChars(jpath, path);
        LOGE("nativeListDir: unsafe or malformed path");
        return nullptr;
    }
    const std::string requestedPath(path);
    LOGI("nativeListDir: listing validated path");

    // Detect the inner filesystem type
    FsType fsType = detect_filesystem(sessionFd);
    LOGI("nativeListDir: detected fsType=%s",
         fsType == FS_FAT32 ? "FAT32" :
         fsType == FS_EXFAT ? "exFAT" :
         fsType == FS_NTFS  ? "NTFS"  : "UNKNOWN");
    std::vector<DirEntry> entries;

    if (fsType == FS_FAT32) {
        Fat32Info fi;
        if (!fat32_read_bpb(sessionFd, &fi)) {
            env->ReleaseStringUTFChars(jpath, path);
            LOGE("nativeListDir: FAT32 BPB read failed");
            return nullptr;
        }
        session->validatedFsType = 1;
        uint32_t dirCluster = fat32_find_dir(sessionFd, fi, path);
        LOGI("nativeListDir: FAT32 dirCluster=%u (rootCluster=%u)", dirCluster, fi.rootCluster);
        env->ReleaseStringUTFChars(jpath, path);
        if (dirCluster < 2u) {
            LOGE("nativeListDir: FAT32 directory not found (cluster=%u)", dirCluster);
            return nullptr;
        }
        bool directoryValid = false;
        entries = fat32_list_cluster(sessionFd, fi, dirCluster, &directoryValid);
        if (!directoryValid) return nullptr;

    } else if (fsType == FS_EXFAT) {
        ExFatInfo ei;
        const bool needsFullValidation = session->validatedFsType != 2;
        if (!exfat_read_bpb(sessionFd, &ei, needsFullValidation) ||
            !exfat_validate_root_metadata(sessionFd, &ei, needsFullValidation)) {
            env->ReleaseStringUTFChars(jpath, path);
            LOGE("nativeListDir: exFAT BPB read failed");
            return nullptr;
        }
        session->validatedFsType = 2;
        uint32_t dirCluster = 0;
        bool dirNoFatChain = false;
        uint64_t dirDataLength = 0u;
        bool dirFound = exfat_find_dir(sessionFd, ei, path, &dirCluster,
                                       &dirNoFatChain, &dirDataLength);
        LOGI("nativeListDir: exFAT dirCluster=%u (rootCluster=%u)", dirCluster, ei.rootCluster);
        env->ReleaseStringUTFChars(jpath, path);
        if (!dirFound || dirCluster < 2u) {
            LOGE("nativeListDir: exFAT directory not found (cluster=%u)", dirCluster);
            return nullptr;
        }
        bool directoryValid = false;
        entries = exfat_list_cluster(sessionFd, ei, dirCluster, dirNoFatChain,
                                     dirDataLength, &directoryValid);
        if (!directoryValid) return nullptr;
        LOGI("nativeListDir: exFAT exfat_list_cluster returned %zu entries for dirCluster=%u",
             entries.size(), dirCluster);

    } else {
        env->ReleaseStringUTFChars(jpath, path);
        if (fsType == FS_NTFS)
            LOGE("nativeListDir: NTFS filesystem detected but not yet supported");
        else
            LOGE("nativeListDir: unsupported or unrecognised filesystem (fsType=%d)", (int)fsType);
        return nullptr;
    }

    // Build the Java VolumeEntry[] array
    jclass veClass = env->FindClass("io/veracrypt/android/coreapi/VolumeEntry");
    if (!veClass) { LOGE("nativeListDir: VolumeEntry class not found"); return nullptr; }

    jmethodID initId = env->GetMethodID(veClass, "<init>",
                           "(Ljava/lang/String;Ljava/lang/String;ZJJ)V");
    if (!initId) { LOGE("nativeListDir: VolumeEntry constructor not found"); return nullptr; }

    jobjectArray arr = env->NewObjectArray((jsize)entries.size(), veClass, nullptr);
    if (!arr) {
        LOGE("nativeListDir: NewObjectArray failed (count=%zu)", entries.size());
        return nullptr;
    }

    for (size_t i = 0; i < entries.size(); i++) {
        const DirEntry& e = entries[i];

        std::string entryPath = requestedPath == "/" ? "/" + e.name :
                                requestedPath + "/" + e.name;

        jstring jname  = env->NewStringUTF(e.name.c_str());
        jstring jepath = env->NewStringUTF(entryPath.c_str());
        if (!jname || !jepath || env->ExceptionCheck()) {
            if (jname) env->DeleteLocalRef(jname);
            if (jepath) env->DeleteLocalRef(jepath);
            return nullptr;
        }
        jlong   lastMs = (jlong)fat_datetime_to_ms(e.modDate, e.modTime);

        jobject obj = env->NewObject(veClass, initId,
                          jname, jepath,
                          (jboolean)(e.isDir ? JNI_TRUE : JNI_FALSE),
                          (jlong)e.sizeBytes,
                          lastMs);

        if (!obj || env->ExceptionCheck()) {
            env->DeleteLocalRef(jname);
            env->DeleteLocalRef(jepath);
            if (obj) env->DeleteLocalRef(obj);
            return nullptr;
        }

        env->SetObjectArrayElement(arr, (jsize)i, obj);
        if (env->ExceptionCheck()) {
            env->DeleteLocalRef(jname);
            env->DeleteLocalRef(jepath);
            env->DeleteLocalRef(obj);
            return nullptr;
        }
        env->DeleteLocalRef(jname);
        env->DeleteLocalRef(jepath);
        env->DeleteLocalRef(obj);
    }

    LOGI("nativeListDir: returning %zu entries (fs=%s)",
         entries.size(), fsType == FS_FAT32 ? "FAT32" : "exFAT");
    return arr;
}

/**
 * Read up to `length` bytes from the file at `path` inside the currently open
 * container, starting at byte offset `offset`.
 *
 * nativeParseHeader must have returned 0 before calling this function.
 * The data is decrypted on-the-fly with AES-256-XTS using the master keys
 * cached in g_session.
 *
 * @param fd      File descriptor of the container.
 * @param path    Absolute path of the file inside the container (e.g. "/report.pdf").
 * @param offset  Byte offset within the file to start reading from (>= 0).
 * @param length  Maximum number of bytes to read; capped internally at 4 MiB.
 * @return        jbyteArray with the bytes read (may be shorter than `length` at EOF),
 *                an empty array at EOF, or null if the file is not found or on I/O error.
 */
JNIEXPORT jbyteArray JNICALL
Java_io_veracrypt_android_corenative_NativeBridge_nativeReadFile(
        JNIEnv *env,
        jclass /* clazz */,
        jlong  jhandle,
        jstring jpath,
        jlong  offset,
        jint   length) {

    auto session = find_session((uint64_t)jhandle);
    if (!session || jpath == nullptr || length <= 0 || offset < 0) {
        LOGE("nativeReadFile: invalid arguments");
        return nullptr;
    }
    std::lock_guard<std::mutex> operationLock(session->operationMutex);
    ScopedSessionContext sessionContext(session->state);
    const int sessionFd = session->state.fd;

    // Cap per-call allocation at 4 MiB to avoid OOM in the JNI layer
    if (length > 4 * 1024 * 1024) length = 4 * 1024 * 1024;

    const char* path = env->GetStringUTFChars(jpath, nullptr);
    if (!path) return nullptr;
    if (!safe_absolute_path(path)) {
        env->ReleaseStringUTFChars(jpath, path);
        return nullptr;
    }

    FsType fsType = detect_filesystem(sessionFd);
    DirEntry entry;
    bool     found = false;
    ssize_t  n     = -1;

    std::vector<uint8_t> buf((size_t)length);

    if (fsType == FS_FAT32) {
        Fat32Info fi;
        if (fat32_read_bpb(sessionFd, &fi)) {
            found = fat32_find_file(sessionFd, fi, path, entry);
            if (found) {
                n = fat32_read_file_data(sessionFd, fi, entry, (uint64_t)offset,
                                         buf.data(), length);
            }
        }
    } else if (fsType == FS_EXFAT) {
        ExFatInfo ei;
        const bool needsFullValidation = session->validatedFsType != 2;
        if (exfat_read_bpb(sessionFd, &ei, needsFullValidation) &&
            exfat_validate_root_metadata(sessionFd, &ei, needsFullValidation)) {
            session->validatedFsType = 2;
            found = exfat_find_file(sessionFd, ei, path, entry);
            if (found) {
                n = exfat_read_file_data(sessionFd, ei, entry, (uint64_t)offset,
                                          buf.data(), length);
            }
        }
    }

    env->ReleaseStringUTFChars(jpath, path);

    if (!found) {
        LOGE("nativeReadFile: file not found");
        return nullptr;
    }
    if (n < 0) {
        LOGE("nativeReadFile: I/O error while reading");
        return nullptr;
    }

    jbyteArray result = env->NewByteArray((jsize)n);
    if (!result) {
        LOGE("nativeReadFile: NewByteArray failed for %zd bytes", n);
        return nullptr;
    }
    if (n > 0) {
        env->SetByteArrayRegion(result, 0, (jsize)n,
                                reinterpret_cast<const jbyte*>(buf.data()));
        if (env->ExceptionCheck()) return nullptr;
    }
    LOGI("nativeReadFile: read %zd bytes at offset %lld", n, (long long)offset);
    return result;
}

JNIEXPORT jint JNICALL
Java_io_veracrypt_android_corenative_NativeBridge_nativeGetFileSystemType(
        JNIEnv* /* env */,
        jclass  /* clazz */,
        jlong   jhandle) {
    auto session = find_session((uint64_t)jhandle);
    if (!session) return 0;
    std::lock_guard<std::mutex> operationLock(session->operationMutex);
    ScopedSessionContext sessionContext(session->state);
    switch (detect_filesystem(session->state.fd)) {
        case FS_FAT32: return 1;
        case FS_EXFAT: return 2;
        case FS_NTFS: return 3;
        default: return 0;
    }
}

} // extern "C"
