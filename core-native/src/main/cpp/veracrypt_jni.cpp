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
#include <cstring>
#include <cstdint>
#include <unistd.h>
#include <vector>
#include <string>
#include <algorithm>
#include <time.h>

#define LOG_TAG "VeraCrypt-Native"
#define LOGI(...) __android_log_print(ANDROID_LOG_INFO,  LOG_TAG, __VA_ARGS__)
#define LOGE(...) __android_log_print(ANDROID_LOG_ERROR, LOG_TAG, __VA_ARGS__)


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
// Stores master keys and volume parameters after a successful
// nativeParseHeader call so that nativeListDir can reuse them.
// Not thread-safe; callers must serialize access.
// ============================================================

#define VC_MAX_SECTOR_SIZE 4096

struct VCSession {
    bool     valid;
    uint8_t  masterKey1[32];  // AES-256 data encryption key
    uint8_t  masterKey2[32];  // AES-256 tweak key
    uint64_t dataOffset;      // byte offset of the first data sector in the file
    uint32_t sectorSize;      // bytes per logical sector (from volume header)
};

static VCSession g_session = {};

// ============================================================
// Little-endian helpers
// ============================================================

static inline uint16_t le16r(const uint8_t* p) {
    return (uint16_t)(p[0] | ((uint16_t)p[1] << 8));
}
static inline uint32_t le32r(const uint8_t* p) {
    return (uint32_t)(p[0] | ((uint32_t)p[1]<<8) | ((uint32_t)p[2]<<16) | ((uint32_t)p[3]<<24));
}

// ============================================================
// Sector reader
// Reads one logical sector from fd, decrypts it with AES-256-XTS,
// and writes the plaintext to outBuf (must be at least sectorSize bytes).
// sectorNo is the logical data-sector index starting at 0.
// ============================================================

static bool vc_read_sector(int fd, uint64_t sectorNo, uint8_t outBuf[VC_MAX_SECTOR_SIZE]) {
    if (!g_session.valid) return false;

    uint32_t sz = g_session.sectorSize;
    if (sz == 0 || sz > VC_MAX_SECTOR_SIZE) {
        LOGE("vc_read_sector: unexpected sector size %u", sz);
        return false;
    }

    off64_t fileOff = (off64_t)(g_session.dataOffset + sectorNo * (uint64_t)sz);
    if (lseek64(fd, fileOff, SEEK_SET) < 0) {
        LOGE("vc_read_sector: lseek failed for sector %llu", (unsigned long long)sectorNo);
        return false;
    }

    uint8_t enc[VC_MAX_SECTOR_SIZE];
    ssize_t n = read(fd, enc, sz);
    if (n != (ssize_t)sz) {
        LOGE("vc_read_sector: read %zd of %u bytes at sector %llu", n, sz, (unsigned long long)sectorNo);
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
    uint32_t    sizeBytes;
    uint16_t    modDate;  // FAT date encoding
    uint16_t    modTime;  // FAT time encoding
};

// Convert a UCS-2LE code point to UTF-8; returns number of bytes written (1-3).
static int ucs2_to_utf8(uint16_t c, char* out) {
    if (c < 0x80u) {
        out[0] = (char)c;
        return 1;
    } else if (c < 0x800u) {
        out[0] = (char)(0xC0u | (c >> 6));
        out[1] = (char)(0x80u | (c & 0x3Fu));
        return 2;
    } else {
        out[0] = (char)(0xE0u | (c >> 12));
        out[1] = (char)(0x80u | ((c >> 6) & 0x3Fu));
        out[2] = (char)(0x80u | (c & 0x3Fu));
        return 3;
    }
}

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
    t.tm_isdst = -1;
    time_t ts = mktime(&t);
    return (ts == (time_t)-1) ? 0 : (uint64_t)ts * 1000u;
}

struct Fat32Info {
    uint16_t bytesPerSector;
    uint8_t  sectorsPerCluster;
    uint32_t firstFATSector;   // logical sector index of the first FAT
    uint32_t firstDataSector;  // logical sector index of cluster 2
    uint32_t rootCluster;
};

// Read and parse the FAT32 BIOS Parameter Block (sector 0 of the data area).
static bool fat32_read_bpb(int fd, Fat32Info* fi) {
    uint8_t sec[VC_MAX_SECTOR_SIZE];
    if (!vc_read_sector(fd, 0, sec)) {
        LOGE("fat32_read_bpb: could not read sector 0");
        return false;
    }

    uint16_t bps     = le16r(sec + 11);
    uint8_t  spc     = sec[13];
    uint16_t rsc     = le16r(sec + 14);
    uint8_t  numFATs = sec[16];
    uint32_t spf32   = le32r(sec + 36);
    uint32_t rootCls = le32r(sec + 44);

    if (bps == 0 || spc == 0 || numFATs == 0 || spf32 == 0) {
        LOGE("fat32_read_bpb: invalid BPB values bps=%u spc=%u numFATs=%u spf32=%u",
             bps, spc, numFATs, spf32);
        return false;
    }

    fi->bytesPerSector    = bps;
    fi->sectorsPerCluster = spc;
    fi->firstFATSector    = rsc;
    fi->firstDataSector   = rsc + (uint32_t)numFATs * spf32;
    fi->rootCluster       = rootCls;

    LOGI("fat32_read_bpb: bps=%u spc=%u firstFAT=%u firstData=%u rootClus=%u",
         bps, spc, fi->firstFATSector, fi->firstDataSector, rootCls);
    return true;
}

// Return the logical sector index for the start of a given cluster (>= 2).
static uint32_t fat32_cluster_to_sector(const Fat32Info& fi, uint32_t cluster) {
    if (cluster < 2) return fi.firstDataSector;
    return fi.firstDataSector + (cluster - 2u) * (uint32_t)fi.sectorsPerCluster;
}

// Follow the FAT chain: return the cluster that follows `cluster`.
// Returns 0x0FFFFFFF (end-of-chain marker) on error or EOF.
static uint32_t fat32_next_cluster(int fd, const Fat32Info& fi, uint32_t cluster) {
    uint32_t fatByteOff  = cluster * 4u;
    uint32_t fatSector   = fi.firstFATSector + fatByteOff / g_session.sectorSize;
    uint32_t entryOff    = fatByteOff % g_session.sectorSize;

    uint8_t sec[VC_MAX_SECTOR_SIZE];
    if (!vc_read_sector(fd, fatSector, sec)) return 0x0FFFFFFFu;
    if (entryOff + 4u > g_session.sectorSize) return 0x0FFFFFFFu;

    return le32r(sec + entryOff) & 0x0FFFFFFFu;
}

// Read a string of UCS-2LE characters from a LFN directory entry.
// offsets[] and counts[] describe which byte positions / how many chars each holds.
static std::string lfn_extract_chars(const uint8_t* entry,
                                     const int offsets[], const int counts[], int groups) {
    std::string result;
    for (int g = 0; g < groups; g++) {
        for (int c = 0; c < counts[g]; c++) {
            int o = offsets[g] + c * 2;
            uint16_t ch = (uint16_t)(entry[o] | ((uint16_t)entry[o + 1] << 8));
            if (ch == 0x0000u || ch == 0xFFFFu) return result;
            char buf[4];
            int nb = ucs2_to_utf8(ch, buf);
            result.append(buf, (size_t)nb);
        }
    }
    return result;
}

// List all (non-deleted, non-dot) entries in the directory starting at startCluster.
static std::vector<DirEntry> fat32_list_cluster(int fd, const Fat32Info& fi,
                                                 uint32_t startCluster) {
    std::vector<DirEntry> results;

    // LFN accumulation: seq → piece (seq 1 = first chars, highest seq = last chars on disk)
    // We accumulate piece strings indexed by (seq-1) then concatenate in order.
    static const int LFN_MAX_SEQ = 20; // 20 × 13 chars = 260 > MAX_PATH
    std::string lfnParts[LFN_MAX_SEQ];
    int         lfnMaxSeq = 0;
    bool        haveLFN   = false;

    static const int LFN_OFF[]  = {1, 14, 28};
    static const int LFN_CNT[]  = {5,  6,  2};

    uint32_t cluster = startCluster;
    bool endOfDir = false;

    while (!endOfDir && cluster >= 2u && cluster < 0x0FFFFFF8u) {
        uint32_t firstSec = fat32_cluster_to_sector(fi, cluster);

        for (uint8_t s = 0; !endOfDir && s < fi.sectorsPerCluster; s++) {
            uint8_t sec[VC_MAX_SECTOR_SIZE];
            if (!vc_read_sector(fd, firstSec + s, sec)) break;

            uint32_t sectorBytes     = g_session.sectorSize;
            uint32_t entriesPerSector = sectorBytes / 32u;

            for (uint32_t e = 0; e < entriesPerSector; e++) {
                const uint8_t* ent = sec + e * 32u;

                if (ent[0] == 0x00u) { endOfDir = true; break; } // end of directory
                if (ent[0] == 0xE5u) {                            // deleted entry
                    haveLFN = false; lfnMaxSeq = 0;
                    continue;
                }

                uint8_t attr = ent[11];

                if (attr == 0x0Fu) {
                    // Long File Name entry
                    uint8_t seq    = ent[0] & 0x1Fu;
                    bool    isLast = (ent[0] & 0x40u) != 0u; // "last" = highest seq, on disk first

                    if (isLast) {
                        // Reset accumulator for a new LFN sequence
                        for (int i = 0; i < LFN_MAX_SEQ; i++) lfnParts[i].clear();
                        lfnMaxSeq = (int)seq;
                        haveLFN   = true;
                    }

                    if (haveLFN && seq >= 1u && seq <= (uint8_t)LFN_MAX_SEQ) {
                        lfnParts[seq - 1] = lfn_extract_chars(ent, LFN_OFF, LFN_CNT, 3);
                    }
                    continue;
                }

                // Skip volume-ID and pure-system entries
                if (attr & 0x08u) { haveLFN = false; lfnMaxSeq = 0; continue; }

                // Ordinary file or sub-directory entry
                std::string name;
                if (haveLFN && lfnMaxSeq > 0) {
                    for (int i = 0; i < lfnMaxSeq && i < LFN_MAX_SEQ; i++) name += lfnParts[i];
                } else {
                    name = fat_83_to_string(ent);
                }
                haveLFN = false; lfnMaxSeq = 0;

                if (name == "." || name == "..") continue;
                if (name.empty()) continue;

                bool     isDir = (attr & 0x10u) != 0u;
                uint32_t fsize = le32r(ent + 28);
                uint16_t mdate = le16r(ent + 24);
                uint16_t mtime = le16r(ent + 22);

                results.push_back({name, isDir, fsize, mdate, mtime});
            }
        }

        if (!endOfDir) cluster = fat32_next_cluster(fd, fi, cluster);
    }

    return results;
}

// Resolve `path` to a cluster number.  Only root ("/") is supported in this
// milestone; deeper paths always return 0 (not found).
static uint32_t fat32_find_dir(const Fat32Info& fi, const char* path) {
    if (path == nullptr || path[0] == '\0' ||
        (path[0] == '/' && path[1] == '\0')) {
        return fi.rootCluster;
    }
    LOGE("fat32_find_dir: sub-directory navigation not yet implemented (%s)", path);
    return 0u;
}

// ============================================================
// JNI entry points
// ============================================================

extern "C" {

JNIEXPORT jstring JNICALL
Java_io_veracrypt_android_corenative_NativeBridge_nativeGetVersion(
        JNIEnv *env,
        jclass /* clazz */) {
    return env->NewStringUTF("0.3.0");
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
JNIEXPORT jint JNICALL
Java_io_veracrypt_android_corenative_NativeBridge_nativeParseHeader(
        JNIEnv *env,
        jclass /* clazz */,
        jint   jfd,
        jbyteArray password) {

    g_session.valid = false;

    if (jfd < 0 || password == nullptr) {
        LOGE("nativeParseHeader: invalid arguments");
        return -2;
    }

    // Read first 512 bytes from the container
    if (lseek64((int)jfd, 0, SEEK_SET) < 0) {
        LOGE("nativeParseHeader: lseek failed");
        return -2;
    }
    uint8_t hdr[512];
    ssize_t nr = read((int)jfd, hdr, 512);
    if (nr != 512) {
        LOGE("nativeParseHeader: read only %zd bytes", nr);
        return -2;
    }

    jsize  pwdLen = env->GetArrayLength(password);
    jbyte* pwd_j  = env->GetByteArrayElements(password, nullptr);
    if (!pwd_j) {
        LOGE("nativeParseHeader: GetByteArrayElements failed");
        return -2;
    }
    const uint8_t* pwd = reinterpret_cast<const uint8_t*>(pwd_j);

    // Salt: first 64 bytes of the header
    uint8_t dk[64];
    LOGI("nativeParseHeader: deriving key (PBKDF2-SHA512, 500000 iter)…");
    pbkdf2_sha512(pwd, (size_t)pwdLen, hdr, 64, 500000u, dk, 64);

    env->ReleaseByteArrayElements(password, pwd_j, JNI_ABORT);

    // Decrypt the 448-byte encrypted block (header[64..511]) with AES-256-XTS, unit 0
    uint8_t plain[448];
    aes256_xts_decrypt(dk, dk + 32, 0u, hdr + 64, plain, 448);

    // Validate magic "VERA"
    if (plain[0]!='V'||plain[1]!='E'||plain[2]!='R'||plain[3]!='A') {
        LOGI("nativeParseHeader: magic mismatch (%02x%02x%02x%02x)",
             plain[0], plain[1], plain[2], plain[3]);
        return -1;
    }

    // Validate CRC32 of header fields (plain[0..187]) stored at plain[188..191]
    uint32_t crc_hdr_stored = ((uint32_t)plain[188]<<24)|((uint32_t)plain[189]<<16)|
                               ((uint32_t)plain[190]<< 8)| (uint32_t)plain[191];
    uint32_t crc_hdr_calc   = crc32_compute(plain, 188);
    if (crc_hdr_calc != crc_hdr_stored) {
        LOGI("nativeParseHeader: header CRC32 mismatch (calc=%08x stored=%08x)",
             crc_hdr_calc, crc_hdr_stored);
        return -1;
    }

    // Validate CRC32 of master-keys area (plain[192..447]) stored at plain[8..11]
    uint32_t crc_keys_stored = ((uint32_t)plain[8]<<24)|((uint32_t)plain[9]<<16)|
                                ((uint32_t)plain[10]<<8)| (uint32_t)plain[11];
    uint32_t crc_keys_calc   = crc32_compute(plain + 192, 256);
    if (crc_keys_calc != crc_keys_stored) {
        LOGI("nativeParseHeader: keys CRC32 mismatch (calc=%08x stored=%08x)",
             crc_keys_calc, crc_keys_stored);
        return -1;
    }

    // Extract volume parameters from the decrypted header
    uint64_t dataOffset = be64_read(plain + 44);
    uint32_t sectorSize = ((uint32_t)plain[64]<<24)|((uint32_t)plain[65]<<16)|
                          ((uint32_t)plain[66]<< 8)| (uint32_t)plain[67];
    if (sectorSize == 0u || sectorSize > VC_MAX_SECTOR_SIZE) sectorSize = 512u;

    // Populate session (master keys are at plain[192..255])
    memcpy(g_session.masterKey1, plain + 192, 32);
    memcpy(g_session.masterKey2, plain + 224, 32);
    g_session.dataOffset = dataOffset;
    g_session.sectorSize = sectorSize;
    g_session.valid      = true;

    LOGI("nativeParseHeader: success – dataOffset=%llu sectorSize=%u",
         (unsigned long long)dataOffset, sectorSize);
    return 0;
}

/**
 * List the files and sub-directories at `path` inside the container.
 *
 * nativeParseHeader must have returned 0 before calling this function.
 * Reads FAT32 structures from fd using the master keys cached in g_session.
 *
 * @param fd    File descriptor of the container (same as passed to nativeParseHeader).
 * @param path  Absolute path inside the container; currently only "/" is supported.
 * @return jobjectArray of io.veracrypt.android.coreapi.VolumeEntry, or null on error.
 */
JNIEXPORT jobjectArray JNICALL
Java_io_veracrypt_android_corenative_NativeBridge_nativeListDir(
        JNIEnv *env,
        jclass /* clazz */,
        jint   jfd,
        jstring jpath) {

    if (!g_session.valid || jfd < 0) {
        LOGE("nativeListDir: no valid session or bad fd");
        return nullptr;
    }

    const char* path = env->GetStringUTFChars(jpath, nullptr);
    if (!path) return nullptr;

    Fat32Info fi;
    bool bpbOk = fat32_read_bpb((int)jfd, &fi);
    if (!bpbOk) {
        env->ReleaseStringUTFChars(jpath, path);
        LOGE("nativeListDir: failed to read FAT32 BPB");
        return nullptr;
    }

    uint32_t dirCluster = fat32_find_dir(fi, path);
    env->ReleaseStringUTFChars(jpath, path);

    if (dirCluster < 2u) {
        LOGE("nativeListDir: directory not found");
        return nullptr;
    }

    std::vector<DirEntry> entries = fat32_list_cluster((int)jfd, fi, dirCluster);

    // Build the Java VolumeEntry[] array
    jclass     veClass = env->FindClass("io/veracrypt/android/coreapi/VolumeEntry");
    if (!veClass) { LOGE("nativeListDir: VolumeEntry class not found"); return nullptr; }

    jmethodID  initId  = env->GetMethodID(veClass, "<init>",
                             "(Ljava/lang/String;Ljava/lang/String;ZJJ)V");
    if (!initId)  { LOGE("nativeListDir: VolumeEntry constructor not found"); return nullptr; }

    jobjectArray arr = env->NewObjectArray((jsize)entries.size(), veClass, nullptr);
    if (!arr) return nullptr;

    for (size_t i = 0; i < entries.size(); i++) {
        const DirEntry& e = entries[i];

        // Build the full path string (root children are /name)
        std::string entryPath = "/" + e.name;

        jstring jname  = env->NewStringUTF(e.name.c_str());
        jstring jepath = env->NewStringUTF(entryPath.c_str());
        jlong   lastMs = (jlong)fat_datetime_to_ms(e.modDate, e.modTime);

        jobject obj = env->NewObject(veClass, initId,
                          jname, jepath,
                          (jboolean)(e.isDir ? JNI_TRUE : JNI_FALSE),
                          (jlong)e.sizeBytes,
                          lastMs);

        env->SetObjectArrayElement(arr, (jsize)i, obj);
        env->DeleteLocalRef(jname);
        env->DeleteLocalRef(jepath);
        env->DeleteLocalRef(obj);
    }

    LOGI("nativeListDir: returning %zu entries", entries.size());
    return arr;
}

} // extern "C"
