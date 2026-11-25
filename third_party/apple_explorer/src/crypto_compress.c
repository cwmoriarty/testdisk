#define _DEFAULT_SOURCE
#define _POSIX_C_SOURCE 200809L

#include "aex_internal.h"
#include <ctype.h>

/* ---------------- Fletcher-64 (APFS Object Checksum) & CRC32c ---------------- */

uint64_t aex_fletcher64(const void *data, size_t len) {
    /* APFS computes Fletcher-64 over bytes [8..len-1], modulus 2^32 - 1 */
    if ((len % 4U) != 0 || len < 8U) return 0;
    const uint8_t *p = (const uint8_t *)data;
    uint64_t sum1 = 0;
    uint64_t sum2 = 0;
    const uint64_t mod = 0xFFFFFFFFULL;

    for (size_t off = 8U; off < len; off += 4U) {
        sum1 += (uint64_t)aex_le32(p + off);
        sum2 += sum1;
        if (sum1 >= (1ULL << 56)) {
            sum1 %= mod;
            sum2 %= mod;
        }
    }
    sum1 %= mod;
    sum2 %= mod;

    uint64_t c1 = mod - ((sum1 + sum2) % mod);
    uint64_t c2 = mod - ((sum1 + c1) % mod);
    return (c2 << 32) | c1;
}

uint32_t aex_crc32c(uint32_t crc, const void *buf, size_t len) {
    const uint8_t *p = (const uint8_t *)buf;
    for (size_t i = 0; i < len; i++) {
        crc ^= p[i];
        for (int b = 0; b < 8; b++) {
            crc = (crc & 1U) ? ((crc >> 1) ^ 0x82F63B78U) : (crc >> 1);
        }
    }
    return crc;
}

/* ---------------- Portable SHA-1, SHA-256, HMAC, PBKDF2 ---------------- */

static inline uint32_t rotl32(uint32_t x, int n) { return (x << n) | (x >> (32 - n)); }
static inline uint32_t rotr32(uint32_t x, int n) { return (x >> n) | (x << (32 - n)); }

void aex_sha1(const void *data, size_t len, uint8_t out_digest[20]) {
    uint32_t h0 = 0x67452301U, h1 = 0xEFCDAB89U, h2 = 0x98BADCFEU, h3 = 0x10325476U, h4 = 0xC3D2E1F0U;
    size_t bit_len_lo = len * 8U;
    uint64_t bit_len = (uint64_t)len * 8ULL;
    (void)bit_len_lo;

    size_t padded = ((len + 9U + 63U) / 64U) * 64U;
    uint8_t *buf = (uint8_t *)calloc(1, padded);
    if (!buf) { memset(out_digest, 0, 20); return; }
    if (len > 0) memcpy(buf, data, len);
    buf[len] = 0x80U;
    for (int i = 0; i < 8; i++) buf[padded - 1 - i] = (uint8_t)((bit_len >> (i * 8)) & 0xFFU);

    uint32_t w[80];
    for (size_t off = 0; off < padded; off += 64U) {
        for (int i = 0; i < 16; i++) w[i] = aex_be32(buf + off + i * 4);
        for (int i = 16; i < 80; i++) w[i] = rotl32(w[i - 3] ^ w[i - 8] ^ w[i - 14] ^ w[i - 16], 1);
        uint32_t a = h0, b = h1, c = h2, d = h3, e = h4;
        for (int i = 0; i < 80; i++) {
            uint32_t f, k;
            if (i < 20)      { f = (b & c) | ((~b) & d); k = 0x5A827999U; }
            else if (i < 40) { f = b ^ c ^ d;            k = 0x6ED9EBA1U; }
            else if (i < 60) { f = (b & c) | (b & d) | (c & d); k = 0x8F1BBCDCU; }
            else             { f = b ^ c ^ d;            k = 0xCA62C1D6U; }
            uint32_t tmp = rotl32(a, 5) + f + e + k + w[i];
            e = d; d = c; c = rotl32(b, 30); b = a; a = tmp;
        }
        h0 += a; h1 += b; h2 += c; h3 += d; h4 += e;
    }
    aex_put_be32(out_digest + 0, h0);
    aex_put_be32(out_digest + 4, h1);
    aex_put_be32(out_digest + 8, h2);
    aex_put_be32(out_digest + 12, h3);
    aex_put_be32(out_digest + 16, h4);
    free(buf);
}

void aex_sha256(const void *data, size_t len, uint8_t out_digest[32]) {
    static const uint32_t k[64] = {
        0x428a2f98U,0x71374491U,0xb5c0fbcfU,0xe9b5dba5U,0x3956c25bU,0x59f111f1U,0x923f82a4U,0xab1c5ed5U,
        0xd807aa98U,0x12835b01U,0x243185beU,0x550c7dc3U,0x72be5d74U,0x80deb1feU,0x9bdc06a7U,0xc19bf174U,
        0xe49b69c1U,0xefbe4786U,0x0fc19dc6U,0x240ca1ccU,0x2de92c6fU,0x4a7484aaU,0x5cb0a9dcU,0x76f988daU,
        0x983e5152U,0xa831c66dU,0xb00327c8U,0xbf597fc7U,0xc6e00bf3U,0xd5a79147U,0x06ca6351U,0x14292967U,
        0x27b70a85U,0x2e1b2138U,0x4d2c6dfcU,0x53380d13U,0x650a7354U,0x766a0abbU,0x81c2c92eU,0x92722c85U,
        0xa2bfe8a1U,0xa81a664bU,0xc24b8b70U,0xc76c51a3U,0xd192e819U,0xd6990624U,0xf40e3585U,0x106aa070U,
        0x19a4c116U,0x1e376c08U,0x2748774cU,0x34b0bcb5U,0x391c0cb3U,0x4ed8aa4aU,0x5b9cca4fU,0x682e6ff3U,
        0x748f82eeU,0x78a5636fU,0x84c87814U,0x8cc70208U,0x90befffaU,0xa4506cebU,0xbef9a3f7U,0xc67178f2U
    };
    uint32_t h[8] = {
        0x6a09e667U,0xbb67ae85U,0x3c6ef372U,0xa54ff53aU,
        0x510e527fU,0x9b05688cU,0x1f83d9abU,0x5be0cd19U
    };
    uint64_t bit_len = (uint64_t)len * 8ULL;
    size_t padded = ((len + 9U + 63U) / 64U) * 64U;
    uint8_t *buf = (uint8_t *)calloc(1, padded);
    if (!buf) { memset(out_digest, 0, 32); return; }
    if (len > 0) memcpy(buf, data, len);
    buf[len] = 0x80U;
    for (int i = 0; i < 8; i++) buf[padded - 1 - i] = (uint8_t)((bit_len >> (i * 8)) & 0xFFU);

    uint32_t w[64];
    for (size_t off = 0; off < padded; off += 64U) {
        for (int i = 0; i < 16; i++) w[i] = aex_be32(buf + off + i * 4);
        for (int i = 16; i < 64; i++) {
            uint32_t s0 = rotr32(w[i - 15], 7) ^ rotr32(w[i - 15], 18) ^ (w[i - 15] >> 3);
            uint32_t s1 = rotr32(w[i - 2], 17) ^ rotr32(w[i - 2], 19) ^ (w[i - 2] >> 10);
            w[i] = w[i - 16] + s0 + w[i - 7] + s1;
        }
        uint32_t a = h[0], b = h[1], c = h[2], d = h[3], e = h[4], f = h[5], g = h[6], hh = h[7];
        for (int i = 0; i < 64; i++) {
            uint32_t S1 = rotr32(e, 6) ^ rotr32(e, 11) ^ rotr32(e, 25);
            uint32_t ch = (e & f) ^ ((~e) & g);
            uint32_t t1 = hh + S1 + ch + k[i] + w[i];
            uint32_t S0 = rotr32(a, 2) ^ rotr32(a, 13) ^ rotr32(a, 22);
            uint32_t maj = (a & b) ^ (a & c) ^ (b & c);
            uint32_t t2 = S0 + maj;
            hh = g; g = f; f = e; e = d + t1; d = c; c = b; b = a; a = t1 + t2;
        }
        h[0] += a; h[1] += b; h[2] += c; h[3] += d;
        h[4] += e; h[5] += f; h[6] += g; h[7] += hh;
    }
    for (int i = 0; i < 8; i++) aex_put_be32(out_digest + i * 4, h[i]);
    free(buf);
}

void aex_hmac_sha1(const uint8_t *key, size_t key_len, const void *msg, size_t msg_len, uint8_t out_mac[20]) {
    uint8_t kpad[64];
    memset(kpad, 0, sizeof(kpad));
    if (key_len > 64U) aex_sha1(key, key_len, kpad);
    else if (key_len > 0) memcpy(kpad, key, key_len);

    uint8_t *inner = (uint8_t *)malloc(64U + msg_len);
    if (!inner) { memset(out_mac, 0, 20); return; }
    for (int i = 0; i < 64; i++) inner[i] = kpad[i] ^ 0x36U;
    if (msg_len > 0) memcpy(inner + 64U, msg, msg_len);
    uint8_t ih[20];
    aex_sha1(inner, 64U + msg_len, ih);
    free(inner);

    uint8_t outer[64 + 20];
    for (int i = 0; i < 64; i++) outer[i] = kpad[i] ^ 0x5CU;
    memcpy(outer + 64, ih, 20);
    aex_sha1(outer, sizeof(outer), out_mac);
}

void aex_hmac_sha256(const uint8_t *key, size_t key_len, const void *msg, size_t msg_len, uint8_t out_mac[32]) {
    uint8_t kpad[64];
    memset(kpad, 0, sizeof(kpad));
    if (key_len > 64U) aex_sha256(key, key_len, kpad);
    else if (key_len > 0) memcpy(kpad, key, key_len);

    uint8_t *inner = (uint8_t *)malloc(64U + msg_len);
    if (!inner) { memset(out_mac, 0, 32); return; }
    for (int i = 0; i < 64; i++) inner[i] = kpad[i] ^ 0x36U;
    if (msg_len > 0) memcpy(inner + 64U, msg, msg_len);
    uint8_t ih[32];
    aex_sha256(inner, 64U + msg_len, ih);
    free(inner);

    uint8_t outer[64 + 32];
    for (int i = 0; i < 64; i++) outer[i] = kpad[i] ^ 0x5CU;
    memcpy(outer + 64, ih, 32);
    aex_sha256(outer, sizeof(outer), out_mac);
}

void aex_pbkdf2_sha1(const char *pass, size_t pass_len, const uint8_t *salt, size_t salt_len, uint32_t iters, uint8_t *out, size_t out_len) {
    uint8_t *sbuf = (uint8_t *)malloc(salt_len + 4U);
    if (!sbuf) return;
    if (salt_len > 0) memcpy(sbuf, salt, salt_len);
    uint32_t blk = 1U;
    size_t pos = 0;
    while (pos < out_len) {
        aex_put_be32(sbuf + salt_len, blk++);
        uint8_t u[20], t[20];
        aex_hmac_sha1((const uint8_t *)pass, pass_len, sbuf, salt_len + 4U, u);
        memcpy(t, u, 20);
        for (uint32_t i = 1U; i < iters; i++) {
            aex_hmac_sha1((const uint8_t *)pass, pass_len, u, 20U, u);
            for (int j = 0; j < 20; j++) t[j] ^= u[j];
        }
        size_t take = (out_len - pos < 20U) ? (out_len - pos) : 20U;
        memcpy(out + pos, t, take);
        pos += take;
    }
    free(sbuf);
}

void aex_pbkdf2_sha256(const char *pass, size_t pass_len, const uint8_t *salt, size_t salt_len, uint32_t iters, uint8_t *out, size_t out_len) {
    uint8_t *sbuf = (uint8_t *)malloc(salt_len + 4U);
    if (!sbuf) return;
    if (salt_len > 0) memcpy(sbuf, salt, salt_len);
    uint32_t blk = 1U;
    size_t pos = 0;
    while (pos < out_len) {
        aex_put_be32(sbuf + salt_len, blk++);
        uint8_t u[32], t[32];
        aex_hmac_sha256((const uint8_t *)pass, pass_len, sbuf, salt_len + 4U, u);
        memcpy(t, u, 32);
        for (uint32_t i = 1U; i < iters; i++) {
            aex_hmac_sha256((const uint8_t *)pass, pass_len, u, 32U, u);
            for (int j = 0; j < 32; j++) t[j] ^= u[j];
        }
        size_t take = (out_len - pos < 32U) ? (out_len - pos) : 32U;
        memcpy(out + pos, t, take);
        pos += take;
    }
    free(sbuf);
}

/* ---------------- Portable AES-128 / AES-256 (ECB, CBC, XTS, RFC 3394 Key Unwrap) ---------------- */

static const uint8_t k_sbox[256] = {
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

static const uint8_t k_rsbox[256] = {
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

static uint8_t gf_mul2(uint8_t x) { return (uint8_t)((x << 1) ^ ((x & 0x80U) ? 0x1BU : 0x00U)); }
static uint8_t gf_mul(uint8_t x, uint8_t y) {
    uint8_t r = 0;
    for (int i = 0; i < 8; i++) {
        if (y & 1U) r ^= x;
        x = gf_mul2(x);
        y >>= 1;
    }
    return r;
}

static uint32_t sub_word(uint32_t w) {
    return ((uint32_t)k_sbox[(w >> 24) & 0xFFU] << 24) |
           ((uint32_t)k_sbox[(w >> 16) & 0xFFU] << 16) |
           ((uint32_t)k_sbox[(w >> 8) & 0xFFU] << 8) |
           (uint32_t)k_sbox[w & 0xFFU];
}

int aex_aes_init_enc(aex_aes_ctx_t *ctx, const uint8_t *key, size_t key_bytes) {
    if (!ctx || !key || (key_bytes != 16U && key_bytes != 32U)) return -EINVAL;
    int nk = (int)(key_bytes / 4U);
    ctx->nr = (nk == 4) ? 10 : 14;
    int total_words = 4 * (ctx->nr + 1);
    for (int i = 0; i < nk; i++) ctx->rk[i] = aex_be32(key + i * 4);

    static const uint8_t rcon[11] = { 0x00,0x01,0x02,0x04,0x08,0x10,0x20,0x40,0x80,0x1B,0x36 };
    for (int i = nk; i < total_words; i++) {
        uint32_t temp = ctx->rk[i - 1];
        if ((i % nk) == 0) {
            temp = sub_word((temp << 8) | (temp >> 24)) ^ ((uint32_t)rcon[i / nk] << 24);
        } else if (nk > 6 && (i % nk) == 4) {
            temp = sub_word(temp);
        }
        ctx->rk[i] = ctx->rk[i - nk] ^ temp;
    }
    return 0;
}

int aex_aes_init_dec(aex_aes_ctx_t *ctx, const uint8_t *key, size_t key_bytes) {
    return aex_aes_init_enc(ctx, key, key_bytes);
}

static void add_round_key(uint8_t s[16], const uint32_t *rk) {
    for (int c = 0; c < 4; c++) {
        uint32_t w = rk[c];
        s[c * 4 + 0] ^= (uint8_t)(w >> 24);
        s[c * 4 + 1] ^= (uint8_t)(w >> 16);
        s[c * 4 + 2] ^= (uint8_t)(w >> 8);
        s[c * 4 + 3] ^= (uint8_t)(w);
    }
}

void aex_aes_encrypt_block(const aex_aes_ctx_t *ctx, const uint8_t in[16], uint8_t out[16]) {
    uint8_t s[16], t[16];
    memcpy(s, in, 16);
    add_round_key(s, ctx->rk);
    for (int r = 1; r <= ctx->nr; r++) {
        for (int i = 0; i < 16; i++) s[i] = k_sbox[s[i]];
        /* ShiftRows */
        memcpy(t, s, 16);
        s[1] = t[5]; s[5] = t[9]; s[9] = t[13]; s[13] = t[1];
        s[2] = t[10]; s[6] = t[14]; s[10] = t[2]; s[14] = t[6];
        s[3] = t[15]; s[7] = t[3]; s[11] = t[7]; s[15] = t[11];
        if (r < ctx->nr) {
            for (int c = 0; c < 4; c++) {
                uint8_t a0 = s[c*4+0], a1 = s[c*4+1], a2 = s[c*4+2], a3 = s[c*4+3];
                uint8_t xr = a0 ^ a1 ^ a2 ^ a3;
                s[c*4+0] ^= xr ^ gf_mul2(a0 ^ a1);
                s[c*4+1] ^= xr ^ gf_mul2(a1 ^ a2);
                s[c*4+2] ^= xr ^ gf_mul2(a2 ^ a3);
                s[c*4+3] ^= xr ^ gf_mul2(a3 ^ a0);
            }
        }
        add_round_key(s, ctx->rk + r * 4);
    }
    memcpy(out, s, 16);
}

void aex_aes_decrypt_block(const aex_aes_ctx_t *ctx, const uint8_t in[16], uint8_t out[16]) {
    uint8_t s[16], t[16];
    memcpy(s, in, 16);
    add_round_key(s, ctx->rk + ctx->nr * 4);
    for (int r = ctx->nr - 1; r >= 0; r--) {
        /* InvShiftRows */
        memcpy(t, s, 16);
        s[1] = t[13]; s[5] = t[1]; s[9] = t[5]; s[13] = t[9];
        s[2] = t[10]; s[6] = t[14]; s[10] = t[2]; s[14] = t[6];
        s[3] = t[7]; s[7] = t[11]; s[11] = t[15]; s[15] = t[3];
        for (int i = 0; i < 16; i++) s[i] = k_rsbox[s[i]];
        add_round_key(s, ctx->rk + r * 4);
        if (r > 0) {
            for (int c = 0; c < 4; c++) {
                uint8_t a0 = s[c*4+0], a1 = s[c*4+1], a2 = s[c*4+2], a3 = s[c*4+3];
                s[c*4+0] = gf_mul(a0, 0x0E) ^ gf_mul(a1, 0x0B) ^ gf_mul(a2, 0x0D) ^ gf_mul(a3, 0x09);
                s[c*4+1] = gf_mul(a0, 0x09) ^ gf_mul(a1, 0x0E) ^ gf_mul(a2, 0x0B) ^ gf_mul(a3, 0x0D);
                s[c*4+2] = gf_mul(a0, 0x0D) ^ gf_mul(a1, 0x09) ^ gf_mul(a2, 0x0E) ^ gf_mul(a3, 0x0B);
                s[c*4+3] = gf_mul(a0, 0x0B) ^ gf_mul(a1, 0x0D) ^ gf_mul(a2, 0x09) ^ gf_mul(a3, 0x0E);
            }
        }
    }
    memcpy(out, s, 16);
}

int aex_aes_cbc_decrypt(const uint8_t *key, size_t key_bytes, const uint8_t iv[16], const uint8_t *in, uint8_t *out, size_t len) {
    if ((len % 16U) != 0) return -EINVAL;
    aex_aes_ctx_t ctx;
    int rc = aex_aes_init_dec(&ctx, key, key_bytes);
    if (rc != 0) return rc;
    uint8_t prev[16], tmp[16], next_prev[16];
    memcpy(prev, iv, 16);
    for (size_t off = 0; off < len; off += 16U) {
        memcpy(next_prev, in + off, 16);
        aex_aes_decrypt_block(&ctx, in + off, tmp);
        for (int i = 0; i < 16; i++) out[off + i] = tmp[i] ^ prev[i];
        memcpy(prev, next_prev, 16);
    }
    return 0;
}

int aex_aes_xts_decrypt_sector(
    const aex_aes_ctx_t *dec_k1,
    const aex_aes_ctx_t *enc_k2,
    uint64_t tweak_no,
    const uint8_t *in,
    uint8_t *out,
    size_t sector_bytes
) {
    if ((sector_bytes % 16U) != 0 || sector_bytes == 0) return -EINVAL;
    uint8_t tweak[16];
    memset(tweak, 0, 16);
    aex_put_le64(tweak, tweak_no);
    aex_aes_encrypt_block(enc_k2, tweak, tweak);

    uint8_t blk[16];
    for (size_t off = 0; off < sector_bytes; off += 16U) {
        for (int i = 0; i < 16; i++) blk[i] = in[off + i] ^ tweak[i];
        aex_aes_decrypt_block(dec_k1, blk, blk);
        for (int i = 0; i < 16; i++) out[off + i] = blk[i] ^ tweak[i];

        uint8_t carry = (uint8_t)((tweak[15] >> 7) & 1U);
        for (int i = 15; i > 0; i--) tweak[i] = (uint8_t)((tweak[i] << 1) | (tweak[i - 1] >> 7));
        tweak[0] = (uint8_t)((tweak[0] << 1) ^ (carry ? 0x87U : 0x00U));
    }
    return 0;
}

/* RFC 3394 AES Key Unwrap (used by APFS FileVault 2 Keybags) */
int aex_aes_key_unwrap(const uint8_t *kek, size_t kek_bytes, const uint8_t *wrapped, size_t wrapped_len, uint8_t *out_plain) {
    if (wrapped_len < 24U || (wrapped_len % 8U) != 0) return -EINVAL;
    aex_aes_ctx_t ctx;
    int rc = aex_aes_init_dec(&ctx, kek, kek_bytes);
    if (rc != 0) return rc;

    size_t n = (wrapped_len / 8U) - 1U;
    uint8_t a[8];
    memcpy(a, wrapped, 8);
    memcpy(out_plain, wrapped + 8U, n * 8U);

    for (int j = 5; j >= 0; j--) {
        for (size_t i = n; i >= 1U; i--) {
            uint64_t t = (uint64_t)(n * (size_t)j + i);
            uint8_t b[16];
            memcpy(b, a, 8);
            for (int k = 0; k < 8; k++) b[7 - k] ^= (uint8_t)((t >> (k * 8)) & 0xFFU);
            memcpy(b + 8, out_plain + (i - 1U) * 8U, 8);
            aex_aes_decrypt_block(&ctx, b, b);
            memcpy(a, b, 8);
            memcpy(out_plain + (i - 1U) * 8U, b + 8, 8);
        }
    }

    static const uint8_t iv_3394[8] = { 0xA6,0xA6,0xA6,0xA6,0xA6,0xA6,0xA6,0xA6 };
    if (memcmp(a, iv_3394, 8) != 0) return -EACCES;
    return 0;
}

/* ---------------- Portable RFC 1951 / 1950 Deflate & Zlib Decompressor ---------------- */

typedef struct {
    const uint8_t *src;
    size_t         len;
    size_t         pos;
    uint32_t       bitbuf;
    int            bitcnt;
} bit_reader_t;

static int br_fill(bit_reader_t *br, int need) {
    while (br->bitcnt < need) {
        if (br->pos >= br->len) return -EIO;
        br->bitbuf |= ((uint32_t)br->src[br->pos++]) << br->bitcnt;
        br->bitcnt += 8;
    }
    return 0;
}

static int br_bits(bit_reader_t *br, int n, uint32_t *out) {
    if (n == 0) { *out = 0; return 0; }
    if (br_fill(br, n) != 0) return -EIO;
    *out = br->bitbuf & ((1U << n) - 1U);
    br->bitbuf >>= n;
    br->bitcnt -= n;
    return 0;
}

typedef struct {
    uint16_t counts[16];
    uint16_t symbols[288];
} huff_t;

static int huff_build(huff_t *h, const uint8_t *lengths, int num) {
    memset(h->counts, 0, sizeof(h->counts));
    for (int i = 0; i < num; i++) {
        if (lengths[i] > 15U) return -EINVAL;
        h->counts[lengths[i]]++;
    }
    if (h->counts[0] == num) return 0;
    uint16_t offs[16];
    offs[1] = 0;
    for (int len = 1; len < 15; len++) offs[len + 1] = (uint16_t)(offs[len] + h->counts[len]);
    for (int sym = 0; sym < num; sym++) {
        if (lengths[sym] != 0) h->symbols[offs[lengths[sym]]++] = (uint16_t)sym;
    }
    return 0;
}

static int huff_decode(bit_reader_t *br, const huff_t *h, int *out_sym) {
    int code = 0, first = 0, index = 0;
    for (int len = 1; len <= 15; len++) {
        uint32_t bit = 0;
        if (br_bits(br, 1, &bit) != 0) return -EIO;
        code |= (int)bit;
        int count = h->counts[len];
        if (code - count < first) {
            *out_sym = h->symbols[index + (code - first)];
            return 0;
        }
        index += count;
        first += count;
        first <<= 1;
        code <<= 1;
    }
    return -EINVAL;
}

static int inflate_raw(const uint8_t *src, size_t src_len, uint8_t *dst, size_t dst_cap, size_t *out_len) {
    static const uint16_t len_base[29] = {
        3,4,5,6,7,8,9,10,11,13,15,17,19,23,27,31,35,43,51,59,67,83,99,115,131,163,195,227,258
    };
    static const uint8_t len_ext[29] = {
        0,0,0,0,0,0,0,0,1,1,1,1,2,2,2,2,3,3,3,3,4,4,4,4,5,5,5,5,0
    };
    static const uint16_t dist_base[30] = {
        1,2,3,4,5,7,9,13,17,25,33,49,65,97,129,193,257,385,513,769,1025,1537,2049,3073,4097,6145,8193,12289,16385,24577
    };
    static const uint8_t dist_ext[30] = {
        0,0,0,0,1,1,2,2,3,3,4,4,5,5,6,6,7,7,8,8,9,9,10,10,11,11,12,12,13,13
    };
    static const uint8_t cl_order[19] = { 16,17,18,0,8,7,9,6,10,5,11,4,12,3,13,2,14,1,15 };

    bit_reader_t br = { src, src_len, 0, 0, 0 };
    size_t out_pos = 0;
    uint32_t bfinal = 0;

    do {
        uint32_t btype = 0;
        if (br_bits(&br, 1, &bfinal) != 0 || br_bits(&br, 2, &btype) != 0) return -EIO;
        if (btype == 0U) {
            br.bitbuf = 0;
            br.bitcnt = 0;
            if (br.pos + 4U > br.len) return -EIO;
            uint16_t blen = aex_le16(br.src + br.pos);
            uint16_t nlen = aex_le16(br.src + br.pos + 2U);
            br.pos += 4U;
            if ((uint16_t)(~nlen) != blen) return -EINVAL;
            if (br.pos + blen > br.len || out_pos + blen > dst_cap) return -ENOSPC;
            memcpy(dst + out_pos, br.src + br.pos, blen);
            br.pos += blen;
            out_pos += blen;
        } else if (btype == 1U || btype == 2U) {
            huff_t lit_h, dist_h;
            uint8_t lengths[320];
            if (btype == 1U) {
                int i = 0;
                for (; i <= 143; i++) lengths[i] = 8;
                for (; i <= 255; i++) lengths[i] = 9;
                for (; i <= 279; i++) lengths[i] = 7;
                for (; i <= 287; i++) lengths[i] = 8;
                if (huff_build(&lit_h, lengths, 288) != 0) return -EINVAL;
                for (i = 0; i < 30; i++) lengths[i] = 5;
                if (huff_build(&dist_h, lengths, 30) != 0) return -EINVAL;
            } else {
                uint32_t hlit = 0, hdist = 0, hclen = 0;
                if (br_bits(&br, 5, &hlit) != 0 || br_bits(&br, 5, &hdist) != 0 || br_bits(&br, 4, &hclen) != 0) return -EIO;
                hlit += 257U; hdist += 1U; hclen += 4U;
                if (hlit > 286U || hdist > 30U) return -EINVAL;
                uint8_t cl_len[19];
                memset(cl_len, 0, sizeof(cl_len));
                for (uint32_t i = 0; i < hclen; i++) {
                    uint32_t v = 0;
                    if (br_bits(&br, 3, &v) != 0) return -EIO;
                    cl_len[cl_order[i]] = (uint8_t)v;
                }
                huff_t cl_h;
                if (huff_build(&cl_h, cl_len, 19) != 0) return -EINVAL;
                uint32_t idx = 0, total = hlit + hdist;
                memset(lengths, 0, sizeof(lengths));
                while (idx < total) {
                    int sym = 0;
                    if (huff_decode(&br, &cl_h, &sym) != 0) return -EIO;
                    if (sym < 16) {
                        lengths[idx++] = (uint8_t)sym;
                    } else {
                        uint32_t rep = 0;
                        uint8_t val = 0;
                        if (sym == 16) {
                            if (idx == 0 || br_bits(&br, 2, &rep) != 0) return -EINVAL;
                            rep += 3U; val = lengths[idx - 1U];
                        } else if (sym == 17) {
                            if (br_bits(&br, 3, &rep) != 0) return -EINVAL;
                            rep += 3U;
                        } else {
                            if (br_bits(&br, 7, &rep) != 0) return -EINVAL;
                            rep += 11U;
                        }
                        if (idx + rep > total) return -EINVAL;
                        while (rep--) lengths[idx++] = val;
                    }
                }
                if (huff_build(&lit_h, lengths, (int)hlit) != 0 ||
                    huff_build(&dist_h, lengths + hlit, (int)hdist) != 0) return -EINVAL;
            }

            for (;;) {
                int sym = 0;
                if (huff_decode(&br, &lit_h, &sym) != 0) return -EIO;
                if (sym < 256) {
                    if (out_pos >= dst_cap) return -ENOSPC;
                    dst[out_pos++] = (uint8_t)sym;
                } else if (sym == 256) {
                    break;
                } else {
                    sym -= 257;
                    if (sym < 0 || sym >= 29) return -EINVAL;
                    uint32_t ext = 0;
                    if (br_bits(&br, len_ext[sym], &ext) != 0) return -EIO;
                    size_t copy_len = (size_t)len_base[sym] + ext;
                    int dsym = 0;
                    if (huff_decode(&br, &dist_h, &dsym) != 0 || dsym < 0 || dsym >= 30) return -EINVAL;
                    uint32_t dext = 0;
                    if (br_bits(&br, dist_ext[dsym], &dext) != 0) return -EIO;
                    size_t dist = (size_t)dist_base[dsym] + dext;
                    if (dist > out_pos || out_pos + copy_len > dst_cap) return -EINVAL;
                    for (size_t k = 0; k < copy_len; k++) {
                        dst[out_pos] = dst[out_pos - dist];
                        out_pos++;
                    }
                }
            }
        } else {
            return -EINVAL;
        }
    } while (!bfinal);

    *out_len = out_pos;
    return 0;
}

int aex_zlib_decompress(const uint8_t *src, size_t src_len, uint8_t *dst, size_t dst_cap, size_t *out_len) {
    if (!src || !dst || !out_len || src_len == 0) return -EINVAL;
    /* Uncompressed decmpfs chunk starting with 0xFF marker */
    if (src[0] == 0xFFU && src_len - 1U <= dst_cap) {
        memcpy(dst, src + 1U, src_len - 1U);
        *out_len = src_len - 1U;
        return 0;
    }
    /* Standard RFC 1950 2-byte zlib header (CMF/FLG divisible by 31) */
    if (src_len >= 6U && (src[0] & 0x0FU) == 8U && (((uint16_t)src[0] * 256U + src[1]) % 31U) == 0U) {
        size_t hdr = (src[1] & 0x20U) ? 6U : 2U;
        if (hdr < src_len) {
            return inflate_raw(src + hdr, src_len - hdr, dst, dst_cap, out_len);
        }
    }
    return inflate_raw(src, src_len, dst, dst_cap, out_len);
}

/* ---------------- Portable Apple LZVN & LZFSE Decompressors ---------------- */

int aex_lzvn_decompress(const uint8_t *src, size_t src_len, uint8_t *dst, size_t dst_cap, size_t *out_len) {
    if (!src || !dst || !out_len || src_len == 0) return -EINVAL;
    if (src[0] == 0x06U && src_len == 1U) { *out_len = 0; return 0; }

    size_t sp = 0, dp = 0, prev_d = 0;
    while (sp < src_len) {
        uint8_t op = src[sp++];
        if (op == 0x06U) { /* EOS */
            *out_len = dp;
            return 0;
        }
        if (op == 0x0EU || op == 0x16U || op == 0x1EU || op == 0x26U) {
            /* NOP / undefined padding */
            continue;
        }
        size_t L = 0, M = 0, D = 0;
        if (op == 0xE0U) { /* Large literal */
            if (sp >= src_len) return -EIO;
            L = (size_t)src[sp++] + 16U;
            if (sp + L > src_len || dp + L > dst_cap) return -EINVAL;
            memcpy(dst + dp, src + sp, L);
            sp += L; dp += L;
            continue;
        }
        if ((op & 0xF0U) == 0xE0U) { /* Small literal (0xE1..0xEF) */
            L = (size_t)(op & 0x0FU);
            if (sp + L > src_len || dp + L > dst_cap) return -EINVAL;
            memcpy(dst + dp, src + sp, L);
            sp += L; dp += L;
            continue;
        }
        if (op == 0xF0U) { /* Large match */
            if (sp >= src_len) return -EIO;
            M = (size_t)src[sp++] + 16U;
            D = prev_d;
        } else if ((op & 0xF0U) == 0xF0U) { /* Small match (0xF1..0xFF) */
            M = (size_t)(op & 0x0FU);
            D = prev_d;
        } else if ((op & 0x07U) == 0x06U) { /* Match with previous D (pre_d) */
            L = (size_t)((op >> 6) & 0x03U);
            M = (size_t)(((op >> 3) & 0x07U) + 3U);
            D = prev_d;
        } else if ((op & 0x07U) == 0x07U) { /* Large D (2 bytes) */
            if (sp + 2U > src_len) return -EIO;
            L = (size_t)((op >> 6) & 0x03U);
            M = (size_t)(((op >> 3) & 0x07U) + 3U);
            D = (size_t)aex_le16(src + sp);
            sp += 2U;
        } else if ((op & 0xE0U) == 0xA0U) { /* Medium D (101LLMMM DDDDDDMM DDDDDDDD) */
            if (sp + 2U > src_len) return -EIO;
            uint16_t b12 = aex_le16(src + sp);
            sp += 2U;
            L = (size_t)((op >> 3) & 0x03U);
            M = (size_t)((((op & 0x07U) << 2) | (b12 & 0x03U)) + 3U);
            D = (size_t)(b12 >> 2);
        } else if ((op & 0xC0U) != 0xC0U && (op & 0x07U) < 0x06U) { /* Small D (LLMMMDDD DDDDDDDD) */
            if (sp >= src_len) return -EIO;
            L = (size_t)((op >> 6) & 0x03U);
            M = (size_t)(((op >> 3) & 0x07U) + 3U);
            D = (((size_t)(op & 0x07U)) << 8) | (size_t)src[sp++];
        } else {
            return -EINVAL;
        }

        if (sp + L > src_len || dp + L + M > dst_cap) return -EINVAL;
        if (L > 0) {
            memcpy(dst + dp, src + sp, L);
            sp += L;
            dp += L;
        }
        if (D == 0 || D > dp) return -EINVAL;
        prev_d = D;
        for (size_t i = 0; i < M; i++) {
            dst[dp] = dst[dp - D];
            dp++;
        }
    }
    *out_len = dp;
    return 0;
}

int aex_lzfse_decompress(const uint8_t *src, size_t src_len, uint8_t *dst, size_t dst_cap, size_t *out_len) {
    if (!src || !dst || !out_len) return -EINVAL;
    size_t sp = 0, dp = 0;
    while (sp + 4U <= src_len) {
        uint32_t magic = aex_le32(src + sp);
        if (magic == 0x24787662U) { /* "bvx$" end of stream */
            *out_len = dp;
            return 0;
        } else if (magic == 0x2D787662U) { /* "bvx-" uncompressed raw block */
            if (sp + 8U > src_len) return -EIO;
            uint32_t n_raw = aex_le32(src + sp + 4U);
            sp += 8U;
            if (sp + n_raw > src_len || dp + n_raw > dst_cap) return -EINVAL;
            memcpy(dst + dp, src + sp, n_raw);
            sp += n_raw;
            dp += n_raw;
        } else if (magic == 0x6E787662U) { /* "bvxn" LZVN-encoded LZFSE block */
            if (sp + 12U > src_len) return -EIO;
            uint32_t n_raw = aex_le32(src + sp + 4U);
            uint32_t n_pay = aex_le32(src + sp + 8U);
            sp += 12U;
            if (sp + n_pay > src_len || dp + n_raw > dst_cap) return -EINVAL;
            size_t got = 0;
            int rc = aex_lzvn_decompress(src + sp, n_pay, dst + dp, n_raw, &got);
            if (rc != 0) return rc;
            sp += n_pay;
            dp += got;
        } else {
            return -ENOTSUP;
        }
    }
    *out_len = dp;
    return 0;
}

/* Transparent HFS+ & APFS com.apple.decmpfs Decompressor */
int aex_decmpfs_decompress(
    const uint8_t *xattr_bytes,
    size_t xattr_len,
    const uint8_t *rsrc_bytes,
    size_t rsrc_len,
    uint64_t uncompressed_size,
    uint8_t **out_buf,
    size_t *out_len
) {
    if (!xattr_bytes || xattr_len < 16U || !out_buf || !out_len) return -EINVAL;
    if (aex_le32(xattr_bytes) != 0x636D7066U) return -EINVAL; /* "fpmc" LE = 'cmpf' */

    uint32_t ctype = aex_le32(xattr_bytes + 4U);
    uint64_t orig_sz = aex_le64(xattr_bytes + 8U);
    if (uncompressed_size > 0 && orig_sz == 0) orig_sz = uncompressed_size;
    if (orig_sz > (256ULL << 20)) return -ENOMEM;

    size_t alloc_sz = (size_t)(orig_sz ? orig_sz : 1U);
    uint8_t *dst = (uint8_t *)calloc(1, alloc_sz);
    if (!dst) return -ENOMEM;

    const uint8_t *in_pay = xattr_bytes + 16U;
    size_t in_len = xattr_len - 16U;

    /* Inline attributes: 3 = zlib, 7 = lzvn, 11 = lzfse */
    if (ctype == 3U || ctype == 7U || ctype == 11U) {
        if (orig_sz == 0) { *out_buf = dst; *out_len = 0; return 0; }
        if (in_len > 0 && in_pay[0] == 0xFFU && in_len - 1U <= alloc_sz) {
            memcpy(dst, in_pay + 1U, in_len - 1U);
            *out_buf = dst; *out_len = in_len - 1U;
            return 0;
        }
        size_t got = 0;
        int rc = (ctype == 3U) ? aex_zlib_decompress(in_pay, in_len, dst, alloc_sz, &got)
               : (ctype == 7U) ? aex_lzvn_decompress(in_pay, in_len, dst, alloc_sz, &got)
                               : aex_lzfse_decompress(in_pay, in_len, dst, alloc_sz, &got);
        if (rc != 0) { free(dst); return rc; }
        *out_buf = dst; *out_len = got;
        return 0;
    }

    /* Resource-fork chunked attributes: 4 = zlib rsrc, 8 = lzvn rsrc, 12 = lzfse rsrc */
    if ((ctype == 4U || ctype == 8U || ctype == 12U) && rsrc_bytes && rsrc_len >= 16U) {
        uint32_t data_off = (ctype == 4U) ? aex_be32(rsrc_bytes) : 0U;
        if (ctype == 4U) {
            /* Standard HFS+ resource fork header + cmpf chunk table at data_off + 4 */
            if ((size_t)data_off + 8U > rsrc_len) { free(dst); return -EINVAL; }
            const uint8_t *blk = rsrc_bytes + data_off + 4U;
            size_t blk_rem = rsrc_len - (data_off + 4U);
            if (blk_rem < 4U) { free(dst); return -EINVAL; }
            uint32_t nchunks = aex_le32(blk);
            if ((size_t)nchunks * 8U + 4U > blk_rem) { free(dst); return -EINVAL; }
            size_t dpos = 0;
            for (uint32_t i = 0; i < nchunks && dpos < (size_t)orig_sz; i++) {
                uint32_t coff = aex_le32(blk + 4U + i * 8U);
                uint32_t clen = aex_le32(blk + 8U + i * 8U);
                if ((size_t)coff + clen > blk_rem) { free(dst); return -EINVAL; }
                size_t want = (size_t)orig_sz - dpos;
                if (want > 65536U) want = 65536U;
                size_t got = 0;
                int rc = aex_zlib_decompress(blk + coff, clen, dst + dpos, want, &got);
                if (rc != 0) { free(dst); return rc; }
                dpos += got;
            }
            *out_buf = dst; *out_len = dpos;
            return 0;
        } else {
            /* LZVN / LZFSE offset table starting at byte 0 of resource fork / dstream */
            uint32_t first_off = aex_le32(rsrc_bytes);
            if (first_off < 4U || first_off > rsrc_len) { free(dst); return -EINVAL; }
            uint32_t n_offs = first_off / 4U;
            if (n_offs < 2U) { free(dst); return -EINVAL; }
            size_t dpos = 0;
            for (uint32_t i = 0; i + 1U < n_offs && dpos < (size_t)orig_sz; i++) {
                uint32_t start = aex_le32(rsrc_bytes + i * 4U);
                uint32_t end = aex_le32(rsrc_bytes + (i + 1U) * 4U);
                if (end < start || end > rsrc_len) { free(dst); return -EINVAL; }
                size_t clen = end - start;
                size_t want = (size_t)orig_sz - dpos;
                if (want > 65536U) want = 65536U;
                size_t got = 0;
                int rc = (ctype == 8U)
                    ? aex_lzvn_decompress(rsrc_bytes + start, clen, dst + dpos, want, &got)
                    : aex_lzfse_decompress(rsrc_bytes + start, clen, dst + dpos, want, &got);
                if (rc != 0) { free(dst); return rc; }
                dpos += got;
            }
            *out_buf = dst; *out_len = dpos;
            return 0;
        }
    }

    free(dst);
    return -ENOTSUP;
}

/* ---------------- UTF-16BE / MacRoman to UTF-8 & Case Folding ---------------- */

static size_t encode_utf8_cp(uint32_t cp, char *out, size_t cap) {
    /* HFS+ swaps ':' on disk with '/' in Finder; expose safe ':' on host */
    if (cp == '/') cp = ':';
    if (cp < 0x80U) {
        if (cap < 1U) return 0;
        out[0] = (char)cp;
        return 1U;
    } else if (cp < 0x800U) {
        if (cap < 2U) return 0;
        out[0] = (char)(0xC0U | (cp >> 6));
        out[1] = (char)(0x80U | (cp & 0x3FU));
        return 2U;
    } else if (cp < 0x10000U) {
        if (cap < 3U) return 0;
        out[0] = (char)(0xE0U | (cp >> 12));
        out[1] = (char)(0x80U | ((cp >> 6) & 0x3FU));
        out[2] = (char)(0x80U | (cp & 0x3FU));
        return 3U;
    } else {
        if (cap < 4U) return 0;
        out[0] = (char)(0xF0U | (cp >> 18));
        out[1] = (char)(0x80U | ((cp >> 12) & 0x3FU));
        out[2] = (char)(0x80U | ((cp >> 6) & 0x3FU));
        out[3] = (char)(0x80U | (cp & 0x3FU));
        return 4U;
    }
}

size_t aex_utf16be_to_utf8(const uint8_t *u16be, size_t char_count, char *out_utf8, size_t out_cap) {
    if (!out_utf8 || out_cap == 0) return 0;
    size_t pos = 0;
    for (size_t i = 0; i < char_count; i++) {
        uint32_t w1 = aex_be16(u16be + i * 2U);
        if (w1 == 0) break;
        uint32_t cp = w1;
        if (w1 >= 0xD800U && w1 <= 0xDBFFU && i + 1U < char_count) {
            uint32_t w2 = aex_be16(u16be + (i + 1U) * 2U);
            if (w2 >= 0xDC00U && w2 <= 0xDFFFU) {
                cp = 0x10000U + (((w1 - 0xD800U) << 10) | (w2 - 0xDC00U));
                i++;
            }
        }
        size_t w = encode_utf8_cp(cp, out_utf8 + pos, out_cap - 1U - pos);
        if (w == 0) break;
        pos += w;
    }
    out_utf8[pos] = '\0';
    return pos;
}

size_t aex_macroman_to_utf8(const uint8_t *mac, size_t len, char *out_utf8, size_t out_cap) {
    if (!out_utf8 || out_cap == 0) return 0;
    size_t pos = 0;
    for (size_t i = 0; i < len; i++) {
        uint8_t c = mac[i];
        if (c == 0) break;
        uint32_t cp = (c < 0x80U) ? c : (0x00A0U + (c - 0x80U));
        size_t w = encode_utf8_cp(cp, out_utf8 + pos, out_cap - 1U - pos);
        if (w == 0) break;
        pos += w;
    }
    out_utf8[pos] = '\0';
    return pos;
}

int aex_strcasecmp_utf8(const char *a, const char *b) {
    while (*a && *b) {
        unsigned char ca = (unsigned char)tolower((unsigned char)*a);
        unsigned char cb = (unsigned char)tolower((unsigned char)*b);
        if (ca != cb) return (int)ca - (int)cb;
        a++; b++;
    }
    return (int)tolower((unsigned char)*a) - (int)tolower((unsigned char)*b);
}
