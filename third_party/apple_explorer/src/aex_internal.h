#ifndef AEX_INTERNAL_H
#define AEX_INTERNAL_H

#include "../include/apple_explorer.h"
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>

#ifndef S_IFMT
#define S_IFMT  0170000
#endif
#ifndef S_IFDIR
#define S_IFDIR 0040000
#endif
#ifndef S_IFREG
#define S_IFREG 0100000
#endif
#ifndef S_IFLNK
#define S_IFLNK 0120000
#endif

#ifndef ENOTSUP
#ifdef EOPNOTSUPP
#define ENOTSUP EOPNOTSUPP
#else
#define ENOTSUP 95
#endif
#endif
#ifndef EOVERFLOW
#define EOVERFLOW ERANGE
#endif
#ifndef ELOOP
#define ELOOP 40
#endif

static inline uint16_t aex_le16(const void *p) {
    const uint8_t *b = (const uint8_t *)p;
    return (uint16_t)b[0] | ((uint16_t)b[1] << 8);
}
static inline uint32_t aex_le32(const void *p) {
    const uint8_t *b = (const uint8_t *)p;
    return (uint32_t)b[0] | ((uint32_t)b[1] << 8) | ((uint32_t)b[2] << 16) | ((uint32_t)b[3] << 24);
}
static inline uint64_t aex_le64(const void *p) {
    const uint8_t *b = (const uint8_t *)p;
    return (uint64_t)aex_le32(b) | ((uint64_t)aex_le32(b + 4) << 32);
}
static inline uint16_t aex_be16(const void *p) {
    const uint8_t *b = (const uint8_t *)p;
    return ((uint16_t)b[0] << 8) | (uint16_t)b[1];
}
static inline uint32_t aex_be32(const void *p) {
    const uint8_t *b = (const uint8_t *)p;
    return ((uint32_t)b[0] << 24) | ((uint32_t)b[1] << 16) | ((uint32_t)b[2] << 8) | (uint32_t)b[3];
}
static inline uint64_t aex_be64(const void *p) {
    const uint8_t *b = (const uint8_t *)p;
    return ((uint64_t)aex_be32(b) << 32) | (uint64_t)aex_be32(b + 4);
}
static inline void aex_put_le64(void *p, uint64_t v) {
    uint8_t *b = (uint8_t *)p;
    for (int i = 0; i < 8; i++) b[i] = (uint8_t)((v >> (i * 8)) & 0xFFU);
}
static inline void aex_put_be32(void *p, uint32_t v) {
    uint8_t *b = (uint8_t *)p;
    b[0] = (uint8_t)(v >> 24);
    b[1] = (uint8_t)(v >> 16);
    b[2] = (uint8_t)(v >> 8);
    b[3] = (uint8_t)(v);
}

/* Crypto & Checksum Primitives (crypto_compress.c) */
uint64_t aex_fletcher64(const void *data, size_t len);
uint32_t aex_crc32c(uint32_t crc, const void *buf, size_t len);

void aex_sha1(const void *data, size_t len, uint8_t out_digest[20]);
void aex_sha256(const void *data, size_t len, uint8_t out_digest[32]);
void aex_hmac_sha1(const uint8_t *key, size_t key_len, const void *msg, size_t msg_len, uint8_t out_mac[20]);
void aex_hmac_sha256(const uint8_t *key, size_t key_len, const void *msg, size_t msg_len, uint8_t out_mac[32]);
void aex_pbkdf2_sha1(const char *pass, size_t pass_len, const uint8_t *salt, size_t salt_len, uint32_t iters, uint8_t *out, size_t out_len);
void aex_pbkdf2_sha256(const char *pass, size_t pass_len, const uint8_t *salt, size_t salt_len, uint32_t iters, uint8_t *out, size_t out_len);

typedef struct {
    int      nr;
    uint32_t rk[60];
} aex_aes_ctx_t;

int aex_aes_init_enc(aex_aes_ctx_t *ctx, const uint8_t *key, size_t key_bytes);
int aex_aes_init_dec(aex_aes_ctx_t *ctx, const uint8_t *key, size_t key_bytes);
void aex_aes_encrypt_block(const aex_aes_ctx_t *ctx, const uint8_t in[16], uint8_t out[16]);
void aex_aes_decrypt_block(const aex_aes_ctx_t *ctx, const uint8_t in[16], uint8_t out[16]);
int aex_aes_cbc_decrypt(const uint8_t *key, size_t key_bytes, const uint8_t iv[16], const uint8_t *in, uint8_t *out, size_t len);
int aex_aes_xts_decrypt_sector(
    const aex_aes_ctx_t *dec_k1,
    const aex_aes_ctx_t *enc_k2,
    uint64_t tweak_no,
    const uint8_t *in,
    uint8_t *out,
    size_t sector_bytes
);
int aex_aes_key_unwrap(const uint8_t *kek, size_t kek_bytes, const uint8_t *wrapped, size_t wrapped_len, uint8_t *out_plain);

/* Decompression Primitives (crypto_compress.c) */
int aex_zlib_decompress(const uint8_t *src, size_t src_len, uint8_t *dst, size_t dst_cap, size_t *out_len);
int aex_lzvn_decompress(const uint8_t *src, size_t src_len, uint8_t *dst, size_t dst_cap, size_t *out_len);
int aex_lzfse_decompress(const uint8_t *src, size_t src_len, uint8_t *dst, size_t dst_cap, size_t *out_len);
int aex_decmpfs_decompress(
    const uint8_t *xattr_bytes,
    size_t xattr_len,
    const uint8_t *rsrc_bytes,
    size_t rsrc_len,
    uint64_t uncompressed_size,
    uint8_t **out_buf,
    size_t *out_len
);

/* UTF-16BE / MacRoman Conversion & Case Folding (crypto_compress.c) */
size_t aex_utf16be_to_utf8(const uint8_t *u16be, size_t char_count, char *out_utf8, size_t out_cap);
size_t aex_macroman_to_utf8(const uint8_t *mac, size_t len, char *out_utf8, size_t out_cap);
int aex_strcasecmp_utf8(const char *a, const char *b);

/* Sub-slice Stream Helper */
typedef struct {
    aex_stream_t *parent;
    uint64_t      offset;
    uint64_t      size;
} aex_slice_t;

int aex_slice_read(const aex_slice_t *sl, uint64_t off, size_t len, void *buf);

/* Filesystem Vtable */
typedef struct aex_fs_ops {
    void (*close_priv)(void *priv);
    uint64_t (*root_ino)(const void *priv);
    int (*list_snapshots)(void *priv, aex_snapshot_desc_t *out_snaps, size_t max_snaps, size_t *out_count);
    int (*statfs)(void *priv, uint64_t *total_bytes, uint64_t *used_bytes, uint32_t *block_size);
    int (*getattr)(void *priv, uint64_t ino, aex_attr_t *out_attr);
    int (*readdir)(void *priv, uint64_t dir_ino, aex_readdir_cb cb, void *user_ctx);
    int (*lookup)(void *priv, uint64_t dir_ino, const char *name, uint64_t *out_ino);
    int (*read_data)(void *priv, uint64_t ino, int is_rsrc, uint64_t offset, size_t length, void *buffer, size_t *out_read);
    int (*readlink)(void *priv, uint64_t ino, char *buffer, size_t buffer_cap, size_t *out_len);
} aex_fs_ops_t;

struct aex_handle {
    aex_stream_t       *owned_stream;
    aex_slice_t         slice;
    aex_fs_kind_t       kind;
    char                vol_name[128];
    const aex_fs_ops_t *ops;
    void               *priv;
};

/* HFS / HFS+ / HFSX + Backups.backupdb Driver (fs_hfs.c) */
int aex_hfs_probe_slice(const aex_slice_t *sl, aex_fs_kind_t *out_kind, char *out_label, size_t label_cap);
int aex_hfs_open(aex_t *h);

/* APFS + FileVault 2 + Snapshots Driver (fs_apfs.c) */
int aex_apfs_probe_slice(const aex_slice_t *sl);
int aex_apfs_list_volumes(const aex_slice_t *sl, const char *password, aex_volume_desc_t *out_vols, size_t max_vols, size_t *out_count);
int aex_apfs_open(aex_t *h, int volume_index, const char *snapshot_name, const char *password);

#endif /* AEX_INTERNAL_H */
