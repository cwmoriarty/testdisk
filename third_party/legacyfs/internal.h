#ifndef LEGACYFS_INTERNAL_H
#define LEGACYFS_INTERNAL_H

#include "legacyfs.h"
#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>

#ifndef S_IFSOCK
#define S_IFSOCK 0140000
#endif
#ifndef S_IFLNK
#define S_IFLNK  0120000
#endif
#ifndef S_IFREG
#define S_IFREG  0100000
#endif
#ifndef S_IFBLK
#define S_IFBLK  0060000
#endif
#ifndef S_IFDIR
#define S_IFDIR  0040000
#endif
#ifndef S_IFCHR
#define S_IFCHR  0020000
#endif
#ifndef S_IFIFO
#define S_IFIFO  0010000
#endif
#ifndef S_IFMT
#define S_IFMT   0170000
#endif

static inline uint16_t lfs_le16(const void *p) {
    const uint8_t *b = (const uint8_t *)p;
    return (uint16_t)b[0] | ((uint16_t)b[1] << 8);
}

static inline uint32_t lfs_le32(const void *p) {
    const uint8_t *b = (const uint8_t *)p;
    return (uint32_t)b[0] |
           ((uint32_t)b[1] << 8) |
           ((uint32_t)b[2] << 16) |
           ((uint32_t)b[3] << 24);
}

static inline uint64_t lfs_le64(const void *p) {
    const uint8_t *b = (const uint8_t *)p;
    return (uint64_t)lfs_le32(b) | ((uint64_t)lfs_le32(b + 4) << 32);
}

static inline uint16_t lfs_be16(const void *p) {
    const uint8_t *b = (const uint8_t *)p;
    return ((uint16_t)b[0] << 8) | (uint16_t)b[1];
}

static inline uint32_t lfs_be32(const void *p) {
    const uint8_t *b = (const uint8_t *)p;
    return ((uint32_t)b[0] << 24) |
           ((uint32_t)b[1] << 16) |
           ((uint32_t)b[2] << 8) |
           (uint32_t)b[3];
}

static inline uint64_t lfs_be64(const void *p) {
    const uint8_t *b = (const uint8_t *)p;
    return ((uint64_t)lfs_be32(b) << 32) | (uint64_t)lfs_be32(b + 4);
}

static inline int lfs_is_pow2_u32(uint32_t v) {
    return v != 0 && (v & (v - 1U)) == 0;
}

static inline legacyfs_ftype_t lfs_mode_to_ftype(uint32_t mode) {
    switch (mode & S_IFMT) {
    case S_IFREG:  return LEGACYFS_FT_REG;
    case S_IFDIR:  return LEGACYFS_FT_DIR;
    case S_IFLNK:  return LEGACYFS_FT_SYMLINK;
    case S_IFCHR:  return LEGACYFS_FT_CHRDEV;
    case S_IFBLK:  return LEGACYFS_FT_BLKDEV;
    case S_IFIFO:  return LEGACYFS_FT_FIFO;
    case S_IFSOCK: return LEGACYFS_FT_SOCK;
    default:       return LEGACYFS_FT_UNKNOWN;
    }
}

typedef struct legacyfs_ops {
    int (*mount)(legacyfs_t *fs);
    void (*unmount)(legacyfs_t *fs);
    uint64_t (*root_ino)(const legacyfs_t *fs);
    int (*statfs)(legacyfs_t *fs, legacyfs_statfs_t *out_stat);
    int (*getattr)(legacyfs_t *fs, uint64_t ino, legacyfs_attr_t *out_attr);
    int (*readdir)(legacyfs_t *fs, uint64_t dir_ino, legacyfs_readdir_cb cb, void *user_ctx);
    int (*lookup)(legacyfs_t *fs, uint64_t dir_ino, const char *name, uint64_t *out_ino);
    int (*read)(legacyfs_t *fs, uint64_t ino, uint64_t offset, size_t length, void *buffer, size_t *out_read);
    int (*readlink)(legacyfs_t *fs, uint64_t ino, char *buffer, size_t buffer_size, size_t *out_len);
} legacyfs_ops_t;

struct legacyfs_handle {
    legacyfs_read_fn read_fn;
    void *io_ctx;
    int owns_io_ctx;
    uint64_t part_size;
    legacyfs_probe_info_t info;
    const legacyfs_ops_t *ops;
    void *priv;
};

int lfs_read_bytes(const legacyfs_t *fs, uint64_t offset, size_t length, void *buffer);
void lfs_format_uuid(const uint8_t uuid[16], char out[64]);
void lfs_copy_trimmed_label(const uint8_t *raw, size_t max_len, char *out, size_t out_size);

/* Driver vtables */
extern const legacyfs_ops_t lfs_reiserfs_ops;
extern const legacyfs_ops_t lfs_minix_ops;
extern const legacyfs_ops_t lfs_sysv_ops;
extern const legacyfs_ops_t lfs_cramfs_ops;
extern const legacyfs_ops_t lfs_romfs_ops;
extern const legacyfs_ops_t lfs_squashfs_ops;
extern const legacyfs_ops_t lfs_erofs_ops;
extern const legacyfs_ops_t lfs_iso9660_ops;
extern const legacyfs_ops_t lfs_ufs_ops;
extern const legacyfs_ops_t lfs_jfs_ops;

#endif /* LEGACYFS_INTERNAL_H */
