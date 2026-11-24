#define _DEFAULT_SOURCE
#define _POSIX_C_SOURCE 200809L
#include "internal.h"
#include <ctype.h>
#include <fcntl.h>
#include <stdio.h>
#include <strings.h>
#include <sys/ioctl.h>
#include <unistd.h>

#ifdef __APPLE__
#include <sys/disk.h>
#endif
#ifdef __linux__
#include <linux/fs.h>
#endif

static const legacyfs_format_desc_t k_formats[] = {
    { LEGACYFS_KIND_UNKNOWN,    "unknown",    "Unknown",             NULL,            0, 0 },
    { LEGACYFS_KIND_REISERFS,   "reiserfs",   "ReiserFS",            "fuse-reiserfs", 1, 0 },
    { LEGACYFS_KIND_MINIX,      "minix",      "Minix",               "fuse-minix",    1, 0 },
    { LEGACYFS_KIND_CRAMFS,     "cramfs",     "CramFS",              "fuse-cramfs",   1, 0 },
    { LEGACYFS_KIND_ROMFS,      "romfs",      "ROMFS",               "fuse-romfs",    1, 0 },
    { LEGACYFS_KIND_ISO9660,    "iso9660",    "ISO9660",             "fuse-iso9660",  1, 0 },
    { LEGACYFS_KIND_SQUASHFS,   "squashfs",   "SquashFS",            "fuse-squashfs", 1, 0 },
    { LEGACYFS_KIND_EROFS,      "erofs",      "EROFS",               "fuse-erofs",    1, 0 },
    { LEGACYFS_KIND_UFS,        "ufs",        "UFS/UFS2",            "fuse-ufs",      1, 0 },
    { LEGACYFS_KIND_JFS,        "jfs",        "JFS",                 "fuse-jfs",      1, 0 },
    { LEGACYFS_KIND_SYSV,       "sysv",       "SysV",                "fuse-sysv",     1, 0 },

    { LEGACYFS_KIND_REISER4,    "reiser4",    "Reiser4",             NULL,            0, 0 },
    { LEGACYFS_KIND_BTRFS,      "btrfs",      "Btrfs",               "fuse-btrfs",    1, 0 },
    { LEGACYFS_KIND_XFS,        "xfs",        "XFS",                 "fuse-xfs",      1, 0 },
    { LEGACYFS_KIND_F2FS,       "f2fs",       "F2FS",                NULL,            0, 0 },
    { LEGACYFS_KIND_NILFS2,     "nilfs2",     "NILFS2",              NULL,            0, 0 },
    { LEGACYFS_KIND_ZFS,        "zfs",        "ZFS",                 NULL,            0, 1 },
    { LEGACYFS_KIND_GFS2,       "gfs2",       "GFS2",                NULL,            0, 0 },
    { LEGACYFS_KIND_OCFS2,      "ocfs2",      "OCFS2",               NULL,            0, 0 },
    { LEGACYFS_KIND_BCACHEFS,   "bcachefs",   "BCacheFS",            NULL,            0, 0 },
    { LEGACYFS_KIND_BEFS,       "befs",       "BeFS",                NULL,            0, 0 },
    { LEGACYFS_KIND_HPFS,       "hpfs",       "HPFS",                NULL,            0, 0 },
    { LEGACYFS_KIND_AFFS,       "affs",       "Amiga FFS",           NULL,            0, 0 },
    { LEGACYFS_KIND_HFS,        "hfs",        "Classic Mac HFS",     NULL,            0, 0 },
    { LEGACYFS_KIND_UDF,        "udf",        "UDF",                 "fuse-udf",      1, 0 },
    { LEGACYFS_KIND_VMFS,       "vmfs",       "VMware VMFS",         NULL,            0, 1 },
    { LEGACYFS_KIND_REFS,       "refs",       "Microsoft ReFS",      NULL,            0, 0 },
    { LEGACYFS_KIND_WBFS,       "wbfs",       "Wii WBFS",            NULL,            0, 0 },
    { LEGACYFS_KIND_FATX,       "fatx",       "Xbox FATX",           NULL,            0, 0 },
    { LEGACYFS_KIND_QNX4,       "qnx4",       "QNX4",                NULL,            0, 0 },
    { LEGACYFS_KIND_QNX6,       "qnx6",       "QNX6",                NULL,            0, 0 },
    { LEGACYFS_KIND_JFFS2,      "jffs2",      "JFFS2",               NULL,            0, 0 },
    { LEGACYFS_KIND_UBIFS,      "ubifs",      "UBIFS",               NULL,            0, 0 },
    { LEGACYFS_KIND_LUKS1,      "luks1",      "LUKS1 Encrypted",     NULL,            0, 1 },
    { LEGACYFS_KIND_LUKS2,      "luks2",      "LUKS2 Encrypted",     NULL,            0, 1 },
    { LEGACYFS_KIND_LVM2,       "lvm2",       "LVM2 Physical Vol",   NULL,            0, 1 },
    { LEGACYFS_KIND_LINUX_RAID, "linux_raid", "Linux MD RAID",       NULL,            0, 1 },
    { LEGACYFS_KIND_LINUX_SWAP, "linux_swap", "Linux Swap",          NULL,            0, 1 },
};

const char *legacyfs_version(void) {
    return LEGACYFS_VERSION;
}

size_t legacyfs_supported_formats(const legacyfs_format_desc_t **out_table) {
    if (out_table) {
        *out_table = k_formats + 1;
    }
    return (sizeof(k_formats) / sizeof(k_formats[0])) - 1;
}

const legacyfs_format_desc_t *legacyfs_describe_kind(legacyfs_kind_t kind) {
    if ((int)kind < 0 || (size_t)kind >= sizeof(k_formats) / sizeof(k_formats[0])) {
        return &k_formats[0];
    }
    return &k_formats[(size_t)kind];
}

legacyfs_kind_t legacyfs_kind_from_name(const char *name) {
    if (!name || !name[0]) return LEGACYFS_KIND_UNKNOWN;
    const char *base = strrchr(name, '/');
    base = base ? (base + 1) : name;
    if (strncmp(base, "fuse-", 5) == 0) {
        base += 5;
    }
    for (size_t i = 1; i < sizeof(k_formats) / sizeof(k_formats[0]); i++) {
        if (strcasecmp(base, k_formats[i].short_name) == 0) {
            return k_formats[i].kind;
        }
    }
    if (strcasecmp(base, "ffs") == 0 || strcasecmp(base, "ufs2") == 0) return LEGACYFS_KIND_UFS;
    if (strcasecmp(base, "rfs") == 0 || strcasecmp(base, "reiser") == 0) return LEGACYFS_KIND_REISERFS;
    if (strcasecmp(base, "iso") == 0 || strcasecmp(base, "cd9660") == 0) return LEGACYFS_KIND_ISO9660;
    return LEGACYFS_KIND_UNKNOWN;
}

void lfs_format_uuid(const uint8_t u[16], char out[64]) {
    int all_zero = 1;
    for (int i = 0; i < 16; i++) {
        if (u[i] != 0) { all_zero = 0; break; }
    }
    if (all_zero) {
        out[0] = '\0';
        return;
    }
    snprintf(out, 64,
             "%02x%02x%02x%02x-%02x%02x-%02x%02x-%02x%02x-%02x%02x%02x%02x%02x%02x",
             u[0], u[1], u[2], u[3], u[4], u[5], u[6], u[7],
             u[8], u[9], u[10], u[11], u[12], u[13], u[14], u[15]);
}

void lfs_copy_trimmed_label(const uint8_t *raw, size_t max_len, char *out, size_t out_size) {
    if (!out || out_size == 0) return;
    out[0] = '\0';
    if (!raw || max_len == 0) return;

    size_t len = 0;
    while (len < max_len && raw[len] != 0) {
        len++;
    }
    while (len > 0 && (raw[len - 1] == ' ' || raw[len - 1] == '\t' || raw[len - 1] == '\r' || raw[len - 1] == '\n')) {
        len--;
    }
    size_t start = 0;
    while (start < len && (raw[start] == ' ' || raw[start] == '\t')) {
        start++;
    }
    size_t copy_len = len - start;
    if (copy_len >= out_size) {
        copy_len = out_size - 1;
    }
    size_t dst = 0;
    for (size_t i = 0; i < copy_len; i++) {
        uint8_t c = raw[start + i];
        if (c >= 0x20 && c != 0x7F) {
            out[dst++] = (char)c;
        }
    }
    out[dst] = '\0';
}

int lfs_read_bytes(const legacyfs_t *fs, uint64_t offset, size_t length, void *buffer) {
    if (!fs || !fs->read_fn || (!buffer && length > 0)) return -EINVAL;
    if (length == 0) return 0;
    if (offset > UINT64_MAX - (uint64_t)length) return -EOVERFLOW;
    if (fs->part_size > 0 && offset + (uint64_t)length > fs->part_size) return -EIO;
    int rc = fs->read_fn(fs->io_ctx, offset, length, buffer);
    return rc == 0 ? 0 : (rc > 0 ? -rc : rc);
}

typedef struct {
    int fd;
    int is_char_dev;
    uint32_t align;
    uint64_t size;
} lfs_fd_ctx_t;

static int lfs_fd_pread_exact(int fd, uint64_t offset, size_t length, void *buf) {
    uint8_t *dst = (uint8_t *)buf;
    size_t done = 0;
    while (done < length) {
        ssize_t n = pread(fd, dst + done, length - done, (off_t)(offset + done));
        if (n < 0) {
            if (errno == EINTR) continue;
            return errno ? errno : EIO;
        }
        if (n == 0) return EIO;
        done += (size_t)n;
    }
    return 0;
}

static int lfs_fd_read_cb(void *ctx_ptr, uint64_t offset, size_t length, void *buffer) {
    lfs_fd_ctx_t *ctx = (lfs_fd_ctx_t *)ctx_ptr;
    if (!ctx || ctx->fd < 0) return EINVAL;
    if (length == 0) return 0;
    if (offset > (uint64_t)INT64_MAX - (uint64_t)length) return EOVERFLOW;

    if (!ctx->is_char_dev) {
        return lfs_fd_pread_exact(ctx->fd, offset, length, buffer);
    }

    uint64_t align = ctx->align ? ctx->align : 4096U;
    uint64_t aligned_start = (offset / align) * align;
    size_t head_skip = (size_t)(offset - aligned_start);
    if (length > SIZE_MAX - head_skip - (size_t)align) return EOVERFLOW;
    size_t aligned_len = ((head_skip + length + (size_t)align - 1U) / (size_t)align) * (size_t)align;

    if (head_skip == 0 && aligned_len == length) {
        return lfs_fd_pread_exact(ctx->fd, offset, length, buffer);
    }

    uint8_t *bounce = (uint8_t *)malloc(aligned_len);
    if (!bounce) return ENOMEM;
    ssize_t n = pread(ctx->fd, bounce, aligned_len, (off_t)aligned_start);
    if (n <= (ssize_t)head_skip) {
        free(bounce);
        return EIO;
    }
    size_t avail = (size_t)n - head_skip;
    if (avail < length) {
        free(bounce);
        return EIO;
    }
    memcpy(buffer, bounce + head_skip, length);
    free(bounce);
    return 0;
}

static int lfs_open_fd_ctx(const char *path, lfs_fd_ctx_t **out_ctx) {
    if (!path || !out_ctx) return -EINVAL;
    int fd = open(path, O_RDONLY);
    if (fd < 0) {
        return errno ? -errno : -EIO;
    }

    struct stat st;
    if (fstat(fd, &st) != 0) {
        int err = errno ? -errno : -EIO;
        close(fd);
        return err;
    }

    lfs_fd_ctx_t *ctx = (lfs_fd_ctx_t *)calloc(1, sizeof(lfs_fd_ctx_t));
    if (!ctx) {
        close(fd);
        return -ENOMEM;
    }
    ctx->fd = fd;
    ctx->is_char_dev = S_ISCHR(st.st_mode) ? 1 : 0;
    ctx->align = 4096U;
    ctx->size = S_ISREG(st.st_mode) ? (uint64_t)st.st_size : 0;

#ifdef __APPLE__
    if (S_ISBLK(st.st_mode) || S_ISCHR(st.st_mode)) {
        uint32_t bsize = 0;
        uint64_t bcount = 0;
        if (ioctl(fd, DKIOCGETBLOCKSIZE, &bsize) == 0 && bsize >= 512) {
            ctx->align = bsize < 4096U ? 4096U : bsize;
            if (ioctl(fd, DKIOCGETBLOCKCOUNT, &bcount) == 0) {
                ctx->size = bcount * (uint64_t)bsize;
            }
        }
    }
#endif
#ifdef __linux__
    if (S_ISBLK(st.st_mode)) {
        uint64_t bytes = 0;
        if (ioctl(fd, BLKGETSIZE64, &bytes) == 0) {
            ctx->size = bytes;
        }
    }
#endif

    *out_ctx = ctx;
    return 0;
}

int legacyfs_probe_path(const char *path, legacyfs_probe_info_t *out_info) {
    lfs_fd_ctx_t *ctx = NULL;
    int rc = lfs_open_fd_ctx(path, &ctx);
    if (rc != 0) return rc;
    rc = legacyfs_probe_io(lfs_fd_read_cb, ctx, ctx->size, out_info);
    close(ctx->fd);
    free(ctx);
    return rc;
}

static const legacyfs_ops_t *lfs_ops_for_kind(legacyfs_kind_t kind) {
    switch (kind) {
    case LEGACYFS_KIND_REISERFS: return &lfs_reiserfs_ops;
    case LEGACYFS_KIND_MINIX:    return &lfs_minix_ops;
    case LEGACYFS_KIND_SYSV:     return &lfs_sysv_ops;
    case LEGACYFS_KIND_CRAMFS:   return &lfs_cramfs_ops;
    case LEGACYFS_KIND_ROMFS:    return &lfs_romfs_ops;
    case LEGACYFS_KIND_SQUASHFS: return &lfs_squashfs_ops;
    case LEGACYFS_KIND_EROFS:    return &lfs_erofs_ops;
    case LEGACYFS_KIND_ISO9660:  return &lfs_iso9660_ops;
    case LEGACYFS_KIND_UFS:      return &lfs_ufs_ops;
    case LEGACYFS_KIND_JFS:      return &lfs_jfs_ops;
    case LEGACYFS_KIND_BTRFS:    return &lfs_btrfs_ops;
    case LEGACYFS_KIND_XFS:      return &lfs_xfs_ops;
    case LEGACYFS_KIND_UDF:      return &lfs_udf_ops;
    default:                     return NULL;
    }
}

int legacyfs_open_io(
    legacyfs_read_fn read_fn,
    void *io_ctx,
    uint64_t partition_size,
    legacyfs_kind_t forced_kind,
    legacyfs_t **out_fs
) {
    if (!read_fn || !out_fs) return -EINVAL;
    *out_fs = NULL;

    legacyfs_probe_info_t info;
    memset(&info, 0, sizeof(info));
    int prc = legacyfs_probe_io(read_fn, io_ctx, partition_size, &info);
    if (forced_kind != LEGACYFS_KIND_UNKNOWN) {
        info.kind = forced_kind;
        const legacyfs_format_desc_t *desc = legacyfs_describe_kind(forced_kind);
        snprintf(info.name, sizeof(info.name), "%s", desc->display_name);
        info.can_mount_ro = desc->can_mount_ro;
    } else if (prc != 0) {
        return prc;
    }

    const legacyfs_ops_t *ops = lfs_ops_for_kind(info.kind);
    if (!ops || !ops->mount) {
        return -ENOTSUP;
    }

    legacyfs_t *fs = (legacyfs_t *)calloc(1, sizeof(legacyfs_t));
    if (!fs) return -ENOMEM;
    fs->read_fn = read_fn;
    fs->io_ctx = io_ctx;
    fs->owns_io_ctx = 0;
    fs->part_size = partition_size;
    fs->info = info;
    fs->ops = ops;

    int mrc = ops->mount(fs);
    if (mrc != 0) {
        free(fs);
        return mrc;
    }

    *out_fs = fs;
    return 0;
}

int legacyfs_open_path(const char *path, legacyfs_kind_t forced_kind, legacyfs_t **out_fs) {
    if (!path || !out_fs) return -EINVAL;
    *out_fs = NULL;

    lfs_fd_ctx_t *ctx = NULL;
    int rc = lfs_open_fd_ctx(path, &ctx);
    if (rc != 0) return rc;

    legacyfs_t *fs = NULL;
    rc = legacyfs_open_io(lfs_fd_read_cb, ctx, ctx->size, forced_kind, &fs);
    if (rc != 0) {
        close(ctx->fd);
        free(ctx);
        return rc;
    }
    fs->owns_io_ctx = 1;
    *out_fs = fs;
    return 0;
}

void legacyfs_close(legacyfs_t *fs) {
    if (!fs) return;
    if (fs->ops && fs->ops->unmount) {
        fs->ops->unmount(fs);
    }
    if (fs->owns_io_ctx && fs->io_ctx) {
        lfs_fd_ctx_t *ctx = (lfs_fd_ctx_t *)fs->io_ctx;
        if (ctx->fd >= 0) close(ctx->fd);
        free(ctx);
    }
    free(fs);
}

legacyfs_kind_t legacyfs_get_kind(const legacyfs_t *fs) {
    return fs ? fs->info.kind : LEGACYFS_KIND_UNKNOWN;
}

const legacyfs_probe_info_t *legacyfs_get_info(const legacyfs_t *fs) {
    return fs ? &fs->info : NULL;
}

uint64_t legacyfs_root_ino(const legacyfs_t *fs) {
    if (!fs || !fs->ops || !fs->ops->root_ino) return 0;
    return fs->ops->root_ino(fs);
}

int legacyfs_statfs(legacyfs_t *fs, legacyfs_statfs_t *out_stat) {
    if (!fs || !out_stat || !fs->ops) return -EINVAL;
    memset(out_stat, 0, sizeof(*out_stat));
    out_stat->namemax = 255;
    out_stat->block_size = fs->info.block_size ? fs->info.block_size : 4096U;
    if (fs->info.total_bytes && out_stat->block_size) {
        out_stat->total_blocks = fs->info.total_bytes / out_stat->block_size;
        out_stat->free_blocks = fs->info.free_bytes / out_stat->block_size;
    }
    if (fs->ops->statfs) {
        return fs->ops->statfs(fs, out_stat);
    }
    return 0;
}

int legacyfs_getattr(legacyfs_t *fs, uint64_t ino, legacyfs_attr_t *out_attr) {
    if (!fs || !out_attr || !fs->ops || !fs->ops->getattr) return -EINVAL;
    memset(out_attr, 0, sizeof(*out_attr));
    return fs->ops->getattr(fs, ino, out_attr);
}

int legacyfs_readdir(legacyfs_t *fs, uint64_t dir_ino, legacyfs_readdir_cb cb, void *user_ctx) {
    if (!fs || !cb || !fs->ops || !fs->ops->readdir) return -EINVAL;
    return fs->ops->readdir(fs, dir_ino, cb, user_ctx);
}

typedef struct {
    const char *target;
    uint64_t found_ino;
    int found;
} lfs_lookup_ctx_t;

static int lfs_default_lookup_cb(void *user_ctx, const char *name, uint64_t ino, legacyfs_ftype_t ftype) {
    (void)ftype;
    lfs_lookup_ctx_t *lctx = (lfs_lookup_ctx_t *)user_ctx;
    if (strcmp(name, lctx->target) == 0) {
        lctx->found_ino = ino;
        lctx->found = 1;
        return 1;
    }
    return 0;
}

int legacyfs_lookup(legacyfs_t *fs, uint64_t dir_ino, const char *name, uint64_t *out_ino) {
    if (!fs || !name || !name[0] || !out_ino || !fs->ops) return -EINVAL;
    if (strcmp(name, ".") == 0) {
        *out_ino = dir_ino;
        return 0;
    }
    if (fs->ops->lookup) {
        return fs->ops->lookup(fs, dir_ino, name, out_ino);
    }
    lfs_lookup_ctx_t lctx = { name, 0, 0 };
    int rc = legacyfs_readdir(fs, dir_ino, lfs_default_lookup_cb, &lctx);
    if (rc != 0) return rc;
    if (!lctx.found) return -ENOENT;
    *out_ino = lctx.found_ino;
    return 0;
}

int legacyfs_lookup_path(legacyfs_t *fs, const char *path, uint64_t *out_ino) {
    if (!fs || !path || !out_ino) return -EINVAL;
    uint64_t cur = legacyfs_root_ino(fs);
    if (cur == 0) return -EIO;

    const char *p = path;
    while (*p == '/') p++;
    if (*p == '\0') {
        *out_ino = cur;
        return 0;
    }

    uint64_t stack[64];
    int depth = 0;

    while (*p != '\0') {
        const char *slash = strchr(p, '/');
        size_t comp_len = slash ? (size_t)(slash - p) : strlen(p);
        if (comp_len == 0) {
            p++;
            continue;
        }
        if (comp_len >= 256) return -ENAMETOOLONG;

        char comp[256];
        memcpy(comp, p, comp_len);
        comp[comp_len] = '\0';

        if (strcmp(comp, ".") == 0) {
            /* stay on cur */
        } else if (strcmp(comp, "..") == 0) {
            if (depth > 0) {
                cur = stack[--depth];
            } else {
                cur = legacyfs_root_ino(fs);
            }
        } else {
            legacyfs_attr_t attr;
            int arc = legacyfs_getattr(fs, cur, &attr);
            if (arc != 0) return arc;
            if (attr.ftype != LEGACYFS_FT_DIR) return -ENOTDIR;

            if (depth < 64) {
                stack[depth++] = cur;
            }
            uint64_t next_ino = 0;
            int lrc = legacyfs_lookup(fs, cur, comp, &next_ino);
            if (lrc != 0) return lrc;
            cur = next_ino;
        }

        if (!slash) break;
        p = slash + 1;
        while (*p == '/') p++;
    }

    *out_ino = cur;
    return 0;
}

int legacyfs_read(legacyfs_t *fs, uint64_t ino, uint64_t offset, size_t length, void *buffer, size_t *out_read) {
    if (out_read) *out_read = 0;
    if (!fs || (!buffer && length > 0) || !fs->ops || !fs->ops->read) return -EINVAL;
    if (length == 0) return 0;
    return fs->ops->read(fs, ino, offset, length, buffer, out_read);
}

int legacyfs_readlink(legacyfs_t *fs, uint64_t ino, char *buffer, size_t buffer_size, size_t *out_len) {
    if (out_len) *out_len = 0;
    if (!fs || !buffer || buffer_size == 0 || !fs->ops) return -EINVAL;
    if (!fs->ops->readlink) return -ENOTSUP;
    int rc = fs->ops->readlink(fs, ino, buffer, buffer_size, out_len);
    if (rc == 0) {
        size_t l = out_len ? *out_len : strlen(buffer);
        if (l >= buffer_size) l = buffer_size - 1;
        buffer[l] = '\0';
        if (out_len) *out_len = l;
    }
    return rc;
}
