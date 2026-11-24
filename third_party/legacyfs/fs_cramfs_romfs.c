#include "internal.h"
#include <zlib.h>

/* =========================================================================
 * CramFS Read-Only Driver (with zlib block decompression)
 * =========================================================================
 * Inode is identified by (base_offset + byte_offset_of_cramfs_inode) + 1
 * so root inode at base_offset + 64 is always > 0.
 */
#define CRAMFS_BLK_SIZE 4096U

typedef struct {
    uint64_t base_off;
    uint32_t image_size;
} cramfs_priv_t;

typedef struct {
    uint16_t mode;
    uint16_t uid;
    uint32_t size;
    uint8_t gid;
    uint16_t namelen_bytes;
    uint32_t data_offset_bytes;
} cramfs_inode_t;

static void cramfs_parse_inode(const uint8_t raw[12], cramfs_inode_t *out) {
    uint32_t w0 = lfs_le32(raw + 0);
    uint32_t w1 = lfs_le32(raw + 4);
    uint32_t w2 = lfs_le32(raw + 8);
    out->mode = (uint16_t)(w0 & 0xFFFFU);
    out->uid = (uint16_t)(w0 >> 16);
    out->size = w1 & 0x00FFFFFFU;
    out->gid = (uint8_t)(w1 >> 24);
    out->namelen_bytes = (uint16_t)((w2 & 0x3FU) << 2);
    out->data_offset_bytes = (w2 >> 6) << 2;
}

static int cramfs_mount(legacyfs_t *fs) {
    static const uint64_t bases[2] = { 0ULL, 512ULL };
    uint8_t sb[76];
    for (int i = 0; i < 2; i++) {
        if (lfs_read_bytes(fs, bases[i], sizeof(sb), sb) != 0) continue;
        if (lfs_le32(sb) != 0x28cd3d45U) continue;
        if (memcmp(sb + 16, "Compressed ROMFS", 16) != 0) continue;

        cramfs_priv_t *p = (cramfs_priv_t *)calloc(1, sizeof(cramfs_priv_t));
        if (!p) return -ENOMEM;
        p->base_off = bases[i];
        p->image_size = lfs_le32(sb + 4);
        fs->priv = p;
        return 0;
    }
    return -EINVAL;
}

static void cramfs_unmount(legacyfs_t *fs) {
    free(fs->priv);
    fs->priv = NULL;
}

static uint64_t cramfs_root_ino(const legacyfs_t *fs) {
    const cramfs_priv_t *p = (const cramfs_priv_t *)fs->priv;
    /* Root cramfs_inode sits inside superblock at offset +64 */
    return p->base_off + 64ULL + 1ULL;
}

static int cramfs_load_inode(legacyfs_t *fs, uint64_t ino, cramfs_inode_t *ci) {
    if (ino == 0) return -ENOENT;
    uint8_t raw[12];
    int rc = lfs_read_bytes(fs, ino - 1ULL, sizeof(raw), raw);
    if (rc != 0) return rc;
    cramfs_parse_inode(raw, ci);
    if (ci->mode == 0) return -ENOENT;
    return 0;
}

static int cramfs_getattr(legacyfs_t *fs, uint64_t ino, legacyfs_attr_t *out_attr) {
    cramfs_inode_t ci;
    int rc = cramfs_load_inode(fs, ino, &ci);
    if (rc != 0) return rc;

    out_attr->ino = ino;
    out_attr->mode = ci.mode;
    out_attr->uid = ci.uid;
    out_attr->gid = ci.gid;
    out_attr->nlink = 1;
    out_attr->size = ci.size;
    out_attr->blocks_512 = (ci.size + 511ULL) / 512ULL;
    out_attr->ftype = lfs_mode_to_ftype(ci.mode);
    return 0;
}

static int cramfs_readdir(legacyfs_t *fs, uint64_t dir_ino, legacyfs_readdir_cb cb, void *user_ctx) {
    const cramfs_priv_t *p = (const cramfs_priv_t *)fs->priv;
    cramfs_inode_t dir_ci;
    int rc = cramfs_load_inode(fs, dir_ino, &dir_ci);
    if (rc != 0) return rc;
    if (lfs_mode_to_ftype(dir_ci.mode) != LEGACYFS_FT_DIR) return -ENOTDIR;
    if (dir_ci.size == 0 || dir_ci.data_offset_bytes == 0) return 0;

    uint64_t cur = p->base_off + (uint64_t)dir_ci.data_offset_bytes;
    uint64_t end = cur + (uint64_t)dir_ci.size;
    uint32_t guard = 0;

    while (cur + 12ULL <= end && guard++ < 65536U) {
        uint8_t raw[12];
        rc = lfs_read_bytes(fs, cur, sizeof(raw), raw);
        if (rc != 0) return rc;

        cramfs_inode_t child;
        cramfs_parse_inode(raw, &child);
        if (child.namelen_bytes == 0 || cur + 12ULL + child.namelen_bytes > end) {
            break;
        }

        char name[260];
        size_t read_n = child.namelen_bytes < 256 ? child.namelen_bytes : 256;
        rc = lfs_read_bytes(fs, cur + 12ULL, read_n, name);
        if (rc != 0) return rc;
        name[read_n] = '\0';
        size_t actual_len = strlen(name);
        if (actual_len > 0 && strcmp(name, ".") != 0 && strcmp(name, "..") != 0) {
            uint64_t child_ino = cur + 1ULL;
            if (cb(user_ctx, name, child_ino, lfs_mode_to_ftype(child.mode)) != 0) {
                break;
            }
        }
        cur += 12ULL + (uint64_t)child.namelen_bytes;
    }
    return 0;
}

static int cramfs_read_compressed(legacyfs_t *fs, const cramfs_inode_t *ci, uint64_t offset, size_t length, void *buffer, size_t *out_read) {
    const cramfs_priv_t *p = (const cramfs_priv_t *)fs->priv;
    if (offset >= ci->size || length == 0) {
        if (out_read) *out_read = 0;
        return 0;
    }
    size_t to_read = length;
    if ((uint64_t)to_read > (uint64_t)ci->size - offset) {
        to_read = (size_t)((uint64_t)ci->size - offset);
    }

    uint32_t nblocks = (ci->size + CRAMFS_BLK_SIZE - 1U) / CRAMFS_BLK_SIZE;
    if (nblocks == 0 || ci->data_offset_bytes == 0) {
        memset(buffer, 0, to_read);
        if (out_read) *out_read = to_read;
        return 0;
    }

    uint64_t ptr_table_off = p->base_off + (uint64_t)ci->data_offset_bytes;
    uint8_t *ptrs = (uint8_t *)malloc((size_t)nblocks * 4U);
    uint8_t *comp = (uint8_t *)malloc(CRAMFS_BLK_SIZE * 2U);
    uint8_t *decomp = (uint8_t *)malloc(CRAMFS_BLK_SIZE);
    if (!ptrs || !comp || !decomp) {
        free(ptrs);
        free(comp);
        free(decomp);
        return -ENOMEM;
    }

    int rc = lfs_read_bytes(fs, ptr_table_off, (size_t)nblocks * 4U, ptrs);
    if (rc != 0) {
        free(ptrs);
        free(comp);
        free(decomp);
        return rc;
    }

    uint8_t *dst = (uint8_t *)buffer;
    size_t done = 0;
    while (done < to_read) {
        uint64_t cur = offset + done;
        uint32_t blk_idx = (uint32_t)(cur / CRAMFS_BLK_SIZE);
        size_t boff = (size_t)(cur % CRAMFS_BLK_SIZE);
        size_t chunk = CRAMFS_BLK_SIZE - boff;
        if (chunk > to_read - done) chunk = to_read - done;

        uint32_t start_off = (blk_idx == 0)
            ? (ci->data_offset_bytes + nblocks * 4U)
            : (lfs_le32(ptrs + (size_t)(blk_idx - 1) * 4U) & 0x3FFFFFFFU);
        uint32_t raw_end = lfs_le32(ptrs + (size_t)blk_idx * 4U);
        uint32_t end_off = raw_end & 0x3FFFFFFFU;
        int is_uncompressed = (raw_end & 0x80000000U) != 0;

        if (end_off == start_off) {
            memset(dst + done, 0, chunk);
        } else if (end_off < start_off || (end_off - start_off) > CRAMFS_BLK_SIZE * 2U) {
            free(ptrs);
            free(comp);
            free(decomp);
            return -EIO;
        } else {
            uint32_t clen = end_off - start_off;
            rc = lfs_read_bytes(fs, p->base_off + start_off, clen, comp);
            if (rc != 0) {
                free(ptrs);
                free(comp);
                free(decomp);
                return rc;
            }
            if (is_uncompressed) {
                memset(decomp, 0, CRAMFS_BLK_SIZE);
                memcpy(decomp, comp, clen < CRAMFS_BLK_SIZE ? clen : CRAMFS_BLK_SIZE);
            } else {
                uLongf out_sz = CRAMFS_BLK_SIZE;
                memset(decomp, 0, CRAMFS_BLK_SIZE);
                if (uncompress(decomp, &out_sz, comp, clen) != Z_OK) {
                    free(ptrs);
                    free(comp);
                    free(decomp);
                    return -EIO;
                }
            }
            memcpy(dst + done, decomp + boff, chunk);
        }
        done += chunk;
    }

    free(ptrs);
    free(comp);
    free(decomp);
    if (out_read) *out_read = done;
    return 0;
}

static int cramfs_read(legacyfs_t *fs, uint64_t ino, uint64_t offset, size_t length, void *buffer, size_t *out_read) {
    cramfs_inode_t ci;
    int rc = cramfs_load_inode(fs, ino, &ci);
    if (rc != 0) return rc;
    legacyfs_ftype_t ft = lfs_mode_to_ftype(ci.mode);
    if (ft == LEGACYFS_FT_DIR) return -EISDIR;
    if (ft != LEGACYFS_FT_REG) return -EINVAL;
    return cramfs_read_compressed(fs, &ci, offset, length, buffer, out_read);
}

static int cramfs_readlink(legacyfs_t *fs, uint64_t ino, char *buffer, size_t buffer_size, size_t *out_len) {
    cramfs_inode_t ci;
    int rc = cramfs_load_inode(fs, ino, &ci);
    if (rc != 0) return rc;
    if (lfs_mode_to_ftype(ci.mode) != LEGACYFS_FT_SYMLINK) return -EINVAL;
    size_t got = 0;
    rc = cramfs_read_compressed(fs, &ci, 0, buffer_size - 1, buffer, &got);
    if (rc != 0) return rc;
    buffer[got] = '\0';
    if (out_len) *out_len = got;
    return 0;
}

const legacyfs_ops_t lfs_cramfs_ops = {
    .mount = cramfs_mount,
    .unmount = cramfs_unmount,
    .root_ino = cramfs_root_ino,
    .statfs = NULL,
    .getattr = cramfs_getattr,
    .readdir = cramfs_readdir,
    .lookup = NULL,
    .read = cramfs_read,
    .readlink = cramfs_readlink,
};

/* =========================================================================
 * ROMFS (-rom1fs-) Read-Only Driver
 * =========================================================================
 * Every file header sits on a 16-byte boundary; `ino` = header_offset + 1.
 */
typedef struct {
    uint32_t image_size;
    uint32_t root_hdr_off;
} romfs_priv_t;

typedef struct {
    uint32_t next_off;
    uint8_t type;        /* 0=hardlink, 1=dir, 2=reg, 3=symlink, 4=blk, 5=chr, 6=sock, 7=fifo */
    int exec_bit;
    uint32_t spec_info;
    uint32_t size;
    uint32_t data_off;
    char name[256];
} romfs_hdr_t;

static int romfs_read_hdr(legacyfs_t *fs, uint32_t off, romfs_hdr_t *out) {
    const romfs_priv_t *p = (const romfs_priv_t *)fs->priv;
    if (off + 16U > p->image_size || (off & 15U) != 0) return -ENOENT;

    uint8_t raw[288];
    size_t can_read = p->image_size - off;
    if (can_read > sizeof(raw)) can_read = sizeof(raw);
    int rc = lfs_read_bytes(fs, off, can_read, raw);
    if (rc != 0) return rc;

    memset(out, 0, sizeof(*out));
    uint32_t nf = lfs_be32(raw + 0);
    out->next_off = nf & ~15U;
    out->type = (uint8_t)(nf & 7U);
    out->exec_bit = (nf & 8U) ? 1 : 0;
    out->spec_info = lfs_be32(raw + 4);
    out->size = lfs_be32(raw + 8);

    size_t max_name = can_read - 16U;
    size_t nlen = 0;
    while (nlen < max_name && nlen < 255U && raw[16U + nlen] != 0) {
        out->name[nlen] = (char)raw[16U + nlen];
        nlen++;
    }
    out->name[nlen] = '\0';
    size_t padded_name = ((nlen + 16U) & ~15U);
    out->data_off = off + 16U + (uint32_t)padded_name;
    return 0;
}

static int romfs_resolve_hardlink(legacyfs_t *fs, uint32_t off, romfs_hdr_t *out, uint32_t *resolved_off) {
    for (int depth = 0; depth < 16; depth++) {
        int rc = romfs_read_hdr(fs, off, out);
        if (rc != 0) return rc;
        if (out->type != 0) {
            if (resolved_off) *resolved_off = off;
            return 0;
        }
        off = out->spec_info & ~15U;
    }
    return -ELOOP;
}

static int romfs_mount(legacyfs_t *fs) {
    uint8_t sb[272];
    int rc = lfs_read_bytes(fs, 0, 32, sb);
    if (rc != 0) return rc;
    if (memcmp(sb, "-rom1fs-", 8) != 0) return -EINVAL;

    uint32_t full_size = lfs_be32(sb + 8);
    if (full_size < 32) return -EINVAL;
    size_t probe_len = full_size < sizeof(sb) ? full_size : sizeof(sb);
    rc = lfs_read_bytes(fs, 0, probe_len, sb);
    if (rc != 0) return rc;

    size_t vlen = 0;
    while (16U + vlen < probe_len && sb[16U + vlen] != 0) {
        vlen++;
    }
    uint32_t root_off = 16U + (uint32_t)((vlen + 16U) & ~15U);
    if (root_off >= full_size) return -EINVAL;

    romfs_priv_t *p = (romfs_priv_t *)calloc(1, sizeof(romfs_priv_t));
    if (!p) return -ENOMEM;
    p->image_size = full_size;
    p->root_hdr_off = root_off;
    fs->priv = p;
    return 0;
}

static void romfs_unmount(legacyfs_t *fs) {
    free(fs->priv);
    fs->priv = NULL;
}

static uint64_t romfs_root_ino(const legacyfs_t *fs) {
    const romfs_priv_t *p = (const romfs_priv_t *)fs->priv;
    return (uint64_t)p->root_hdr_off + 1ULL;
}

static int romfs_getattr(legacyfs_t *fs, uint64_t ino, legacyfs_attr_t *out_attr) {
    if (ino == 0) return -ENOENT;
    romfs_hdr_t h;
    int rc = romfs_resolve_hardlink(fs, (uint32_t)(ino - 1ULL), &h, NULL);
    if (rc != 0) return rc;

    out_attr->ino = ino;
    out_attr->nlink = 1;
    out_attr->size = h.size;
    out_attr->blocks_512 = (h.size + 511ULL) / 512ULL;

    switch (h.type) {
    case 1:
        out_attr->mode = S_IFDIR | 0555U;
        out_attr->ftype = LEGACYFS_FT_DIR;
        break;
    case 2:
        out_attr->mode = S_IFREG | (h.exec_bit ? 0555U : 0444U);
        out_attr->ftype = LEGACYFS_FT_REG;
        break;
    case 3:
        out_attr->mode = S_IFLNK | 0777U;
        out_attr->ftype = LEGACYFS_FT_SYMLINK;
        break;
    default:
        out_attr->mode = S_IFREG | 0444U;
        out_attr->ftype = LEGACYFS_FT_UNKNOWN;
        break;
    }
    return 0;
}

static int romfs_readdir(legacyfs_t *fs, uint64_t dir_ino, legacyfs_readdir_cb cb, void *user_ctx) {
    if (dir_ino == 0) return -ENOENT;
    romfs_hdr_t dh;
    int rc = romfs_resolve_hardlink(fs, (uint32_t)(dir_ino - 1ULL), &dh, NULL);
    if (rc != 0) return rc;
    if (dh.type != 1) return -ENOTDIR;

    uint32_t cur = dh.spec_info & ~15U;
    uint32_t guard = 0;
    while (cur != 0 && guard++ < 65536U) {
        romfs_hdr_t raw_h;
        rc = romfs_read_hdr(fs, cur, &raw_h);
        if (rc != 0) return rc;

        if (raw_h.name[0] != '\0' && strcmp(raw_h.name, ".") != 0 && strcmp(raw_h.name, "..") != 0) {
            romfs_hdr_t target_h;
            uint32_t target_off = cur;
            if (romfs_resolve_hardlink(fs, cur, &target_h, &target_off) == 0) {
                legacyfs_ftype_t ft = LEGACYFS_FT_UNKNOWN;
                if (target_h.type == 1) ft = LEGACYFS_FT_DIR;
                else if (target_h.type == 2) ft = LEGACYFS_FT_REG;
                else if (target_h.type == 3) ft = LEGACYFS_FT_SYMLINK;
                if (cb(user_ctx, raw_h.name, (uint64_t)target_off + 1ULL, ft) != 0) {
                    break;
                }
            }
        }
        if (raw_h.next_off == 0 || raw_h.next_off == cur) break;
        cur = raw_h.next_off;
    }
    return 0;
}

static int romfs_read(legacyfs_t *fs, uint64_t ino, uint64_t offset, size_t length, void *buffer, size_t *out_read) {
    romfs_hdr_t h;
    int rc = romfs_resolve_hardlink(fs, (uint32_t)(ino - 1ULL), &h, NULL);
    if (rc != 0) return rc;
    if (h.type == 1) return -EISDIR;
    if (h.type != 2) return -EINVAL;
    if (offset >= h.size || length == 0) {
        if (out_read) *out_read = 0;
        return 0;
    }
    size_t to_read = length;
    if ((uint64_t)to_read > (uint64_t)h.size - offset) {
        to_read = (size_t)((uint64_t)h.size - offset);
    }
    rc = lfs_read_bytes(fs, (uint64_t)h.data_off + offset, to_read, buffer);
    if (rc != 0) return rc;
    if (out_read) *out_read = to_read;
    return 0;
}

static int romfs_readlink(legacyfs_t *fs, uint64_t ino, char *buffer, size_t buffer_size, size_t *out_len) {
    romfs_hdr_t h;
    int rc = romfs_resolve_hardlink(fs, (uint32_t)(ino - 1ULL), &h, NULL);
    if (rc != 0) return rc;
    if (h.type != 3) return -EINVAL;
    size_t to_read = h.size < buffer_size - 1 ? h.size : buffer_size - 1;
    rc = lfs_read_bytes(fs, h.data_off, to_read, buffer);
    if (rc != 0) return rc;
    buffer[to_read] = '\0';
    if (out_len) *out_len = to_read;
    return 0;
}

const legacyfs_ops_t lfs_romfs_ops = {
    .mount = romfs_mount,
    .unmount = romfs_unmount,
    .root_ino = romfs_root_ino,
    .statfs = NULL,
    .getattr = romfs_getattr,
    .readdir = romfs_readdir,
    .lookup = NULL,
    .read = romfs_read,
    .readlink = romfs_readlink,
};
