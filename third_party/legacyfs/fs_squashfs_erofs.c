#include "internal.h"
#include <zlib.h>

/* =========================================================================
 * SquashFS 4.0 Read-Only Driver (uncompressed and zlib metadata/data/frags)
 * =========================================================================
 * `ino` = squashfs_inode_ref + 1, where ref = ((uint64_t)meta_rel_off << 16) | inner_off
 */
#define SQFS_META_SIZE 8192U
#define SQFS_COMP_ZLIB 1U
#define SQFS_INVALID_FRAG 0xFFFFFFFFU

typedef struct {
    uint32_t block_size;
    uint16_t compression;
    uint16_t no_ids;
    uint64_t root_ref;
    uint64_t bytes_used;
    uint64_t id_table_start;
    uint64_t inode_table_start;
    uint64_t dir_table_start;
    uint64_t frag_table_start;
    uint32_t frag_count;
} sqfs_priv_t;

static int sqfs_decompress_buf(uint16_t comp, const uint8_t *src, size_t src_len, uint8_t *dst, size_t dst_cap, size_t *out_len) {
    if (comp == SQFS_COMP_ZLIB) {
        uLongf dlen = (uLongf)dst_cap;
        if (uncompress(dst, &dlen, src, (uLong)src_len) != Z_OK) {
            return -EIO;
        }
        *out_len = (size_t)dlen;
        return 0;
    }
    return -ENOTSUP;
}

static int sqfs_read_meta_block(legacyfs_t *fs, uint64_t disk_pos, uint8_t out_buf[SQFS_META_SIZE], size_t *out_uncomp_len, uint64_t *out_next_pos) {
    const sqfs_priv_t *p = (const sqfs_priv_t *)fs->priv;
    uint8_t hdr_raw[2];
    int rc = lfs_read_bytes(fs, disk_pos, 2, hdr_raw);
    if (rc != 0) return rc;

    uint16_t hdr = lfs_le16(hdr_raw);
    uint16_t clen = hdr & 0x7FFFU;
    int uncomp = (hdr & 0x8000U) != 0;
    if (clen == 0 || clen > SQFS_META_SIZE) return -EIO;

    uint8_t cbuf[SQFS_META_SIZE];
    rc = lfs_read_bytes(fs, disk_pos + 2ULL, clen, cbuf);
    if (rc != 0) return rc;

    if (uncomp) {
        memcpy(out_buf, cbuf, clen);
        *out_uncomp_len = clen;
    } else {
        size_t ulen = 0;
        rc = sqfs_decompress_buf(p->compression, cbuf, clen, out_buf, SQFS_META_SIZE, &ulen);
        if (rc != 0) return rc;
        *out_uncomp_len = ulen;
    }
    if (out_next_pos) *out_next_pos = disk_pos + 2ULL + (uint64_t)clen;
    return 0;
}

static int sqfs_read_meta_bytes(legacyfs_t *fs, uint64_t block_disk_pos, uint32_t inner_off, void *dst_ptr, size_t len) {
    uint8_t *dst = (uint8_t *)dst_ptr;
    size_t done = 0;
    uint64_t cur_pos = block_disk_pos;
    uint32_t cur_inner = inner_off;
    uint8_t mbuf[SQFS_META_SIZE];

    while (done < len) {
        size_t ulen = 0;
        uint64_t next_pos = 0;
        int rc = sqfs_read_meta_block(fs, cur_pos, mbuf, &ulen, &next_pos);
        if (rc != 0) return rc;
        if (cur_inner >= ulen) {
            cur_inner -= (uint32_t)ulen;
            cur_pos = next_pos;
            continue;
        }
        size_t avail = ulen - cur_inner;
        size_t take = (len - done < avail) ? (len - done) : avail;
        memcpy(dst + done, mbuf + cur_inner, take);
        done += take;
        cur_inner = 0;
        cur_pos = next_pos;
    }
    return 0;
}

static int sqfs_mount(legacyfs_t *fs) {
    uint8_t sb[96];
    int rc = lfs_read_bytes(fs, 0, sizeof(sb), sb);
    if (rc != 0) return rc;
    if (lfs_le32(sb) != 0x73717368U) return -EINVAL;
    if (lfs_le16(sb + 28) != 4) return -ENOTSUP;

    uint32_t bsize = lfs_le32(sb + 12);
    if (bsize < 4096U || bsize > (1U << 20) || !lfs_is_pow2_u32(bsize)) return -EINVAL;

    sqfs_priv_t *p = (sqfs_priv_t *)calloc(1, sizeof(sqfs_priv_t));
    if (!p) return -ENOMEM;
    p->block_size = bsize;
    p->frag_count = lfs_le32(sb + 16);
    p->compression = lfs_le16(sb + 20);
    p->no_ids = lfs_le16(sb + 26);
    p->root_ref = lfs_le64(sb + 32);
    p->bytes_used = lfs_le64(sb + 40);
    p->id_table_start = lfs_le64(sb + 48);
    p->inode_table_start = lfs_le64(sb + 64);
    p->dir_table_start = lfs_le64(sb + 72);
    p->frag_table_start = lfs_le64(sb + 80);
    fs->priv = p;
    return 0;
}

static void sqfs_unmount(legacyfs_t *fs) {
    free(fs->priv);
    fs->priv = NULL;
}

static uint64_t sqfs_root_ino(const legacyfs_t *fs) {
    const sqfs_priv_t *p = (const sqfs_priv_t *)fs->priv;
    return p->root_ref + 1ULL;
}

typedef struct {
    uint16_t itype;
    legacyfs_attr_t attr;
    /* dir fields */
    uint32_t dir_start_blk;
    uint16_t dir_offset;
    uint32_t dir_raw_size;
    /* file fields */
    uint64_t blocks_start;
    uint32_t frag_idx;
    uint32_t frag_off;
    uint64_t block_list_meta_pos;
    uint32_t block_list_inner_off;
    /* symlink fields */
    uint64_t symlink_meta_pos;
    uint32_t symlink_inner_off;
} sqfs_inode_t;

static uint32_t sqfs_lookup_id(legacyfs_t *fs, uint16_t idx) {
    const sqfs_priv_t *p = (const sqfs_priv_t *)fs->priv;
    if (idx >= p->no_ids || p->id_table_start == 0 || p->id_table_start == UINT64_MAX) return 0;
    uint64_t blk_ptr_off = p->id_table_start + ((uint64_t)idx / 2048ULL) * 8ULL;
    uint8_t ptr_raw[8];
    if (lfs_read_bytes(fs, blk_ptr_off, 8, ptr_raw) != 0) return 0;
    uint64_t meta_pos = lfs_le64(ptr_raw);
    uint8_t id_raw[4];
    if (sqfs_read_meta_bytes(fs, meta_pos, ((uint32_t)idx % 2048U) * 4U, id_raw, 4) != 0) return 0;
    return lfs_le32(id_raw);
}

static int sqfs_load_inode(legacyfs_t *fs, uint64_t ino, sqfs_inode_t *out) {
    if (ino == 0) return -ENOENT;
    const sqfs_priv_t *p = (const sqfs_priv_t *)fs->priv;
    uint64_t ref = ino - 1ULL;
    uint64_t meta_pos = p->inode_table_start + (ref >> 16);
    uint32_t inner = (uint32_t)(ref & 0xFFFFU);

    uint8_t base[56];
    int rc = sqfs_read_meta_bytes(fs, meta_pos, inner, base, 24);
    if (rc != 0) return rc;

    memset(out, 0, sizeof(*out));
    out->itype = lfs_le16(base + 0);
    uint16_t perm = lfs_le16(base + 2) & 07777U;
    uint16_t uid_i = lfs_le16(base + 4);
    uint16_t gid_i = lfs_le16(base + 6);
    out->attr.ino = ino;
    out->attr.uid = sqfs_lookup_id(fs, uid_i);
    out->attr.gid = sqfs_lookup_id(fs, gid_i);
    out->attr.mtime_sec = lfs_le32(base + 8);
    out->attr.atime_sec = out->attr.mtime_sec;
    out->attr.ctime_sec = out->attr.mtime_sec;
    out->attr.nlink = 1;

    switch (out->itype) {
    case 1: /* BASIC_DIR (32B) */
        rc = sqfs_read_meta_bytes(fs, meta_pos, inner, base, 32);
        if (rc != 0) return rc;
        out->dir_start_blk = lfs_le32(base + 16);
        out->attr.nlink = lfs_le32(base + 20);
        out->dir_raw_size = lfs_le16(base + 24);
        out->dir_offset = lfs_le16(base + 26);
        out->attr.size = out->dir_raw_size >= 3 ? out->dir_raw_size - 3 : 0;
        out->attr.mode = S_IFDIR | perm;
        out->attr.ftype = LEGACYFS_FT_DIR;
        break;
    case 8: /* LDISK_DIR (40B) */
        rc = sqfs_read_meta_bytes(fs, meta_pos, inner, base, 40);
        if (rc != 0) return rc;
        out->attr.nlink = lfs_le32(base + 16);
        out->dir_raw_size = lfs_le32(base + 20);
        out->dir_start_blk = lfs_le32(base + 24);
        out->dir_offset = lfs_le16(base + 34);
        out->attr.size = out->dir_raw_size >= 3 ? out->dir_raw_size - 3 : 0;
        out->attr.mode = S_IFDIR | perm;
        out->attr.ftype = LEGACYFS_FT_DIR;
        break;
    case 2: /* BASIC_FILE (32B) */
        rc = sqfs_read_meta_bytes(fs, meta_pos, inner, base, 32);
        if (rc != 0) return rc;
        out->blocks_start = lfs_le32(base + 16);
        out->frag_idx = lfs_le32(base + 20);
        out->frag_off = lfs_le32(base + 24);
        out->attr.size = lfs_le32(base + 28);
        out->block_list_meta_pos = meta_pos;
        out->block_list_inner_off = inner + 32U;
        out->attr.mode = S_IFREG | perm;
        out->attr.ftype = LEGACYFS_FT_REG;
        break;
    case 9: /* LDISK_FILE (56B) */
        rc = sqfs_read_meta_bytes(fs, meta_pos, inner, base, 56);
        if (rc != 0) return rc;
        out->blocks_start = lfs_le64(base + 16);
        out->attr.size = lfs_le64(base + 24);
        out->attr.nlink = lfs_le32(base + 40);
        out->frag_idx = lfs_le32(base + 44);
        out->frag_off = lfs_le32(base + 48);
        out->block_list_meta_pos = meta_pos;
        out->block_list_inner_off = inner + 56U;
        out->attr.mode = S_IFREG | perm;
        out->attr.ftype = LEGACYFS_FT_REG;
        break;
    case 3: /* BASIC_SYMLINK */
    case 10:
        out->attr.nlink = lfs_le32(base + 16);
        out->attr.size = lfs_le32(base + 20);
        out->symlink_meta_pos = meta_pos;
        out->symlink_inner_off = inner + 24U;
        out->attr.mode = S_IFLNK | 0777U;
        out->attr.ftype = LEGACYFS_FT_SYMLINK;
        break;
    default:
        out->attr.mode = perm;
        out->attr.ftype = LEGACYFS_FT_UNKNOWN;
        break;
    }
    out->attr.blocks_512 = (out->attr.size + 511ULL) / 512ULL;
    return 0;
}

static int sqfs_getattr(legacyfs_t *fs, uint64_t ino, legacyfs_attr_t *out_attr) {
    sqfs_inode_t si;
    int rc = sqfs_load_inode(fs, ino, &si);
    if (rc != 0) return rc;
    *out_attr = si.attr;
    return 0;
}

static int sqfs_readdir(legacyfs_t *fs, uint64_t dir_ino, legacyfs_readdir_cb cb, void *user_ctx) {
    const sqfs_priv_t *p = (const sqfs_priv_t *)fs->priv;
    sqfs_inode_t si;
    int rc = sqfs_load_inode(fs, dir_ino, &si);
    if (rc != 0) return rc;
    if (si.attr.ftype != LEGACYFS_FT_DIR) return -ENOTDIR;
    if (si.dir_raw_size <= 3) return 0;

    uint32_t total_dir_bytes = si.dir_raw_size - 3U;
    if (total_dir_bytes > (16U * 1024U * 1024U)) return -EIO;

    uint8_t *dbuf = (uint8_t *)malloc(total_dir_bytes);
    if (!dbuf) return -ENOMEM;

    rc = sqfs_read_meta_bytes(fs, p->dir_table_start + si.dir_start_blk, si.dir_offset, dbuf, total_dir_bytes);
    if (rc != 0) {
        free(dbuf);
        return rc;
    }

    uint32_t pos = 0;
    while (pos + 12U <= total_dir_bytes) {
        uint32_t count = lfs_le32(dbuf + pos + 0) + 1U;
        uint32_t start_blk = lfs_le32(dbuf + pos + 4);
        pos += 12U;

        for (uint32_t i = 0; i < count && pos + 8U <= total_dir_bytes; i++) {
            uint16_t e_off = lfs_le16(dbuf + pos + 0);
            uint16_t e_type = lfs_le16(dbuf + pos + 4);
            uint16_t nlen = lfs_le16(dbuf + pos + 6) + 1U;
            pos += 8U;
            if (pos + nlen > total_dir_bytes || nlen > 255U) {
                free(dbuf);
                return -EIO;
            }
            char name[256];
            memcpy(name, dbuf + pos, nlen);
            name[nlen] = '\0';
            pos += nlen;

            legacyfs_ftype_t ft = LEGACYFS_FT_UNKNOWN;
            if (e_type == 1 || e_type == 8) ft = LEGACYFS_FT_DIR;
            else if (e_type == 2 || e_type == 9) ft = LEGACYFS_FT_REG;
            else if (e_type == 3 || e_type == 10) ft = LEGACYFS_FT_SYMLINK;

            uint64_t child_ino = (((uint64_t)start_blk << 16) | (uint64_t)e_off) + 1ULL;
            if (cb(user_ctx, name, child_ino, ft) != 0) {
                free(dbuf);
                return 0;
            }
        }
    }

    free(dbuf);
    return 0;
}

static int sqfs_read_fragment(legacyfs_t *fs, uint32_t frag_idx, uint32_t frag_off, size_t len, uint8_t *dst) {
    const sqfs_priv_t *p = (const sqfs_priv_t *)fs->priv;
    if (frag_idx >= p->frag_count || p->frag_table_start == UINT64_MAX) return -EIO;

    uint64_t ptr_off = p->frag_table_start + ((uint64_t)frag_idx / 512ULL) * 8ULL;
    uint8_t ptr_raw[8];
    int rc = lfs_read_bytes(fs, ptr_off, 8, ptr_raw);
    if (rc != 0) return rc;
    uint64_t frag_meta_pos = lfs_le64(ptr_raw);

    uint8_t fentry[16];
    rc = sqfs_read_meta_bytes(fs, frag_meta_pos, (frag_idx % 512U) * 16U, fentry, 16);
    if (rc != 0) return rc;

    uint64_t start_blk = lfs_le64(fentry + 0);
    uint32_t raw_sz = lfs_le32(fentry + 8);
    uint32_t disk_sz = raw_sz & 0x00FFFFFFU;
    int uncomp = (raw_sz & 0x01000000U) != 0;
    if (disk_sz > p->block_size * 2U) return -EIO;

    uint8_t *cbuf = (uint8_t *)malloc(disk_sz ? disk_sz : 1U);
    uint8_t *ubuf = (uint8_t *)malloc(p->block_size);
    if (!cbuf || !ubuf) {
        free(cbuf);
        free(ubuf);
        return -ENOMEM;
    }

    rc = lfs_read_bytes(fs, start_blk, disk_sz, cbuf);
    if (rc == 0) {
        size_t ulen = 0;
        if (uncomp) {
            if (disk_sz > p->block_size) rc = -EIO;
            else {
                memcpy(ubuf, cbuf, disk_sz);
                ulen = disk_sz;
            }
        } else {
            rc = sqfs_decompress_buf(p->compression, cbuf, disk_sz, ubuf, p->block_size, &ulen);
        }
        if (rc == 0) {
            if ((uint64_t)frag_off + len > ulen) rc = -EIO;
            else memcpy(dst, ubuf + frag_off, len);
        }
    }

    free(cbuf);
    free(ubuf);
    return rc;
}

static int sqfs_read(legacyfs_t *fs, uint64_t ino, uint64_t offset, size_t length, void *buffer, size_t *out_read) {
    const sqfs_priv_t *p = (const sqfs_priv_t *)fs->priv;
    sqfs_inode_t si;
    int rc = sqfs_load_inode(fs, ino, &si);
    if (rc != 0) return rc;
    if (si.attr.ftype == LEGACYFS_FT_DIR) return -EISDIR;
    if (si.attr.ftype != LEGACYFS_FT_REG) return -EINVAL;

    if (offset >= si.attr.size || length == 0) {
        if (out_read) *out_read = 0;
        return 0;
    }
    size_t to_read = length;
    if ((uint64_t)to_read > si.attr.size - offset) {
        to_read = (size_t)(si.attr.size - offset);
    }

    uint64_t full_blocks = (si.frag_idx == SQFS_INVALID_FRAG)
        ? ((si.attr.size + p->block_size - 1ULL) / p->block_size)
        : (si.attr.size / p->block_size);

    uint8_t *bsizes = NULL;
    if (full_blocks > 0) {
        if (full_blocks > (1ULL << 22)) return -EIO;
        bsizes = (uint8_t *)malloc((size_t)full_blocks * 4U);
        if (!bsizes) return -ENOMEM;
        rc = sqfs_read_meta_bytes(fs, si.block_list_meta_pos, si.block_list_inner_off, bsizes, (size_t)full_blocks * 4U);
        if (rc != 0) {
            free(bsizes);
            return rc;
        }
    }

    uint8_t *cbuf = (uint8_t *)malloc(p->block_size * 2U);
    uint8_t *ubuf = (uint8_t *)malloc(p->block_size);
    if (!cbuf || !ubuf) {
        free(bsizes);
        free(cbuf);
        free(ubuf);
        return -ENOMEM;
    }

    uint64_t disk_cursor = si.blocks_start;
    uint64_t cur_blk_idx = 0;
    uint8_t *dst = (uint8_t *)buffer;
    size_t done = 0;

    while (done < to_read) {
        uint64_t cur = offset + done;
        uint64_t target_blk = cur / p->block_size;
        size_t boff = (size_t)(cur % p->block_size);
        size_t chunk = p->block_size - boff;
        if (chunk > to_read - done) chunk = to_read - done;

        if (target_blk < full_blocks) {
            while (cur_blk_idx < target_blk) {
                uint32_t raw_sz = lfs_le32(bsizes + cur_blk_idx * 4U);
                disk_cursor += (raw_sz & 0x00FFFFFFU);
                cur_blk_idx++;
            }
            uint32_t raw_sz = lfs_le32(bsizes + target_blk * 4U);
            uint32_t dsz = raw_sz & 0x00FFFFFFU;
            int uncomp = (raw_sz & 0x01000000U) != 0;
            if (dsz == 0) {
                memset(dst + done, 0, chunk);
            } else {
                if (dsz > p->block_size * 2U) { rc = -EIO; break; }
                rc = lfs_read_bytes(fs, disk_cursor, dsz, cbuf);
                if (rc != 0) break;
                if (uncomp) {
                    memset(ubuf, 0, p->block_size);
                    memcpy(ubuf, cbuf, dsz < p->block_size ? dsz : p->block_size);
                } else {
                    size_t ulen = 0;
                    memset(ubuf, 0, p->block_size);
                    rc = sqfs_decompress_buf(p->compression, cbuf, dsz, ubuf, p->block_size, &ulen);
                    if (rc != 0) break;
                }
                memcpy(dst + done, ubuf + boff, chunk);
            }
        } else {
            /* Tail stored in fragment */
            rc = sqfs_read_fragment(fs, si.frag_idx, si.frag_off + (uint32_t)boff, chunk, dst + done);
            if (rc != 0) break;
        }
        done += chunk;
    }

    free(bsizes);
    free(cbuf);
    free(ubuf);
    if (rc != 0) return rc;
    if (out_read) *out_read = done;
    return 0;
}

static int sqfs_readlink(legacyfs_t *fs, uint64_t ino, char *buffer, size_t buffer_size, size_t *out_len) {
    sqfs_inode_t si;
    int rc = sqfs_load_inode(fs, ino, &si);
    if (rc != 0) return rc;
    if (si.attr.ftype != LEGACYFS_FT_SYMLINK) return -EINVAL;

    size_t to_read = si.attr.size < buffer_size - 1 ? (size_t)si.attr.size : buffer_size - 1;
    rc = sqfs_read_meta_bytes(fs, si.symlink_meta_pos, si.symlink_inner_off, buffer, to_read);
    if (rc != 0) return rc;
    buffer[to_read] = '\0';
    if (out_len) *out_len = to_read;
    return 0;
}

const legacyfs_ops_t lfs_squashfs_ops = {
    .mount = sqfs_mount,
    .unmount = sqfs_unmount,
    .root_ino = sqfs_root_ino,
    .statfs = NULL,
    .getattr = sqfs_getattr,
    .readdir = sqfs_readdir,
    .lookup = NULL,
    .read = sqfs_read,
    .readlink = sqfs_readlink,
};

/* =========================================================================
 * EROFS Read-Only Driver (flat-plain and flat-inline tail-packed layouts)
 * =========================================================================
 * `ino` = nid + 1
 */
typedef struct {
    uint32_t block_size;
    uint16_t root_nid;
    uint32_t meta_blkaddr;
    uint64_t build_time;
} erofs_priv_t;

typedef struct {
    legacyfs_attr_t attr;
    uint8_t datalayout;    /* 0 = FLAT_PLAIN, 2 = FLAT_INLINE */
    uint32_t raw_blkaddr;
    uint64_t inline_off;
} erofs_inode_t;

static int erofs_mount(legacyfs_t *fs) {
    uint8_t sb[128];
    int rc = lfs_read_bytes(fs, 1024ULL, sizeof(sb), sb);
    if (rc != 0) return rc;
    if (lfs_le32(sb) != 0xE0F5E1E2U) return -EINVAL;
    uint8_t blkszbits = sb[12];
    if (blkszbits < 9 || blkszbits > 16) return -EINVAL;

    erofs_priv_t *p = (erofs_priv_t *)calloc(1, sizeof(erofs_priv_t));
    if (!p) return -ENOMEM;
    p->block_size = 1U << blkszbits;
    p->root_nid = lfs_le16(sb + 14);
    p->build_time = lfs_le64(sb + 24);
    p->meta_blkaddr = lfs_le32(sb + 40);
    fs->priv = p;
    return 0;
}

static void erofs_unmount(legacyfs_t *fs) {
    free(fs->priv);
    fs->priv = NULL;
}

static uint64_t erofs_root_ino(const legacyfs_t *fs) {
    const erofs_priv_t *p = (const erofs_priv_t *)fs->priv;
    return (uint64_t)p->root_nid + 1ULL;
}

static int erofs_load_inode(legacyfs_t *fs, uint64_t ino, erofs_inode_t *out) {
    if (ino == 0) return -ENOENT;
    const erofs_priv_t *p = (const erofs_priv_t *)fs->priv;
    uint64_t nid = ino - 1ULL;
    uint64_t ioff = (uint64_t)p->meta_blkaddr * p->block_size + nid * 32ULL;

    uint8_t raw[64];
    int rc = lfs_read_bytes(fs, ioff, 32, raw);
    if (rc != 0) return rc;

    memset(out, 0, sizeof(*out));
    uint16_t ifmt = lfs_le16(raw + 0);
    uint16_t xattr_icount = lfs_le16(raw + 2);
    size_t xattr_bytes = (xattr_icount == 0) ? 0U : (12U + (size_t)(xattr_icount - 1U) * 4U);
    out->datalayout = (uint8_t)((ifmt >> 1) & 0x07U);
    out->attr.ino = ino;

    if ((ifmt & 1U) == 0) {
        /* Compact 32B inode */
        out->attr.mode = lfs_le16(raw + 4);
        out->attr.nlink = lfs_le16(raw + 6);
        out->attr.size = lfs_le32(raw + 8);
        out->raw_blkaddr = lfs_le32(raw + 16);
        out->attr.uid = lfs_le16(raw + 24);
        out->attr.gid = lfs_le16(raw + 26);
        out->attr.mtime_sec = (int64_t)p->build_time;
        out->inline_off = ioff + 32ULL + xattr_bytes;
    } else {
        /* Extended 64B inode */
        rc = lfs_read_bytes(fs, ioff, 64, raw);
        if (rc != 0) return rc;
        out->attr.mode = lfs_le16(raw + 4);
        out->attr.size = lfs_le64(raw + 8);
        out->raw_blkaddr = lfs_le32(raw + 16);
        out->attr.uid = lfs_le32(raw + 24);
        out->attr.gid = lfs_le32(raw + 28);
        out->attr.mtime_sec = (int64_t)lfs_le64(raw + 32);
        out->attr.nlink = lfs_le32(raw + 44);
        out->inline_off = ioff + 64ULL + xattr_bytes;
    }
    if (out->attr.mode == 0) return -ENOENT;
    out->attr.atime_sec = out->attr.mtime_sec;
    out->attr.ctime_sec = out->attr.mtime_sec;
    out->attr.blocks_512 = (out->attr.size + 511ULL) / 512ULL;
    out->attr.ftype = lfs_mode_to_ftype(out->attr.mode);
    return 0;
}

static int erofs_read_inode_data(legacyfs_t *fs, const erofs_inode_t *ei, uint64_t offset, size_t length, void *buffer, size_t *out_read) {
    const erofs_priv_t *p = (const erofs_priv_t *)fs->priv;
    if (ei->datalayout != 0 && ei->datalayout != 2) return -ENOTSUP;
    if (offset >= ei->attr.size || length == 0) {
        if (out_read) *out_read = 0;
        return 0;
    }
    size_t to_read = length;
    if ((uint64_t)to_read > ei->attr.size - offset) {
        to_read = (size_t)(ei->attr.size - offset);
    }

    uint64_t full_blocks = ei->attr.size / p->block_size;
    uint64_t plain_limit = (ei->datalayout == 2) ? (full_blocks * p->block_size) : ei->attr.size;
    uint8_t *dst = (uint8_t *)buffer;
    size_t done = 0;

    if (offset < plain_limit) {
        uint64_t plain_avail = plain_limit - offset;
        size_t take = ((uint64_t)to_read < plain_avail) ? to_read : (size_t)plain_avail;
        int rc = lfs_read_bytes(fs, (uint64_t)ei->raw_blkaddr * p->block_size + offset, take, dst);
        if (rc != 0) return rc;
        done += take;
    }

    if (done < to_read && ei->datalayout == 2) {
        uint64_t tail_off = (offset + done) - plain_limit;
        size_t rem = to_read - done;
        int rc = lfs_read_bytes(fs, ei->inline_off + tail_off, rem, dst + done);
        if (rc != 0) return rc;
        done += rem;
    }

    if (out_read) *out_read = done;
    return 0;
}

static int erofs_getattr(legacyfs_t *fs, uint64_t ino, legacyfs_attr_t *out_attr) {
    erofs_inode_t ei;
    int rc = erofs_load_inode(fs, ino, &ei);
    if (rc != 0) return rc;
    *out_attr = ei.attr;
    return 0;
}

static int erofs_readdir(legacyfs_t *fs, uint64_t dir_ino, legacyfs_readdir_cb cb, void *user_ctx) {
    const erofs_priv_t *p = (const erofs_priv_t *)fs->priv;
    erofs_inode_t ei;
    int rc = erofs_load_inode(fs, dir_ino, &ei);
    if (rc != 0) return rc;
    if (ei.attr.ftype != LEGACYFS_FT_DIR) return -ENOTDIR;

    uint8_t *blk = (uint8_t *)malloc(p->block_size);
    if (!blk) return -ENOMEM;

    uint64_t pos = 0;
    while (pos < ei.attr.size) {
        size_t chunk = p->block_size;
        if ((uint64_t)chunk > ei.attr.size - pos) {
            chunk = (size_t)(ei.attr.size - pos);
        }
        size_t got = 0;
        rc = erofs_read_inode_data(fs, &ei, pos, chunk, blk, &got);
        if (rc != 0 || got < 12) break;

        uint16_t first_nameoff = lfs_le16(blk + 8);
        if (first_nameoff < 12 || first_nameoff > got || (first_nameoff % 12U) != 0) {
            rc = -EIO;
            break;
        }
        uint16_t count = first_nameoff / 12U;

        for (uint16_t i = 0; i < count; i++) {
            const uint8_t *de = blk + (size_t)i * 12U;
            uint64_t child_nid = lfs_le64(de + 0);
            uint16_t noff = lfs_le16(de + 8);
            uint8_t ft_raw = de[10];
            uint16_t nend = (i + 1U < count) ? lfs_le16(blk + (size_t)(i + 1U) * 12U + 8U) : (uint16_t)got;
            if (noff >= got || nend > got || nend <= noff) continue;

            size_t nlen = 0;
            size_t max_n = (size_t)(nend - noff);
            while (nlen < max_n && nlen < 255U && blk[noff + nlen] != 0) {
                nlen++;
            }
            if (nlen == 0) continue;

            char name[256];
            memcpy(name, blk + noff, nlen);
            name[nlen] = '\0';
            if (strcmp(name, ".") == 0 || strcmp(name, "..") == 0) continue;

            legacyfs_ftype_t ft = LEGACYFS_FT_UNKNOWN;
            if (ft_raw == 1) ft = LEGACYFS_FT_REG;
            else if (ft_raw == 2) ft = LEGACYFS_FT_DIR;
            else if (ft_raw == 7) ft = LEGACYFS_FT_SYMLINK;

            if (cb(user_ctx, name, child_nid + 1ULL, ft) != 0) {
                free(blk);
                return 0;
            }
        }
        pos += got;
    }

    free(blk);
    return rc;
}

static int erofs_read(legacyfs_t *fs, uint64_t ino, uint64_t offset, size_t length, void *buffer, size_t *out_read) {
    erofs_inode_t ei;
    int rc = erofs_load_inode(fs, ino, &ei);
    if (rc != 0) return rc;
    if (ei.attr.ftype == LEGACYFS_FT_DIR) return -EISDIR;
    if (ei.attr.ftype != LEGACYFS_FT_REG) return -EINVAL;
    return erofs_read_inode_data(fs, &ei, offset, length, buffer, out_read);
}

static int erofs_readlink(legacyfs_t *fs, uint64_t ino, char *buffer, size_t buffer_size, size_t *out_len) {
    erofs_inode_t ei;
    int rc = erofs_load_inode(fs, ino, &ei);
    if (rc != 0) return rc;
    if (ei.attr.ftype != LEGACYFS_FT_SYMLINK) return -EINVAL;
    size_t got = 0;
    rc = erofs_read_inode_data(fs, &ei, 0, buffer_size - 1, buffer, &got);
    if (rc != 0) return rc;
    buffer[got] = '\0';
    if (out_len) *out_len = got;
    return 0;
}

const legacyfs_ops_t lfs_erofs_ops = {
    .mount = erofs_mount,
    .unmount = erofs_unmount,
    .root_ino = erofs_root_ino,
    .statfs = NULL,
    .getattr = erofs_getattr,
    .readdir = erofs_readdir,
    .lookup = NULL,
    .read = erofs_read,
    .readlink = erofs_readlink,
};
