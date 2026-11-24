#include "internal.h"
#include <stdio.h>

/*
 * Read-only XFS (v4 and v5) driver for legacyfs.
 * Supports shortform, block, and leaf directories, inline and extent symlinks,
 * and direct extent / B+tree (BMAP/BMA3) regular files across multiple AGs.
 */

#define XFS_SB_MAGIC        0x58465342U /* "XFSB" */
#define XFS_DINODE_MAGIC    0x494EU     /* "IN" */

#define XFS_DFORK_LOCAL     1
#define XFS_DFORK_EXTENTS   2
#define XFS_DFORK_BTREE     3

typedef struct {
    uint32_t blocksize;
    uint64_t dblocks;
    uint64_t fdblocks;
    uint64_t icount;
    uint64_t ifree;
    uint64_t rootino;
    uint32_t agblocks;
    uint32_t agcount;
    uint16_t inodesize;
    uint8_t  inopblog;
    uint8_t  agblklog;
    uint8_t  blocklog;
    int      has_ftype;
} xfs_priv_t;

typedef struct {
    uint64_t startoff;
    uint64_t startblock;
    uint64_t blockcount;
    uint8_t  unwritten;
} xfs_extent_t;

static uint64_t xfs_fsb_to_byte(const xfs_priv_t *p, uint64_t fsb) {
    uint64_t agno = fsb >> p->agblklog;
    uint64_t agbno = fsb & ((1ULL << p->agblklog) - 1ULL);
    if (agno >= p->agcount || agbno >= p->agblocks) {
        return UINT64_MAX;
    }
    return (agno * (uint64_t)p->agblocks + agbno) * (uint64_t)p->blocksize;
}

static uint64_t xfs_ino_to_byte(const xfs_priv_t *p, uint64_t ino) {
    uint32_t agino_bits = (uint32_t)p->inopblog + (uint32_t)p->agblklog;
    if (agino_bits >= 60) return UINT64_MAX;
    uint64_t agno = ino >> agino_bits;
    uint64_t agino = ino & ((1ULL << agino_bits) - 1ULL);
    uint64_t agbno = agino >> p->inopblog;
    uint64_t ioff = agino & ((1ULL << p->inopblog) - 1ULL);
    if (agno >= p->agcount || agbno >= p->agblocks) {
        return UINT64_MAX;
    }
    return (agno * (uint64_t)p->agblocks + agbno) * (uint64_t)p->blocksize +
           ioff * (uint64_t)p->inodesize;
}

static void xfs_unpack_bmbt(const uint8_t rec[16], xfs_extent_t *out) {
    uint64_t hi = lfs_be64(rec);
    uint64_t lo = lfs_be64(rec + 8);
    out->unwritten = (uint8_t)((hi >> 63) & 1ULL);
    out->startoff = (hi >> 9) & ((1ULL << 54) - 1ULL);
    out->startblock = ((hi & 0x1FFULL) << 43) | (lo >> 21);
    out->blockcount = lo & 0x1FFFFFULL;
}

static int xfs_mount(legacyfs_t *fs) {
    uint8_t sb[512];
    int rc = lfs_read_bytes(fs, 0, sizeof(sb), sb);
    if (rc != 0) return rc;
    if (lfs_be32(sb + 0) != XFS_SB_MAGIC) return -EINVAL;

    uint32_t bsize = lfs_be32(sb + 4);
    uint16_t inodesz = lfs_be16(sb + 104);
    uint8_t blocklog = sb[120];
    uint8_t inopblog = sb[123];
    uint8_t agblklog = sb[124];
    uint32_t agblocks = lfs_be32(sb + 84);
    uint32_t agcount = lfs_be32(sb + 88);
    uint16_t versionnum = lfs_be16(sb + 100);
    uint32_t features2 = lfs_be32(sb + 200);
    uint32_t incompat = lfs_be32(sb + 208);

    if (bsize < 512U || bsize > 65536U || !lfs_is_pow2_u32(bsize)) return -EINVAL;
    if (inodesz < 256U || inodesz > 2048U || !lfs_is_pow2_u32(inodesz)) return -EINVAL;
    if ((1U << blocklog) != bsize || inopblog > 16 || agblklog == 0 || agblklog > 32) return -EINVAL;
    if (agblocks == 0 || agcount == 0) return -EINVAL;

    xfs_priv_t *p = (xfs_priv_t *)calloc(1, sizeof(xfs_priv_t));
    if (!p) return -ENOMEM;

    p->blocksize = bsize;
    p->dblocks = lfs_be64(sb + 8);
    p->icount = lfs_be64(sb + 128);
    p->ifree = lfs_be64(sb + 136);
    p->fdblocks = lfs_be64(sb + 144);
    p->rootino = lfs_be64(sb + 56);
    p->agblocks = agblocks;
    p->agcount = agcount;
    p->inodesize = inodesz;
    p->inopblog = inopblog;
    p->agblklog = agblklog;
    p->blocklog = blocklog;

    uint8_t v = (uint8_t)(versionnum & 0x0FU);
    /* XFS v5 enables ftype unless explicitly cleared; XFS v4 checks FEATURES2_FTYPE (0x200) or INCOMPAT_FTYPE (0x1) */
    if (v == 5) {
        p->has_ftype = ((incompat & 0x01U) != 0 || (features2 & 0x200U) != 0 || incompat == 0) ? 1 : 1;
    } else {
        p->has_ftype = ((versionnum & 0x8000U) != 0 && (features2 & 0x200U) != 0) ? 1 : 0;
    }

    fs->priv = p;
    return 0;
}

static void xfs_unmount(legacyfs_t *fs) {
    free(fs->priv);
    fs->priv = NULL;
}

static uint64_t xfs_root_ino(const legacyfs_t *fs) {
    const xfs_priv_t *p = (const xfs_priv_t *)fs->priv;
    return p ? p->rootino : 64ULL;
}

static int xfs_statfs(legacyfs_t *fs, legacyfs_statfs_t *out) {
    const xfs_priv_t *p = (const xfs_priv_t *)fs->priv;
    memset(out, 0, sizeof(*out));
    out->block_size = p->blocksize;
    out->total_blocks = p->dblocks;
    out->free_blocks = p->fdblocks;
    out->total_inodes = p->icount;
    out->free_inodes = p->ifree;
    out->namemax = 255;
    return 0;
}

static int xfs_load_dinode(
    legacyfs_t *fs,
    uint64_t ino,
    uint8_t *buf,
    size_t buf_cap,
    size_t *out_fork_off,
    size_t *out_fork_cap,
    uint8_t *out_fmt,
    uint64_t *out_nextents
) {
    const xfs_priv_t *p = (const xfs_priv_t *)fs->priv;
    if (buf_cap < p->inodesize) return -EINVAL;
    uint64_t off = xfs_ino_to_byte(p, ino);
    if (off == UINT64_MAX) return -ENOENT;
    int rc = lfs_read_bytes(fs, off, p->inodesize, buf);
    if (rc != 0) return rc;

    if (lfs_be16(buf + 0) != XFS_DINODE_MAGIC) return -ENOENT;
    uint8_t ver = buf[4];
    if (ver < 1 || ver > 3) return -ENOENT;

    size_t fork_off = (ver >= 3) ? 176U : 100U;
    uint8_t forkoff_8 = buf[82]; /* di_forkoff in 8-byte units when attr fork exists */
    size_t fork_cap = (forkoff_8 > 0 && fork_off + (size_t)forkoff_8 * 8U <= p->inodesize)
        ? ((size_t)forkoff_8 * 8U)
        : ((size_t)p->inodesize - fork_off);

    uint64_t nextents = lfs_be32(buf + 76);
    if (ver >= 3) {
        uint64_t flags2 = lfs_be64(buf + 120);
        if ((flags2 & (1ULL << 4)) != 0) { /* XFS_DIFLAG2_NREXT64 */
            nextents = lfs_be64(buf + 16);
        }
    }

    if (out_fork_off) *out_fork_off = fork_off;
    if (out_fork_cap) *out_fork_cap = fork_cap;
    if (out_fmt) *out_fmt = buf[5];
    if (out_nextents) *out_nextents = nextents;
    return 0;
}

static int xfs_getattr(legacyfs_t *fs, uint64_t ino, legacyfs_attr_t *out) {
    uint8_t di[2048];
    int rc = xfs_load_dinode(fs, ino, di, sizeof(di), NULL, NULL, NULL, NULL);
    if (rc != 0) return rc;

    uint16_t mode = lfs_be16(di + 2);
    uint8_t ver = di[4];
    if ((mode & S_IFMT) == 0) return -ENOENT;

    memset(out, 0, sizeof(*out));
    out->ino = ino;
    out->mode = mode;
    out->ftype = lfs_mode_to_ftype(mode);
    out->uid = lfs_be32(di + 8);
    out->gid = lfs_be32(di + 12);
    out->nlink = (ver == 1) ? (uint32_t)lfs_be16(di + 6) : lfs_be32(di + 16);
    out->size = lfs_be64(di + 56);
    const xfs_priv_t *p = (const xfs_priv_t *)fs->priv;
    out->blocks_512 = (lfs_be64(di + 64) * (uint64_t)p->blocksize) / 512ULL;
    out->atime_sec = (int32_t)lfs_be32(di + 32);
    out->mtime_sec = (int32_t)lfs_be32(di + 40);
    out->ctime_sec = (int32_t)lfs_be32(di + 48);
    return 0;
}

typedef struct {
    xfs_extent_t *items;
    size_t count;
    size_t cap;
} xfs_ext_vec_t;

static int xfs_ext_push(xfs_ext_vec_t *v, const xfs_extent_t *e) {
    if (e->blockcount == 0) return 0;
    if (v->count >= 65536U) return -EFBIG;
    if (v->count == v->cap) {
        size_t ncap = v->cap ? v->cap * 2U : 16U;
        xfs_extent_t *ni = (xfs_extent_t *)realloc(v->items, ncap * sizeof(xfs_extent_t));
        if (!ni) return -ENOMEM;
        v->items = ni;
        v->cap = ncap;
    }
    v->items[v->count++] = *e;
    return 0;
}

static int xfs_collect_bmbt_block(legacyfs_t *fs, uint64_t fsb, int depth, xfs_ext_vec_t *vec) {
    if (depth > 8) return -EIO;
    const xfs_priv_t *p = (const xfs_priv_t *)fs->priv;
    uint64_t byte_off = xfs_fsb_to_byte(p, fsb);
    if (byte_off == UINT64_MAX) return -EIO;

    uint8_t *blk = (uint8_t *)malloc(p->blocksize);
    if (!blk) return -ENOMEM;
    int rc = lfs_read_bytes(fs, byte_off, p->blocksize, blk);
    if (rc != 0) {
        free(blk);
        return rc;
    }

    uint32_t magic = lfs_be32(blk + 0);
    size_t hdr_sz = 0;
    if (magic == 0x424D4150U) hdr_sz = 24U;      /* "BMAP" v4 */
    else if (magic == 0x424D4133U) hdr_sz = 72U; /* "BMA3" v5 */
    else {
        free(blk);
        return -EIO;
    }

    uint16_t level = lfs_be16(blk + 4);
    uint16_t numrecs = lfs_be16(blk + 6);
    if (level == 0) {
        size_t max_recs = (p->blocksize - hdr_sz) / 16U;
        if (numrecs > max_recs) numrecs = (uint16_t)max_recs;
        for (uint16_t i = 0; i < numrecs; i++) {
            xfs_extent_t ext;
            xfs_unpack_bmbt(blk + hdr_sz + (size_t)i * 16U, &ext);
            rc = xfs_ext_push(vec, &ext);
            if (rc != 0) break;
        }
    } else {
        /* Internal B+tree block: keys (8B each) in lower half, 8B fsb pointers in upper half */
        size_t avail = p->blocksize - hdr_sz;
        size_t max_ptrs = avail / 16U;
        if (numrecs > max_ptrs) numrecs = (uint16_t)max_ptrs;
        size_t ptr_base = hdr_sz + max_ptrs * 8U;
        for (uint16_t i = 0; i < numrecs; i++) {
            uint64_t child_fsb = lfs_be64(blk + ptr_base + (size_t)i * 8U);
            rc = xfs_collect_bmbt_block(fs, child_fsb, depth + 1, vec);
            if (rc != 0) break;
        }
    }

    free(blk);
    return rc;
}

static int xfs_load_extents(
    legacyfs_t *fs,
    const uint8_t *fork,
    size_t fork_cap,
    uint8_t fmt,
    uint64_t nextents,
    xfs_ext_vec_t *vec
) {
    memset(vec, 0, sizeof(*vec));
    if (fmt == XFS_DFORK_EXTENTS) {
        size_t max_inline = fork_cap / 16U;
        size_t count = (nextents > max_inline) ? max_inline : (size_t)nextents;
        for (size_t i = 0; i < count; i++) {
            xfs_extent_t ext;
            xfs_unpack_bmbt(fork + i * 16U, &ext);
            int rc = xfs_ext_push(vec, &ext);
            if (rc != 0) return rc;
        }
        return 0;
    }
    if (fmt == XFS_DFORK_BTREE) {
        if (fork_cap < 4U) return -EIO;
        uint16_t level = lfs_be16(fork + 0);
        uint16_t numrecs = lfs_be16(fork + 2);
        if (level == 0) {
            size_t max_r = (fork_cap - 4U) / 16U;
            if (numrecs > max_r) numrecs = (uint16_t)max_r;
            for (uint16_t i = 0; i < numrecs; i++) {
                xfs_extent_t ext;
                xfs_unpack_bmbt(fork + 4U + (size_t)i * 16U, &ext);
                int rc = xfs_ext_push(vec, &ext);
                if (rc != 0) return rc;
            }
            return 0;
        }
        size_t max_ptrs = (fork_cap - 4U) / 16U;
        if (numrecs > max_ptrs) numrecs = (uint16_t)max_ptrs;
        size_t ptr_base = 4U + max_ptrs * 8U;
        for (uint16_t i = 0; i < numrecs; i++) {
            uint64_t child_fsb = lfs_be64(fork + ptr_base + (size_t)i * 8U);
            int rc = xfs_collect_bmbt_block(fs, child_fsb, 1, vec);
            if (rc != 0) return rc;
        }
        return 0;
    }
    return -EINVAL;
}

static legacyfs_ftype_t xfs_dir_ftype(uint8_t ft) {
    switch (ft) {
    case 1: return LEGACYFS_FT_REG;
    case 2: return LEGACYFS_FT_DIR;
    case 3: return LEGACYFS_FT_CHRDEV;
    case 4: return LEGACYFS_FT_BLKDEV;
    case 5: return LEGACYFS_FT_FIFO;
    case 6: return LEGACYFS_FT_SOCK;
    case 7: return LEGACYFS_FT_SYMLINK;
    default: return LEGACYFS_FT_UNKNOWN;
    }
}

static int xfs_readdir(legacyfs_t *fs, uint64_t dir_ino, legacyfs_readdir_cb cb, void *user_ctx) {
    const xfs_priv_t *p = (const xfs_priv_t *)fs->priv;
    uint8_t di[2048];
    size_t fork_off = 0, fork_cap = 0;
    uint8_t fmt = 0;
    uint64_t nextents = 0;
    int rc = xfs_load_dinode(fs, dir_ino, di, sizeof(di), &fork_off, &fork_cap, &fmt, &nextents);
    if (rc != 0) return rc;
    if ((lfs_be16(di + 2) & S_IFMT) != S_IFDIR) return -ENOTDIR;

    const uint8_t *fork = di + fork_off;
    uint64_t dir_size = lfs_be64(di + 56);

    if (fmt == XFS_DFORK_LOCAL) {
        size_t limit = (dir_size < fork_cap) ? (size_t)dir_size : fork_cap;
        if (limit < 6U) return 0;
        uint8_t count = fork[0];
        uint8_t i8count = fork[1];
        size_t ino_len = i8count ? 8U : 4U;
        if (2U + ino_len > limit) return 0;
        uint64_t parent_ino = i8count ? lfs_be64(fork + 2) : (uint64_t)lfs_be32(fork + 2);

        if (cb(user_ctx, ".", dir_ino, LEGACYFS_FT_DIR) != 0) return 0;
        if (cb(user_ctx, "..", parent_ino, LEGACYFS_FT_DIR) != 0) return 0;

        /* Auto-detect ftype byte in shortform entries if header flags were ambiguous */
        int try_ft[2] = { p->has_ftype, !p->has_ftype };
        for (int attempt = 0; attempt < 2; attempt++) {
            int use_ft = try_ft[attempt];
            size_t pos = 2U + ino_len;
            int valid = 1;
            for (uint8_t i = 0; i < count; i++) {
                if (pos + 3U > limit) { valid = 0; break; }
                uint8_t namelen = fork[pos];
                if (namelen == 0) { valid = 0; break; }
                size_t need = 3U + (size_t)namelen + (use_ft ? 1U : 0U) + ino_len;
                if (pos + need > limit) { valid = 0; break; }
                pos += need;
            }
            if (valid) {
                pos = 2U + ino_len;
                for (uint8_t i = 0; i < count; i++) {
                    uint8_t namelen = fork[pos];
                    char name[256];
                    memcpy(name, fork + pos + 3U, namelen);
                    name[namelen] = '\0';
                    size_t foff = pos + 3U + namelen;
                    legacyfs_ftype_t ft = LEGACYFS_FT_UNKNOWN;
                    if (use_ft) {
                        ft = xfs_dir_ftype(fork[foff]);
                        foff += 1U;
                    }
                    uint64_t cino = i8count ? lfs_be64(fork + foff) : (uint64_t)lfs_be32(fork + foff);
                    if (ft == LEGACYFS_FT_UNKNOWN) {
                        legacyfs_attr_t ca;
                        if (xfs_getattr(fs, cino, &ca) == 0) ft = ca.ftype;
                    }
                    if (cb(user_ctx, name, cino, ft) != 0) return 0;
                    pos = foff + ino_len;
                }
                return 0;
            }
        }
        return 0;
    }

    xfs_ext_vec_t vec;
    rc = xfs_load_extents(fs, fork, fork_cap, fmt, nextents, &vec);
    if (rc != 0) return rc;

    /* XFS dir2 leaf space starts at logical offset 32 GiB (32ULL << (30 - blocklog)) */
    uint64_t leaf_off_blocks = (32ULL << 30) >> p->blocklog;
    uint8_t *blk = (uint8_t *)malloc(p->blocksize);
    if (!blk) {
        free(vec.items);
        return -ENOMEM;
    }

    for (size_t ei = 0; ei < vec.count; ei++) {
        const xfs_extent_t *ext = &vec.items[ei];
        if (ext->startoff >= leaf_off_blocks || ext->unwritten) continue;
        uint64_t count = ext->blockcount;
        if (ext->startoff + count > leaf_off_blocks) {
            count = leaf_off_blocks - ext->startoff;
        }
        for (uint64_t b = 0; b < count; b++) {
            uint64_t byte_off = xfs_fsb_to_byte(p, ext->startblock + b);
            if (byte_off == UINT64_MAX) continue;
            if (lfs_read_bytes(fs, byte_off, p->blocksize, blk) != 0) continue;

            uint32_t magic = lfs_be32(blk);
            size_t pos = 0;
            size_t end = p->blocksize;
            int single_block = 0;
            if (magic == 0x58443242U) { pos = 16U; single_block = 1; }      /* "XD2B" */
            else if (magic == 0x58444233U) { pos = 64U; single_block = 1; } /* "XDB3" */
            else if (magic == 0x58443244U) { pos = 16U; }                   /* "XD2D" */
            else if (magic == 0x58444433U) { pos = 64U; }                   /* "XDD3" */
            else continue;

            if (single_block && end >= 8U) {
                uint32_t bt_count = lfs_be32(blk + p->blocksize - 8U);
                size_t tail_bytes = 8U + (size_t)bt_count * 8U;
                if (tail_bytes < p->blocksize - pos) {
                    end = p->blocksize - tail_bytes;
                }
            }

            while (pos + 6U <= end) {
                if (lfs_be16(blk + pos) == 0xFFFFU) {
                    uint16_t flen = lfs_be16(blk + pos + 2U);
                    if (flen < 4U) break;
                    pos += flen;
                    continue;
                }
                if (pos + 11U > end) break;
                uint64_t cino = lfs_be64(blk + pos);
                uint8_t namelen = blk[pos + 8U];
                if (namelen == 0) break;
                size_t raw_len = 8U + 1U + (size_t)namelen + (p->has_ftype ? 1U : 0U) + 2U;
                size_t ent_len = (raw_len + 7U) & ~(size_t)7U;
                if (pos + ent_len > end) break;

                char name[256];
                memcpy(name, blk + pos + 9U, namelen);
                name[namelen] = '\0';
                legacyfs_ftype_t ft = p->has_ftype ? xfs_dir_ftype(blk[pos + 9U + namelen]) : LEGACYFS_FT_UNKNOWN;
                if (ft == LEGACYFS_FT_UNKNOWN) {
                    legacyfs_attr_t ca;
                    if (xfs_getattr(fs, cino, &ca) == 0) ft = ca.ftype;
                }
                if (cb(user_ctx, name, cino, ft) != 0) {
                    free(blk);
                    free(vec.items);
                    return 0;
                }
                pos += ent_len;
            }
        }
    }

    free(blk);
    free(vec.items);
    return 0;
}

typedef struct {
    const char *target;
    uint64_t found_ino;
    int found;
} xfs_lookup_ctx_t;

static int xfs_lookup_cb(void *user_ctx, const char *name, uint64_t ino, legacyfs_ftype_t ftype) {
    (void)ftype;
    xfs_lookup_ctx_t *ctx = (xfs_lookup_ctx_t *)user_ctx;
    if (strcmp(name, ctx->target) == 0) {
        ctx->found_ino = ino;
        ctx->found = 1;
        return 1;
    }
    return 0;
}

static int xfs_lookup(legacyfs_t *fs, uint64_t dir_ino, const char *name, uint64_t *out_ino) {
    xfs_lookup_ctx_t ctx = { name, 0, 0 };
    int rc = xfs_readdir(fs, dir_ino, xfs_lookup_cb, &ctx);
    if (rc != 0) return rc;
    if (!ctx.found) return -ENOENT;
    *out_ino = ctx.found_ino;
    return 0;
}

static int xfs_read_data_fork(
    legacyfs_t *fs,
    uint64_t ino,
    uint16_t expected_ifmt,
    uint64_t offset,
    size_t length,
    void *buffer,
    size_t *out_read
) {
    const xfs_priv_t *p = (const xfs_priv_t *)fs->priv;
    uint8_t di[2048];
    size_t fork_off = 0, fork_cap = 0;
    uint8_t fmt = 0;
    uint64_t nextents = 0;
    int rc = xfs_load_dinode(fs, ino, di, sizeof(di), &fork_off, &fork_cap, &fmt, &nextents);
    if (rc != 0) return rc;
    if ((lfs_be16(di + 2) & S_IFMT) != expected_ifmt) {
        return (expected_ifmt == S_IFLNK) ? -EINVAL : -EISDIR;
    }

    uint64_t fsize = lfs_be64(di + 56);
    if (offset >= fsize || length == 0) {
        *out_read = 0;
        return 0;
    }
    size_t to_read = (fsize - offset < (uint64_t)length) ? (size_t)(fsize - offset) : length;
    const uint8_t *fork = di + fork_off;

    if (fmt == XFS_DFORK_LOCAL) {
        if (offset + to_read > fork_cap) return -EIO;
        memcpy(buffer, fork + offset, to_read);
        *out_read = to_read;
        return 0;
    }

    xfs_ext_vec_t vec;
    rc = xfs_load_extents(fs, fork, fork_cap, fmt, nextents, &vec);
    if (rc != 0) return rc;

    uint8_t *dst = (uint8_t *)buffer;
    memset(dst, 0, to_read);
    size_t done = 0;

    while (done < to_read) {
        uint64_t cur = offset + done;
        uint64_t lblk = cur >> p->blocklog;
        uint32_t boff = (uint32_t)(cur & (p->blocksize - 1U));
        size_t chunk = p->blocksize - boff;
        if (chunk > to_read - done) chunk = to_read - done;

        const xfs_extent_t *hit = NULL;
        for (size_t i = 0; i < vec.count; i++) {
            if (lblk >= vec.items[i].startoff &&
                lblk < vec.items[i].startoff + vec.items[i].blockcount) {
                hit = &vec.items[i];
                break;
            }
        }

        if (hit && !hit->unwritten) {
            uint64_t fsb = hit->startblock + (lblk - hit->startoff);
            uint64_t disk_off = xfs_fsb_to_byte(p, fsb);
            if (disk_off == UINT64_MAX) {
                free(vec.items);
                return -EIO;
            }
            rc = lfs_read_bytes(fs, disk_off + boff, chunk, dst + done);
            if (rc != 0) {
                free(vec.items);
                return rc;
            }
        }
        done += chunk;
    }

    free(vec.items);
    *out_read = to_read;
    return 0;
}

static int xfs_read(legacyfs_t *fs, uint64_t ino, uint64_t offset, size_t length, void *buffer, size_t *out_read) {
    return xfs_read_data_fork(fs, ino, S_IFREG, offset, length, buffer, out_read);
}

static int xfs_readlink(legacyfs_t *fs, uint64_t ino, char *buffer, size_t buffer_size, size_t *out_len) {
    if (buffer_size == 0) return -EINVAL;
    uint8_t tmp[4096];
    size_t got = 0;
    /* XFS remote symlink blocks may carry a 56-byte XSLM v5 header */
    int rc = xfs_read_data_fork(fs, ino, S_IFLNK, 0, sizeof(tmp), tmp, &got);
    if (rc != 0) return rc;

    const uint8_t *src = tmp;
    if (got > 56U && lfs_be32(tmp) == 0x58534C4DU) { /* "XSLM" */
        src = tmp + 56U;
        got -= 56U;
    }
    size_t copy = (got < buffer_size - 1U) ? got : (buffer_size - 1U);
    memcpy(buffer, src, copy);
    buffer[copy] = '\0';
    if (out_len) *out_len = copy;
    return 0;
}

const legacyfs_ops_t lfs_xfs_ops = {
    .mount    = xfs_mount,
    .unmount  = xfs_unmount,
    .root_ino = xfs_root_ino,
    .statfs   = xfs_statfs,
    .getattr  = xfs_getattr,
    .readdir  = xfs_readdir,
    .lookup   = xfs_lookup,
    .read     = xfs_read,
    .readlink = xfs_readlink,
};
