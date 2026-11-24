#include "internal.h"
#include <stdio.h>
#include <zlib.h>

/*
 * Read-only Btrfs driver for legacyfs.
 * Parses sys_chunk_array + CHUNK_TREE logical-to-physical mappings,
 * ROOT_TREE -> FS_TREE lookup, multi-level B-trees, INODE_ITEM, DIR_INDEX / DIR_ITEM,
 * inline + regular extents, symlinks, and transparent zlib decompression.
 */

#define BTRFS_SUPER_OFFSET          65536ULL
#define BTRFS_HEADER_SIZE           101U

#define BTRFS_INODE_ITEM_KEY        1U
#define BTRFS_DIR_ITEM_KEY          84U
#define BTRFS_DIR_INDEX_KEY         96U
#define BTRFS_EXTENT_DATA_KEY       108U
#define BTRFS_ROOT_ITEM_KEY         132U
#define BTRFS_CHUNK_ITEM_KEY        228U

#define BTRFS_FS_TREE_OBJECTID      5ULL
#define BTRFS_FIRST_FREE_OBJECTID   256ULL

typedef struct {
    uint64_t logical;
    uint64_t length;
    uint64_t physical;
} btrfs_chunk_map_t;

typedef struct {
    uint32_t sectorsize;
    uint32_t nodesize;
    uint64_t total_bytes;
    uint64_t bytes_used;
    uint64_t tree_root_logical;
    uint64_t fs_root_logical;
    uint64_t root_dir_oid;
    btrfs_chunk_map_t *chunks;
    size_t chunk_count;
    size_t chunk_cap;
} btrfs_priv_t;

typedef struct {
    uint64_t objectid;
    uint8_t  type;
    uint64_t offset;
} btrfs_key_t;

static int btrfs_key_cmp(const btrfs_key_t *a, const btrfs_key_t *b) {
    if (a->objectid != b->objectid) return (a->objectid < b->objectid) ? -1 : 1;
    if (a->type != b->type) return (a->type < b->type) ? -1 : 1;
    if (a->offset != b->offset) return (a->offset < b->offset) ? -1 : 1;
    return 0;
}

static void btrfs_parse_key(const uint8_t p[17], btrfs_key_t *out) {
    out->objectid = lfs_le64(p + 0);
    out->type = p[8];
    out->offset = lfs_le64(p + 9);
}

static int btrfs_add_chunk(btrfs_priv_t *p, uint64_t logical, uint64_t length, uint64_t physical) {
    if (length == 0 || p->chunk_count >= 16384U) return 0;
    for (size_t i = 0; i < p->chunk_count; i++) {
        if (p->chunks[i].logical == logical) return 0;
    }
    if (p->chunk_count == p->chunk_cap) {
        size_t ncap = p->chunk_cap ? p->chunk_cap * 2U : 16U;
        btrfs_chunk_map_t *nc = (btrfs_chunk_map_t *)realloc(p->chunks, ncap * sizeof(btrfs_chunk_map_t));
        if (!nc) return -ENOMEM;
        p->chunks = nc;
        p->chunk_cap = ncap;
    }
    p->chunks[p->chunk_count].logical = logical;
    p->chunks[p->chunk_count].length = length;
    p->chunks[p->chunk_count].physical = physical;
    p->chunk_count++;
    return 0;
}

static int btrfs_map_logical(const btrfs_priv_t *p, uint64_t logical, uint64_t *out_phys, uint64_t *out_avail) {
    for (size_t i = 0; i < p->chunk_count; i++) {
        uint64_t start = p->chunks[i].logical;
        uint64_t len = p->chunks[i].length;
        if (logical >= start && logical < start + len) {
            uint64_t delta = logical - start;
            *out_phys = p->chunks[i].physical + delta;
            if (out_avail) *out_avail = len - delta;
            return 0;
        }
    }
    /* Single-device fallback when logical == physical */
    if (p->chunk_count == 0) {
        *out_phys = logical;
        if (out_avail) *out_avail = UINT64_MAX;
        return 0;
    }
    return -EIO;
}

static int btrfs_read_logical(const legacyfs_t *fs, uint64_t logical, size_t len, void *buf) {
    const btrfs_priv_t *p = (const btrfs_priv_t *)fs->priv;
    uint8_t *dst = (uint8_t *)buf;
    size_t done = 0;
    while (done < len) {
        uint64_t phys = 0, avail = 0;
        int rc = btrfs_map_logical(p, logical + done, &phys, &avail);
        if (rc != 0) return rc;
        size_t step = (avail < (uint64_t)(len - done)) ? (size_t)avail : (len - done);
        if (step == 0) return -EIO;
        rc = lfs_read_bytes(fs, phys, step, dst + done);
        if (rc != 0) return rc;
        done += step;
    }
    return 0;
}

typedef int (*btrfs_item_cb)(
    legacyfs_t *fs,
    const btrfs_key_t *key,
    const uint8_t *data,
    uint32_t data_len,
    void *ctx
);

static int btrfs_walk_range(
    legacyfs_t *fs,
    uint64_t node_logical,
    int depth,
    const btrfs_key_t *min_key,
    const btrfs_key_t *max_key,
    btrfs_item_cb cb,
    void *ctx
) {
    if (depth > 8 || node_logical == 0) return -EIO;
    const btrfs_priv_t *p = (const btrfs_priv_t *)fs->priv;
    uint8_t *node = (uint8_t *)malloc(p->nodesize);
    if (!node) return -ENOMEM;

    int rc = btrfs_read_logical(fs, node_logical, p->nodesize, node);
    if (rc != 0) {
        free(node);
        return rc;
    }

    uint32_t nritems = lfs_le32(node + 96);
    uint8_t level = node[100];
    if (level > 7) {
        free(node);
        return -EIO;
    }

    if (level == 0) {
        size_t max_items = (p->nodesize - BTRFS_HEADER_SIZE) / 25U;
        if (nritems > max_items) {
            free(node);
            return -EIO;
        }
        size_t data_Limit = p->nodesize - BTRFS_HEADER_SIZE;
        for (uint32_t i = 0; i < nritems; i++) {
            const uint8_t *it = node + BTRFS_HEADER_SIZE + (size_t)i * 25U;
            btrfs_key_t k;
            btrfs_parse_key(it, &k);
            if (btrfs_key_cmp(&k, min_key) < 0) continue;
            if (btrfs_key_cmp(&k, max_key) > 0) break;

            uint32_t data_off = lfs_le32(it + 17);
            uint32_t data_sz = lfs_le32(it + 21);
            if (data_off > data_Limit || data_Limit - data_off < data_sz) {
                free(node);
                return -EIO;
            }
            int stop = cb(fs, &k, node + BTRFS_HEADER_SIZE + data_off, data_sz, ctx);
            if (stop != 0) {
                free(node);
                return stop;
            }
        }
        free(node);
        return 0;
    }

    size_t max_ptrs = (p->nodesize - BTRFS_HEADER_SIZE) / 33U;
    if (nritems > max_ptrs) {
        free(node);
        return -EIO;
    }

    for (uint32_t i = 0; i < nritems; i++) {
        const uint8_t *kp = node + BTRFS_HEADER_SIZE + (size_t)i * 33U;
        btrfs_key_t k;
        btrfs_parse_key(kp, &k);
        if (btrfs_key_cmp(&k, max_key) > 0) break;

        if (i + 1U < nritems) {
            btrfs_key_t next_k;
            btrfs_parse_key(kp + 33U, &next_k);
            if (btrfs_key_cmp(&next_k, min_key) < 0) continue;
        }

        uint64_t child_logical = lfs_le64(kp + 17);
        rc = btrfs_walk_range(fs, child_logical, depth + 1, min_key, max_key, cb, ctx);
        if (rc != 0) {
            free(node);
            return rc;
        }
    }

    free(node);
    return 0;
}

static int btrfs_chunk_item_cb(
    legacyfs_t *fs,
    const btrfs_key_t *key,
    const uint8_t *data,
    uint32_t data_len,
    void *ctx
) {
    (void)ctx;
    btrfs_priv_t *p = (btrfs_priv_t *)fs->priv;
    if (key->type != BTRFS_CHUNK_ITEM_KEY || data_len < 80U) return 0;
    uint64_t length = lfs_le64(data + 0);
    uint16_t num_stripes = lfs_le16(data + 44);
    if (num_stripes == 0) return 0;
    uint64_t phys0 = lfs_le64(data + 48U + 8U);
    (void)btrfs_add_chunk(p, key->offset, length, phys0);
    return 0;
}

static int btrfs_root_item_cb(
    legacyfs_t *fs,
    const btrfs_key_t *key,
    const uint8_t *data,
    uint32_t data_len,
    void *ctx
) {
    (void)fs;
    uint64_t *out_bytenr = (uint64_t *)ctx;
    if (key->type == BTRFS_ROOT_ITEM_KEY && data_len >= 184U) {
        /* In struct btrfs_root_item: inode(160B) + generation(8B) + root_dirid(8B) -> bytenr at +176 */
        *out_bytenr = lfs_le64(data + 176U);
        return 1;
    }
    return 0;
}

static int btrfs_mount(legacyfs_t *fs) {
    uint8_t sb[4096];
    int rc = lfs_read_bytes(fs, BTRFS_SUPER_OFFSET, sizeof(sb), sb);
    if (rc != 0) return rc;
    if (memcmp(sb + 64, "_BHRfS_M", 8) != 0) return -EINVAL;

    uint32_t sectorsize = lfs_le32(sb + 144);
    uint32_t nodesize = lfs_le32(sb + 148);
    if (sectorsize < 512U || sectorsize > 65536U || !lfs_is_pow2_u32(sectorsize)) return -EINVAL;
    if (nodesize < 4096U || nodesize > 65536U || !lfs_is_pow2_u32(nodesize)) return -EINVAL;

    btrfs_priv_t *p = (btrfs_priv_t *)calloc(1, sizeof(btrfs_priv_t));
    if (!p) return -ENOMEM;
    fs->priv = p;

    p->sectorsize = sectorsize;
    p->nodesize = nodesize;
    p->total_bytes = lfs_le64(sb + 112);
    p->bytes_used = lfs_le64(sb + 120);
    p->tree_root_logical = lfs_le64(sb + 80);
    uint64_t chunk_root_logical = lfs_le64(sb + 88);
    uint64_t root_dir_oid = lfs_le64(sb + 128);
    p->root_dir_oid = (root_dir_oid >= 256ULL) ? root_dir_oid : BTRFS_FIRST_FREE_OBJECTID;

    /* 1. Bootstrap sys_chunk_array at offset +811 (0x32B) */
    uint32_t sys_arr_sz = lfs_le32(sb + 160);
    if (sys_arr_sz > 2048U) sys_arr_sz = 2048U;
    size_t pos = 0;
    const uint8_t *sys_arr = sb + 811U;
    while (pos + 17U + 80U <= sys_arr_sz) {
        btrfs_key_t ck;
        btrfs_parse_key(sys_arr + pos, &ck);
        const uint8_t *ch = sys_arr + pos + 17U;
        uint64_t clen = lfs_le64(ch + 0);
        uint16_t nstripes = lfs_le16(ch + 44U);
        if (nstripes == 0) break;
        size_t item_len = 48U + (size_t)nstripes * 32U;
        if (pos + 17U + item_len > sys_arr_sz) break;
        if (ck.type == BTRFS_CHUNK_ITEM_KEY) {
            uint64_t phys0 = lfs_le64(ch + 48U + 8U);
            (void)btrfs_add_chunk(p, ck.offset, clen, phys0);
        }
        pos += 17U + item_len;
    }

    /* 2. Walk CHUNK_TREE to discover all data and metadata chunks */
    if (chunk_root_logical != 0) {
        btrfs_key_t cmin = { 0, BTRFS_CHUNK_ITEM_KEY, 0 };
        btrfs_key_t cmax = { UINT64_MAX, BTRFS_CHUNK_ITEM_KEY, UINT64_MAX };
        (void)btrfs_walk_range(fs, chunk_root_logical, 0, &cmin, &cmax, btrfs_chunk_item_cb, NULL);
    }

    /* 3. Resolve FS_TREE (objectid = 5) from ROOT_TREE, or fall back directly to tree_root_logical */
    uint64_t fs_root = 0;
    if (p->tree_root_logical != 0) {
        btrfs_key_t rmin = { BTRFS_FS_TREE_OBJECTID, BTRFS_ROOT_ITEM_KEY, 0 };
        btrfs_key_t rmax = { BTRFS_FS_TREE_OBJECTID, BTRFS_ROOT_ITEM_KEY, UINT64_MAX };
        (void)btrfs_walk_range(fs, p->tree_root_logical, 0, &rmin, &rmax, btrfs_root_item_cb, &fs_root);
    }
    p->fs_root_logical = (fs_root != 0) ? fs_root : p->tree_root_logical;
    if (p->fs_root_logical == 0) {
        free(p->chunks);
        free(p);
        fs->priv = NULL;
        return -EINVAL;
    }

    return 0;
}

static void btrfs_unmount(legacyfs_t *fs) {
    btrfs_priv_t *p = (btrfs_priv_t *)fs->priv;
    if (p) {
        free(p->chunks);
        free(p);
        fs->priv = NULL;
    }
}

static uint64_t btrfs_root_ino(const legacyfs_t *fs) {
    const btrfs_priv_t *p = (const btrfs_priv_t *)fs->priv;
    return p ? p->root_dir_oid : BTRFS_FIRST_FREE_OBJECTID;
}

static int btrfs_statfs(legacyfs_t *fs, legacyfs_statfs_t *out) {
    const btrfs_priv_t *p = (const btrfs_priv_t *)fs->priv;
    memset(out, 0, sizeof(*out));
    out->block_size = p->sectorsize;
    out->total_blocks = p->total_bytes / p->sectorsize;
    out->free_blocks = (p->total_bytes > p->bytes_used) ? ((p->total_bytes - p->bytes_used) / p->sectorsize) : 0;
    out->namemax = 255;
    return 0;
}

typedef struct {
    legacyfs_attr_t *out;
    int found;
} btrfs_getattr_ctx_t;

static int btrfs_inode_cb(
    legacyfs_t *fs,
    const btrfs_key_t *key,
    const uint8_t *data,
    uint32_t data_len,
    void *ctx
) {
    (void)fs;
    btrfs_getattr_ctx_t *g = (btrfs_getattr_ctx_t *)ctx;
    if (key->type != BTRFS_INODE_ITEM_KEY || data_len < 160U) return 0;

    legacyfs_attr_t *out = g->out;
    memset(out, 0, sizeof(*out));
    out->ino = key->objectid;
    out->size = lfs_le64(data + 16U);
    out->blocks_512 = lfs_le64(data + 24U) / 512ULL;
    out->nlink = lfs_le32(data + 40U);
    out->uid = lfs_le32(data + 44U);
    out->gid = lfs_le32(data + 48U);
    out->mode = lfs_le32(data + 52U);
    out->ftype = lfs_mode_to_ftype(out->mode);
    out->atime_sec = (int64_t)lfs_le64(data + 112U);
    out->ctime_sec = (int64_t)lfs_le64(data + 124U);
    out->mtime_sec = (int64_t)lfs_le64(data + 136U);
    g->found = 1;
    return 1;
}

static int btrfs_getattr(legacyfs_t *fs, uint64_t ino, legacyfs_attr_t *out) {
    const btrfs_priv_t *p = (const btrfs_priv_t *)fs->priv;
    btrfs_key_t kmin = { ino, BTRFS_INODE_ITEM_KEY, 0 };
    btrfs_key_t kmax = { ino, BTRFS_INODE_ITEM_KEY, UINT64_MAX };
    btrfs_getattr_ctx_t g = { out, 0 };
    (void)btrfs_walk_range(fs, p->fs_root_logical, 0, &kmin, &kmax, btrfs_inode_cb, &g);
    return g.found ? 0 : -ENOENT;
}

static legacyfs_ftype_t btrfs_dir_type_to_ftype(uint8_t dt) {
    switch (dt) {
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

typedef struct {
    legacyfs_readdir_cb cb;
    void *user_ctx;
    int emitted_any;
} btrfs_dir_ctx_t;

static int btrfs_dir_index_cb(
    legacyfs_t *fs,
    const btrfs_key_t *key,
    const uint8_t *data,
    uint32_t data_len,
    void *ctx
) {
    (void)fs;
    btrfs_dir_ctx_t *d = (btrfs_dir_ctx_t *)ctx;
    if ((key->type != BTRFS_DIR_INDEX_KEY && key->type != BTRFS_DIR_ITEM_KEY) || data_len < 30U) return 0;

    uint32_t pos = 0;
    while (pos + 30U <= data_len) {
        btrfs_key_t loc;
        btrfs_parse_key(data + pos, &loc);
        uint16_t xdata_len = lfs_le16(data + pos + 25U);
        uint16_t name_len = lfs_le16(data + pos + 27U);
        uint8_t dtype = data[pos + 29U];
        uint32_t rec_sz = 30U + (uint32_t)name_len + (uint32_t)xdata_len;
        if (name_len == 0 || name_len > 255U || pos + rec_sz > data_len) break;

        char name[256];
        memcpy(name, data + pos + 30U, name_len);
        name[name_len] = '\0';

        /* Only visit actual INODE_ITEM children inside this FS_TREE */
        if (loc.type == BTRFS_INODE_ITEM_KEY) {
            d->emitted_any = 1;
            if (d->cb(d->user_ctx, name, loc.objectid, btrfs_dir_type_to_ftype(dtype)) != 0) {
                return 1;
            }
        }
        pos += rec_sz;
    }
    return 0;
}

static int btrfs_readdir(legacyfs_t *fs, uint64_t dir_ino, legacyfs_readdir_cb cb, void *user_ctx) {
    const btrfs_priv_t *p = (const btrfs_priv_t *)fs->priv;
    legacyfs_attr_t attr;
    int rc = btrfs_getattr(fs, dir_ino, &attr);
    if (rc != 0) return rc;
    if (attr.ftype != LEGACYFS_FT_DIR) return -ENOTDIR;

    if (cb(user_ctx, ".", dir_ino, LEGACYFS_FT_DIR) != 0) return 0;
    if (cb(user_ctx, "..", p->root_dir_oid, LEGACYFS_FT_DIR) != 0) return 0;

    btrfs_dir_ctx_t dctx = { cb, user_ctx, 0 };
    btrfs_key_t imin = { dir_ino, BTRFS_DIR_INDEX_KEY, 0 };
    btrfs_key_t imax = { dir_ino, BTRFS_DIR_INDEX_KEY, UINT64_MAX };
    (void)btrfs_walk_range(fs, p->fs_root_logical, 0, &imin, &imax, btrfs_dir_index_cb, &dctx);

    if (!dctx.emitted_any) {
        btrfs_key_t dmin = { dir_ino, BTRFS_DIR_ITEM_KEY, 0 };
        btrfs_key_t dmax = { dir_ino, BTRFS_DIR_ITEM_KEY, UINT64_MAX };
        (void)btrfs_walk_range(fs, p->fs_root_logical, 0, &dmin, &dmax, btrfs_dir_index_cb, &dctx);
    }
    return 0;
}

typedef struct {
    const char *target;
    uint64_t found_ino;
    int found;
} btrfs_lookup_ctx_t;

static int btrfs_lookup_cb(void *user_ctx, const char *name, uint64_t ino, legacyfs_ftype_t ftype) {
    (void)ftype;
    btrfs_lookup_ctx_t *ctx = (btrfs_lookup_ctx_t *)user_ctx;
    if (strcmp(name, ctx->target) == 0) {
        ctx->found_ino = ino;
        ctx->found = 1;
        return 1;
    }
    return 0;
}

static int btrfs_lookup(legacyfs_t *fs, uint64_t dir_ino, const char *name, uint64_t *out_ino) {
    btrfs_lookup_ctx_t ctx = { name, 0, 0 };
    int rc = btrfs_readdir(fs, dir_ino, btrfs_lookup_cb, &ctx);
    if (rc != 0) return rc;
    if (!ctx.found) return -ENOENT;
    *out_ino = ctx.found_ino;
    return 0;
}

typedef struct {
    uint64_t req_off;
    size_t req_len;
    uint8_t *dst;
    int err;
} btrfs_read_ctx_t;

static int btrfs_extent_cb(
    legacyfs_t *fs,
    const btrfs_key_t *key,
    const uint8_t *data,
    uint32_t data_len,
    void *ctx
) {
    btrfs_read_ctx_t *r = (btrfs_read_ctx_t *)ctx;
    if (key->type != BTRFS_EXTENT_DATA_KEY || data_len < 21U) return 0;

    uint64_t ext_file_off = key->offset;
    uint64_t ram_bytes = lfs_le64(data + 8U);
    uint8_t comp = data[16U];
    uint8_t etype = data[20U];
    uint64_t req_end = r->req_off + r->req_len;

    if (etype == 0) { /* INLINE */
        uint32_t inline_sz = data_len - 21U;
        uint64_t ext_len = (comp == 0) ? inline_sz : ram_bytes;
        if (ext_len > (1ULL << 20)) return 0;
        if (ext_file_off >= req_end || ext_file_off + ext_len <= r->req_off) return 0;

        uint8_t *plain = NULL;
        const uint8_t *src = data + 21U;
        if (comp == 1) { /* ZLIB */
            plain = (uint8_t *)malloc((size_t)ext_len);
            if (!plain) { r->err = -ENOMEM; return 1; }
            uLongf dlen = (uLongf)ext_len;
            if (uncompress(plain, &dlen, src, inline_sz) != Z_OK) {
                free(plain);
                r->err = -EIO;
                return 1;
            }
            src = plain;
            ext_len = dlen;
        } else if (comp != 0) {
            r->err = -ENOTSUP;
            return 1;
        }

        uint64_t ov_start = (r->req_off > ext_file_off) ? r->req_off : ext_file_off;
        uint64_t ov_end = (req_end < ext_file_off + ext_len) ? req_end : (ext_file_off + ext_len);
        if (ov_end > ov_start) {
            memcpy(r->dst + (ov_start - r->req_off), src + (ov_start - ext_file_off), (size_t)(ov_end - ov_start));
        }
        free(plain);
        return 0;
    }

    if ((etype != 1 && etype != 2) || data_len < 53U) return 0;
    uint64_t disk_bytenr = lfs_le64(data + 21U);
    uint64_t disk_num_bytes = lfs_le64(data + 29U);
    uint64_t inner_off = lfs_le64(data + 37U);
    uint64_t num_bytes = lfs_le64(data + 45U);

    if (ext_file_off >= req_end || ext_file_off + num_bytes <= r->req_off) return 0;
    if (disk_bytenr == 0 || etype == 2) {
        /* Sparse hole or unwritten prealloc extent */
        return 0;
    }

    uint64_t ov_start = (r->req_off > ext_file_off) ? r->req_off : ext_file_off;
    uint64_t ov_end = (req_end < ext_file_off + num_bytes) ? req_end : (ext_file_off + num_bytes);
    size_t copy_len = (size_t)(ov_end - ov_start);

    if (comp == 0) {
        uint64_t logical_pos = disk_bytenr + inner_off + (ov_start - ext_file_off);
        int rc = btrfs_read_logical(fs, logical_pos, copy_len, r->dst + (ov_start - r->req_off));
        if (rc != 0) {
            r->err = rc;
            return 1;
        }
        return 0;
    }

    if (comp == 1) { /* ZLIB regular extent */
        if (disk_num_bytes == 0 || disk_num_bytes > (4ULL << 20) || ram_bytes > (16ULL << 20)) {
            r->err = -EIO;
            return 1;
        }
        uint8_t *cbuf = (uint8_t *)malloc((size_t)disk_num_bytes);
        uint8_t *ubuf = (uint8_t *)malloc((size_t)ram_bytes);
        if (!cbuf || !ubuf) {
            free(cbuf);
            free(ubuf);
            r->err = -ENOMEM;
            return 1;
        }
        int rc = btrfs_read_logical(fs, disk_bytenr, (size_t)disk_num_bytes, cbuf);
        if (rc == 0) {
            uLongf dlen = (uLongf)ram_bytes;
            if (uncompress(ubuf, &dlen, cbuf, (uLong)disk_num_bytes) == Z_OK &&
                inner_off + (ov_start - ext_file_off) + copy_len <= dlen) {
                memcpy(r->dst + (ov_start - r->req_off),
                       ubuf + inner_off + (ov_start - ext_file_off),
                       copy_len);
            } else {
                r->err = -EIO;
            }
        } else {
            r->err = rc;
        }
        free(cbuf);
        free(ubuf);
        return (r->err != 0) ? 1 : 0;
    }

    r->err = -ENOTSUP;
    return 1;
}

static int btrfs_read_extents(
    legacyfs_t *fs,
    uint64_t ino,
    legacyfs_ftype_t expected_ft,
    uint64_t offset,
    size_t length,
    void *buffer,
    size_t *out_read
) {
    const btrfs_priv_t *p = (const btrfs_priv_t *)fs->priv;
    legacyfs_attr_t attr;
    int rc = btrfs_getattr(fs, ino, &attr);
    if (rc != 0) return rc;
    if (attr.ftype != expected_ft) {
        return (expected_ft == LEGACYFS_FT_SYMLINK) ? -EINVAL : -EISDIR;
    }
    if (offset >= attr.size || length == 0) {
        *out_read = 0;
        return 0;
    }

    size_t to_read = (attr.size - offset < (uint64_t)length) ? (size_t)(attr.size - offset) : length;
    memset(buffer, 0, to_read);

    btrfs_read_ctx_t rctx = { offset, to_read, (uint8_t *)buffer, 0 };
    btrfs_key_t emin = { ino, BTRFS_EXTENT_DATA_KEY, 0 };
    btrfs_key_t emax = { ino, BTRFS_EXTENT_DATA_KEY, offset + to_read };
    (void)btrfs_walk_range(fs, p->fs_root_logical, 0, &emin, &emax, btrfs_extent_cb, &rctx);
    if (rctx.err != 0) return rctx.err;

    *out_read = to_read;
    return 0;
}

static int btrfs_read(legacyfs_t *fs, uint64_t ino, uint64_t offset, size_t length, void *buffer, size_t *out_read) {
    return btrfs_read_extents(fs, ino, LEGACYFS_FT_REG, offset, length, buffer, out_read);
}

static int btrfs_readlink(legacyfs_t *fs, uint64_t ino, char *buffer, size_t buffer_size, size_t *out_len) {
    if (buffer_size == 0) return -EINVAL;
    size_t got = 0;
    int rc = btrfs_read_extents(fs, ino, LEGACYFS_FT_SYMLINK, 0, buffer_size - 1U, buffer, &got);
    if (rc != 0) return rc;
    buffer[got] = '\0';
    if (out_len) *out_len = got;
    return 0;
}

const legacyfs_ops_t lfs_btrfs_ops = {
    .mount    = btrfs_mount,
    .unmount  = btrfs_unmount,
    .root_ino = btrfs_root_ino,
    .statfs   = btrfs_statfs,
    .getattr  = btrfs_getattr,
    .readdir  = btrfs_readdir,
    .lookup   = btrfs_lookup,
    .read     = btrfs_read,
    .readlink = btrfs_readlink,
};
