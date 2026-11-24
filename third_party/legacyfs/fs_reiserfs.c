#include "internal.h"

#define RFS_ROOT_PARENT_ID 1U
#define RFS_ROOT_OBJECT_ID 2U

#define RFS_TYPE_STAT_DATA 0
#define RFS_TYPE_INDIRECT  1
#define RFS_TYPE_DIRECT    2
#define RFS_TYPE_DIRENTRY  3
#define RFS_TYPE_ANY       15

#define RFS_DEH_VISIBLE    0x0004U

typedef struct {
    uint64_t sb_offset;
    uint32_t block_count;
    uint32_t free_blocks;
    uint32_t root_block;
    uint16_t block_size;
    uint16_t tree_height;
    int is_v36;
} rfs_priv_t;

typedef struct {
    uint32_t dir_id;
    uint32_t object_id;
    uint64_t offset;
    int type;
} rfs_key_t;

static uint64_t rfs_pack_ino(uint32_t dir_id, uint32_t obj_id) {
    return ((uint64_t)dir_id << 32) | (uint64_t)obj_id;
}

static void rfs_unpack_ino(uint64_t ino, uint32_t *dir_id, uint32_t *obj_id) {
    *dir_id = (uint32_t)(ino >> 32);
    *obj_id = (uint32_t)(ino & 0xFFFFFFFFU);
}

static void rfs_decode_key(const uint8_t raw[16], int hint_ver, rfs_key_t *out) {
    out->dir_id = lfs_le32(raw + 0);
    out->object_id = lfs_le32(raw + 4);
    uint64_t v64 = lfs_le64(raw + 8);
    uint32_t uniq = lfs_le32(raw + 12);

    int use_v2 = 0;
    if (hint_ver == 1) {
        use_v2 = 1;
    } else if (hint_ver == 0) {
        use_v2 = 0;
    } else {
        uint32_t top4 = (uint32_t)(v64 >> 60);
        if (top4 == 1 || top4 == 2 || top4 == 3) {
            use_v2 = 1;
        } else if (uniq == 0 && lfs_le32(raw + 8) == 0) {
            use_v2 = 1;
        }
    }

    if (use_v2) {
        out->offset = v64 & 0x0FFFFFFFFFFFFFFFULL;
        out->type = (int)(v64 >> 60);
    } else {
        out->offset = lfs_le32(raw + 8);
        if (uniq == 0U) out->type = RFS_TYPE_STAT_DATA;
        else if (uniq == 500U) out->type = RFS_TYPE_DIRENTRY;
        else if (uniq == 0xFFFFFFFFU) out->type = RFS_TYPE_DIRECT;
        else if (uniq == 0xFFFFFFFEU) out->type = RFS_TYPE_INDIRECT;
        else out->type = RFS_TYPE_DIRENTRY;
    }
}

static int rfs_cmp_obj(uint32_t d1, uint32_t o1, uint32_t d2, uint32_t o2) {
    if (d1 != d2) return d1 < d2 ? -1 : 1;
    if (o1 != o2) return o1 < o2 ? -1 : 1;
    return 0;
}

typedef int (*rfs_item_visitor_fn)(
    legacyfs_t *fs,
    const rfs_key_t *key,
    uint16_t entry_count,
    uint16_t item_ver,
    const uint8_t *body,
    uint16_t body_len,
    void *ctx
);

static int rfs_visit_object_node(
    legacyfs_t *fs,
    uint32_t block_nr,
    uint32_t target_dir_id,
    uint32_t target_obj_id,
    int depth,
    rfs_item_visitor_fn visitor,
    void *vctx
) {
    const rfs_priv_t *p = (const rfs_priv_t *)fs->priv;
    if (depth > 8 || block_nr == 0 || block_nr >= p->block_count) {
        return -EIO;
    }

    uint8_t *blk = (uint8_t *)malloc(p->block_size);
    if (!blk) return -ENOMEM;

    int rc = lfs_read_bytes(fs, (uint64_t)block_nr * (uint64_t)p->block_size, p->block_size, blk);
    if (rc != 0) {
        free(blk);
        return rc;
    }

    uint16_t level = lfs_le16(blk + 0);
    uint16_t nr_item = lfs_le16(blk + 2);

    if (level == 1) {
        /* Leaf node */
        if (24U + (uint32_t)nr_item * 24U > p->block_size) {
            free(blk);
            return -EIO;
        }
        for (uint16_t i = 0; i < nr_item; i++) {
            const uint8_t *ih = blk + 24U + (size_t)i * 24U;
            uint16_t ec = lfs_le16(ih + 16);
            uint16_t ilen = lfs_le16(ih + 18);
            uint16_t iloc = lfs_le16(ih + 20);
            uint16_t iver = lfs_le16(ih + 22);
            if ((uint32_t)iloc + (uint32_t)ilen > p->block_size) {
                continue;
            }
            rfs_key_t k;
            rfs_decode_key(ih, iver <= 1 ? (int)iver : -1, &k);
            int cmp = rfs_cmp_obj(k.dir_id, k.object_id, target_dir_id, target_obj_id);
            if (cmp < 0) continue;
            if (cmp > 0) break;
            int stop = visitor(fs, &k, ec, iver, blk + iloc, ilen, vctx);
            if (stop != 0) {
                free(blk);
                return stop > 0 ? 0 : stop;
            }
        }
        free(blk);
        return 0;
    }

    if (level < 2 || level > 8) {
        free(blk);
        return -EIO;
    }

    /* Internal node: 24B header, nr_item * 16B keys, (nr_item + 1) * 8B disk_child */
    uint32_t keys_off = 24U;
    uint32_t dc_off = keys_off + (uint32_t)nr_item * 16U;
    if (dc_off + ((uint32_t)nr_item + 1U) * 8U > p->block_size) {
        free(blk);
        return -EIO;
    }

    for (uint16_t i = 0; i <= nr_item; i++) {
        /* Child i has lower bound key[i-1] and upper bound key[i]. */
        if (i < nr_item) {
            rfs_key_t right_delim;
            rfs_decode_key(blk + keys_off + (size_t)i * 16U, -1, &right_delim);
            if (rfs_cmp_obj(right_delim.dir_id, right_delim.object_id, target_dir_id, target_obj_id) < 0) {
                continue;
            }
        }
        if (i > 0) {
            rfs_key_t left_delim;
            rfs_decode_key(blk + keys_off + (size_t)(i - 1) * 16U, -1, &left_delim);
            if (rfs_cmp_obj(left_delim.dir_id, left_delim.object_id, target_dir_id, target_obj_id) > 0) {
                break;
            }
        }
        uint32_t child_blk = lfs_le32(blk + dc_off + (size_t)i * 8U);
        int sub = rfs_visit_object_node(fs, child_blk, target_dir_id, target_obj_id, depth + 1, visitor, vctx);
        if (sub != 0) {
            free(blk);
            return sub;
        }
    }

    free(blk);
    return 0;
}

static int rfs_mount(legacyfs_t *fs) {
    static const uint64_t sboffs[2] = { 65536ULL, 8192ULL };
    uint8_t sb[256];

    for (int i = 0; i < 2; i++) {
        if (lfs_read_bytes(fs, sboffs[i], sizeof(sb), sb) != 0) continue;
        int is_v36 = 0;
        if (memcmp(sb + 52, "ReIsErFs", 8) == 0) {
            is_v36 = 0;
        } else if (memcmp(sb + 52, "ReIsEr2Fs", 9) == 0 || memcmp(sb + 52, "ReIsEr3Fs", 9) == 0) {
            is_v36 = 1;
        } else {
            continue;
        }

        uint32_t blocks = lfs_le32(sb + 0);
        uint32_t free_b = lfs_le32(sb + 4);
        uint32_t root_b = lfs_le32(sb + 8);
        uint16_t height = lfs_le16(sb + 40);
        uint16_t bsize = lfs_le16(sb + 44);
        if (bsize < 512 || bsize > 8192 || !lfs_is_pow2_u32(bsize)) continue;
        if (blocks < 16 || root_b == 0 || root_b >= blocks) continue;

        rfs_priv_t *p = (rfs_priv_t *)calloc(1, sizeof(rfs_priv_t));
        if (!p) return -ENOMEM;
        p->sb_offset = sboffs[i];
        p->block_count = blocks;
        p->free_blocks = free_b;
        p->root_block = root_b;
        p->block_size = bsize;
        p->tree_height = height;
        p->is_v36 = is_v36;
        fs->priv = p;
        return 0;
    }
    return -EINVAL;
}

static void rfs_unmount(legacyfs_t *fs) {
    free(fs->priv);
    fs->priv = NULL;
}

static uint64_t rfs_root_ino(const legacyfs_t *fs) {
    (void)fs;
    return rfs_pack_ino(RFS_ROOT_PARENT_ID, RFS_ROOT_OBJECT_ID);
}

typedef struct {
    legacyfs_attr_t *out;
    uint64_t ino;
    int found;
} rfs_stat_ctx_t;

static int rfs_stat_visitor(
    legacyfs_t *fs,
    const rfs_key_t *key,
    uint16_t entry_count,
    uint16_t item_ver,
    const uint8_t *body,
    uint16_t body_len,
    void *ctx_ptr
) {
    (void)fs;
    (void)entry_count;
    if (key->type != RFS_TYPE_STAT_DATA) return 0;

    rfs_stat_ctx_t *sctx = (rfs_stat_ctx_t *)ctx_ptr;
    legacyfs_attr_t *a = sctx->out;
    a->ino = sctx->ino;

    if (item_ver == 0 && body_len >= 32) {
        a->mode = lfs_le16(body + 0);
        a->nlink = lfs_le16(body + 2);
        a->uid = lfs_le16(body + 4);
        a->gid = lfs_le16(body + 6);
        a->size = lfs_le32(body + 8);
        a->atime_sec = lfs_le32(body + 12);
        a->mtime_sec = lfs_le32(body + 16);
        a->ctime_sec = lfs_le32(body + 20);
        a->blocks_512 = (a->size + 511ULL) / 512ULL;
        a->ftype = lfs_mode_to_ftype(a->mode);
        sctx->found = 1;
        return 1;
    }
    if (body_len >= 44) {
        a->mode = lfs_le16(body + 0);
        a->nlink = lfs_le32(body + 4);
        a->size = lfs_le64(body + 8);
        a->uid = lfs_le32(body + 16);
        a->gid = lfs_le32(body + 20);
        a->ctime_sec = lfs_le32(body + 24);
        a->mtime_sec = lfs_le32(body + 28);
        a->atime_sec = lfs_le32(body + 32);
        a->blocks_512 = lfs_le32(body + 36);
        a->ftype = lfs_mode_to_ftype(a->mode);
        sctx->found = 1;
        return 1;
    }
    return 0;
}

static int rfs_getattr(legacyfs_t *fs, uint64_t ino, legacyfs_attr_t *out_attr) {
    const rfs_priv_t *p = (const rfs_priv_t *)fs->priv;
    uint32_t dir_id = 0, obj_id = 0;
    rfs_unpack_ino(ino, &dir_id, &obj_id);

    rfs_stat_ctx_t sctx = { out_attr, ino, 0 };
    int rc = rfs_visit_object_node(fs, p->root_block, dir_id, obj_id, 0, rfs_stat_visitor, &sctx);
    if (rc != 0) return rc;
    return sctx.found ? 0 : -ENOENT;
}

typedef struct {
    char name[256];
    uint64_t child_ino;
} rfs_dirent_tmp_t;

typedef struct {
    rfs_dirent_tmp_t *entries;
    size_t count;
    size_t cap;
} rfs_dir_collect_t;

static int rfs_dir_visitor(
    legacyfs_t *fs,
    const rfs_key_t *key,
    uint16_t entry_count,
    uint16_t item_ver,
    const uint8_t *body,
    uint16_t body_len,
    void *ctx_ptr
) {
    (void)fs;
    (void)item_ver;
    if (key->type != RFS_TYPE_DIRENTRY) return 0;
    if ((uint32_t)entry_count * 16U > body_len) return 0;

    rfs_dir_collect_t *dctx = (rfs_dir_collect_t *)ctx_ptr;
    for (uint16_t i = 0; i < entry_count; i++) {
        const uint8_t *deh = body + (size_t)i * 16U;
        uint32_t e_dir_id = lfs_le32(deh + 4);
        uint32_t e_obj_id = lfs_le32(deh + 8);
        uint16_t e_loc = lfs_le16(deh + 12);
        uint16_t e_state = lfs_le16(deh + 14);
        if ((e_state & RFS_DEH_VISIBLE) == 0) continue;

        uint16_t e_end = (i == 0) ? body_len : lfs_le16(body + (size_t)(i - 1) * 16U + 12U);
        if (e_loc >= body_len || e_end > body_len || e_end <= e_loc) continue;
        if (e_loc < (uint32_t)entry_count * 16U) continue;

        size_t max_nlen = (size_t)(e_end - e_loc);
        size_t nlen = 0;
        while (nlen < max_nlen && nlen < 255 && body[e_loc + nlen] != 0) {
            nlen++;
        }
        if (nlen == 0) continue;
        if ((nlen == 1 && body[e_loc] == '.') ||
            (nlen == 2 && body[e_loc] == '.' && body[e_loc + 1] == '.')) {
            continue;
        }

        if (dctx->count == dctx->cap) {
            size_t new_cap = dctx->cap ? dctx->cap * 2 : 32;
            rfs_dirent_tmp_t * grown = (rfs_dirent_tmp_t *)realloc(dctx->entries, new_cap * sizeof(rfs_dirent_tmp_t));
            if (!grown) return -ENOMEM;
            dctx->entries = grown;
            dctx->cap = new_cap;
        }
        memcpy(dctx->entries[dctx->count].name, body + e_loc, nlen);
        dctx->entries[dctx->count].name[nlen] = '\0';
        dctx->entries[dctx->count].child_ino = rfs_pack_ino(e_dir_id, e_obj_id);
        dctx->count++;
    }
    return 0;
}

static int rfs_readdir(legacyfs_t *fs, uint64_t dir_ino, legacyfs_readdir_cb cb, void *user_ctx) {
    legacyfs_attr_t dir_attr;
    int arc = rfs_getattr(fs, dir_ino, &dir_attr);
    if (arc != 0) return arc;
    if (dir_attr.ftype != LEGACYFS_FT_DIR) return -ENOTDIR;

    const rfs_priv_t *p = (const rfs_priv_t *)fs->priv;
    uint32_t dir_id = 0, obj_id = 0;
    rfs_unpack_ino(dir_ino, &dir_id, &obj_id);

    rfs_dir_collect_t dctx = { NULL, 0, 0 };
    int rc = rfs_visit_object_node(fs, p->root_block, dir_id, obj_id, 0, rfs_dir_visitor, &dctx);
    if (rc != 0) {
        free(dctx.entries);
        return rc;
    }

    for (size_t i = 0; i < dctx.count; i++) {
        legacyfs_attr_t cattr;
        legacyfs_ftype_t ft = LEGACYFS_FT_UNKNOWN;
        if (rfs_getattr(fs, dctx.entries[i].child_ino, &cattr) == 0) {
            ft = cattr.ftype;
        }
        if (cb(user_ctx, dctx.entries[i].name, dctx.entries[i].child_ino, ft) != 0) {
            break;
        }
    }

    free(dctx.entries);
    return 0;
}

typedef struct {
    uint64_t req_off;
    size_t req_len;
    uint8_t *dst;
    uint64_t file_size;
} rfs_read_ctx_t;

static int rfs_data_visitor(
    legacyfs_t *fs,
    const rfs_key_t *key,
    uint16_t entry_count,
    uint16_t item_ver,
    const uint8_t *body,
    uint16_t body_len,
    void *ctx_ptr
) {
    (void)entry_count;
    (void)item_ver;
    if (key->type != RFS_TYPE_DIRECT && key->type != RFS_TYPE_INDIRECT) return 0;
    if (key->offset == 0) return 0;

    rfs_read_ctx_t *rctx = (rfs_read_ctx_t *)ctx_ptr;
    const rfs_priv_t *p = (const rfs_priv_t *)fs->priv;
    uint64_t item_start = key->offset - 1ULL;
    uint64_t req_end = rctx->req_off + (uint64_t)rctx->req_len;

    if (key->type == RFS_TYPE_DIRECT) {
        uint64_t item_end = item_start + (uint64_t)body_len;
        uint64_t ov_start = item_start > rctx->req_off ? item_start : rctx->req_off;
        uint64_t ov_end = item_end < req_end ? item_end : req_end;
        if (ov_start < ov_end) {
            memcpy(rctx->dst + (ov_start - rctx->req_off),
                   body + (ov_start - item_start),
                   (size_t)(ov_end - ov_start));
        }
        return 0;
    }

    /* TYPE_INDIRECT: array of u32 block numbers */
    uint32_t ptr_count = body_len / 4U;
    uint64_t item_span = (uint64_t)ptr_count * (uint64_t)p->block_size;
    uint64_t item_end = item_start + item_span;
    if (item_end <= rctx->req_off || item_start >= req_end) {
        return 0;
    }

    uint8_t *tmp = (uint8_t *)malloc(p->block_size);
    if (!tmp) return -ENOMEM;

    for (uint32_t k = 0; k < ptr_count; k++) {
        uint64_t b_start = item_start + (uint64_t)k * (uint64_t)p->block_size;
        uint64_t b_end = b_start + (uint64_t)p->block_size;
        uint64_t ov_start = b_start > rctx->req_off ? b_start : rctx->req_off;
        uint64_t ov_end = b_end < req_end ? b_end : req_end;
        if (ov_start >= ov_end) continue;

        uint32_t disk_blk = lfs_le32(body + (size_t)k * 4U);
        if (disk_blk == 0) {
            memset(rctx->dst + (ov_start - rctx->req_off), 0, (size_t)(ov_end - ov_start));
        } else {
            if (disk_blk >= p->block_count) {
                free(tmp);
                return -EIO;
            }
            int rc = lfs_read_bytes(fs, (uint64_t)disk_blk * (uint64_t)p->block_size, p->block_size, tmp);
            if (rc != 0) {
                free(tmp);
                return rc;
            }
            memcpy(rctx->dst + (ov_start - rctx->req_off),
                   tmp + (ov_start - b_start),
                   (size_t)(ov_end - ov_start));
        }
    }

    free(tmp);
    return 0;
}

static int rfs_read_common(legacyfs_t *fs, uint64_t ino, legacyfs_ftype_t expected_ft, uint64_t offset, size_t length, void *buffer, size_t *out_read) {
    legacyfs_attr_t attr;
    int arc = rfs_getattr(fs, ino, &attr);
    if (arc != 0) return arc;
    if (attr.ftype != expected_ft) {
        return attr.ftype == LEGACYFS_FT_DIR ? -EISDIR : -EINVAL;
    }
    if (offset >= attr.size || length == 0) {
        if (out_read) *out_read = 0;
        return 0;
    }

    size_t to_read = length;
    if ((uint64_t)to_read > attr.size - offset) {
        to_read = (size_t)(attr.size - offset);
    }
    memset(buffer, 0, to_read);

    const rfs_priv_t *p = (const rfs_priv_t *)fs->priv;
    uint32_t dir_id = 0, obj_id = 0;
    rfs_unpack_ino(ino, &dir_id, &obj_id);

    rfs_read_ctx_t rctx = { offset, to_read, (uint8_t *)buffer, attr.size };
    int rc = rfs_visit_object_node(fs, p->root_block, dir_id, obj_id, 0, rfs_data_visitor, &rctx);
    if (rc != 0) return rc;
    if (out_read) *out_read = to_read;
    return 0;
}

static int rfs_read(legacyfs_t *fs, uint64_t ino, uint64_t offset, size_t length, void *buffer, size_t *out_read) {
    return rfs_read_common(fs, ino, LEGACYFS_FT_REG, offset, length, buffer, out_read);
}

static int rfs_readlink(legacyfs_t *fs, uint64_t ino, char *buffer, size_t buffer_size, size_t *out_len) {
    if (buffer_size < 2) return -EINVAL;
    size_t got = 0;
    int rc = rfs_read_common(fs, ino, LEGACYFS_FT_SYMLINK, 0, buffer_size - 1, buffer, &got);
    if (rc != 0) return rc;
    buffer[got] = '\0';
    if (out_len) *out_len = got;
    return 0;
}

const legacyfs_ops_t lfs_reiserfs_ops = {
    .mount = rfs_mount,
    .unmount = rfs_unmount,
    .root_ino = rfs_root_ino,
    .statfs = NULL,
    .getattr = rfs_getattr,
    .readdir = rfs_readdir,
    .lookup = NULL,
    .read = rfs_read,
    .readlink = rfs_readlink,
};
