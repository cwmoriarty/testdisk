#include "internal.h"
#include <stdio.h>

/*
 * Read-only UDF (ECMA-167 / OSTA UDF 1.02 - 2.60) driver for legacyfs.
 * Supports 512, 2048, and 4096-byte logical blocks, File Entry (261) and
 * Extended File Entry (266), inline ICB data, short_ad and long_ad extents,
 * OSTA CS0 8-bit and 16-bit UTF-16BE filenames, and PathComponent symlinks.
 */

#define UDF_TAG_PVD     1U
#define UDF_TAG_AVDP    2U
#define UDF_TAG_PD      5U
#define UDF_TAG_LVD     6U
#define UDF_TAG_TD      8U
#define UDF_TAG_FSD     256U
#define UDF_TAG_FID     257U
#define UDF_TAG_FE      261U
#define UDF_TAG_EFE     266U

typedef struct {
    uint32_t bsize;
    uint32_t part_start_lba;
    uint32_t part_len_blocks;
    uint32_t root_icb_lbn;
} udf_priv_t;

typedef struct {
    uint64_t phys_byte;
    uint32_t byte_len;
    int      is_sparse;
} udf_ext_t;

static void udf_decode_cs0(const uint8_t *raw, size_t raw_len, char *out, size_t out_cap) {
    if (out_cap == 0) return;
    out[0] = '\0';
    if (!raw || raw_len == 0) return;

    uint8_t comp = raw[0];
    size_t pos = 0;
    if (comp == 8) {
        for (size_t i = 1; i < raw_len && pos + 1U < out_cap; i++) {
            uint8_t c = raw[i];
            if (c == 0) break;
            if (c < 0x80U) {
                out[pos++] = (char)c;
            } else if (pos + 2U < out_cap) {
                out[pos++] = (char)(0xC0U | (c >> 6));
                out[pos++] = (char)(0x80U | (c & 0x3FU));
            }
        }
    } else if (comp == 16) {
        for (size_t i = 1; i + 1U < raw_len && pos + 1U < out_cap; i += 2U) {
            uint16_t ch = lfs_be16(raw + i);
            if (ch == 0) break;
            if (ch < 0x80U) {
                out[pos++] = (char)ch;
            } else if (ch < 0x800U && pos + 2U < out_cap) {
                out[pos++] = (char)(0xC0U | (ch >> 6));
                out[pos++] = (char)(0x80U | (ch & 0x3FU));
            } else if (pos + 3U < out_cap) {
                out[pos++] = (char)(0xE0U | (ch >> 12));
                out[pos++] = (char)(0x80U | ((ch >> 6) & 0x3FU));
                out[pos++] = (char)(0x80U | (ch & 0x3FU));
            }
        }
    }
    out[pos] = '\0';
}

static int udf_mount(legacyfs_t *fs) {
    static const uint32_t bs_cands[3] = { 2048U, 512U, 4096U };
    uint8_t blk[4096];
    uint32_t bsize = 0;
    uint32_t mvds_len = 0, mvds_loc = 0;

    for (int i = 0; i < 3; i++) {
        uint32_t cand = bs_cands[i];
        if (lfs_read_bytes(fs, 256ULL * cand, cand, blk) != 0) continue;
        if (lfs_le16(blk + 0) == UDF_TAG_AVDP && lfs_le32(blk + 12) == 256U) {
            bsize = cand;
            mvds_len = lfs_le32(blk + 16);
            mvds_loc = lfs_le32(blk + 20);
            break;
        }
    }
    if (bsize == 0 || mvds_len < bsize || mvds_loc == 0) return -EINVAL;

    uint32_t part_start = 0, part_len = 0, fsd_lbn = 0;
    int have_pd = 0, have_lvd = 0;
    uint32_t vds_blocks = mvds_len / bsize;
    if (vds_blocks > 64U) vds_blocks = 64U;

    for (uint32_t b = 0; b < vds_blocks; b++) {
        if (lfs_read_bytes(fs, (uint64_t)(mvds_loc + b) * bsize, bsize, blk) != 0) break;
        uint16_t tag = lfs_le16(blk + 0);
        if (tag == UDF_TAG_TD || tag == 0) break;
        if (tag == UDF_TAG_PD) {
            part_start = lfs_le32(blk + 188);
            part_len = lfs_le32(blk + 192);
            have_pd = 1;
        } else if (tag == UDF_TAG_LVD) {
            uint32_t lbs = lfs_le32(blk + 212);
            if (lbs != bsize) return -EINVAL;
            fsd_lbn = lfs_le32(blk + 248 + 4);
            /* Extract LogicalVolIdent dstring (128 bytes at +84, length in byte 127) */
            if (fs->info.label[0] == '\0') {
                uint8_t dlen = blk[84 + 127];
                if (dlen > 1 && dlen <= 127) {
                    udf_decode_cs0(blk + 84, dlen, fs->info.label, sizeof(fs->info.label));
                }
            }
            have_lvd = 1;
        }
    }
    if (!have_pd || !have_lvd || part_len == 0) return -EINVAL;

    if (lfs_read_bytes(fs, (uint64_t)(part_start + fsd_lbn) * bsize, bsize, blk) != 0) return -EIO;
    if (lfs_le16(blk + 0) != UDF_TAG_FSD) return -EINVAL;

    uint32_t root_lbn = lfs_le32(blk + 400 + 4);

    udf_priv_t *p = (udf_priv_t *)calloc(1, sizeof(udf_priv_t));
    if (!p) return -ENOMEM;
    p->bsize = bsize;
    p->part_start_lba = part_start;
    p->part_len_blocks = part_len;
    p->root_icb_lbn = root_lbn;
    fs->priv = p;
    return 0;
}

static void udf_unmount(legacyfs_t *fs) {
    free(fs->priv);
    fs->priv = NULL;
}

static uint64_t udf_root_ino(const legacyfs_t *fs) {
    const udf_priv_t *p = (const udf_priv_t *)fs->priv;
    /* Encode ino as lbn + 2 so root_ino is always >= 2 even when root_icb_lbn == 0 */
    return p ? ((uint64_t)p->root_icb_lbn + 2ULL) : 2ULL;
}

static int udf_statfs(legacyfs_t *fs, legacyfs_statfs_t *out) {
    const udf_priv_t *p = (const udf_priv_t *)fs->priv;
    memset(out, 0, sizeof(*out));
    out->block_size = p->bsize;
    out->total_blocks = p->part_len_blocks;
    out->namemax = 255;
    return 0;
}

static int udf_load_fe(
    legacyfs_t *fs,
    uint64_t ino,
    uint8_t blk[4096],
    legacyfs_attr_t *out_attr,
    uint16_t *out_ad_type,
    const uint8_t **out_ad_ptr,
    uint32_t *out_ad_len
) {
    const udf_priv_t *p = (const udf_priv_t *)fs->priv;
    if (ino < 2ULL) return -ENOENT;
    uint64_t lbn = ino - 2ULL;
    if (lbn >= p->part_len_blocks) return -ENOENT;

    int rc = lfs_read_bytes(fs, ((uint64_t)p->part_start_lba + lbn) * p->bsize, p->bsize, blk);
    if (rc != 0) return rc;

    uint16_t tag = lfs_le16(blk + 0);
    size_t hdr_base = 0;
    uint32_t l_ea = 0, l_ad = 0;
    if (tag == UDF_TAG_FE) {
        hdr_base = 176U;
        l_ea = lfs_le32(blk + 168);
        l_ad = lfs_le32(blk + 172);
    } else if (tag == UDF_TAG_EFE) {
        hdr_base = 216U;
        l_ea = lfs_le32(blk + 208);
        l_ad = lfs_le32(blk + 212);
    } else {
        return -ENOENT;
    }

    if (hdr_base > p->bsize || l_ea > p->bsize - hdr_base || l_ad > p->bsize - hdr_base - l_ea) {
        return -EIO;
    }

    uint8_t icb_ftype = blk[16 + 11];
    uint16_t icb_flags = lfs_le16(blk + 16 + 18);
    uint32_t uid = lfs_le32(blk + 36);
    uint32_t gid = lfs_le32(blk + 40);
    uint32_t perms = lfs_le32(blk + 44);
    uint16_t nlink = lfs_le16(blk + 48);
    uint64_t info_len = lfs_le64(blk + 56);

    uint32_t posix_perm =
        ((perms >> 0) & 0x7U) |        /* other rwx (UDF bits 0..2: X,W,R -> remap safely) */
        (((perms >> 5) & 0x7U) << 3) | /* group */
        (((perms >> 10) & 0x7U) << 6); /* owner */
    if (posix_perm == 0) {
        posix_perm = (icb_ftype == 4) ? 0755U : 0644U;
    } else {
        /* UDF bit0=X, bit1=W, bit2=R matches POSIX bit0=X, bit1=W, bit2=R */
    }

    uint32_t ifmt = S_IFREG;
    if (icb_ftype == 4) ifmt = S_IFDIR;
    else if (icb_ftype == 12) { ifmt = S_IFLNK; posix_perm = 0777U; }

    if (out_attr) {
        memset(out_attr, 0, sizeof(*out_attr));
        out_attr->ino = ino;
        out_attr->mode = ifmt | (posix_perm & 0777U);
        out_attr->ftype = lfs_mode_to_ftype(out_attr->mode);
        out_attr->uid = (uid == 0xFFFFFFFFU) ? 0U : uid;
        out_attr->gid = (gid == 0xFFFFFFFFU) ? 0U : gid;
        out_attr->nlink = nlink ? nlink : 1U;
        out_attr->size = info_len;
        out_attr->blocks_512 = (info_len + 511ULL) / 512ULL;
    }

    if (out_ad_type) *out_ad_type = icb_flags & 0x7U;
    if (out_ad_ptr) *out_ad_ptr = blk + hdr_base + l_ea;
    if (out_ad_len) *out_ad_len = l_ad;
    return 0;
}

static int udf_getattr(legacyfs_t *fs, uint64_t ino, legacyfs_attr_t *out) {
    uint8_t blk[4096];
    return udf_load_fe(fs, ino, blk, out, NULL, NULL, NULL);
}

static int udf_read_fe_bytes(
    legacyfs_t *fs,
    uint64_t ino,
    uint64_t offset,
    size_t length,
    void *buffer,
    size_t *out_read
) {
    const udf_priv_t *p = (const udf_priv_t *)fs->priv;
    uint8_t blk[4096];
    legacyfs_attr_t attr;
    uint16_t ad_type = 0;
    const uint8_t *ad_ptr = NULL;
    uint32_t ad_len = 0;

    int rc = udf_load_fe(fs, ino, blk, &attr, &ad_type, &ad_ptr, &ad_len);
    if (rc != 0) return rc;
    if (offset >= attr.size || length == 0) {
        *out_read = 0;
        return 0;
    }

    size_t to_read = (attr.size - offset < (uint64_t)length) ? (size_t)(attr.size - offset) : length;
    uint8_t *dst = (uint8_t *)buffer;
    memset(dst, 0, to_read);

    if (ad_type == 3U) { /* Inline AD_IN_ICB */
        if (offset + to_read > ad_len) return -EIO;
        memcpy(dst, ad_ptr + offset, to_read);
        *out_read = to_read;
        return 0;
    }

    size_t rec_sz = (ad_type == 0U) ? 8U : ((ad_type == 1U) ? 16U : 0U);
    if (rec_sz == 0U) return -ENOTSUP;

    uint64_t cur_file_off = 0;
    for (uint32_t pos = 0; pos + rec_sz <= ad_len; pos += (uint32_t)rec_sz) {
        uint32_t raw_len = lfs_le32(ad_ptr + pos);
        uint32_t ext_type = (raw_len >> 30) & 0x3U;
        uint32_t ext_len = raw_len & 0x3FFFFFFFU;
        if (ext_len == 0 || ext_type == 3U) break; /* End of descriptors */

        uint32_t lbn = lfs_le32(ad_ptr + pos + 4U);
        uint64_t req_end = offset + to_read;
        if (cur_file_off < req_end && cur_file_off + ext_len > offset) {
            uint64_t ov_start = (offset > cur_file_off) ? offset : cur_file_off;
            uint64_t ov_end = (req_end < cur_file_off + ext_len) ? req_end : (cur_file_off + ext_len);
            size_t copy_len = (size_t)(ov_end - ov_start);
            if (ext_type == 0U) { /* Recorded and allocated */
                uint64_t phys = ((uint64_t)p->part_start_lba + lbn) * p->bsize + (ov_start - cur_file_off);
                rc = lfs_read_bytes(fs, phys, copy_len, dst + (ov_start - offset));
                if (rc != 0) return rc;
            }
        }
        cur_file_off += ext_len;
    }

    *out_read = to_read;
    return 0;
}

static int udf_readdir(legacyfs_t *fs, uint64_t dir_ino, legacyfs_readdir_cb cb, void *user_ctx) {
    const udf_priv_t *p = (const udf_priv_t *)fs->priv;
    legacyfs_attr_t attr;
    int rc = udf_getattr(fs, dir_ino, &attr);
    if (rc != 0) return rc;
    if (attr.ftype != LEGACYFS_FT_DIR) return -ENOTDIR;

    if (cb(user_ctx, ".", dir_ino, LEGACYFS_FT_DIR) != 0) return 0;
    if (cb(user_ctx, "..", udf_root_ino(fs), LEGACYFS_FT_DIR) != 0) return 0;

    if (attr.size == 0 || attr.size > (16ULL << 20)) return 0;
    uint8_t *dbuf = (uint8_t *)malloc((size_t)attr.size);
    if (!dbuf) return -ENOMEM;

    size_t got = 0;
    rc = udf_read_fe_bytes(fs, dir_ino, 0, (size_t)attr.size, dbuf, &got);
    if (rc != 0) {
        free(dbuf);
        return rc;
    }

    size_t pos = 0;
    while (pos + 38U <= got) {
        if (lfs_le16(dbuf + pos) != UDF_TAG_FID) break;
        uint8_t fchars = dbuf[pos + 18U];
        uint8_t l_fi = dbuf[pos + 19U];
        uint32_t child_lbn = lfs_le32(dbuf + pos + 20U + 4U);
        uint16_t l_iu = lfs_le16(dbuf + pos + 36U);
        size_t fid_len = (38U + (size_t)l_iu + (size_t)l_fi + 3U) & ~(size_t)3U;
        if (fid_len == 0 || pos + fid_len > got) break;

        /* Skip deleted (0x04) and parent (0x08) FIDs */
        if ((fchars & (0x04U | 0x08U)) == 0 && l_fi > 0 && child_lbn < p->part_len_blocks) {
            char name[256];
            udf_decode_cs0(dbuf + pos + 38U + l_iu, l_fi, name, sizeof(name));
            if (name[0] != '\0') {
                uint64_t cino = (uint64_t)child_lbn + 2ULL;
                legacyfs_ftype_t ft = (fchars & 0x02U) ? LEGACYFS_FT_DIR : LEGACYFS_FT_REG;
                if (ft == LEGACYFS_FT_REG) {
                    legacyfs_attr_t ca;
                    if (udf_getattr(fs, cino, &ca) == 0) ft = ca.ftype;
                }
                if (cb(user_ctx, name, cino, ft) != 0) {
                    free(dbuf);
                    return 0;
                }
            }
        }
        pos += fid_len;
    }

    free(dbuf);
    return 0;
}

typedef struct {
    const char *target;
    uint64_t found_ino;
    int found;
} udf_lookup_ctx_t;

static int udf_lookup_cb(void *user_ctx, const char *name, uint64_t ino, legacyfs_ftype_t ftype) {
    (void)ftype;
    udf_lookup_ctx_t *ctx = (udf_lookup_ctx_t *)user_ctx;
    if (strcmp(name, ctx->target) == 0) {
        ctx->found_ino = ino;
        ctx->found = 1;
        return 1;
    }
    return 0;
}

static int udf_lookup(legacyfs_t *fs, uint64_t dir_ino, const char *name, uint64_t *out_ino) {
    udf_lookup_ctx_t ctx = { name, 0, 0 };
    int rc = udf_readdir(fs, dir_ino, udf_lookup_cb, &ctx);
    if (rc != 0) return rc;
    if (!ctx.found) return -ENOENT;
    *out_ino = ctx.found_ino;
    return 0;
}

static int udf_read(legacyfs_t *fs, uint64_t ino, uint64_t offset, size_t length, void *buffer, size_t *out_read) {
    legacyfs_attr_t attr;
    int rc = udf_getattr(fs, ino, &attr);
    if (rc != 0) return rc;
    if (attr.ftype != LEGACYFS_FT_REG) return -EISDIR;
    return udf_read_fe_bytes(fs, ino, offset, length, buffer, out_read);
}

static int udf_readlink(legacyfs_t *fs, uint64_t ino, char *buffer, size_t buffer_size, size_t *out_len) {
    if (buffer_size == 0) return -EINVAL;
    legacyfs_attr_t attr;
    int rc = udf_getattr(fs, ino, &attr);
    if (rc != 0) return rc;
    if (attr.ftype != LEGACYFS_FT_SYMLINK) return -EINVAL;
    if (attr.size > 4096ULL) return -EIO;

    uint8_t raw[4096];
    size_t got = 0;
    rc = udf_read_fe_bytes(fs, ino, 0, (size_t)attr.size, raw, &got);
    if (rc != 0) return rc;

    size_t out_pos = 0;
    size_t pos = 0;
    while (pos + 4U <= got && out_pos + 1U < buffer_size) {
        uint8_t ctype = raw[pos];
        uint8_t clen = raw[pos + 1U];
        if (pos + 4U + clen > got) break;

        if (ctype == 1U || ctype == 2U) {
            out_pos = 0;
            buffer[out_pos++] = '/';
        } else {
            char seg[256];
            if (ctype == 3U) snprintf(seg, sizeof(seg), "..");
            else if (ctype == 4U) snprintf(seg, sizeof(seg), ".");
            else if (ctype == 5U) udf_decode_cs0(raw + pos + 4U, clen, seg, sizeof(seg));
            else seg[0] = '\0';

            if (seg[0] != '\0') {
                if (out_pos > 0 && buffer[out_pos - 1U] != '/' && out_pos + 1U < buffer_size) {
                    buffer[out_pos++] = '/';
                }
                size_t slen = strlen(seg);
                if (out_pos + slen >= buffer_size) slen = buffer_size - 1U - out_pos;
                memcpy(buffer + out_pos, seg, slen);
                out_pos += slen;
            }
        }
        pos += 4U + clen;
    }
    buffer[out_pos] = '\0';
    if (out_len) *out_len = out_pos;
    return 0;
}

const legacyfs_ops_t lfs_udf_ops = {
    .mount    = udf_mount,
    .unmount  = udf_unmount,
    .root_ino = udf_root_ino,
    .statfs   = udf_statfs,
    .getattr  = udf_getattr,
    .readdir  = udf_readdir,
    .lookup   = udf_lookup,
    .read     = udf_read,
    .readlink = udf_readlink,
};
