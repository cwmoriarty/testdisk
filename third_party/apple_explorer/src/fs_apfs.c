#define _DEFAULT_SOURCE
#define _POSIX_C_SOURCE 200809L

#include "aex_internal.h"
#include <sys/stat.h>

#define APFS_NX_MAGIC   0x4253584EU /* "NXSB" */
#define APFS_VOL_MAGIC  0x42535041U /* "APSB" */

#define APFS_TYPE_SNAP_METADATA 1U
#define APFS_TYPE_INODE         3U
#define APFS_TYPE_XATTR         4U
#define APFS_TYPE_FILE_EXTENT   8U
#define APFS_TYPE_DIR_REC       9U

#define APFS_SNAP_DIR_INO    0xFF00000000000001ULL
#define APFS_BACKUPS_DIR_INO 0xFF00000000000002ULL

typedef struct {
    uint64_t xid;
    int64_t  create_sec;
    uint64_t root_tree_paddr;
    char     name[256];
    char     short_date[64];
} apfs_snap_entry_t;

typedef struct {
    aex_slice_t       slice;
    uint32_t          block_size;
    uint64_t          nx_blocks;
    uint64_t          nx_xid;
    uint64_t          nx_omap_tree_paddr;
    uint8_t           nx_uuid[16];
    uint64_t          nx_keybag_paddr;
    uint64_t          nx_keybag_blocks;

    uint64_t          vol_omap_tree_paddr;
    uint64_t          live_root_tree_paddr;
    uint64_t          live_xid;
    uint64_t          used_blocks;
    uint16_t          vol_role;
    int               case_insensitive;
    int               encrypted;
    aex_aes_ctx_t     vek_dec_k1;
    aex_aes_ctx_t     vek_enc_k2;

    apfs_snap_entry_t snaps[128];
    size_t            snap_count;
    int               pinned_snap_idx; /* -1 = live + synthetic /Snapshots & /Backups */
} apfs_priv_t;

static int read_raw_block(const aex_slice_t *sl, uint32_t bsz, uint64_t paddr, uint8_t *buf) {
    return aex_slice_read(sl, paddr * (uint64_t)bsz, bsz, buf);
}

static int verify_apfs_obj(const uint8_t *buf, uint32_t bsz) {
    uint64_t stored = aex_le64(buf);
    return (aex_fletcher64(buf, bsz) == stored) ? 0 : -EIO;
}

static int decrypt_xts_blocks(
    const aex_aes_ctx_t *dec_k1,
    const aex_aes_ctx_t *enc_k2,
    uint64_t start_paddr,
    uint32_t bsz,
    uint8_t *buf,
    size_t num_blocks
) {
    uint32_t secs_per_blk = bsz / 512U;
    for (size_t b = 0; b < num_blocks; b++) {
        uint64_t base_tweak = (start_paddr + (uint64_t)b) * (uint64_t)secs_per_blk;
        for (uint32_t s = 0; s < secs_per_blk; s++) {
            uint8_t *sec = buf + b * bsz + s * 512U;
            int rc = aex_aes_xts_decrypt_sector(dec_k1, enc_k2, base_tweak + s, sec, sec, 512U);
            if (rc != 0) return rc;
        }
    }
    return 0;
}

static int read_vol_block(const apfs_priv_t *ap, uint64_t paddr, int is_encrypted_btree, uint8_t *buf) {
    int rc = read_raw_block(&ap->slice, ap->block_size, paddr, buf);
    if (rc != 0) return rc;
    if (ap->encrypted && is_encrypted_btree) {
        rc = decrypt_xts_blocks(&ap->vek_dec_k1, &ap->vek_enc_k2, paddr, ap->block_size, buf, 1U);
        if (rc != 0) return rc;
    }
    return verify_apfs_obj(buf, ap->block_size);
}

/* Scan container superblock at block 0 + checkpoint descriptor ring for newest valid NXSB */
static int find_latest_nxsb(const aex_slice_t *sl, uint8_t **out_nxsb, uint32_t *out_bsz) {
    uint8_t b0[4096];
    if (aex_slice_read(sl, 0ULL, sizeof(b0), b0) != 0) return -EIO;
    if (aex_le32(b0 + 32U) != APFS_NX_MAGIC) return -EINVAL;
    uint32_t bsz = aex_le32(b0 + 36U);
    if (bsz < 4096U || bsz > 65536U || (bsz & (bsz - 1U)) != 0) return -EINVAL;

    uint8_t *best = (uint8_t *)malloc(bsz);
    uint8_t *cand = (uint8_t *)malloc(bsz);
    if (!best || !cand) { free(best); free(cand); return -ENOMEM; }

    if (read_raw_block(sl, bsz, 0ULL, best) != 0) { free(best); free(cand); return -EIO; }
    uint64_t best_xid = (verify_apfs_obj(best, bsz) == 0) ? aex_le64(best + 16U) : 0ULL;

    uint32_t xp_desc_blks = aex_le32(best + 104U) & 0x7FFFFFFFU;
    uint64_t xp_desc_base = aex_le64(best + 112U);
    if (xp_desc_blks > 0 && xp_desc_blks <= 2048U && xp_desc_base > 0) {
        for (uint32_t i = 0; i < xp_desc_blks; i++) {
            if (read_raw_block(sl, bsz, xp_desc_base + i, cand) != 0) continue;
            if ((aex_le32(cand + 24U) & 0xFFFFU) != 0x0001U) continue;
            if (aex_le32(cand + 32U) != APFS_NX_MAGIC) continue;
            if (verify_apfs_obj(cand, bsz) != 0) continue;
            uint64_t xid = aex_le64(cand + 16U);
            if (xid >= best_xid) {
                memcpy(best, cand, bsz);
                best_xid = xid;
            }
        }
    }

    free(cand);
    if (best_xid == 0 && verify_apfs_obj(best, bsz) != 0) {
        free(best);
        return -EINVAL;
    }
    *out_nxsb = best;
    *out_bsz = bsz;
    return 0;
}

/* Read OMAP root tree physical block from an omap_phys_t block */
static int read_omap_tree_paddr(const aex_slice_t *sl, uint32_t bsz, uint64_t omap_paddr, uint64_t *out_tree_paddr) {
    if (omap_paddr == 0) return -EINVAL;
    uint8_t *buf = (uint8_t *)malloc(bsz);
    if (!buf) return -ENOMEM;
    int rc = read_raw_block(sl, bsz, omap_paddr, buf);
    if (rc == 0) rc = verify_apfs_obj(buf, bsz);
    if (rc == 0) *out_tree_paddr = aex_le64(buf + 48U);
    free(buf);
    return rc;
}

/* Resolve virtual OID -> physical block address in an APFS OMAP B-tree (fixed-KV B-tree, always unencrypted) */
static int omap_lookup(
    const aex_slice_t *sl,
    uint32_t bsz,
    uint64_t tree_root_paddr,
    uint64_t target_oid,
    uint64_t max_xid,
    uint64_t *out_paddr
) {
    if (tree_root_paddr == 0) return -ENOENT;
    uint8_t *nbuf = (uint8_t *)malloc(bsz);
    if (!nbuf) return -ENOMEM;

    uint64_t cur_paddr = tree_root_paddr;
    for (int depth = 0; depth < 16; depth++) {
        if (read_raw_block(sl, bsz, cur_paddr, nbuf) != 0 || verify_apfs_obj(nbuf, bsz) != 0) {
            free(nbuf);
            return -EIO;
        }
        uint16_t flags = aex_le16(nbuf + 32U);
        uint32_t nkeys = aex_le32(nbuf + 36U);
        uint16_t toc_off = aex_le16(nbuf + 40U);
        uint16_t toc_len = aex_le16(nbuf + 42U);
        size_t key_base = 56U + toc_off + toc_len;
        size_t val_end = bsz - ((flags & 0x0001U) ? 40U : 0U);
        if (key_base >= val_end) { free(nbuf); return -EINVAL; }

        int best_idx = -1;
        for (uint32_t i = 0; i < nkeys; i++) {
            size_t tpos = 56U + toc_off + (size_t)i * 4U;
            if (tpos + 4U > key_base) break;
            uint16_t koff = aex_le16(nbuf + tpos);
            if (key_base + koff + 16U > val_end) continue;
            uint64_t k_oid = aex_le64(nbuf + key_base + koff);
            uint64_t k_xid = aex_le64(nbuf + key_base + koff + 8U);
            if (k_oid < target_oid || (k_oid == target_oid && k_xid <= max_xid)) {
                best_idx = (int)i;
            } else {
                break;
            }
        }
        if (best_idx < 0) { free(nbuf); return -ENOENT; }

        size_t tpos = 56U + toc_off + (size_t)best_idx * 4U;
        uint16_t koff = aex_le16(nbuf + tpos);
        uint16_t voff = aex_le16(nbuf + tpos + 2U);
        if (voff > val_end) { free(nbuf); return -EINVAL; }

        if ((flags & 0x0002U) != 0) { /* Leaf node */
            uint64_t k_oid = aex_le64(nbuf + key_base + koff);
            if (k_oid != target_oid || val_end - voff + 16U > bsz) {
                free(nbuf);
                return -ENOENT;
            }
            uint32_t ov_flags = aex_le32(nbuf + (val_end - voff));
            if ((ov_flags & 0x00000001U) != 0) { /* OMAP_VAL_DELETED */
                free(nbuf);
                return -ENOENT;
            }
            *out_paddr = aex_le64(nbuf + (val_end - voff) + 8U);
            free(nbuf);
            return 0;
        } else { /* Index node -> value is paddr_t (8 bytes) */
            if (val_end - voff + 8U > bsz) {
                free(nbuf);
                return -EINVAL;
            }
            cur_paddr = aex_le64(nbuf + (val_end - voff));
        }
    }
    free(nbuf);
    return -ELOOP;
}

/* Unwrap FileVault 2 APFS Volume Encryption Key (VEK) from Container + Volume Keybags */
static int unwrap_apfs_filevault_vek(
    const apfs_priv_t *ap,
    const uint8_t vol_uuid[16],
    const char *password,
    uint8_t out_vek[32]
) {
    if (!password || !password[0]) return -EACCES;
    if (ap->nx_keybag_paddr == 0 || ap->nx_keybag_blocks == 0 || ap->nx_keybag_blocks > 64ULL) {
        return -ENOENT;
    }

    size_t kb_bytes = (size_t)ap->nx_keybag_blocks * ap->block_size;
    uint8_t *ckb = (uint8_t *)malloc(kb_bytes);
    if (!ckb) return -ENOMEM;
    if (aex_slice_read(&ap->slice, ap->nx_keybag_paddr * ap->block_size, kb_bytes, ckb) != 0) {
        free(ckb);
        return -EIO;
    }

    aex_aes_ctx_t nx_dec, nx_enc;
    aex_aes_init_dec(&nx_dec, ap->nx_uuid, 16U);
    aex_aes_init_enc(&nx_enc, ap->nx_uuid, 16U);
    (void)decrypt_xts_blocks(&nx_dec, &nx_enc, ap->nx_keybag_paddr, ap->block_size, ckb, (size_t)ap->nx_keybag_blocks);
    if (verify_apfs_obj(ckb, (uint32_t)kb_bytes) != 0) {
        free(ckb);
        return -EINVAL;
    }

    /* Parse kb_locker_t starting at byte 32 (kl_version u16, kl_nkeys u16, kl_nbytes u32, pad 8B -> entries at +48) */
    uint16_t nkeys = aex_le16(ckb + 34U);
    size_t pos = 48U;
    uint8_t wrapped_vek[64];
    size_t wrapped_vek_len = 0;
    uint64_t recs_paddr = 0, recs_blocks = 0;

    for (uint16_t i = 0; i < nkeys && pos + 24U <= kb_bytes; i++) {
        const uint8_t *euuid = ckb + pos;
        uint16_t etag = aex_le16(ckb + pos + 16U);
        uint16_t eklen = aex_le16(ckb + pos + 18U);
        const uint8_t *edata = ckb + pos + 24U;
        if (pos + 24U + eklen > kb_bytes) break;

        if (memcmp(euuid, vol_uuid, 16U) == 0) {
            if (etag == 2U && eklen >= 40U && eklen <= sizeof(wrapped_vek)) { /* KB_TAG_VOLUME_KEY */
                /* In DER-encoded or raw wrapped VEK, last 40 bytes hold RFC 3394 wrapped 32B VEK */
                size_t woff = (eklen > 40U && edata[eklen - 42U] == 0x04U && edata[eklen - 41U] == 40U) ? (eklen - 40U) : 0U;
                wrapped_vek_len = (woff > 0) ? 40U : eklen;
                memcpy(wrapped_vek, edata + woff, wrapped_vek_len);
            } else if (etag == 3U && eklen >= 16U) { /* KB_TAG_VOLUME_UNLOCK_RECORDS (prange_t) */
                recs_paddr = aex_le64(edata);
                recs_blocks = aex_le64(edata + 8U);
            }
        }
        pos += ((24U + (size_t)eklen + 15U) & ~(size_t)15U);
    }
    free(ckb);

    if (wrapped_vek_len < 24U || recs_paddr == 0 || recs_blocks == 0 || recs_blocks > 64ULL) {
        return -ENOENT;
    }

    size_t rbytes = (size_t)recs_blocks * ap->block_size;
    uint8_t *vkb = (uint8_t *)malloc(rbytes);
    if (!vkb) return -ENOMEM;
    if (aex_slice_read(&ap->slice, recs_paddr * ap->block_size, rbytes, vkb) != 0) {
        free(vkb);
        return -EIO;
    }

    aex_aes_ctx_t v_dec, v_enc;
    aex_aes_init_dec(&v_dec, vol_uuid, 16U);
    aex_aes_init_enc(&v_enc, vol_uuid, 16U);
    (void)decrypt_xts_blocks(&v_dec, &v_enc, recs_paddr, ap->block_size, vkb, (size_t)recs_blocks);
    if (verify_apfs_obj(vkb, (uint32_t)rbytes) != 0) {
        free(vkb);
        return -EINVAL;
    }

    uint16_t vnkeys = aex_le16(vkb + 34U);
    size_t vpos = 48U;
    for (uint16_t i = 0; i < vnkeys && vpos + 24U <= rbytes; i++) {
        uint16_t etag = aex_le16(vkb + vpos + 16U);
        uint16_t eklen = aex_le16(vkb + vpos + 18U);
        const uint8_t *edata = vkb + vpos + 24U;
        if (vpos + 24U + eklen > rbytes) break;

        if (etag == 3U && eklen >= 64U) {
            /* Scan TLV/DER KEK blob for wrapped KEK (40B), salt (16B), and iterations */
            const uint8_t *wkek = NULL, *salt = NULL;
            uint64_t iters = 0;
            for (size_t p = 0; p + 2U < eklen; ) {
                uint8_t tag = edata[p++];
                size_t tlen = edata[p++];
                if ((tlen & 0x80U) != 0) {
                    size_t nb = tlen & 0x7FU;
                    if (nb == 0 || nb > 4U || p + nb > eklen) break;
                    tlen = 0;
                    for (size_t b = 0; b < nb; b++) tlen = (tlen << 8) | edata[p++];
                }
                if (p + tlen > eklen) break;
                if (tag == 0x30U) continue; /* SEQUENCE: step inside */
                if (tag == 0x83U && tlen == 40U) wkek = edata + p;
                else if (tag == 0x84U && tlen >= 1U && tlen <= 8U) {
                    iters = 0;
                    for (size_t b = 0; b < tlen; b++) iters = (iters << 8) | edata[p + b];
                } else if (tag == 0x85U && tlen == 16U) {
                    salt = edata + p;
                }
                p += tlen;
            }
            if (wkek && salt && iters > 0 && iters <= 10000000ULL) {
                uint8_t pw_dk[32], kek[32];
                aex_pbkdf2_sha256(password, strlen(password), salt, 16U, (uint32_t)iters, pw_dk, 32U);
                if (aex_aes_key_unwrap(pw_dk, 32U, wkek, 40U, kek) == 0 &&
                    aex_aes_key_unwrap(kek, 32U, wrapped_vek, 40U, out_vek) == 0) {
                    free(vkb);
                    return 0;
                }
            }
        }
        vpos += ((24U + (size_t)eklen + 15U) & ~(size_t)15U);
    }

    free(vkb);
    return -EACCES;
}

/* ---------------- Variable-KV APFS B-Tree Traversal (FS Tree & Snap Meta Tree) ---------------- */

typedef int (*apfs_kv_cb)(
    void *ctx,
    uint64_t obj_id,
    uint8_t obj_type,
    const uint8_t *key,
    uint16_t key_len,
    const uint8_t *val,
    uint16_t val_len
);

static int apfs_btree_scan_id(
    const apfs_priv_t *ap,
    uint64_t tree_root_paddr,
    uint64_t omap_tree_paddr, /* 0 if physical tree (like snap_meta_tree), non-0 if virtual FS tree */
    uint64_t max_xid,
    int is_encrypted,
    int filter_by_id,
    uint64_t target_obj_id,
    apfs_kv_cb cb,
    void *cb_ctx,
    int depth
) {
    if (tree_root_paddr == 0 || depth > 16) return 0;
    uint8_t *nbuf = (uint8_t *)malloc(ap->block_size);
    if (!nbuf) return -ENOMEM;

    if (read_vol_block(ap, tree_root_paddr, is_encrypted, nbuf) != 0) {
        free(nbuf);
        return -EIO;
    }

    uint16_t flags = aex_le16(nbuf + 32U);
    uint32_t nkeys = aex_le32(nbuf + 36U);
    uint16_t toc_off = aex_le16(nbuf + 40U);
    uint16_t toc_len = aex_le16(nbuf + 42U);
    int fixed_kv = (flags & 0x0004U) != 0;
    size_t key_base = 56U + toc_off + toc_len;
    size_t val_end = ap->block_size - ((flags & 0x0001U) ? 40U : 0U);
    if (key_base >= val_end) { free(nbuf); return -EINVAL; }

    for (uint32_t i = 0; i < nkeys; i++) {
        uint16_t koff = 0, klen = 0, voff = 0, vlen = 0;
        if (fixed_kv) {
            size_t tpos = 56U + toc_off + (size_t)i * 4U;
            if (tpos + 4U > key_base) break;
            koff = aex_le16(nbuf + tpos);
            voff = aex_le16(nbuf + tpos + 2U);
            klen = 8U;
            vlen = ((flags & 0x0002U) != 0) ? 16U : 8U;
        } else {
            size_t tpos = 56U + toc_off + (size_t)i * 8U;
            if (tpos + 8U > key_base) break;
            koff = aex_le16(nbuf + tpos);
            klen = aex_le16(nbuf + tpos + 2U);
            voff = aex_le16(nbuf + tpos + 4U);
            vlen = aex_le16(nbuf + tpos + 6U);
        }
        if (klen < 8U || key_base + koff + klen > val_end || voff > val_end || (val_end - voff) + vlen > ap->block_size) {
            continue;
        }

        const uint8_t *kptr = nbuf + key_base + koff;
        const uint8_t *vptr = nbuf + (val_end - voff);
        uint64_t khdr = aex_le64(kptr);
        uint64_t oid = khdr & 0x0FFFFFFFFFFFFFFFULL;
        uint8_t otype = (uint8_t)(khdr >> 60);

        if ((flags & 0x0002U) != 0) { /* Leaf node */
            if (filter_by_id) {
                if (oid < target_obj_id) continue;
                if (oid > target_obj_id) break;
            }
            if (cb(cb_ctx, oid, otype, kptr, klen, vptr, vlen) != 0) {
                free(nbuf);
                return 1;
            }
        } else { /* Index node */
            if (vlen < 8U) continue;
            if (filter_by_id && oid > target_obj_id) break;
            /* Check next key's oid to skip subtrees strictly before target_obj_id */
            if (filter_by_id && i + 1U < nkeys) {
                size_t ntpos = 56U + toc_off + (size_t)(i + 1U) * (fixed_kv ? 4U : 8U);
                if (ntpos + 2U <= key_base) {
                    uint16_t nkoff = aex_le16(nbuf + ntpos);
                    if (key_base + nkoff + 8U <= val_end) {
                        uint64_t next_oid = aex_le64(nbuf + key_base + nkoff) & 0x0FFFFFFFFFFFFFFFULL;
                        if (next_oid < target_obj_id) continue;
                    }
                }
            }
            uint64_t child_id = aex_le64(vptr);
            uint64_t child_paddr = child_id;
            if (omap_tree_paddr != 0) {
                if (omap_lookup(&ap->slice, ap->block_size, omap_tree_paddr, child_id, max_xid, &child_paddr) != 0) {
                    continue;
                }
            }
            int sub = apfs_btree_scan_id(
                ap, child_paddr, omap_tree_paddr, max_xid, is_encrypted,
                filter_by_id, target_obj_id, cb, cb_ctx, depth + 1
            );
            if (sub == 1) { free(nbuf); return 1; }
        }
    }

    free(nbuf);
    return 0;
}

/* Parse Snapshot Metadata B-tree (snap_meta_tree_oid) */
static int snap_meta_cb(
    void *ctx,
    uint64_t obj_id,
    uint8_t obj_type,
    const uint8_t *key,
    uint16_t key_len,
    const uint8_t *val,
    uint16_t val_len
) {
    (void)key;
    (void)key_len;
    apfs_priv_t *ap = (apfs_priv_t *)ctx;
    if (obj_type != APFS_TYPE_SNAP_METADATA || val_len < 50U || ap->snap_count >= 128U) return 0;

    uint64_t sblock_paddr = aex_le64(val + 8U);
    uint64_t ctime_ns = aex_le64(val + 16U);
    uint16_t nlen = aex_le16(val + 48U);
    if (50U + nlen > val_len || sblock_paddr == 0) return 0;

    /* Read frozen APSB at sblock_paddr to resolve its root_tree_oid at snapshot xid */
    uint8_t *sbuf = (uint8_t *)malloc(ap->block_size);
    if (!sbuf) return 0;
    if (read_vol_block(ap, sblock_paddr, 0, sbuf) == 0 && aex_le32(sbuf + 32U) == APFS_VOL_MAGIC) {
        uint64_t snap_omap_paddr = aex_le64(sbuf + 128U);
        uint64_t snap_root_oid = aex_le64(sbuf + 136U);
        uint64_t snap_omap_tree = ap->vol_omap_tree_paddr;
        (void)read_omap_tree_paddr(&ap->slice, ap->block_size, snap_omap_paddr, &snap_omap_tree);
        uint64_t snap_root_paddr = 0;
        if (omap_lookup(&ap->slice, ap->block_size, snap_omap_tree, snap_root_oid, obj_id, &snap_root_paddr) == 0) {
            apfs_snap_entry_t *se = &ap->snaps[ap->snap_count++];
            memset(se, 0, sizeof(*se));
            se->xid = obj_id;
            se->create_sec = (int64_t)(ctime_ns / 1000000000ULL);
            se->root_tree_paddr = snap_root_paddr;
            size_t cpy = (nlen < sizeof(se->name) - 1U) ? nlen : (sizeof(se->name) - 1U);
            memcpy(se->name, val + 50U, cpy);
            se->name[cpy] = '\0';

            /* Extract friendly Time Machine date if named com.apple.TimeMachine.YYYY-MM-DD-HHMMSS.backup */
            const char *tm_pfx = "com.apple.TimeMachine.";
            if (strncmp(se->name, tm_pfx, strlen(tm_pfx)) == 0) {
                const char *dt = se->name + strlen(tm_pfx);
                const char *dot = strstr(dt, ".backup");
                size_t dlen = dot ? (size_t)(dot - dt) : strlen(dt);
                if (dlen >= sizeof(se->short_date)) dlen = sizeof(se->short_date) - 1U;
                memcpy(se->short_date, dt, dlen);
                se->short_date[dlen] = '\0';
            } else {
                size_t dlen = strlen(se->name);
                if (dlen >= sizeof(se->short_date)) dlen = sizeof(se->short_date) - 1U;
                memcpy(se->short_date, se->name, dlen);
                se->short_date[dlen] = '\0';
            }
        }
    }
    free(sbuf);
    return 0;
}

/* ---------------- APFS Inode, DirRec, Xattr, and Extent Readers ---------------- */

typedef struct {
    int      found;
    uint64_t private_id;
    uint64_t dstream_size;
    uint64_t uncomp_size;
    uint32_t bsd_flags;
    uint16_t mode;
    uint32_t uid;
    uint32_t gid;
    uint32_t nlink;
    int64_t  crtime_sec;
    int64_t  mtime_sec;
    int64_t  ctime_sec;
    int64_t  atime_sec;
} apfs_inode_info_t;

static int parse_inode_cb(
    void *ctx,
    uint64_t obj_id,
    uint8_t obj_type,
    const uint8_t *key,
    uint16_t key_len,
    const uint8_t *val,
    uint16_t val_len
) {
    (void)obj_id; (void)key; (void)key_len;
    if (obj_type != APFS_TYPE_INODE || val_len < 92U) return 0;
    apfs_inode_info_t *out = (apfs_inode_info_t *)ctx;
    memset(out, 0, sizeof(*out));
    out->found = 1;
    out->private_id = aex_le64(val + 8U);
    out->crtime_sec = (int64_t)(aex_le64(val + 16U) / 1000000000ULL);
    out->mtime_sec  = (int64_t)(aex_le64(val + 24U) / 1000000000ULL);
    out->ctime_sec  = (int64_t)(aex_le64(val + 32U) / 1000000000ULL);
    out->atime_sec  = (int64_t)(aex_le64(val + 40U) / 1000000000ULL);
    out->nlink      = aex_le32(val + 56U);
    out->bsd_flags  = aex_le32(val + 68U);
    out->uid        = aex_le32(val + 72U);
    out->gid        = aex_le32(val + 76U);
    out->mode       = aex_le16(val + 80U);
    out->uncomp_size = aex_le64(val + 84U);

    /* Parse xf_blob_t at val + 92 for INO_EXT_TYPE_DSTREAM (8) */
    if (val_len >= 96U) {
        uint16_t num_exts = aex_le16(val + 92U);
        size_t hdr_end = 96U + (size_t)num_exts * 4U;
        if (hdr_end <= val_len) {
            size_t dpos = hdr_end;
            for (uint16_t i = 0; i < num_exts; i++) {
                uint8_t xtype = val[96U + i * 4U];
                uint16_t xsize = aex_le16(val + 96U + i * 4U + 2U);
                if (dpos + xsize > val_len) break;
                if (xtype == 8U && xsize >= 16U) { /* INO_EXT_TYPE_DSTREAM */
                    out->dstream_size = aex_le64(val + dpos);
                }
                dpos += ((size_t)xsize + 7U) & ~(size_t)7U;
            }
        }
    }
    return 1;
}

typedef struct {
    const char *want_name;
    uint8_t    *out_data;
    size_t      out_len;
    uint64_t    dstream_oid;
    uint64_t    dstream_size;
    int         found;
} apfs_xattr_query_t;

static int parse_xattr_cb(
    void *ctx,
    uint64_t obj_id,
    uint8_t obj_type,
    const uint8_t *key,
    uint16_t key_len,
    const uint8_t *val,
    uint16_t val_len
) {
    (void)obj_id;
    if (obj_type != APFS_TYPE_XATTR || key_len < 11U || val_len < 4U) return 0;
    apfs_xattr_query_t *q = (apfs_xattr_query_t *)ctx;
    uint16_t nlen = aex_le16(key + 8U);
    if (10U + nlen > key_len) return 0;
    if (strncmp((const char *)(key + 10U), q->want_name, nlen) != 0) return 0;

    uint16_t xflags = aex_le16(val + 0U);
    uint16_t xdlen = aex_le16(val + 2U);
    if (4U + xdlen > val_len) return 0;

    if ((xflags & 0x0002U) != 0) { /* XATTR_DATA_EMBEDDED */
        q->out_data = (uint8_t *)malloc(xdlen ? xdlen : 1U);
        if (q->out_data && xdlen > 0) memcpy(q->out_data, val + 4U, xdlen);
        q->out_len = xdlen;
        q->found = 1;
    } else if ((xflags & 0x0001U) != 0 && xdlen >= 24U) { /* XATTR_DATA_STREAM */
        q->dstream_oid = aex_le64(val + 4U);
        q->dstream_size = aex_le64(val + 12U);
        q->found = 1;
    }
    return 1;
}

typedef struct {
    const apfs_priv_t *ap;
    uint64_t           req_off;
    size_t             req_len;
    uint8_t           *dst;
    size_t             max_written;
    int                err;
} apfs_ext_read_t;

static int read_extent_cb(
    void *ctx,
    uint64_t obj_id,
    uint8_t obj_type,
    const uint8_t *key,
    uint16_t key_len,
    const uint8_t *val,
    uint16_t val_len
) {
    (void)obj_id;
    if (obj_type != APFS_TYPE_FILE_EXTENT || key_len < 16U || val_len < 24U) return 0;
    apfs_ext_read_t *er = (apfs_ext_read_t *)ctx;
    uint64_t log_off = aex_le64(key + 8U);
    uint64_t ext_len = aex_le64(val + 0U) & 0x00FFFFFFFFFFFFFFULL;
    uint64_t phys_blk = aex_le64(val + 8U);
    if (ext_len == 0) return 0;

    uint64_t req_end = er->req_off + er->req_len;
    uint64_t ext_end = log_off + ext_len;
    if (ext_end <= er->req_off || log_off >= req_end) return 0;

    uint64_t ov_start = (log_off > er->req_off) ? log_off : er->req_off;
    uint64_t ov_end = (ext_end < req_end) ? ext_end : req_end;
    size_t ov_len = (size_t)(ov_end - ov_start);
    size_t dst_off = (size_t)(ov_start - er->req_off);

    if (phys_blk == 0) {
        /* Sparse hole */
        memset(er->dst + dst_off, 0, ov_len);
    } else {
        uint64_t byte_in_ext = ov_start - log_off;
        uint32_t bsz = er->ap->block_size;
        uint64_t first_b = byte_in_ext / bsz;
        uint64_t last_b = (byte_in_ext + ov_len - 1ULL) / bsz;
        size_t nblks = (size_t)(last_b - first_b + 1ULL);
        uint8_t *tmp = (uint8_t *)malloc(nblks * bsz);
        if (!tmp) { er->err = -ENOMEM; return 1; }
        int rc = aex_slice_read(&er->ap->slice, (phys_blk + first_b) * bsz, nblks * bsz, tmp);
        if (rc == 0 && er->ap->encrypted) {
            rc = decrypt_xts_blocks(&er->ap->vek_dec_k1, &er->ap->vek_enc_k2, phys_blk + first_b, bsz, tmp, nblks);
        }
        if (rc != 0) { free(tmp); er->err = rc; return 1; }
        memcpy(er->dst + dst_off, tmp + (size_t)(byte_in_ext - first_b * bsz), ov_len);
        free(tmp);
    }
    if (dst_off + ov_len > er->max_written) er->max_written = dst_off + ov_len;
    return 0;
}

static int read_dstream_bytes(
    const apfs_priv_t *ap,
    uint64_t tree_paddr,
    uint64_t max_xid,
    uint64_t private_id,
    uint64_t logical_size,
    uint64_t offset,
    size_t length,
    void *buffer,
    size_t *out_read
) {
    *out_read = 0;
    if (length == 0 || offset >= logical_size) return 0;
    if (offset + length > logical_size) length = (size_t)(logical_size - offset);
    memset(buffer, 0, length);

    apfs_ext_read_t er = { ap, offset, length, (uint8_t *)buffer, 0, 0 };
    (void)apfs_btree_scan_id(
        ap, tree_paddr, ap->vol_omap_tree_paddr, max_xid, 1,
        1, private_id, read_extent_cb, &er, 0
    );
    if (er.err != 0) return er.err;
    *out_read = length;
    return 0;
}

static void decode_ino_context(const apfs_priv_t *ap, uint64_t pub_ino, uint64_t *out_tree_paddr, uint64_t *out_xid, uint64_t *out_raw_ino, uint8_t *out_snap_tag) {
    if (ap->pinned_snap_idx >= 0 && (size_t)ap->pinned_snap_idx < ap->snap_count) {
        *out_tree_paddr = ap->snaps[ap->pinned_snap_idx].root_tree_paddr;
        *out_xid = ap->snaps[ap->pinned_snap_idx].xid;
        *out_raw_ino = pub_ino & 0x00FFFFFFFFFFFFFFULL;
        *out_snap_tag = 0;
        return;
    }
    uint8_t tag = (uint8_t)(pub_ino >> 56);
    if (tag >= 1U && tag <= ap->snap_count) {
        *out_tree_paddr = ap->snaps[tag - 1U].root_tree_paddr;
        *out_xid = ap->snaps[tag - 1U].xid;
        *out_raw_ino = pub_ino & 0x00FFFFFFFFFFFFFFULL;
        *out_snap_tag = tag;
    } else {
        *out_tree_paddr = ap->live_root_tree_paddr;
        *out_xid = ap->live_xid;
        *out_raw_ino = pub_ino;
        *out_snap_tag = 0;
    }
}

static int extract_drec_name(const uint8_t *key, uint16_t key_len, char *out_name, size_t name_cap) {
    if (key_len >= 13U) {
        uint32_t nh = aex_le32(key + 8U);
        uint16_t nlen = (uint16_t)(nh & 0x3FFU);
        if (nlen > 0 && 12U + nlen == key_len && key[12U + nlen - 1U] == '\0') {
            size_t cpy = (nlen - 1U < name_cap - 1U) ? (nlen - 1U) : (name_cap - 1U);
            memcpy(out_name, key + 12U, cpy);
            out_name[cpy] = '\0';
            return 0;
        }
    }
    if (key_len >= 11U) {
        uint16_t nlen = aex_le16(key + 8U);
        if (nlen > 0 && 10U + nlen <= key_len) {
            size_t cpy = (nlen < name_cap) ? nlen : (name_cap - 1U);
            memcpy(out_name, key + 10U, cpy);
            out_name[cpy] = '\0';
            return 0;
        }
    }
    return -EINVAL;
}

typedef struct {
    aex_readdir_cb cb;
    void          *user_ctx;
    uint8_t        snap_tag;
    int            stopped;
} apfs_readdir_ctx_t;

static int drec_readdir_cb(
    void *ctx,
    uint64_t obj_id,
    uint8_t obj_type,
    const uint8_t *key,
    uint16_t key_len,
    const uint8_t *val,
    uint16_t val_len
) {
    (void)obj_id;
    if (obj_type != APFS_TYPE_DIR_REC || val_len < 18U) return 0;
    apfs_readdir_ctx_t *rcx = (apfs_readdir_ctx_t *)ctx;
    char name[256];
    if (extract_drec_name(key, key_len, name, sizeof(name)) != 0 || !name[0]) return 0;

    uint64_t child_ino = aex_le64(val + 0U) & 0x00FFFFFFFFFFFFFFULL;
    if (rcx->snap_tag > 0) child_ino |= ((uint64_t)rcx->snap_tag << 56);
    uint16_t dt = aex_le16(val + 16U) & 0x000FU;
    aex_ftype_t ft = (dt == 4U) ? AEX_FT_DIR : (dt == 10U) ? AEX_FT_SYMLINK : AEX_FT_REG;
    if (rcx->cb(rcx->user_ctx, name, child_ino, ft) != 0) {
        rcx->stopped = 1;
        return 1;
    }
    return 0;
}

typedef struct {
    const char *want_name;
    int         case_insensitive;
    uint8_t     snap_tag;
    uint64_t    found_ino;
    int         found;
} apfs_lookup_ctx_t;

static int drec_lookup_cb(
    void *ctx,
    uint64_t obj_id,
    uint8_t obj_type,
    const uint8_t *key,
    uint16_t key_len,
    const uint8_t *val,
    uint16_t val_len
) {
    (void)obj_id;
    if (obj_type != APFS_TYPE_DIR_REC || val_len < 18U) return 0;
    apfs_lookup_ctx_t *lcx = (apfs_lookup_ctx_t *)ctx;
    char name[256];
    if (extract_drec_name(key, key_len, name, sizeof(name)) != 0) return 0;
    int match = lcx->case_insensitive ? (aex_strcasecmp_utf8(name, lcx->want_name) == 0) : (strcmp(name, lcx->want_name) == 0);
    if (match) {
        uint64_t child_ino = aex_le64(val + 0U) & 0x00FFFFFFFFFFFFFFULL;
        if (lcx->snap_tag > 0) child_ino |= ((uint64_t)lcx->snap_tag << 56);
        lcx->found_ino = child_ino;
        lcx->found = 1;
        return 1;
    }
    return 0;
}

/* ---------------- APFS Vtable Operations ---------------- */

static void apfs_close_priv(void *priv) {
    apfs_priv_t *ap = (apfs_priv_t *)priv;
    if (!ap) return;
    memset(&ap->vek_dec_k1, 0, sizeof(ap->vek_dec_k1));
    memset(&ap->vek_enc_k2, 0, sizeof(ap->vek_enc_k2));
    free(ap);
}

static uint64_t apfs_root_ino(const void *priv) {
    (void)priv;
    return 2ULL; /* APFS_ROOT_DIR_INO_NUM = 2 */
}

static int apfs_list_snapshots(void *priv, aex_snapshot_desc_t *out_snaps, size_t max_snaps, size_t *out_count) {
    const apfs_priv_t *ap = (const apfs_priv_t *)priv;
    *out_count = ap->snap_count;
    if (out_snaps) {
        size_t n = (ap->snap_count < max_snaps) ? ap->snap_count : max_snaps;
        for (size_t i = 0; i < n; i++) {
            out_snaps[i].xid = ap->snaps[i].xid;
            out_snaps[i].timestamp_sec = ap->snaps[i].create_sec;
            snprintf(out_snaps[i].name, sizeof(out_snaps[i].name), "%s", ap->snaps[i].name);
        }
    }
    return 0;
}

static int apfs_statfs(void *priv, uint64_t *total_bytes, uint64_t *used_bytes, uint32_t *block_size) {
    const apfs_priv_t *ap = (const apfs_priv_t *)priv;
    if (total_bytes) *total_bytes = ap->nx_blocks * ap->block_size;
    if (used_bytes) *used_bytes = ap->used_blocks * ap->block_size;
    if (block_size) *block_size = ap->block_size;
    return 0;
}

static int apfs_getattr(void *priv, uint64_t ino, aex_attr_t *out_attr) {
    const apfs_priv_t *ap = (const apfs_priv_t *)priv;
    memset(out_attr, 0, sizeof(*out_attr));

    if (ino == APFS_SNAP_DIR_INO || ino == APFS_BACKUPS_DIR_INO) {
        out_attr->ino = ino;
        out_attr->mode = S_IFDIR | 0555;
        out_attr->nlink = (uint32_t)(ap->snap_count + 2U);
        out_attr->ftype = AEX_FT_DIR;
        return 0;
    }

    uint64_t tree_paddr = 0, xid = 0, raw_ino = 0;
    uint8_t snap_tag = 0;
    decode_ino_context(ap, ino, &tree_paddr, &xid, &raw_ino, &snap_tag);

    apfs_inode_info_t ii;
    memset(&ii, 0, sizeof(ii));
    (void)apfs_btree_scan_id(ap, tree_paddr, ap->vol_omap_tree_paddr, xid, 1, 1, raw_ino, parse_inode_cb, &ii, 0);
    if (!ii.found) return -ENOENT;

    out_attr->ino = ino;
    out_attr->uid = ii.uid;
    out_attr->gid = ii.gid;
    out_attr->nlink = ii.nlink ? ii.nlink : 1U;
    out_attr->crtime_sec = ii.crtime_sec;
    out_attr->mtime_sec = ii.mtime_sec;
    out_attr->ctime_sec = ii.ctime_sec;
    out_attr->atime_sec = ii.atime_sec;

    uint16_t fmt = ii.mode & S_IFMT;
    if (fmt == S_IFDIR) {
        out_attr->ftype = AEX_FT_DIR;
        out_attr->mode = S_IFDIR | 0555;
    } else if (fmt == S_IFLNK) {
        out_attr->ftype = AEX_FT_SYMLINK;
        out_attr->mode = S_IFLNK | 0777;
    } else {
        out_attr->ftype = AEX_FT_REG;
        out_attr->mode = S_IFREG | 0444;
        out_attr->size = ((ii.bsd_flags & 0x20U) != 0 && ii.uncomp_size > 0) ? ii.uncomp_size : ii.dstream_size;
        if ((ii.bsd_flags & 0x20U) != 0 && ii.uncomp_size == 0) {
            apfs_xattr_query_t xq = { "com.apple.decmpfs", NULL, 0, 0, 0, 0 };
            (void)apfs_btree_scan_id(ap, tree_paddr, ap->vol_omap_tree_paddr, xid, 1, 1, raw_ino, parse_xattr_cb, &xq, 0);
            if (xq.found && xq.out_data && xq.out_len >= 16U && aex_le32(xq.out_data) == 0x636D7066U) {
                out_attr->size = aex_le64(xq.out_data + 8U);
            }
            free(xq.out_data);
        }
    }
    return 0;
}

static int apfs_readdir(void *priv, uint64_t dir_ino, aex_readdir_cb cb, void *user_ctx) {
    const apfs_priv_t *ap = (const apfs_priv_t *)priv;

    if (dir_ino == APFS_SNAP_DIR_INO || dir_ino == APFS_BACKUPS_DIR_INO) {
        for (size_t i = 0; i < ap->snap_count; i++) {
            const char *entry_name = (dir_ino == APFS_BACKUPS_DIR_INO) ? ap->snaps[i].short_date : ap->snaps[i].name;
            uint64_t snap_root_ino = ((uint64_t)(i + 1U) << 56) | 2ULL;
            if (cb(user_ctx, entry_name, snap_root_ino, AEX_FT_DIR) != 0) break;
        }
        return 0;
    }

    uint64_t tree_paddr = 0, xid = 0, raw_ino = 0;
    uint8_t snap_tag = 0;
    decode_ino_context(ap, dir_ino, &tree_paddr, &xid, &raw_ino, &snap_tag);

    /* Expose synthetic /Snapshots and /Backups (for Time Machine APFS volumes) at live root */
    if (raw_ino == 2ULL && snap_tag == 0 && ap->pinned_snap_idx < 0 && ap->snap_count > 0) {
        if (cb(user_ctx, "Snapshots", APFS_SNAP_DIR_INO, AEX_FT_DIR) != 0) return 0;
        if ((ap->vol_role & 0x0080U) != 0 || strncmp(ap->snaps[0].name, "com.apple.TimeMachine.", 22) == 0) {
            if (cb(user_ctx, "Backups", APFS_BACKUPS_DIR_INO, AEX_FT_DIR) != 0) return 0;
        }
    }

    apfs_readdir_ctx_t rcx = { cb, user_ctx, snap_tag, 0 };
    (void)apfs_btree_scan_id(ap, tree_paddr, ap->vol_omap_tree_paddr, xid, 1, 1, raw_ino, drec_readdir_cb, &rcx, 0);
    return 0;
}

static int apfs_lookup(void *priv, uint64_t dir_ino, const char *name, uint64_t *out_ino) {
    const apfs_priv_t *ap = (const apfs_priv_t *)priv;

    if (dir_ino == APFS_SNAP_DIR_INO || dir_ino == APFS_BACKUPS_DIR_INO) {
        for (size_t i = 0; i < ap->snap_count; i++) {
            if (strcmp(ap->snaps[i].name, name) == 0 || strcmp(ap->snaps[i].short_date, name) == 0) {
                *out_ino = ((uint64_t)(i + 1U) << 56) | 2ULL;
                return 0;
            }
        }
        return -ENOENT;
    }

    uint64_t tree_paddr = 0, xid = 0, raw_ino = 0;
    uint8_t snap_tag = 0;
    decode_ino_context(ap, dir_ino, &tree_paddr, &xid, &raw_ino, &snap_tag);

    if (raw_ino == 2ULL && snap_tag == 0 && ap->pinned_snap_idx < 0 && ap->snap_count > 0) {
        if (aex_strcasecmp_utf8(name, "Snapshots") == 0) {
            *out_ino = APFS_SNAP_DIR_INO;
            return 0;
        }
        if (((ap->vol_role & 0x0080U) != 0 || strncmp(ap->snaps[0].name, "com.apple.TimeMachine.", 22) == 0) &&
            aex_strcasecmp_utf8(name, "Backups") == 0) {
            *out_ino = APFS_BACKUPS_DIR_INO;
            return 0;
        }
    }

    apfs_lookup_ctx_t lcx = { name, ap->case_insensitive, snap_tag, 0, 0 };
    (void)apfs_btree_scan_id(ap, tree_paddr, ap->vol_omap_tree_paddr, xid, 1, 1, raw_ino, drec_lookup_cb, &lcx, 0);
    if (!lcx.found) return -ENOENT;
    *out_ino = lcx.found_ino;
    return 0;
}

static int apfs_read_data(
    void *priv,
    uint64_t ino,
    int is_rsrc,
    uint64_t offset,
    size_t length,
    void *buffer,
    size_t *out_read
) {
    const apfs_priv_t *ap = (const apfs_priv_t *)priv;
    if (ino == APFS_SNAP_DIR_INO || ino == APFS_BACKUPS_DIR_INO) return -EISDIR;

    uint64_t tree_paddr = 0, xid = 0, raw_ino = 0;
    uint8_t snap_tag = 0;
    decode_ino_context(ap, ino, &tree_paddr, &xid, &raw_ino, &snap_tag);

    apfs_inode_info_t ii;
    memset(&ii, 0, sizeof(ii));
    (void)apfs_btree_scan_id(ap, tree_paddr, ap->vol_omap_tree_paddr, xid, 1, 1, raw_ino, parse_inode_cb, &ii, 0);
    if (!ii.found) return -ENOENT;
    if ((ii.mode & S_IFMT) == S_IFDIR) return -EISDIR;

    if (is_rsrc) {
        apfs_xattr_query_t rq = { "com.apple.ResourceFork", NULL, 0, 0, 0, 0 };
        (void)apfs_btree_scan_id(ap, tree_paddr, ap->vol_omap_tree_paddr, xid, 1, 1, raw_ino, parse_xattr_cb, &rq, 0);
        if (!rq.found) { *out_read = 0; return 0; }
        if (rq.out_data) {
            if (offset >= rq.out_len) *out_read = 0;
            else {
                size_t av = rq.out_len - (size_t)offset;
                if (av > length) av = length;
                memcpy(buffer, rq.out_data + offset, av);
                *out_read = av;
            }
            free(rq.out_data);
            return 0;
        }
        return read_dstream_bytes(ap, tree_paddr, xid, rq.dstream_oid, rq.dstream_size, offset, length, buffer, out_read);
    }

    /* Transparent UF_COMPRESSED (com.apple.decmpfs) decompression */
    if ((ii.bsd_flags & 0x20U) != 0) {
        apfs_xattr_query_t xq = { "com.apple.decmpfs", NULL, 0, 0, 0, 0 };
        (void)apfs_btree_scan_id(ap, tree_paddr, ap->vol_omap_tree_paddr, xid, 1, 1, raw_ino, parse_xattr_cb, &xq, 0);
        if (xq.found && xq.out_data) {
            uint8_t *rbuf = NULL;
            size_t rlen = 0;
            apfs_xattr_query_t rq = { "com.apple.ResourceFork", NULL, 0, 0, 0, 0 };
            (void)apfs_btree_scan_id(ap, tree_paddr, ap->vol_omap_tree_paddr, xid, 1, 1, raw_ino, parse_xattr_cb, &rq, 0);
            if (rq.found) {
                if (rq.out_data) {
                    rbuf = rq.out_data;
                    rlen = rq.out_len;
                } else if (rq.dstream_size > 0 && rq.dstream_size <= (64ULL << 20)) {
                    rbuf = (uint8_t *)malloc((size_t)rq.dstream_size);
                    if (rbuf) (void)read_dstream_bytes(ap, tree_paddr, xid, rq.dstream_oid, rq.dstream_size, 0, (size_t)rq.dstream_size, rbuf, &rlen);
                }
            }
            uint8_t *decomp = NULL;
            size_t decomp_len = 0;
            int rc = aex_decmpfs_decompress(xq.out_data, xq.out_len, rbuf, rlen, ii.uncomp_size, &decomp, &decomp_len);
            free(xq.out_data);
            free(rbuf);
            if (rc == 0 && decomp) {
                if (offset >= decomp_len) *out_read = 0;
                else {
                    size_t av = decomp_len - (size_t)offset;
                    if (av > length) av = length;
                    memcpy(buffer, decomp + offset, av);
                    *out_read = av;
                }
                free(decomp);
                return 0;
            }
            free(decomp);
        } else {
            free(xq.out_data);
        }
    }

    return read_dstream_bytes(ap, tree_paddr, xid, ii.private_id, ii.dstream_size, offset, length, buffer, out_read);
}

static int apfs_readlink(void *priv, uint64_t ino, char *buffer, size_t buffer_cap, size_t *out_len) {
    const apfs_priv_t *ap = (const apfs_priv_t *)priv;
    uint64_t tree_paddr = 0, xid = 0, raw_ino = 0;
    uint8_t snap_tag = 0;
    decode_ino_context(ap, ino, &tree_paddr, &xid, &raw_ino, &snap_tag);

    apfs_xattr_query_t sq = { "com.apple.fs.symlink", NULL, 0, 0, 0, 0 };
    (void)apfs_btree_scan_id(ap, tree_paddr, ap->vol_omap_tree_paddr, xid, 1, 1, raw_ino, parse_xattr_cb, &sq, 0);
    if (sq.found && sq.out_data) {
        size_t slen = sq.out_len;
        while (slen > 0 && sq.out_data[slen - 1U] == '\0') slen--;
        if (slen >= buffer_cap) slen = buffer_cap - 1U;
        memcpy(buffer, sq.out_data, slen);
        buffer[slen] = '\0';
        free(sq.out_data);
        if (out_len) *out_len = slen;
        return 0;
    }
    free(sq.out_data);
    return -EINVAL;
}

static const aex_fs_ops_t g_apfs_ops = {
    .close_priv     = apfs_close_priv,
    .root_ino       = apfs_root_ino,
    .list_snapshots = apfs_list_snapshots,
    .statfs         = apfs_statfs,
    .getattr        = apfs_getattr,
    .readdir        = apfs_readdir,
    .lookup         = apfs_lookup,
    .read_data      = apfs_read_data,
    .readlink       = apfs_readlink,
};

/* ---------------- APFS Probe, Volume Enumeration, and Open ---------------- */

int aex_apfs_probe_slice(const aex_slice_t *sl) {
    uint8_t b0[64];
    if (aex_slice_read(sl, 0ULL, sizeof(b0), b0) != 0) return -EIO;
    if (aex_le32(b0 + 32U) != APFS_NX_MAGIC) return -EINVAL;
    uint32_t bsz = aex_le32(b0 + 36U);
    if (bsz < 4096U || bsz > 65536U || (bsz & (bsz - 1U)) != 0) return -EINVAL;
    return 0;
}

int aex_apfs_list_volumes(
    const aex_slice_t *sl,
    const char *password,
    aex_volume_desc_t *out_vols,
    size_t max_vols,
    size_t *out_count
) {
    (void)password;
    *out_count = 0;
    uint8_t *nxsb = NULL;
    uint32_t bsz = 0;
    int rc = find_latest_nxsb(sl, &nxsb, &bsz);
    if (rc != 0) return rc;

    uint64_t nx_xid = aex_le64(nxsb + 16U);
    uint64_t nx_blocks = aex_le64(nxsb + 40U);
    uint64_t nx_omap_paddr = aex_le64(nxsb + 160U);
    uint64_t nx_omap_tree = 0;
    rc = read_omap_tree_paddr(sl, bsz, nx_omap_paddr, &nx_omap_tree);
    if (rc != 0) { free(nxsb); return rc; }

    uint8_t *vbuf = (uint8_t *)malloc(bsz);
    if (!vbuf) { free(nxsb); return -ENOMEM; }

    size_t vcnt = 0;
    for (int slot = 0; slot < 100; slot++) {
        uint64_t fs_oid = aex_le64(nxsb + 184U + (size_t)slot * 8U);
        if (fs_oid == 0) continue;
        uint64_t vpaddr = 0;
        if (omap_lookup(sl, bsz, nx_omap_tree, fs_oid, nx_xid, &vpaddr) != 0) continue;
        if (read_raw_block(sl, bsz, vpaddr, vbuf) != 0 || verify_apfs_obj(vbuf, bsz) != 0) continue;
        if (aex_le32(vbuf + 32U) != APFS_VOL_MAGIC) continue;

        if (out_vols && vcnt < max_vols) {
            aex_volume_desc_t *vd = &out_vols[vcnt];
            memset(vd, 0, sizeof(*vd));
            vd->index = (uint32_t)vcnt;
            vd->kind = AEX_FS_APFS;
            uint64_t fs_flags = aex_le64(vbuf + 264U);
            vd->is_encrypted = ((fs_flags & 0x01ULL) == 0) ? 1 : 0;
            uint16_t role = aex_le16(vbuf + 964U);
            vd->is_time_machine = ((role & 0x0080U) != 0) ? 1 : 0;
            vd->snapshot_count = (uint32_t)aex_le64(vbuf + 216U);
            vd->total_bytes = nx_blocks * bsz;
            vd->used_bytes = aex_le64(vbuf + 88U) * bsz;
            memcpy(vd->name, vbuf + 704U, 127U);
            vd->name[127] = '\0';

            const uint8_t *u = vbuf + 240U;
            snprintf(vd->uuid, sizeof(vd->uuid),
                     "%02X%02X%02X%02X-%02X%02X-%02X%02X-%02X%02X-%02X%02X%02X%02X%02X%02X",
                     u[0],u[1],u[2],u[3], u[4],u[5], u[6],u[7], u[8],u[9], u[10],u[11],u[12],u[13],u[14],u[15]);
            snprintf(vd->role, sizeof(vd->role), "%s",
                     (role & 0x0080U) ? "TimeMachine" : (role & 0x0040U) ? "Data" : (role & 0x0001U) ? "System" : "Standard");
        }
        vcnt++;
    }

    free(vbuf);
    free(nxsb);
    *out_count = vcnt;
    return (vcnt > 0) ? 0 : -ENOENT;
}

int aex_apfs_open(aex_t *h, int volume_index, const char *snapshot_name, const char *password) {
    uint8_t *nxsb = NULL;
    uint32_t bsz = 0;
    int rc = find_latest_nxsb(&h->slice, &nxsb, &bsz);
    if (rc != 0) return rc;

    apfs_priv_t *ap = (apfs_priv_t *)calloc(1, sizeof(apfs_priv_t));
    if (!ap) { free(nxsb); return -ENOMEM; }
    ap->slice = h->slice;
    ap->block_size = bsz;
    ap->nx_blocks = aex_le64(nxsb + 40U);
    ap->nx_xid = aex_le64(nxsb + 16U);
    memcpy(ap->nx_uuid, nxsb + 72U, 16U);
    ap->nx_keybag_paddr = aex_le64(nxsb + 1296U);
    ap->nx_keybag_blocks = aex_le64(nxsb + 1304U);
    ap->pinned_snap_idx = -1;

    uint64_t nx_omap_paddr = aex_le64(nxsb + 160U);
    rc = read_omap_tree_paddr(&h->slice, bsz, nx_omap_paddr, &ap->nx_omap_tree_paddr);
    if (rc != 0) { free(ap); free(nxsb); return rc; }

    /* Select volume slot: if volume_index < 0, prefer Backup or Data volume over sealed System stub */
    uint8_t *vbuf = (uint8_t *)malloc(bsz);
    uint8_t *chosen_vbuf = (uint8_t *)malloc(bsz);
    if (!vbuf || !chosen_vbuf) { free(vbuf); free(chosen_vbuf); free(ap); free(nxsb); return -ENOMEM; }

    int cur_idx = 0, found_vol = 0, best_score = -1;
    for (int slot = 0; slot < 100; slot++) {
        uint64_t fs_oid = aex_le64(nxsb + 184U + (size_t)slot * 8U);
        if (fs_oid == 0) continue;
        uint64_t vpaddr = 0;
        if (omap_lookup(&h->slice, bsz, ap->nx_omap_tree_paddr, fs_oid, ap->nx_xid, &vpaddr) != 0) continue;
        if (read_raw_block(&h->slice, bsz, vpaddr, vbuf) != 0 || verify_apfs_obj(vbuf, bsz) != 0) continue;
        if (aex_le32(vbuf + 32U) != APFS_VOL_MAGIC) continue;

        if (volume_index >= 0) {
            if (cur_idx == volume_index) {
                memcpy(chosen_vbuf, vbuf, bsz);
                found_vol = 1;
                break;
            }
        } else {
            uint16_t role = aex_le16(vbuf + 964U);
            int score = (role & 0x0080U) ? 30 : (role & 0x0040U) ? 20 : (role == 0) ? 15 : 5;
            if (score > best_score) {
                memcpy(chosen_vbuf, vbuf, bsz);
                best_score = score;
                found_vol = 1;
            }
        }
        cur_idx++;
    }
    free(vbuf);
    free(nxsb);

    if (!found_vol) {
        free(chosen_vbuf);
        free(ap);
        return -ENOENT;
    }

    ap->live_xid = aex_le64(chosen_vbuf + 16U);
    uint64_t incompat = aex_le64(chosen_vbuf + 56U);
    ap->case_insensitive = ((incompat & 0x09ULL) != 0) ? 1 : 0;
    ap->used_blocks = aex_le64(chosen_vbuf + 88U);
    ap->vol_role = aex_le16(chosen_vbuf + 964U);
    memcpy(h->vol_name, chosen_vbuf + 704U, 127U);
    h->vol_name[127] = '\0';

    uint64_t fs_flags = aex_le64(chosen_vbuf + 264U);
    ap->encrypted = ((fs_flags & 0x01ULL) == 0) ? 1 : 0;
    if (ap->encrypted) {
        uint8_t vek[32];
        rc = unwrap_apfs_filevault_vek(ap, chosen_vbuf + 240U, password, vek);
        if (rc != 0) {
            free(chosen_vbuf);
            free(ap);
            return rc;
        }
        aex_aes_init_dec(&ap->vek_dec_k1, vek, 16U);
        aex_aes_init_enc(&ap->vek_enc_k2, vek + 16U, 16U);
        memset(vek, 0, sizeof(vek));
    }

    uint64_t vol_omap_paddr = aex_le64(chosen_vbuf + 128U);
    uint64_t root_tree_oid = aex_le64(chosen_vbuf + 136U);
    uint64_t snap_meta_paddr = aex_le64(chosen_vbuf + 152U);
    free(chosen_vbuf);

    rc = read_omap_tree_paddr(&h->slice, bsz, vol_omap_paddr, &ap->vol_omap_tree_paddr);
    if (rc != 0) { apfs_close_priv(ap); return rc; }

    rc = omap_lookup(&h->slice, bsz, ap->vol_omap_tree_paddr, root_tree_oid, ap->live_xid, &ap->live_root_tree_paddr);
    if (rc != 0) { apfs_close_priv(ap); return rc; }

    /* Load Snapshot Metadata B-tree (unencrypted physical B-tree; encrypted if FileVault 2) */
    if (snap_meta_paddr != 0) {
        (void)apfs_btree_scan_id(ap, snap_meta_paddr, 0ULL, ap->live_xid, ap->encrypted, 0, 0ULL, snap_meta_cb, ap, 0);
    }

    if (snapshot_name && snapshot_name[0]) {
        int matched = -1;
        for (size_t i = 0; i < ap->snap_count; i++) {
            if (strcmp(ap->snaps[i].name, snapshot_name) == 0 ||
                strcmp(ap->snaps[i].short_date, snapshot_name) == 0) {
                matched = (int)i;
                break;
            }
        }
        if (matched < 0) { apfs_close_priv(ap); return -ENOENT; }
        ap->pinned_snap_idx = matched;
    }

    h->kind = AEX_FS_APFS;
    h->ops = &g_apfs_ops;
    h->priv = ap;
    return 0;
}
