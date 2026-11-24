#include "internal.h"

/* =========================================================================
 * Minix v1 / v2 / v3 Read-Only Driver
 * ========================================================================= */
typedef struct {
    int version;           /* 1, 2, or 3 */
    uint32_t ninodes;
    uint64_t nzones;
    uint32_t imap_blocks;
    uint32_t zmap_blocks;
    uint32_t block_size;
    uint8_t log_zone_size;
    uint16_t dir_entry_size; /* 16 (v1-14), 32 (v1/v2-30), 64 (v3-60) */
    uint16_t name_max;
    uint64_t inode_table_off;
} minix_priv_t;

static int minix_mount(legacyfs_t *fs) {
    uint8_t sb[64];
    int rc = lfs_read_bytes(fs, 1024ULL, sizeof(sb), sb);
    if (rc != 0) return rc;

    minix_priv_t *p = (minix_priv_t *)calloc(1, sizeof(minix_priv_t));
    if (!p) return -ENOMEM;

    uint16_t m16 = lfs_le16(sb + 16);
    uint16_t m3_magic = lfs_le16(sb + 24);

    if (m3_magic == 0x4D5AU) {
        p->version = 3;
        p->ninodes = lfs_le32(sb + 0);
        p->imap_blocks = lfs_le16(sb + 6);
        p->zmap_blocks = lfs_le16(sb + 8);
        p->log_zone_size = (uint8_t)lfs_le16(sb + 12);
        p->nzones = lfs_le32(sb + 20);
        p->block_size = lfs_le16(sb + 28);
        p->dir_entry_size = 64;
        p->name_max = 60;
    } else if (m16 == 0x137FU || m16 == 0x138FU || m16 == 0x2468U || m16 == 0x2478U) {
        p->version = (m16 == 0x137FU || m16 == 0x138FU) ? 1 : 2;
        p->ninodes = lfs_le16(sb + 0);
        p->nzones = (p->version == 2) ? lfs_le32(sb + 20) : lfs_le16(sb + 2);
        p->imap_blocks = lfs_le16(sb + 4);
        p->zmap_blocks = lfs_le16(sb + 6);
        p->log_zone_size = (uint8_t)lfs_le16(sb + 10);
        p->block_size = 1024U;
        if (m16 == 0x138FU || m16 == 0x2478U) {
            p->dir_entry_size = 32;
            p->name_max = 30;
        } else {
            p->dir_entry_size = 16;
            p->name_max = 14;
        }
    } else {
        free(p);
        return -EINVAL;
    }

    if (p->ninodes == 0 || p->block_size < 1024U || !lfs_is_pow2_u32(p->block_size) || p->log_zone_size > 4) {
        free(p);
        return -EINVAL;
    }

    /* Boot + Superblock occupy 2 blocks in v1/v2 (2048B) or 2048B + bitmaps in v3 (2 blocks if block_size>=1024). */
    uint64_t sb_end_block = (p->block_size == 1024U) ? 2ULL : (2048ULL / p->block_size > 0 ? 2048ULL / p->block_size : 1ULL);
    if (p->version == 3 && p->block_size > 1024U) {
        sb_end_block = 2ULL; /* Minix v3 places imap at block 2 */
    }
    p->inode_table_off = (sb_end_block + (uint64_t)p->imap_blocks + (uint64_t)p->zmap_blocks) * (uint64_t)p->block_size;
    fs->priv = p;
    return 0;
}

static void minix_unmount(legacyfs_t *fs) {
    free(fs->priv);
    fs->priv = NULL;
}

static uint64_t minix_root_ino(const legacyfs_t *fs) {
    (void)fs;
    return 1ULL;
}

typedef struct {
    legacyfs_attr_t attr;
    uint32_t zones[10];
} minix_inode_t;

static int minix_read_inode(legacyfs_t *fs, uint64_t ino, minix_inode_t *out) {
    const minix_priv_t *p = (const minix_priv_t *)fs->priv;
    if (ino == 0 || ino > p->ninodes) return -ENOENT;

    size_t isz = (p->version == 1) ? 32U : 64U;
    uint8_t raw[64];
    int rc = lfs_read_bytes(fs, p->inode_table_off + (ino - 1ULL) * isz, isz, raw);
    if (rc != 0) return rc;

    memset(out, 0, sizeof(*out));
    out->attr.ino = ino;
    if (p->version == 1) {
        out->attr.mode = lfs_le16(raw + 0);
        out->attr.uid = lfs_le16(raw + 2);
        out->attr.size = lfs_le32(raw + 4);
        out->attr.mtime_sec = lfs_le32(raw + 8);
        out->attr.atime_sec = out->attr.mtime_sec;
        out->attr.ctime_sec = out->attr.mtime_sec;
        out->attr.gid = raw[12];
        out->attr.nlink = raw[13];
        for (int i = 0; i < 9; i++) {
            out->zones[i] = lfs_le16(raw + 14 + i * 2);
        }
    } else {
        out->attr.mode = lfs_le16(raw + 0);
        out->attr.nlink = lfs_le16(raw + 2);
        out->attr.uid = lfs_le16(raw + 4);
        out->attr.gid = lfs_le16(raw + 6);
        out->attr.size = lfs_le32(raw + 8);
        out->attr.atime_sec = lfs_le32(raw + 12);
        out->attr.mtime_sec = lfs_le32(raw + 16);
        out->attr.ctime_sec = lfs_le32(raw + 20);
        for (int i = 0; i < 10; i++) {
            out->zones[i] = lfs_le32(raw + 24 + i * 4);
        }
    }
    if (out->attr.mode == 0) return -ENOENT;
    out->attr.blocks_512 = (out->attr.size + 511ULL) / 512ULL;
    out->attr.ftype = lfs_mode_to_ftype(out->attr.mode);
    return 0;
}

static int minix_map_block(legacyfs_t *fs, const minix_inode_t *mi, uint64_t file_blk, uint64_t *out_disk_blk) {
    const minix_priv_t *p = (const minix_priv_t *)fs->priv;
    uint32_t direct_cnt = (p->version == 1) ? 7U : 7U;
    uint32_t ptr_size = (p->version == 1) ? 2U : 4U;
    uint64_t ptrs_per_blk = p->block_size / ptr_size;

    uint64_t zone_shift = p->log_zone_size;
    uint64_t zone_idx = file_blk >> zone_shift;
    uint64_t in_zone_blk = file_blk & ((1ULL << zone_shift) - 1ULL);

    uint32_t zone_num = 0;
    if (zone_idx < direct_cnt) {
        zone_num = mi->zones[zone_idx];
    } else {
        zone_idx -= direct_cnt;
        uint8_t *ibuf = (uint8_t *)malloc(p->block_size);
        if (!ibuf) return -ENOMEM;

        if (zone_idx < ptrs_per_blk) {
            uint32_t ind = mi->zones[7];
            if (ind != 0) {
                if (lfs_read_bytes(fs, ((uint64_t)ind << zone_shift) * p->block_size, p->block_size, ibuf) != 0) {
                    free(ibuf);
                    return -EIO;
                }
                zone_num = (ptr_size == 2) ? lfs_le16(ibuf + zone_idx * 2) : lfs_le32(ibuf + zone_idx * 4);
            }
        } else {
            zone_idx -= ptrs_per_blk;
            if (zone_idx < ptrs_per_blk * ptrs_per_blk) {
                uint32_t dind = mi->zones[8];
                if (dind != 0) {
                    uint64_t l1 = zone_idx / ptrs_per_blk;
                    uint64_t l2 = zone_idx % ptrs_per_blk;
                    if (lfs_read_bytes(fs, ((uint64_t)dind << zone_shift) * p->block_size, p->block_size, ibuf) != 0) {
                        free(ibuf);
                        return -EIO;
                    }
                    uint32_t ind = (ptr_size == 2) ? lfs_le16(ibuf + l1 * 2) : lfs_le32(ibuf + l1 * 4);
                    if (ind != 0) {
                        if (lfs_read_bytes(fs, ((uint64_t)ind << zone_shift) * p->block_size, p->block_size, ibuf) != 0) {
                            free(ibuf);
                            return -EIO;
                        }
                        zone_num = (ptr_size == 2) ? lfs_le16(ibuf + l2 * 2) : lfs_le32(ibuf + l2 * 4);
                    }
                }
            }
        }
        free(ibuf);
    }

    if (zone_num == 0) {
        *out_disk_blk = 0;
    } else {
        *out_disk_blk = ((uint64_t)zone_num << zone_shift) + in_zone_blk;
    }
    return 0;
}

static int minix_read_inode_data(legacyfs_t *fs, const minix_inode_t *mi, uint64_t offset, size_t length, void *buffer, size_t *out_read) {
    const minix_priv_t *p = (const minix_priv_t *)fs->priv;
    if (offset >= mi->attr.size || length == 0) {
        if (out_read) *out_read = 0;
        return 0;
    }
    size_t to_read = length;
    if ((uint64_t)to_read > mi->attr.size - offset) {
        to_read = (size_t)(mi->attr.size - offset);
    }

    uint8_t *dst = (uint8_t *)buffer;
    uint8_t *blk = (uint8_t *)malloc(p->block_size);
    if (!blk) return -ENOMEM;

    size_t done = 0;
    while (done < to_read) {
        uint64_t cur_off = offset + done;
        uint64_t fblk = cur_off / p->block_size;
        size_t boff = (size_t)(cur_off % p->block_size);
        size_t chunk = p->block_size - boff;
        if (chunk > to_read - done) chunk = to_read - done;

        uint64_t dblk = 0;
        int mrc = minix_map_block(fs, mi, fblk, &dblk);
        if (mrc != 0) {
            free(blk);
            return mrc;
        }
        if (dblk == 0) {
            memset(dst + done, 0, chunk);
        } else {
            int rrc = lfs_read_bytes(fs, dblk * p->block_size, p->block_size, blk);
            if (rrc != 0) {
                free(blk);
                return rrc;
            }
            memcpy(dst + done, blk + boff, chunk);
        }
        done += chunk;
    }

    free(blk);
    if (out_read) *out_read = done;
    return 0;
}

static int minix_getattr(legacyfs_t *fs, uint64_t ino, legacyfs_attr_t *out_attr) {
    minix_inode_t mi;
    int rc = minix_read_inode(fs, ino, &mi);
    if (rc != 0) return rc;
    *out_attr = mi.attr;
    return 0;
}

static int minix_readdir(legacyfs_t *fs, uint64_t dir_ino, legacyfs_readdir_cb cb, void *user_ctx) {
    const minix_priv_t *p = (const minix_priv_t *)fs->priv;
    minix_inode_t mi;
    int rc = minix_read_inode(fs, dir_ino, &mi);
    if (rc != 0) return rc;
    if (mi.attr.ftype != LEGACYFS_FT_DIR) return -ENOTDIR;
    if (mi.attr.size > (16ULL * 1024ULL * 1024ULL)) return -EIO;

    uint8_t *dirbuf = (uint8_t *)malloc((size_t)mi.attr.size + 1U);
    if (!dirbuf) return -ENOMEM;

    size_t got = 0;
    rc = minix_read_inode_data(fs, &mi, 0, (size_t)mi.attr.size, dirbuf, &got);
    if (rc != 0) {
        free(dirbuf);
        return rc;
    }

    size_t esz = p->dir_entry_size;
    for (size_t off = 0; off + esz <= got; off += esz) {
        uint32_t cino = (p->version == 3) ? lfs_le32(dirbuf + off) : lfs_le16(dirbuf + off);
        if (cino == 0) continue;

        size_t name_off = (p->version == 3) ? 4U : 2U;
        char name[128];
        size_t nlen = 0;
        while (nlen < p->name_max && dirbuf[off + name_off + nlen] != 0) {
            name[nlen] = (char)dirbuf[off + name_off + nlen];
            nlen++;
        }
        name[nlen] = '\0';
        if (nlen == 0 || strcmp(name, ".") == 0 || strcmp(name, "..") == 0) continue;

        minix_inode_t cmi;
        legacyfs_ftype_t ft = (minix_read_inode(fs, cino, &cmi) == 0) ? cmi.attr.ftype : LEGACYFS_FT_UNKNOWN;
        if (cb(user_ctx, name, cino, ft) != 0) break;
    }

    free(dirbuf);
    return 0;
}

static int minix_read(legacyfs_t *fs, uint64_t ino, uint64_t offset, size_t length, void *buffer, size_t *out_read) {
    minix_inode_t mi;
    int rc = minix_read_inode(fs, ino, &mi);
    if (rc != 0) return rc;
    if (mi.attr.ftype == LEGACYFS_FT_DIR) return -EISDIR;
    if (mi.attr.ftype != LEGACYFS_FT_REG) return -EINVAL;
    return minix_read_inode_data(fs, &mi, offset, length, buffer, out_read);
}

static int minix_readlink(legacyfs_t *fs, uint64_t ino, char *buffer, size_t buffer_size, size_t *out_len) {
    minix_inode_t mi;
    int rc = minix_read_inode(fs, ino, &mi);
    if (rc != 0) return rc;
    if (mi.attr.ftype != LEGACYFS_FT_SYMLINK) return -EINVAL;
    size_t got = 0;
    rc = minix_read_inode_data(fs, &mi, 0, buffer_size - 1, buffer, &got);
    if (rc != 0) return rc;
    buffer[got] = '\0';
    if (out_len) *out_len = got;
    return 0;
}

const legacyfs_ops_t lfs_minix_ops = {
    .mount = minix_mount,
    .unmount = minix_unmount,
    .root_ino = minix_root_ino,
    .statfs = NULL,
    .getattr = minix_getattr,
    .readdir = minix_readdir,
    .lookup = NULL,
    .read = minix_read,
    .readlink = minix_readlink,
};

/* =========================================================================
 * System V (SysV) Read-Only Driver
 * ========================================================================= */
typedef struct {
    uint32_t block_size;
    uint32_t isize_blk;   /* first data zone block index */
    uint32_t fsize_blk;
    uint32_t max_inodes;
    uint64_t itable_off;
} sysv_priv_t;

typedef struct {
    legacyfs_attr_t attr;
    uint32_t addrs[13];
} sysv_inode_t;

static int sysv_mount(legacyfs_t *fs) {
    static const uint64_t sboffs[2] = { 512ULL, 1024ULL };
    uint8_t sb[512];
    for (int i = 0; i < 2; i++) {
        if (lfs_read_bytes(fs, sboffs[i], sizeof(sb), sb) != 0) continue;
        if (lfs_le32(sb + 504) != 0xFD187E20U) continue;
        uint32_t s_type = lfs_le32(sb + 508);
        uint32_t bsize = (s_type == 2) ? 1024U : ((s_type == 3) ? 2048U : 512U);
        uint16_t isize = lfs_le16(sb + 0);
        uint32_t fsize = lfs_le32(sb + 4);
        if (isize < 3 || fsize <= isize) continue;

        sysv_priv_t *p = (sysv_priv_t *)calloc(1, sizeof(sysv_priv_t));
        if (!p) return -ENOMEM;
        p->block_size = bsize;
        p->isize_blk = isize;
        p->fsize_blk = fsize;
        /* Inode table starts at block 2 on standard System V filesystems */
        p->itable_off = 2ULL * (uint64_t)bsize;
        p->max_inodes = ((uint32_t)isize - 2U) * (bsize / 64U);
        fs->priv = p;
        return 0;
    }
    return -EINVAL;
}

static void sysv_unmount(legacyfs_t *fs) {
    free(fs->priv);
    fs->priv = NULL;
}

static uint64_t sysv_root_ino(const legacyfs_t *fs) {
    (void)fs;
    return 2ULL; /* SYSV_ROOT_INO = 2 */
}

static int sysv_read_inode(legacyfs_t *fs, uint64_t ino, sysv_inode_t *out) {
    const sysv_priv_t *p = (const sysv_priv_t *)fs->priv;
    if (ino == 0 || ino > p->max_inodes) return -ENOENT;
    uint8_t raw[64];
    int rc = lfs_read_bytes(fs, p->itable_off + (ino - 1ULL) * 64ULL, sizeof(raw), raw);
    if (rc != 0) return rc;

    memset(out, 0, sizeof(*out));
    out->attr.ino = ino;
    out->attr.mode = lfs_le16(raw + 0);
    if (out->attr.mode == 0) return -ENOENT;
    out->attr.nlink = lfs_le16(raw + 2);
    out->attr.uid = lfs_le16(raw + 4);
    out->attr.gid = lfs_le16(raw + 6);
    out->attr.size = lfs_le32(raw + 8);
    for (int i = 0; i < 13; i++) {
        const uint8_t *a = raw + 12 + i * 3;
        out->addrs[i] = (uint32_t)a[0] | ((uint32_t)a[1] << 8) | ((uint32_t)a[2] << 16);
    }
    out->attr.atime_sec = lfs_le32(raw + 52);
    out->attr.mtime_sec = lfs_le32(raw + 56);
    out->attr.ctime_sec = lfs_le32(raw + 60);
    out->attr.blocks_512 = (out->attr.size + 511ULL) / 512ULL;
    out->attr.ftype = lfs_mode_to_ftype(out->attr.mode);
    return 0;
}

static int sysv_read_data(legacyfs_t *fs, const sysv_inode_t *si, uint64_t offset, size_t length, void *buffer, size_t *out_read) {
    const sysv_priv_t *p = (const sysv_priv_t *)fs->priv;
    if (offset >= si->attr.size || length == 0) {
        if (out_read) *out_read = 0;
        return 0;
    }
    size_t to_read = length;
    if ((uint64_t)to_read > si->attr.size - offset) {
        to_read = (size_t)(si->attr.size - offset);
    }

    uint8_t *dst = (uint8_t *)buffer;
    uint8_t *blk = (uint8_t *)malloc(p->block_size);
    uint8_t *ind = (uint8_t *)malloc(p->block_size);
    if (!blk || !ind) {
        free(blk);
        free(ind);
        return -ENOMEM;
    }

    uint32_t ptrs_per_blk = p->block_size / 4U;
    size_t done = 0;
    while (done < to_read) {
        uint64_t cur = offset + done;
        uint64_t fblk = cur / p->block_size;
        size_t boff = (size_t)(cur % p->block_size);
        size_t chunk = p->block_size - boff;
        if (chunk > to_read - done) chunk = to_read - done;

        uint32_t dblk = 0;
        if (fblk < 10) {
            dblk = si->addrs[fblk];
        } else if (fblk < 10ULL + ptrs_per_blk && si->addrs[10] != 0) {
            if (lfs_read_bytes(fs, (uint64_t)si->addrs[10] * p->block_size, p->block_size, ind) != 0) {
                free(blk);
                free(ind);
                return -EIO;
            }
            dblk = lfs_le32(ind + (fblk - 10ULL) * 4ULL);
        }

        if (dblk == 0) {
            memset(dst + done, 0, chunk);
        } else {
            if (dblk >= p->fsize_blk || lfs_read_bytes(fs, (uint64_t)dblk * p->block_size, p->block_size, blk) != 0) {
                free(blk);
                free(ind);
                return -EIO;
            }
            memcpy(dst + done, blk + boff, chunk);
        }
        done += chunk;
    }

    free(blk);
    free(ind);
    if (out_read) *out_read = done;
    return 0;
}

static int sysv_getattr(legacyfs_t *fs, uint64_t ino, legacyfs_attr_t *out_attr) {
    sysv_inode_t si;
    int rc = sysv_read_inode(fs, ino, &si);
    if (rc != 0) return rc;
    *out_attr = si.attr;
    return 0;
}

static int sysv_readdir(legacyfs_t *fs, uint64_t dir_ino, legacyfs_readdir_cb cb, void *user_ctx) {
    sysv_inode_t si;
    int rc = sysv_read_inode(fs, dir_ino, &si);
    if (rc != 0) return rc;
    if (si.attr.ftype != LEGACYFS_FT_DIR) return -ENOTDIR;
    if (si.attr.size > (8ULL * 1024ULL * 1024ULL)) return -EIO;

    uint8_t *buf = (uint8_t *)malloc((size_t)si.attr.size + 1U);
    if (!buf) return -ENOMEM;
    size_t got = 0;
    rc = sysv_read_data(fs, &si, 0, (size_t)si.attr.size, buf, &got);
    if (rc != 0) {
        free(buf);
        return rc;
    }

    for (size_t off = 0; off + 16U <= got; off += 16U) {
        uint16_t cino = lfs_le16(buf + off);
        if (cino == 0) continue;
        char name[16];
        size_t nlen = 0;
        while (nlen < 14 && buf[off + 2 + nlen] != 0) {
            name[nlen] = (char)buf[off + 2 + nlen];
            nlen++;
        }
        name[nlen] = '\0';
        if (nlen == 0 || strcmp(name, ".") == 0 || strcmp(name, "..") == 0) continue;

        sysv_inode_t csi;
        legacyfs_ftype_t ft = (sysv_read_inode(fs, cino, &csi) == 0) ? csi.attr.ftype : LEGACYFS_FT_UNKNOWN;
        if (cb(user_ctx, name, cino, ft) != 0) break;
    }

    free(buf);
    return 0;
}

static int sysv_read(legacyfs_t *fs, uint64_t ino, uint64_t offset, size_t length, void *buffer, size_t *out_read) {
    sysv_inode_t si;
    int rc = sysv_read_inode(fs, ino, &si);
    if (rc != 0) return rc;
    if (si.attr.ftype == LEGACYFS_FT_DIR) return -EISDIR;
    if (si.attr.ftype != LEGACYFS_FT_REG) return -EINVAL;
    return sysv_read_data(fs, &si, offset, length, buffer, out_read);
}

static int sysv_readlink(legacyfs_t *fs, uint64_t ino, char *buffer, size_t buffer_size, size_t *out_len) {
    sysv_inode_t si;
    int rc = sysv_read_inode(fs, ino, &si);
    if (rc != 0) return rc;
    if (si.attr.ftype != LEGACYFS_FT_SYMLINK) return -EINVAL;
    size_t got = 0;
    rc = sysv_read_data(fs, &si, 0, buffer_size - 1, buffer, &got);
    if (rc != 0) return rc;
    buffer[got] = '\0';
    if (out_len) *out_len = got;
    return 0;
}

const legacyfs_ops_t lfs_sysv_ops = {
    .mount = sysv_mount,
    .unmount = sysv_unmount,
    .root_ino = sysv_root_ino,
    .statfs = NULL,
    .getattr = sysv_getattr,
    .readdir = sysv_readdir,
    .lookup = NULL,
    .read = sysv_read,
    .readlink = sysv_readlink,
};
