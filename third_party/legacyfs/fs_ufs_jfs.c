#include "internal.h"

/* =========================================================================
 * BSD UFS1 / UFS2 (Fast File System) Read-Only Driver
 * ========================================================================= */
typedef struct {
    int is_ufs2;
    uint32_t bsize;
    uint32_t fsize;
    uint32_t frag_per_blk;
    uint32_t iblkno;
    uint32_t cgoffset;
    uint32_t cgmask;
    uint32_t ncg;
    uint32_t ipg;
    uint32_t fpg;
} ufs_priv_t;

typedef struct {
    legacyfs_attr_t attr;
    int64_t db[12];
    int64_t ib[3];
    uint8_t inline_target[120];
    int is_fast_symlink;
} ufs_inode_t;

static int ufs_mount(legacyfs_t *fs) {
    static const uint64_t sboffs[4] = { 65536ULL, 8192ULL, 0ULL, 262144ULL };
    uint8_t sb[1536];

    for (int i = 0; i < 4; i++) {
        if (lfs_read_bytes(fs, sboffs[i], sizeof(sb), sb) != 0) continue;
        uint32_t magic = lfs_le32(sb + 1372);
        if (magic != 0x00011954U && magic != 0x19540119U) continue;

        uint32_t bsize = lfs_le32(sb + 48);
        uint32_t fsize = lfs_le32(sb + 52);
        uint32_t ipg = lfs_le32(sb + 184);
        uint32_t fpg = lfs_le32(sb + 188);
        uint32_t ncg = lfs_le32(sb + 32);
        if (bsize < 4096U || bsize > 65536U || !lfs_is_pow2_u32(bsize)) continue;
        if (fsize < 512U || fsize > bsize || !lfs_is_pow2_u32(fsize)) continue;
        if (ipg == 0 || fpg == 0 || ncg == 0) continue;

        ufs_priv_t *p = (ufs_priv_t *)calloc(1, sizeof(ufs_priv_t));
        if (!p) return -ENOMEM;
        p->is_ufs2 = (magic == 0x19540119U) ? 1 : 0;
        p->iblkno = lfs_le32(sb + 16);
        p->cgoffset = lfs_le32(sb + 24);
        p->cgmask = lfs_le32(sb + 28);
        p->ncg = ncg;
        p->bsize = bsize;
        p->fsize = fsize;
        p->frag_per_blk = bsize / fsize;
        p->ipg = ipg;
        p->fpg = fpg;
        fs->priv = p;
        return 0;
    }
    return -EINVAL;
}

static void ufs_unmount(legacyfs_t *fs) {
    free(fs->priv);
    fs->priv = NULL;
}

static uint64_t ufs_root_ino(const legacyfs_t *fs) {
    (void)fs;
    return 2ULL; /* UFS_ROOTINO = 2 */
}

static int ufs_load_inode(legacyfs_t *fs, uint64_t ino, ufs_inode_t *out) {
    const ufs_priv_t *p = (const ufs_priv_t *)fs->priv;
    uint64_t cg = ino / p->ipg;
    uint64_t cg_ino = ino % p->ipg;
    if (cg >= p->ncg) return -ENOENT;

    uint64_t cgstart = cg * (uint64_t)p->fpg;
    if (!p->is_ufs2) {
        cgstart += (uint64_t)p->cgoffset * (cg & ~(uint64_t)p->cgmask);
    }
    uint64_t itable_byte = (cgstart + (uint64_t)p->iblkno) * (uint64_t)p->fsize;
    size_t isz = p->is_ufs2 ? 256U : 128U;

    uint8_t raw[256];
    int rc = lfs_read_bytes(fs, itable_byte + cg_ino * isz, isz, raw);
    if (rc != 0) return rc;

    memset(out, 0, sizeof(*out));
    out->attr.ino = ino;
    out->attr.mode = lfs_le16(raw + 0);
    if (out->attr.mode == 0) return -ENOENT;
    out->attr.nlink = lfs_le16(raw + 2);

    if (p->is_ufs2) {
        out->attr.uid = lfs_le32(raw + 4);
        out->attr.gid = lfs_le32(raw + 8);
        out->attr.size = lfs_le64(raw + 16);
        out->attr.blocks_512 = lfs_le64(raw + 24);
        out->attr.atime_sec = (int64_t)lfs_le64(raw + 32);
        out->attr.mtime_sec = (int64_t)lfs_le64(raw + 40);
        out->attr.ctime_sec = (int64_t)lfs_le64(raw + 48);
        for (int i = 0; i < 12; i++) out->db[i] = (int64_t)lfs_le64(raw + 112 + i * 8);
        for (int i = 0; i < 3; i++)  out->ib[i] = (int64_t)lfs_le64(raw + 208 + i * 8);
        if (lfs_mode_to_ftype(out->attr.mode) == LEGACYFS_FT_SYMLINK && out->attr.blocks_512 == 0 && out->attr.size <= 120) {
            memcpy(out->inline_target, raw + 112, (size_t)out->attr.size);
            out->is_fast_symlink = 1;
        }
    } else {
        out->attr.size = lfs_le64(raw + 8);
        out->attr.atime_sec = (int32_t)lfs_le32(raw + 16);
        out->attr.mtime_sec = (int32_t)lfs_le32(raw + 24);
        out->attr.ctime_sec = (int32_t)lfs_le32(raw + 32);
        for (int i = 0; i < 12; i++) out->db[i] = (int32_t)lfs_le32(raw + 40 + i * 4);
        for (int i = 0; i < 3; i++)  out->ib[i] = (int32_t)lfs_le32(raw + 88 + i * 4);
        out->attr.blocks_512 = lfs_le32(raw + 104);
        out->attr.uid = lfs_le32(raw + 112);
        out->attr.gid = lfs_le32(raw + 116);
        if (lfs_mode_to_ftype(out->attr.mode) == LEGACYFS_FT_SYMLINK && out->attr.blocks_512 == 0 && out->attr.size <= 60) {
            memcpy(out->inline_target, raw + 40, (size_t)out->attr.size);
            out->is_fast_symlink = 1;
        }
    }
    out->attr.ftype = lfs_mode_to_ftype(out->attr.mode);
    return 0;
}

static int ufs_map_frag(legacyfs_t *fs, const ufs_inode_t *ui, uint64_t lblk, int64_t *out_frag) {
    const ufs_priv_t *p = (const ufs_priv_t *)fs->priv;
    if (lblk < 12) {
        *out_frag = ui->db[lblk];
        return 0;
    }
    size_t ptr_sz = p->is_ufs2 ? 8U : 4U;
    uint64_t ptrs = p->bsize / ptr_sz;
    lblk -= 12;

    uint8_t *ibuf = (uint8_t *)malloc(p->bsize);
    if (!ibuf) return -ENOMEM;

    int64_t frag = 0;
    if (lblk < ptrs) {
        if (ui->ib[0] > 0) {
            if (lfs_read_bytes(fs, (uint64_t)ui->ib[0] * p->fsize, p->bsize, ibuf) != 0) {
                free(ibuf);
                return -EIO;
            }
            frag = p->is_ufs2 ? (int64_t)lfs_le64(ibuf + lblk * 8) : (int32_t)lfs_le32(ibuf + lblk * 4);
        }
    } else if (lblk - ptrs < ptrs * ptrs) {
        uint64_t idx = lblk - ptrs;
        if (ui->ib[1] > 0) {
            if (lfs_read_bytes(fs, (uint64_t)ui->ib[1] * p->fsize, p->bsize, ibuf) != 0) {
                free(ibuf);
                return -EIO;
            }
            uint64_t l1 = idx / ptrs;
            uint64_t l2 = idx % ptrs;
            int64_t ind_frag = p->is_ufs2 ? (int64_t)lfs_le64(ibuf + l1 * 8) : (int32_t)lfs_le32(ibuf + l1 * 4);
            if (ind_frag > 0) {
                if (lfs_read_bytes(fs, (uint64_t)ind_frag * p->fsize, p->bsize, ibuf) != 0) {
                    free(ibuf);
                    return -EIO;
                }
                frag = p->is_ufs2 ? (int64_t)lfs_le64(ibuf + l2 * 8) : (int32_t)lfs_le32(ibuf + l2 * 4);
            }
        }
    }

    free(ibuf);
    *out_frag = frag;
    return 0;
}

static int ufs_read_data(legacyfs_t *fs, const ufs_inode_t *ui, uint64_t offset, size_t length, void *buffer, size_t *out_read) {
    const ufs_priv_t *p = (const ufs_priv_t *)fs->priv;
    if (offset >= ui->attr.size || length == 0) {
        if (out_read) *out_read = 0;
        return 0;
    }
    size_t to_read = length;
    if ((uint64_t)to_read > ui->attr.size - offset) {
        to_read = (size_t)(ui->attr.size - offset);
    }

    uint8_t *dst = (uint8_t *)buffer;
    uint8_t *blk = (uint8_t *)malloc(p->bsize);
    if (!blk) return -ENOMEM;

    size_t done = 0;
    while (done < to_read) {
        uint64_t cur = offset + done;
        uint64_t lblk = cur / p->bsize;
        size_t boff = (size_t)(cur % p->bsize);
        size_t chunk = p->bsize - boff;
        if (chunk > to_read - done) chunk = to_read - done;

        int64_t frag = 0;
        int rc = ufs_map_frag(fs, ui, lblk, &frag);
        if (rc != 0) {
            free(blk);
            return rc;
        }
        if (frag <= 0) {
            memset(dst + done, 0, chunk);
        } else {
            /* Tail block may be fragment-allocated (< bsize); read only needed span */
            size_t need_bytes = boff + chunk;
            rc = lfs_read_bytes(fs, (uint64_t)frag * p->fsize, need_bytes, blk);
            if (rc != 0) {
                free(blk);
                return rc;
            }
            memcpy(dst + done, blk + boff, chunk);
        }
        done += chunk;
    }

    free(blk);
    if (out_read) *out_read = done;
    return 0;
}

static int ufs_getattr(legacyfs_t *fs, uint64_t ino, legacyfs_attr_t *out_attr) {
    ufs_inode_t ui;
    int rc = ufs_load_inode(fs, ino, &ui);
    if (rc != 0) return rc;
    *out_attr = ui.attr;
    return 0;
}

static int ufs_readdir(legacyfs_t *fs, uint64_t dir_ino, legacyfs_readdir_cb cb, void *user_ctx) {
    ufs_inode_t ui;
    int rc = ufs_load_inode(fs, dir_ino, &ui);
    if (rc != 0) return rc;
    if (ui.attr.ftype != LEGACYFS_FT_DIR) return -ENOTDIR;
    if (ui.attr.size == 0 || ui.attr.size > (16ULL * 1024ULL * 1024ULL)) return 0;

    uint8_t *buf = (uint8_t *)malloc((size_t)ui.attr.size);
    if (!buf) return -ENOMEM;
    size_t got = 0;
    rc = ufs_read_data(fs, &ui, 0, (size_t)ui.attr.size, buf, &got);
    if (rc != 0) {
        free(buf);
        return rc;
    }

    size_t pos = 0;
    while (pos + 8U <= got) {
        uint32_t d_ino = lfs_le32(buf + pos + 0);
        uint16_t d_reclen = lfs_le16(buf + pos + 4);
        uint8_t d_type = buf[pos + 6];
        uint8_t d_namlen = buf[pos + 7];
        if (d_reclen < 8U || pos + d_reclen > got) break;

        if (d_ino != 0 && d_namlen > 0 && 8U + d_namlen <= d_reclen) {
            char name[256];
            memcpy(name, buf + pos + 8U, d_namlen);
            name[d_namlen] = '\0';
            if (strcmp(name, ".") != 0 && strcmp(name, "..") != 0) {
                legacyfs_ftype_t ft = LEGACYFS_FT_UNKNOWN;
                if (d_type == 4) ft = LEGACYFS_FT_DIR;
                else if (d_type == 8) ft = LEGACYFS_FT_REG;
                else if (d_type == 10) ft = LEGACYFS_FT_SYMLINK;
                else {
                    ufs_inode_t cui;
                    if (ufs_load_inode(fs, d_ino, &cui) == 0) ft = cui.attr.ftype;
                }
                if (cb(user_ctx, name, d_ino, ft) != 0) break;
            }
        }
        pos += d_reclen;
    }

    free(buf);
    return 0;
}

static int ufs_read(legacyfs_t *fs, uint64_t ino, uint64_t offset, size_t length, void *buffer, size_t *out_read) {
    ufs_inode_t ui;
    int rc = ufs_load_inode(fs, ino, &ui);
    if (rc != 0) return rc;
    if (ui.attr.ftype == LEGACYFS_FT_DIR) return -EISDIR;
    if (ui.attr.ftype != LEGACYFS_FT_REG) return -EINVAL;
    return ufs_read_data(fs, &ui, offset, length, buffer, out_read);
}

static int ufs_readlink(legacyfs_t *fs, uint64_t ino, char *buffer, size_t buffer_size, size_t *out_len) {
    ufs_inode_t ui;
    int rc = ufs_load_inode(fs, ino, &ui);
    if (rc != 0) return rc;
    if (ui.attr.ftype != LEGACYFS_FT_SYMLINK) return -EINVAL;

    if (ui.is_fast_symlink) {
        size_t len = (size_t)ui.attr.size;
        if (len >= buffer_size) len = buffer_size - 1;
        memcpy(buffer, ui.inline_target, len);
        buffer[len] = '\0';
        if (out_len) *out_len = len;
        return 0;
    }
    size_t got = 0;
    rc = ufs_read_data(fs, &ui, 0, buffer_size - 1, buffer, &got);
    if (rc != 0) return rc;
    buffer[got] = '\0';
    if (out_len) *out_len = got;
    return 0;
}

const legacyfs_ops_t lfs_ufs_ops = {
    .mount = ufs_mount,
    .unmount = ufs_unmount,
    .root_ino = ufs_root_ino,
    .statfs = NULL,
    .getattr = ufs_getattr,
    .readdir = ufs_readdir,
    .lookup = NULL,
    .read = ufs_read,
    .readlink = ufs_readlink,
};

/* =========================================================================
 * IBM JFS (JFS1) Read-Only Driver
 * ========================================================================= */
#define JFS_AITBL_OFF     65536ULL
#define JFS_FILESYSTEM_I  16U
#define JFS_BT_INTERNAL   0x04U
#define JFS_BT_LEAF       0x02U
#define JFS_DIR_INDEX_FL  0x00200000U

typedef struct {
    uint32_t bsize;
    uint32_t s_flag;
    uint8_t fileset_imap_di[512];
} jfs_priv_t;

static uint64_t jfs_pxd_addr(const uint8_t raw[8]) {
    return ((uint64_t)raw[3] << 32) | (uint64_t)lfs_le32(raw + 4);
}

static uint32_t jfs_xad_len(const uint8_t raw[16]) {
    return (uint32_t)raw[8] | ((uint32_t)raw[9] << 8) | ((uint32_t)raw[10] << 16);
}

static uint64_t jfs_xad_off(const uint8_t raw[16]) {
    return ((uint64_t)raw[3] << 32) | (uint64_t)lfs_le32(raw + 4);
}

static uint64_t jfs_xad_addr(const uint8_t raw[16]) {
    return ((uint64_t)raw[11] << 32) | (uint64_t)lfs_le32(raw + 12);
}

/* Search xtree rooted at xtroot (288B at dinode + 160) for logical block `lblk`. */
static int jfs_xtree_lookup(legacyfs_t *fs, const uint8_t di[512], uint64_t lblk, uint64_t *out_dblk) {
    const jfs_priv_t *p = (const jfs_priv_t *)fs->priv;
    uint8_t page[4096];
    const uint8_t *node = di + 160;
    size_t node_cap = 288;

    for (int depth = 0; depth < 8; depth++) {
        uint8_t flag = node[16];
        int16_t nextidx = (int16_t)lfs_le16(node + 18);
        if (nextidx < 2 || (size_t)nextidx * 16U > node_cap) {
            *out_dblk = 0;
            return 0;
        }

        if (flag & JFS_BT_LEAF) {
            for (int16_t i = 2; i < nextidx; i++) {
                const uint8_t *xad = node + (size_t)i * 16U;
                uint64_t xoff = jfs_xad_off(xad);
                uint32_t xlen = jfs_xad_len(xad);
                if (lblk >= xoff && lblk < xoff + xlen) {
                    /* XAD_NOTRECORDED (0x04) = unwritten zero extent */
                    if (xad[0] & 0x04U) {
                        *out_dblk = 0;
                    } else {
                        *out_dblk = jfs_xad_addr(xad) + (lblk - xoff);
                    }
                    return 0;
                }
            }
            *out_dblk = 0;
            return 0;
        }

        if (!(flag & JFS_BT_INTERNAL)) {
            return -EIO;
        }

        int16_t chosen = -1;
        for (int16_t i = 2; i < nextidx; i++) {
            const uint8_t *xad = node + (size_t)i * 16U;
            uint64_t xoff = jfs_xad_off(xad);
            if (lblk >= xoff) {
                chosen = i;
            } else {
                break;
            }
        }
        if (chosen < 2) {
            *out_dblk = 0;
            return 0;
        }
        uint64_t child_blk = jfs_xad_addr(node + (size_t)chosen * 16U);
        int rc = lfs_read_bytes(fs, child_blk * p->bsize, sizeof(page), page);
        if (rc != 0) return rc;
        node = page;
        node_cap = sizeof(page);
    }
    return -ELOOP;
}

static int jfs_read_dinode_data(legacyfs_t *fs, const uint8_t di[512], uint64_t size, uint64_t offset, size_t length, void *buffer, size_t *out_read) {
    const jfs_priv_t *p = (const jfs_priv_t *)fs->priv;
    if (offset >= size || length == 0) {
        if (out_read) *out_read = 0;
        return 0;
    }
    size_t to_read = length;
    if ((uint64_t)to_read > size - offset) {
        to_read = (size_t)(size - offset);
    }

    uint8_t *dst = (uint8_t *)buffer;
    uint8_t *blk = (uint8_t *)malloc(p->bsize);
    if (!blk) return -ENOMEM;

    size_t done = 0;
    while (done < to_read) {
        uint64_t cur = offset + done;
        uint64_t lblk = cur / p->bsize;
        size_t boff = (size_t)(cur % p->bsize);
        size_t chunk = p->bsize - boff;
        if (chunk > to_read - done) chunk = to_read - done;

        uint64_t dblk = 0;
        int rc = jfs_xtree_lookup(fs, di, lblk, &dblk);
        if (rc != 0) {
            free(blk);
            return rc;
        }
        if (dblk == 0) {
            memset(dst + done, 0, chunk);
        } else {
            rc = lfs_read_bytes(fs, dblk * p->bsize, p->bsize, blk);
            if (rc != 0) {
                free(blk);
                return rc;
            }
            memcpy(dst + done, blk + boff, chunk);
        }
        done += chunk;
    }

    free(blk);
    if (out_read) *out_read = done;
    return 0;
}

static int jfs_mount(legacyfs_t *fs) {
    uint8_t sb[256];
    int rc = lfs_read_bytes(fs, 32768ULL, sizeof(sb), sb);
    if (rc != 0) return rc;
    if (memcmp(sb, "JFS1", 4) != 0) return -EINVAL;

    uint32_t bsize = lfs_le32(sb + 16);
    if (bsize < 512U || bsize > 65536U || !lfs_is_pow2_u32(bsize)) return -EINVAL;

    jfs_priv_t *p = (jfs_priv_t *)calloc(1, sizeof(jfs_priv_t));
    if (!p) return -ENOMEM;
    p->bsize = bsize;
    p->s_flag = lfs_le32(sb + 36);

    /* Aggregate Inode 16 (Fileset Inode Allocation Map) sits in Primary AIT at 64 KiB + 16 * 512 */
    rc = lfs_read_bytes(fs, JFS_AITBL_OFF + (uint64_t)JFS_FILESYSTEM_I * 512ULL, 512, p->fileset_imap_di);
    if (rc != 0) {
        free(p);
        return rc;
    }
    fs->priv = p;
    return 0;
}

static void jfs_unmount(legacyfs_t *fs) {
    free(fs->priv);
    fs->priv = NULL;
}

static uint64_t jfs_root_ino(const legacyfs_t *fs) {
    (void)fs;
    return 2ULL; /* JFS root directory inode = 2 */
}

static int jfs_load_fileset_dinode(legacyfs_t *fs, uint64_t ino, uint8_t out_di[512]) {
    const jfs_priv_t *p = (const jfs_priv_t *)fs->priv;
    uint64_t imap_size = lfs_le64(p->fileset_imap_di + 24);
    uint64_t iag_idx = ino / 4096ULL;
    uint32_t ext_idx = (uint32_t)((ino % 4096ULL) / 32ULL);
    uint32_t slot = (uint32_t)(ino % 32ULL);

    /* JFS IAGTOLBLK(i, l2nbperpage=0) with IAGPERCTL=1024: i + 1 + (i >> 10) */
    uint64_t iag_4k_page = iag_idx + 1ULL + (iag_idx >> 10);
    uint64_t iag_byte_off = iag_4k_page * 4096ULL;

    uint8_t iag[4096];
    size_t got = 0;
    int rc = jfs_read_dinode_data(fs, p->fileset_imap_di, imap_size, iag_byte_off, sizeof(iag), iag, &got);
    if (rc != 0 || got < sizeof(iag)) return -ENOENT;

    /* iag.inoext[128] sits at offset +3072 inside the 4096-byte iag_t */
    const uint8_t *pxd = iag + 3072U + (size_t)ext_idx * 8U;
    uint64_t ext_blk = jfs_pxd_addr(pxd);
    if (ext_blk == 0) return -ENOENT;

    rc = lfs_read_bytes(fs, ext_blk * p->bsize + (uint64_t)slot * 512ULL, 512, out_di);
    if (rc != 0) return rc;
    if (lfs_le32(out_di + 8) != (uint32_t)ino) return -ENOENT;
    if (lfs_le32(out_di + 40) == 0) return -ENOENT; /* di_nlink == 0 */
    return 0;
}

static void jfs_fill_attr(uint64_t ino, const uint8_t di[512], legacyfs_attr_t *out) {
    memset(out, 0, sizeof(*out));
    out->ino = ino;
    out->size = lfs_le64(di + 24);
    uint64_t nblks = lfs_le64(di + 32);
    out->nlink = lfs_le32(di + 40);
    out->uid = lfs_le32(di + 44);
    out->gid = lfs_le32(di + 48);
    out->mode = lfs_le32(di + 52) & 0177777U;
    out->atime_sec = lfs_le32(di + 56);
    out->ctime_sec = lfs_le32(di + 64);
    out->mtime_sec = lfs_le32(di + 72);
    out->blocks_512 = nblks * 8ULL;
    out->ftype = lfs_mode_to_ftype(out->mode);
}

static int jfs_getattr(legacyfs_t *fs, uint64_t ino, legacyfs_attr_t *out_attr) {
    uint8_t di[512];
    int rc = jfs_load_fileset_dinode(fs, ino, di);
    if (rc != 0) return rc;
    jfs_fill_attr(ino, di, out_attr);
    return 0;
}

static size_t jfs_utf16le_to_utf8(const uint16_t *u16, size_t count, char *out, size_t out_cap) {
    size_t pos = 0;
    for (size_t i = 0; i < count && pos + 4 < out_cap; i++) {
        uint16_t ch = u16[i];
        if (ch == 0) break;
        if (ch < 0x80U) {
            out[pos++] = (char)ch;
        } else if (ch < 0x800U) {
            out[pos++] = (char)(0xC0U | (ch >> 6));
            out[pos++] = (char)(0x80U | (ch & 0x3FU));
        } else {
            out[pos++] = (char)(0xE0U | (ch >> 12));
            out[pos++] = (char)(0x80U | ((ch >> 6) & 0x3FU));
            out[pos++] = (char)(0x80U | (ch & 0x3FU));
        }
    }
    out[pos] = '\0';
    return pos;
}

static int jfs_decode_leaf_entry(
    legacyfs_t *fs,
    const uint8_t *slots_base,
    int max_slots,
    int head_slot,
    int has_dir_index_field,
    legacyfs_readdir_cb cb,
    void *user_ctx
) {
    if (head_slot <= 0 || head_slot >= max_slots) return 0;
    const uint8_t *slot = slots_base + (size_t)head_slot * 32U;
    uint32_t inum = lfs_le32(slot + 0);
    int8_t next_slot = (int8_t)slot[4];
    uint8_t namlen = slot[5];
    if (inum == 0 || namlen == 0) return 0;

    uint16_t u16[256];
    size_t got_chars = 0;
    size_t head_cap = has_dir_index_field ? 12U : 13U;
    size_t take = namlen < head_cap ? namlen : head_cap;
    for (size_t i = 0; i < take; i++) {
        u16[got_chars++] = lfs_le16(slot + 6U + i * 2U);
    }

    int guard = 0;
    while (got_chars < namlen && next_slot > 0 && next_slot < max_slots && guard++ < 32) {
        const uint8_t *cs = slots_base + (size_t)next_slot * 32U;
        next_slot = (int8_t)cs[0];
        uint8_t cnt = cs[1];
        if (cnt > 15) cnt = 15;
        for (uint8_t i = 0; i < cnt && got_chars < namlen && got_chars < 255U; i++) {
            u16[got_chars++] = lfs_le16(cs + 2U + (size_t)i * 2U);
        }
    }

    char name[256];
    jfs_utf16le_to_utf8(u16, got_chars, name, sizeof(name));
    if (name[0] == '\0' || strcmp(name, ".") == 0 || strcmp(name, "..") == 0) return 0;

    legacyfs_attr_t cattr;
    legacyfs_ftype_t ft = (jfs_getattr(fs, inum, &cattr) == 0) ? cattr.ftype : LEGACYFS_FT_UNKNOWN;
    return cb(user_ctx, name, inum, ft);
}

static int jfs_walk_dtpage(legacyfs_t *fs, uint64_t blk_addr, int depth, legacyfs_readdir_cb cb, void *user_ctx) {
    if (depth > 8) return -ELOOP;
    const jfs_priv_t *p = (const jfs_priv_t *)fs->priv;
    uint8_t page[4096];
    int rc = lfs_read_bytes(fs, blk_addr * p->bsize, sizeof(page), page);
    if (rc != 0) return rc;

    uint8_t flag = page[16];
    uint8_t nextidx = page[17];
    int16_t maxslot = (int16_t)lfs_le16(page + 20);
    int16_t stblidx = (int16_t)lfs_le16(page + 22);
    if (maxslot <= 0 || maxslot > 128 || stblidx <= 0 || (size_t)stblidx * 32U + nextidx > sizeof(page)) {
        return -EIO;
    }
    const uint8_t *stbl = page + (size_t)stblidx * 32U;

    if (flag & JFS_BT_LEAF) {
        int has_idx = (p->s_flag & JFS_DIR_INDEX_FL) != 0;
        for (uint8_t i = 0; i < nextidx; i++) {
            if (jfs_decode_leaf_entry(fs, page, maxslot, stbl[i], has_idx, cb, user_ctx) != 0) {
                return 1;
            }
        }
        return 0;
    }
    if (flag & JFS_BT_INTERNAL) {
        for (uint8_t i = 0; i < nextidx; i++) {
            uint8_t s = stbl[i];
            if (s == 0 || s >= maxslot) continue;
            uint64_t child_blk = jfs_pxd_addr(page + (size_t)s * 32U);
            int sub = jfs_walk_dtpage(fs, child_blk, depth + 1, cb, user_ctx);
            if (sub != 0) return sub;
        }
    }
    return 0;
}

static int jfs_readdir(legacyfs_t *fs, uint64_t dir_ino, legacyfs_readdir_cb cb, void *user_ctx) {
    uint8_t di[512];
    int rc = jfs_load_fileset_dinode(fs, dir_ino, di);
    if (rc != 0) return rc;

    legacyfs_attr_t attr;
    jfs_fill_attr(dir_ino, di, &attr);
    if (attr.ftype != LEGACYFS_FT_DIR) return -ENOTDIR;

    /* dtroot_t starts at di + 128 (slot 0 = header 32B, slots 1..9 = +160..447) */
    const uint8_t *dtroot = di + 128;
    uint8_t flag = dtroot[16];
    uint8_t nextidx = dtroot[17];
    const uint8_t *stbl = dtroot + 24; /* 8-byte stbl inside dtroot header */

    if (flag & JFS_BT_LEAF) {
        if (nextidx > 8) nextidx = 8;
        for (uint8_t i = 0; i < nextidx; i++) {
            if (jfs_decode_leaf_entry(fs, dtroot, 10, stbl[i], 0, cb, user_ctx) != 0) {
                break;
            }
        }
        return 0;
    }

    if (flag & JFS_BT_INTERNAL) {
        if (nextidx > 8) nextidx = 8;
        for (uint8_t i = 0; i < nextidx; i++) {
            uint8_t s = stbl[i];
            if (s == 0 || s >= 10) continue;
            uint64_t child_blk = jfs_pxd_addr(dtroot + (size_t)s * 32U);
            int sub = jfs_walk_dtpage(fs, child_blk, 1, cb, user_ctx);
            if (sub < 0) return sub;
            if (sub > 0) break;
        }
    }
    return 0;
}

static int jfs_read(legacyfs_t *fs, uint64_t ino, uint64_t offset, size_t length, void *buffer, size_t *out_read) {
    uint8_t di[512];
    int rc = jfs_load_fileset_dinode(fs, ino, di);
    if (rc != 0) return rc;
    legacyfs_attr_t attr;
    jfs_fill_attr(ino, di, &attr);
    if (attr.ftype == LEGACYFS_FT_DIR) return -EISDIR;
    if (attr.ftype != LEGACYFS_FT_REG) return -EINVAL;
    return jfs_read_dinode_data(fs, di, attr.size, offset, length, buffer, out_read);
}

static int jfs_readlink(legacyfs_t *fs, uint64_t ino, char *buffer, size_t buffer_size, size_t *out_len) {
    uint8_t di[512];
    int rc = jfs_load_fileset_dinode(fs, ino, di);
    if (rc != 0) return rc;
    legacyfs_attr_t attr;
    jfs_fill_attr(ino, di, &attr);
    if (attr.ftype != LEGACYFS_FT_SYMLINK) return -EINVAL;

    uint64_t nblks = lfs_le64(di + 32);
    if (nblks == 0 && attr.size <= 256) {
        size_t len = (size_t)attr.size;
        if (len >= buffer_size) len = buffer_size - 1;
        memcpy(buffer, di + 256, len);
        buffer[len] = '\0';
        if (out_len) *out_len = len;
        return 0;
    }

    size_t got = 0;
    rc = jfs_read_dinode_data(fs, di, attr.size, 0, buffer_size - 1, buffer, &got);
    if (rc != 0) return rc;
    buffer[got] = '\0';
    if (out_len) *out_len = got;
    return 0;
}

const legacyfs_ops_t lfs_jfs_ops = {
    .mount = jfs_mount,
    .unmount = jfs_unmount,
    .root_ino = jfs_root_ino,
    .statfs = NULL,
    .getattr = jfs_getattr,
    .readdir = jfs_readdir,
    .lookup = NULL,
    .read = jfs_read,
    .readlink = jfs_readlink,
};
