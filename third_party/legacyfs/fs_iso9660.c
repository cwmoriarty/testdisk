#include "internal.h"
#include <ctype.h>

/* =========================================================================
 * ISO9660 + Rock Ridge Read-Only Driver
 * =========================================================================
 * `ino` encodes `(dir_record_byte_offset << 1) | 1ULL`.
 */
typedef struct {
    uint32_t lb_size;
    uint64_t root_rec_off;
} iso_priv_t;

typedef struct {
    uint32_t extent_lba;
    uint32_t data_len;
    uint8_t flags;
    legacyfs_attr_t attr;
    char name[256];
    char symlink[512];
} iso_rec_t;

static void iso_parse_rock_ridge(const uint8_t *su, size_t su_len, iso_rec_t *rec) {
    size_t pos = 0;
    size_t nm_len = 0;
    size_t sl_len = 0;

    while (pos + 4 <= su_len) {
        uint8_t c0 = su[pos];
        uint8_t c1 = su[pos + 1];
        uint8_t elen = su[pos + 2];
        if (elen < 4 || pos + elen > su_len) break;

        if (c0 == 'P' && c1 == 'X' && elen >= 36) {
            rec->attr.mode = lfs_le32(su + pos + 4);
            rec->attr.nlink = lfs_le32(su + pos + 12);
            rec->attr.uid = lfs_le32(su + pos + 20);
            rec->attr.gid = lfs_le32(su + pos + 28);
            rec->attr.ftype = lfs_mode_to_ftype(rec->attr.mode);
        } else if (c0 == 'N' && c1 == 'M' && elen >= 5) {
            size_t part = (size_t)(elen - 5);
            if (nm_len + part < sizeof(rec->name) - 1) {
                memcpy(rec->name + nm_len, su + pos + 5, part);
                nm_len += part;
                rec->name[nm_len] = '\0';
            }
        } else if (c0 == 'S' && c1 == 'L' && elen >= 5) {
            size_t cpos = pos + 5;
            while (cpos + 2 <= pos + elen) {
                uint8_t cflags = su[cpos];
                uint8_t clen = su[cpos + 1];
                if (cpos + 2 + clen > pos + elen) break;

                const char *prefix = NULL;
                if (cflags & 0x02) prefix = ".";
                else if (cflags & 0x04) prefix = "..";
                else if (cflags & 0x08) prefix = "/";

                if (sl_len > 0 && rec->symlink[sl_len - 1] != '/' && sl_len + 1 < sizeof(rec->symlink) - 1) {
                    rec->symlink[sl_len++] = '/';
                }
                if (prefix) {
                    size_t plen = strlen(prefix);
                    if (sl_len + plen < sizeof(rec->symlink) - 1) {
                        memcpy(rec->symlink + sl_len, prefix, plen);
                        sl_len += plen;
                    }
                } else if (sl_len + clen < sizeof(rec->symlink) - 1) {
                    memcpy(rec->symlink + sl_len, su + cpos + 2, clen);
                    sl_len += clen;
                }
                rec->symlink[sl_len] = '\0';
                cpos += 2 + clen;
            }
        }
        pos += elen;
    }

    if (rec->attr.ftype == LEGACYFS_FT_SYMLINK) {
        rec->attr.size = strlen(rec->symlink);
    }
}

static int iso_load_rec(legacyfs_t *fs, uint64_t ino, iso_rec_t *out) {
    if ((ino & 1ULL) == 0) return -ENOENT;
    uint64_t rec_off = ino >> 1;

    uint8_t raw[256];
    int rc = lfs_read_bytes(fs, rec_off, 34, raw);
    if (rc != 0) return rc;
    uint8_t rlen = raw[0];
    if (rlen < 34) return -ENOENT;
    rc = lfs_read_bytes(fs, rec_off, rlen, raw);
    if (rc != 0) return rc;

    memset(out, 0, sizeof(*out));
    out->extent_lba = lfs_le32(raw + 2);
    out->data_len = lfs_le32(raw + 10);
    out->flags = raw[25];
    uint8_t id_len = raw[32];
    if (33U + id_len > rlen) return -EIO;

    out->attr.ino = ino;
    out->attr.nlink = 1;
    out->attr.size = out->data_len;
    out->attr.blocks_512 = (out->data_len + 511ULL) / 512ULL;
    if (out->flags & 0x02) {
        out->attr.mode = S_IFDIR | 0555U;
        out->attr.ftype = LEGACYFS_FT_DIR;
    } else {
        out->attr.mode = S_IFREG | 0444U;
        out->attr.ftype = LEGACYFS_FT_REG;
    }

    if (id_len == 1 && raw[33] == 0) {
        strcpy(out->name, ".");
    } else if (id_len == 1 && raw[33] == 1) {
        strcpy(out->name, "..");
    } else {
        size_t copy_n = id_len < 255 ? id_len : 255;
        for (size_t i = 0; i < copy_n; i++) {
            out->name[i] = (char)tolower((unsigned char)raw[33 + i]);
        }
        out->name[copy_n] = '\0';
        char *semi = strchr(out->name, ';');
        if (semi) *semi = '\0';
        size_t nl = strlen(out->name);
        if (nl > 0 && out->name[nl - 1] == '.' && !(out->flags & 0x02)) {
            out->name[nl - 1] = '\0';
        }
    }

    size_t su_off = 33U + id_len;
    if ((id_len & 1U) == 0) su_off++;
    if (su_off < rlen) {
        iso_parse_rock_ridge(raw + su_off, rlen - su_off, out);
    }
    return 0;
}

static int iso_mount(legacyfs_t *fs) {
    uint8_t pvd[2048];
    int rc = lfs_read_bytes(fs, 32768ULL, sizeof(pvd), pvd);
    if (rc != 0) return rc;
    if (pvd[0] != 1 || memcmp(pvd + 1, "CD001", 5) != 0) return -EINVAL;

    uint16_t lb = lfs_le16(pvd + 128);
    if (lb == 0) lb = 2048U;
    if (lb < 512U || lb > 8192U || !lfs_is_pow2_u32(lb)) return -EINVAL;

    iso_priv_t *p = (iso_priv_t *)calloc(1, sizeof(iso_priv_t));
    if (!p) return -ENOMEM;
    p->lb_size = lb;
    p->root_rec_off = 32768ULL + 156ULL;
    fs->priv = p;
    return 0;
}

static void iso_unmount(legacyfs_t *fs) {
    free(fs->priv);
    fs->priv = NULL;
}

static uint64_t iso_root_ino(const legacyfs_t *fs) {
    const iso_priv_t *p = (const iso_priv_t *)fs->priv;
    return (p->root_rec_off << 1) | 1ULL;
}

static int iso_getattr(legacyfs_t *fs, uint64_t ino, legacyfs_attr_t *out_attr) {
    iso_rec_t rec;
    int rc = iso_load_rec(fs, ino, &rec);
    if (rc != 0) return rc;
    *out_attr = rec.attr;
    return 0;
}

static int iso_readdir(legacyfs_t *fs, uint64_t dir_ino, legacyfs_readdir_cb cb, void *user_ctx) {
    const iso_priv_t *p = (const iso_priv_t *)fs->priv;
    iso_rec_t dir_rec;
    int rc = iso_load_rec(fs, dir_ino, &dir_rec);
    if (rc != 0) return rc;
    if (dir_rec.attr.ftype != LEGACYFS_FT_DIR) return -ENOTDIR;
    if (dir_rec.data_len == 0 || dir_rec.data_len > (16U * 1024U * 1024U)) return 0;

    uint64_t base_off = (uint64_t)dir_rec.extent_lba * p->lb_size;
    uint8_t *buf = (uint8_t *)malloc(dir_rec.data_len);
    if (!buf) return -ENOMEM;

    rc = lfs_read_bytes(fs, base_off, dir_rec.data_len, buf);
    if (rc != 0) {
        free(buf);
        return rc;
    }

    uint32_t pos = 0;
    while (pos < dir_rec.data_len) {
        uint8_t rlen = buf[pos];
        if (rlen == 0) {
            /* Advance to next logical sector boundary */
            uint32_t next_sec = ((pos / p->lb_size) + 1U) * p->lb_size;
            if (next_sec <= pos) break;
            pos = next_sec;
            continue;
        }
        if (rlen < 34 || pos + rlen > dir_rec.data_len) break;

        uint64_t child_ino = ((base_off + pos) << 1) | 1ULL;
        iso_rec_t child;
        if (iso_load_rec(fs, child_ino, &child) == 0) {
            if (child.name[0] != '\0' && strcmp(child.name, ".") != 0 && strcmp(child.name, "..") != 0) {
                if (cb(user_ctx, child.name, child_ino, child.attr.ftype) != 0) {
                    break;
                }
            }
        }
        pos += rlen;
    }

    free(buf);
    return 0;
}

static int iso_read(legacyfs_t *fs, uint64_t ino, uint64_t offset, size_t length, void *buffer, size_t *out_read) {
    const iso_priv_t *p = (const iso_priv_t *)fs->priv;
    iso_rec_t rec;
    int rc = iso_load_rec(fs, ino, &rec);
    if (rc != 0) return rc;
    if (rec.attr.ftype == LEGACYFS_FT_DIR) return -EISDIR;
    if (rec.attr.ftype != LEGACYFS_FT_REG) return -EINVAL;

    if (offset >= rec.data_len || length == 0) {
        if (out_read) *out_read = 0;
        return 0;
    }
    size_t to_read = length;
    if ((uint64_t)to_read > (uint64_t)rec.data_len - offset) {
        to_read = (size_t)((uint64_t)rec.data_len - offset);
    }

    rc = lfs_read_bytes(fs, (uint64_t)rec.extent_lba * p->lb_size + offset, to_read, buffer);
    if (rc != 0) return rc;
    if (out_read) *out_read = to_read;
    return 0;
}

static int iso_readlink(legacyfs_t *fs, uint64_t ino, char *buffer, size_t buffer_size, size_t *out_len) {
    iso_rec_t rec;
    int rc = iso_load_rec(fs, ino, &rec);
    if (rc != 0) return rc;
    if (rec.attr.ftype != LEGACYFS_FT_SYMLINK) return -EINVAL;
    size_t slen = strlen(rec.symlink);
    if (slen >= buffer_size) slen = buffer_size - 1;
    memcpy(buffer, rec.symlink, slen);
    buffer[slen] = '\0';
    if (out_len) *out_len = slen;
    return 0;
}

const legacyfs_ops_t lfs_iso9660_ops = {
    .mount = iso_mount,
    .unmount = iso_unmount,
    .root_ino = iso_root_ino,
    .statfs = NULL,
    .getattr = iso_getattr,
    .readdir = iso_readdir,
    .lookup = NULL,
    .read = iso_read,
    .readlink = iso_readlink,
};
