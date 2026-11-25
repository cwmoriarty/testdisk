#define _DEFAULT_SOURCE
#define _POSIX_C_SOURCE 200809L

#include "aex_internal.h"
#include <sys/stat.h>

#define HFS_MAC_EPOCH_DELTA 2082844800LL
#define HFS_VDIR_TAG        0x4000000000000000ULL

typedef struct {
    uint32_t start_block;
    uint32_t block_count;
} hfs_extent_t;

typedef struct {
    uint64_t     logical_size;
    uint32_t     total_blocks;
    hfs_extent_t extents[8];
} hfs_fork_t;

typedef struct {
    uint32_t cnid;
    uint32_t parent_cnid;
    uint16_t rec_type; /* 1 = dir, 2 = file */
    uint16_t mode;
    uint8_t  owner_flags;
    uint32_t uid;
    uint32_t gid;
    uint32_t nlink;
    int64_t  crtime;
    int64_t  mtime;
    int64_t  ctime;
    int64_t  atime;
    uint32_t fd_type;
    uint32_t fd_creator;
    uint32_t special_inum;
    hfs_fork_t data_fork;
    hfs_fork_t rsrc_fork;
    char     name[256];
    int      is_hidden_meta;
} hfs_cat_item_t;

typedef struct {
    aex_slice_t     vol_slice; /* Slice starting at HFS/HFS+ volume (embedded if wrapped) */
    int             is_classic;
    int             case_sensitive;
    uint32_t        block_size;
    uint64_t        alloc_base_off; /* 0 for HFS+, drAlBlSt*512 for Classic HFS */
    uint64_t        total_blocks;
    uint64_t        free_blocks;

    hfs_fork_t      extents_file;
    hfs_fork_t      catalog_file;
    hfs_fork_t      attrs_file;

    uint16_t        ext_node_size;
    uint32_t        ext_first_leaf;
    uint16_t        cat_node_size;
    uint32_t        cat_first_leaf;
    uint16_t        att_node_size;
    uint32_t        att_first_leaf;

    uint32_t        priv_dir_data_cnid;  /* \0\0\0\0HFS+ Private Directory Data\r */
    uint32_t        priv_file_data_cnid; /* \0\0\0\0HFS+ Private Data */

    /* Parsed catalog table for fast O(log N) / O(1) lookup and Backups.backupdb link resolution */
    hfs_cat_item_t *items;
    size_t          item_count;
    size_t          item_cap;
} hfs_priv_t;

static int64_t mac_to_unix_time(uint32_t mac_sec) {
    if (mac_sec == 0) return 0;
    return (int64_t)mac_sec - HFS_MAC_EPOCH_DELTA;
}

static void parse_hfsplus_fork(const uint8_t *p, hfs_fork_t *out) {
    memset(out, 0, sizeof(*out));
    out->logical_size = aex_be64(p + 0U);
    out->total_blocks = aex_be32(p + 12U);
    for (int i = 0; i < 8; i++) {
        out->extents[i].start_block = aex_be32(p + 16U + i * 8U);
        out->extents[i].block_count = aex_be32(p + 20U + i * 8U);
    }
}

static void parse_classic_ext_rec(const uint8_t *p, uint32_t logical_sz, uint32_t blk_sz, hfs_fork_t *out) {
    memset(out, 0, sizeof(*out));
    out->logical_size = logical_sz;
    out->total_blocks = blk_sz ? ((logical_sz + blk_sz - 1U) / blk_sz) : 0U;
    for (int i = 0; i < 3; i++) {
        out->extents[i].start_block = aex_be16(p + i * 4U);
        out->extents[i].block_count = aex_be16(p + i * 4U + 2U);
    }
}

/* Look up overflow extents in Extents Overflow B-tree (CNID 3) if fork exceeds 8 (or 3) extents */
static int lookup_overflow_extents(
    const hfs_priv_t *hp,
    uint32_t file_cnid,
    uint8_t fork_type, /* 0x00 = data, 0xFF = rsrc */
    uint32_t start_block_idx,
    hfs_extent_t out_ext[8]
);

static int read_fork_bytes(
    const hfs_priv_t *hp,
    uint32_t file_cnid,
    uint8_t fork_type,
    const hfs_fork_t *fk,
    uint64_t offset,
    size_t length,
    void *buffer,
    size_t *out_read
) {
    *out_read = 0;
    if (length == 0 || offset >= fk->logical_size) return 0;
    if (offset + length > fk->logical_size) {
        length = (size_t)(fk->logical_size - offset);
    }
    if (hp->block_size == 0) return -EINVAL;

    uint8_t *dst = (uint8_t *)buffer;
    size_t done = 0;
    while (done < length) {
        uint64_t cur = offset + done;
        uint64_t fblk = cur / hp->block_size;
        uint64_t boff = cur % hp->block_size;

        uint32_t accum = 0;
        int found = 0;
        uint32_t phys_blk = 0;
        uint32_t rem_blks = 0;

        for (int i = 0; i < 8; i++) {
            uint32_t cnt = fk->extents[i].block_count;
            if (cnt == 0) break;
            if (fblk >= accum && fblk < accum + cnt) {
                uint32_t delta = (uint32_t)(fblk - accum);
                phys_blk = fk->extents[i].start_block + delta;
                rem_blks = cnt - delta;
                found = 1;
                break;
            }
            accum += cnt;
        }

        if (!found && file_cnid > 4U && hp->ext_node_size >= 512U) {
            hfs_extent_t ov[8];
            if (lookup_overflow_extents(hp, file_cnid, fork_type, accum, ov) == 0) {
                for (int i = 0; i < 8; i++) {
                    uint32_t cnt = ov[i].block_count;
                    if (cnt == 0) break;
                    if (fblk >= accum && fblk < accum + cnt) {
                        uint32_t delta = (uint32_t)(fblk - accum);
                        phys_blk = ov[i].start_block + delta;
                        rem_blks = cnt - delta;
                        found = 1;
                        break;
                    }
                    accum += cnt;
                }
            }
        }

        size_t want = length - done;
        if (!found) {
            /* Sparse / unmapped tail -> zeroes */
            memset(dst + done, 0, want);
            done += want;
            break;
        }

        uint64_t max_contig = (uint64_t)rem_blks * hp->block_size - boff;
        if (want > max_contig) want = (size_t)max_contig;
        uint64_t disk_off = hp->alloc_base_off + (uint64_t)phys_blk * hp->block_size + boff;
        int rc = aex_slice_read(&hp->vol_slice, disk_off, want, dst + done);
        if (rc != 0) return rc;
        done += want;
    }
    *out_read = done;
    return 0;
}

static int read_btree_header(const hfs_priv_t *hp, uint32_t cnid, const hfs_fork_t *fk, uint16_t *out_nsz, uint32_t *out_first_leaf) {
    uint8_t hdr_buf[512];
    size_t got = 0;
    if (fk->logical_size < 128U) return -EINVAL;
    size_t probe_len = (fk->logical_size < sizeof(hdr_buf)) ? (size_t)fk->logical_size : sizeof(hdr_buf);
    int rc = read_fork_bytes(hp, cnid, 0, fk, 0, probe_len, hdr_buf, &got);
    if (rc != 0 || got < 64U) return -EIO;
    if (hdr_buf[8] != 1) return -EINVAL; /* BTNodeDescriptor kind 1 = header node */
    uint16_t nsz = aex_be16(hdr_buf + 14U + 18U);
    uint32_t fleaf = aex_be32(hdr_buf + 14U + 10U);
    if (nsz < 512U || (nsz & (nsz - 1U)) != 0 || nsz > 32768U) return -EINVAL;
    *out_nsz = nsz;
    *out_first_leaf = fleaf;
    return 0;
}

static int lookup_overflow_extents(
    const hfs_priv_t *hp,
    uint32_t file_cnid,
    uint8_t fork_type,
    uint32_t start_block_idx,
    hfs_extent_t out_ext[8]
) {
    memset(out_ext, 0, sizeof(hfs_extent_t) * 8U);
    if (hp->ext_node_size == 0 || hp->ext_first_leaf == 0) return -ENOENT;
    uint8_t *nbuf = (uint8_t *)malloc(hp->ext_node_size);
    if (!nbuf) return -ENOMEM;

    uint32_t node = hp->ext_first_leaf;
    uint32_t guard = 0;
    while (node != 0 && guard++ < 4096U) {
        size_t got = 0;
        if (read_fork_bytes(hp, 3U, 0, &hp->extents_file, (uint64_t)node * hp->ext_node_size, hp->ext_node_size, nbuf, &got) != 0 ||
            got != hp->ext_node_size) break;
        if ((int8_t)nbuf[8] != -1) break;
        uint16_t nrecs = aex_be16(nbuf + 10U);
        for (uint16_t r = 0; r < nrecs && 14U + 2U * ((size_t)r + 1U) <= hp->ext_node_size; r++) {
            uint16_t roff = aex_be16(nbuf + hp->ext_node_size - 2U * (r + 1U));
            if (roff < 14U || roff + 12U > hp->ext_node_size) continue;
            if (!hp->is_classic) {
                uint16_t klen = aex_be16(nbuf + roff);
                if (klen != 10U || roff + 12U + 64U > hp->ext_node_size) continue;
                uint8_t ft = nbuf[roff + 2U];
                uint32_t cnid = aex_be32(nbuf + roff + 4U);
                uint32_t sblk = aex_be32(nbuf + roff + 8U);
                if (cnid == file_cnid && ft == fork_type && sblk == start_block_idx) {
                    for (int i = 0; i < 8; i++) {
                        out_ext[i].start_block = aex_be32(nbuf + roff + 12U + i * 8U);
                        out_ext[i].block_count = aex_be32(nbuf + roff + 16U + i * 8U);
                    }
                    free(nbuf);
                    return 0;
                }
            }
        }
        node = aex_be32(nbuf); /* fLink */
    }
    free(nbuf);
    return -ENOENT;
}

/* Read an inline extended attribute from Attributes B-tree (CNID 8), e.g., com.apple.decmpfs */
static int lookup_hfsplus_xattr(
    const hfs_priv_t *hp,
    uint32_t file_cnid,
    const char *attr_name,
    uint8_t **out_data,
    size_t *out_len
) {
    if (hp->is_classic || hp->att_node_size == 0 || hp->att_first_leaf == 0) return -ENOENT;
    uint8_t *nbuf = (uint8_t *)malloc(hp->att_node_size);
    if (!nbuf) return -ENOMEM;

    uint32_t node = hp->att_first_leaf;
    uint32_t guard = 0;
    while (node != 0 && guard++ < 8192U) {
        size_t got = 0;
        if (read_fork_bytes(hp, 8U, 0, &hp->attrs_file, (uint64_t)node * hp->att_node_size, hp->att_node_size, nbuf, &got) != 0 ||
            got != hp->att_node_size) break;
        if ((int8_t)nbuf[8] != -1) break;
        uint16_t nrecs = aex_be16(nbuf + 10U);
        for (uint16_t r = 0; r < nrecs && 14U + 2U * ((size_t)r + 1U) <= hp->att_node_size; r++) {
            uint16_t roff = aex_be16(nbuf + hp->att_node_size - 2U * (r + 1U));
            if (roff < 14U || roff + 14U > hp->att_node_size) continue;
            uint16_t klen = aex_be16(nbuf + roff);
            if (klen < 12U || (size_t)roff + 2U + klen + 16U > hp->att_node_size) continue;
            uint32_t cnid = aex_be32(nbuf + roff + 4U);
            if (cnid < file_cnid) continue;
            if (cnid > file_cnid) { free(nbuf); return -ENOENT; }
            uint16_t nchars = aex_be16(nbuf + roff + 12U);
            if (12U + (size_t)nchars * 2U > klen) continue;
            char aname[256];
            aex_utf16be_to_utf8(nbuf + roff + 14U, nchars, aname, sizeof(aname));
            if (strcmp(aname, attr_name) != 0) continue;

            const uint8_t *val = nbuf + roff + 2U + klen;
            uint32_t rtype = aex_be32(val);
            if (rtype == 0x00000010U) { /* kHFSPlusAttrInlineData */
                uint32_t asz = aex_be32(val + 12U);
                if ((size_t)(val - nbuf) + 16U + asz > hp->att_node_size) break;
                uint8_t *copy = (uint8_t *)malloc(asz ? asz : 1U);
                if (!copy) { free(nbuf); return -ENOMEM; }
                if (asz > 0) memcpy(copy, val + 16U, asz);
                *out_data = copy;
                *out_len = asz;
                free(nbuf);
                return 0;
            }
        }
        node = aex_be32(nbuf);
    }
    free(nbuf);
    return -ENOENT;
}

static int append_cat_item(hfs_priv_t *hp, const hfs_cat_item_t *it) {
    if (hp->item_count == hp->item_cap) {
        size_t ncap = hp->item_cap ? (hp->item_cap * 2U) : 256U;
        hfs_cat_item_t *narr = (hfs_cat_item_t *)realloc(hp->items, ncap * sizeof(hfs_cat_item_t));
        if (!narr) return -ENOMEM;
        hp->items = narr;
        hp->item_cap = ncap;
    }
    hp->items[hp->item_count++] = *it;
    return 0;
}

static int is_private_dir_data_u16(const uint8_t *u16, uint16_t nchars) {
    /* "\0\0\0\0HFS+ Private Directory Data\r" = 32 UTF-16 code units */
    static const char suffix[] = "HFS+ Private Directory Data\r";
    if (nchars != 4U + sizeof(suffix) - 1U) return 0;
    for (int i = 0; i < 4; i++) if (aex_be16(u16 + i * 2) != 0) return 0;
    for (size_t i = 0; i < sizeof(suffix) - 1U; i++) {
        if (aex_be16(u16 + (4U + i) * 2U) != (uint16_t)(unsigned char)suffix[i]) return 0;
    }
    return 1;
}

static int is_private_file_data_u16(const uint8_t *u16, uint16_t nchars) {
    /* "\0\0\0\0HFS+ Private Data" = 21 UTF-16 code units */
    static const char suffix[] = "HFS+ Private Data";
    if (nchars != 4U + sizeof(suffix) - 1U) return 0;
    for (int i = 0; i < 4; i++) if (aex_be16(u16 + i * 2) != 0) return 0;
    for (size_t i = 0; i < sizeof(suffix) - 1U; i++) {
        if (aex_be16(u16 + (4U + i) * 2U) != (uint16_t)(unsigned char)suffix[i]) return 0;
    }
    return 1;
}

static int load_catalog_leaves(hfs_priv_t *hp, char *vol_name_out, size_t vol_name_cap) {
    uint8_t *nbuf = (uint8_t *)malloc(hp->cat_node_size);
    if (!nbuf) return -ENOMEM;

    uint32_t node = hp->cat_first_leaf;
    uint32_t max_nodes = (uint32_t)((hp->catalog_file.logical_size / hp->cat_node_size) + 2U);
    uint32_t visited = 0;

    while (node != 0 && visited++ < max_nodes) {
        size_t got = 0;
        if (read_fork_bytes(hp, 4U, 0, &hp->catalog_file, (uint64_t)node * hp->cat_node_size, hp->cat_node_size, nbuf, &got) != 0 ||
            got != hp->cat_node_size) break;
        if ((int8_t)nbuf[8] != -1) break;
        uint16_t nrecs = aex_be16(nbuf + 10U);

        for (uint16_t r = 0; r < nrecs && 14U + 2U * ((size_t)r + 1U) <= hp->cat_node_size; r++) {
            uint16_t roff = aex_be16(nbuf + hp->cat_node_size - 2U * (r + 1U));
            if (roff < 14U || roff + 10U >= hp->cat_node_size) continue;

            if (hp->is_classic) {
                uint8_t klen = nbuf[roff];
                if (klen < 6U) continue;
                size_t data_off = roff + ((1U + (size_t)klen + 1U) & ~(size_t)1U);
                if (data_off + 2U > hp->cat_node_size) continue;
                uint32_t parent_id = aex_be32(nbuf + roff + 2U);
                uint8_t nlen = nbuf[roff + 6U];
                if (6U + nlen > klen) continue;
                uint8_t rtype = nbuf[data_off];
                if (rtype != 1U && rtype != 2U) continue;

                hfs_cat_item_t it;
                memset(&it, 0, sizeof(it));
                it.parent_cnid = parent_id;
                it.rec_type = rtype;
                aex_macroman_to_utf8(nbuf + roff + 7U, nlen, it.name, sizeof(it.name));

                if (rtype == 1U) { /* HFSCatalogFolder (70 bytes) */
                    if (data_off + 30U > hp->cat_node_size) continue;
                    it.cnid = aex_be32(nbuf + data_off + 6U);
                    it.crtime = mac_to_unix_time(aex_be32(nbuf + data_off + 10U));
                    it.mtime = mac_to_unix_time(aex_be32(nbuf + data_off + 14U));
                    it.ctime = it.mtime;
                    it.atime = it.mtime;
                    it.mode = S_IFDIR | 0755;
                    it.nlink = 2U;
                    if (it.cnid == 2U && vol_name_out && vol_name_cap > 0U && !vol_name_out[0]) {
                        snprintf(vol_name_out, vol_name_cap, "%.*s", (int)(vol_name_cap - 1U), it.name);
                    }
                } else { /* HFSCatalogFile (102 bytes) */
                    if (data_off + 98U > hp->cat_node_size) continue;
                    it.fd_type = aex_be32(nbuf + data_off + 4U);
                    it.fd_creator = aex_be32(nbuf + data_off + 8U);
                    it.cnid = aex_be32(nbuf + data_off + 20U);
                    uint32_t dsz = aex_be32(nbuf + data_off + 26U);
                    uint32_t rsz = aex_be32(nbuf + data_off + 36U);
                    it.crtime = mac_to_unix_time(aex_be32(nbuf + data_off + 44U));
                    it.mtime = mac_to_unix_time(aex_be32(nbuf + data_off + 48U));
                    it.ctime = it.mtime;
                    it.atime = it.mtime;
                    it.mode = S_IFREG | 0644;
                    it.nlink = 1U;
                    parse_classic_ext_rec(nbuf + data_off + 74U, dsz, hp->block_size, &it.data_fork);
                    parse_classic_ext_rec(nbuf + data_off + 86U, rsz, hp->block_size, &it.rsrc_fork);
                }
                (void)append_cat_item(hp, &it);
            } else {
                uint16_t klen = aex_be16(nbuf + roff);
                if (klen < 6U || (size_t)roff + 2U + klen + 4U > hp->cat_node_size) continue;
                uint32_t parent_id = aex_be32(nbuf + roff + 2U);
                uint16_t nchars = aex_be16(nbuf + roff + 6U);
                if (6U + (size_t)nchars * 2U > klen) continue;
                const uint8_t *u16 = nbuf + roff + 8U;
                const uint8_t *val = nbuf + roff + 2U + klen;
                uint16_t rtype = aex_be16(val);
                if (rtype != 1U && rtype != 2U) continue;

                hfs_cat_item_t it;
                memset(&it, 0, sizeof(it));
                it.parent_cnid = parent_id;
                it.rec_type = rtype;

                if (parent_id == 2U && is_private_dir_data_u16(u16, nchars)) {
                    it.is_hidden_meta = 1;
                    snprintf(it.name, sizeof(it.name), ".HFS+ Private Directory Data");
                } else if (parent_id == 2U && is_private_file_data_u16(u16, nchars)) {
                    it.is_hidden_meta = 1;
                    snprintf(it.name, sizeof(it.name), ".HFS+ Private Data");
                } else {
                    aex_utf16be_to_utf8(u16, nchars, it.name, sizeof(it.name));
                }

                if (rtype == 1U) { /* kHFSPlusFolderRecord (88 bytes) */
                    if ((size_t)(val - nbuf) + 88U > hp->cat_node_size) continue;
                    it.cnid = aex_be32(val + 8U);
                    it.crtime = mac_to_unix_time(aex_be32(val + 12U));
                    it.mtime = mac_to_unix_time(aex_be32(val + 16U));
                    it.ctime = mac_to_unix_time(aex_be32(val + 20U));
                    it.atime = mac_to_unix_time(aex_be32(val + 24U));
                    it.uid = aex_be32(val + 32U);
                    it.gid = aex_be32(val + 36U);
                    it.owner_flags = val[41];
                    it.mode = aex_be16(val + 42U);
                    if ((it.mode & S_IFMT) == 0) it.mode = S_IFDIR | 0755;
                    it.nlink = aex_be32(val + 4U) + 2U;
                    if (it.cnid == 2U && vol_name_out && vol_name_cap > 0U) {
                        snprintf(vol_name_out, vol_name_cap, "%.*s", (int)(vol_name_cap - 1U), it.name);
                    }
                    if (parent_id == 2U && is_private_dir_data_u16(u16, nchars)) {
                        hp->priv_dir_data_cnid = it.cnid;
                    } else if (parent_id == 2U && is_private_file_data_u16(u16, nchars)) {
                        hp->priv_file_data_cnid = it.cnid;
                    }
                } else { /* kHFSPlusFileRecord (248 bytes) */
                    if ((size_t)(val - nbuf) + 248U > hp->cat_node_size) continue;
                    it.cnid = aex_be32(val + 8U);
                    it.crtime = mac_to_unix_time(aex_be32(val + 12U));
                    it.mtime = mac_to_unix_time(aex_be32(val + 16U));
                    it.ctime = mac_to_unix_time(aex_be32(val + 20U));
                    it.atime = mac_to_unix_time(aex_be32(val + 24U));
                    it.uid = aex_be32(val + 32U);
                    it.gid = aex_be32(val + 36U);
                    it.owner_flags = val[41];
                    it.mode = aex_be16(val + 42U);
                    it.special_inum = aex_be32(val + 44U);
                    it.fd_type = aex_be32(val + 48U);
                    it.fd_creator = aex_be32(val + 52U);
                    if ((it.mode & S_IFMT) == 0) {
                        if (it.fd_type == 0x736C6E6BU && it.fd_creator == 0x72686170U) it.mode = S_IFLNK | 0777;
                        else it.mode = S_IFREG | 0644;
                    }
                    it.nlink = 1U;
                    parse_hfsplus_fork(val + 88U, &it.data_fork);
                    parse_hfsplus_fork(val + 168U, &it.rsrc_fork);
                }
                (void)append_cat_item(hp, &it);
            }
        }
        node = aex_be32(nbuf);
    }
    free(nbuf);
    return (hp->item_count > 0) ? 0 : -EINVAL;
}

static const hfs_cat_item_t *find_by_cnid(const hfs_priv_t *hp, uint32_t cnid) {
    for (size_t i = 0; i < hp->item_count; i++) {
        if (hp->items[i].cnid == cnid) return &hp->items[i];
    }
    return NULL;
}

static const hfs_cat_item_t *find_child_raw(const hfs_priv_t *hp, uint32_t parent_cnid, const char *name) {
    for (size_t i = 0; i < hp->item_count; i++) {
        if (hp->items[i].parent_cnid != parent_cnid) continue;
        int match = hp->case_sensitive
            ? (strcmp(hp->items[i].name, name) == 0)
            : (aex_strcasecmp_utf8(hp->items[i].name, name) == 0);
        if (match) return &hp->items[i];
    }
    return NULL;
}

/* Resolve Time Machine Backups.backupdb directory hard links ('fldr'/'hlnk') and file hard links ('hlnk'/'hfs+') */
static const hfs_cat_item_t *resolve_item_target(const hfs_priv_t *hp, const hfs_cat_item_t *it, uint64_t *out_public_ino) {
    if (!it) return NULL;
    if (it->rec_type == 2U && it->fd_type == 0x666C6472U && it->fd_creator == 0x686C6E6BU && hp->priv_dir_data_cnid != 0) {
        /* Backups.backupdb directory hard link -> "dir_<special_inum>" in Private Directory Data */
        char dname[64];
        snprintf(dname, sizeof(dname), "dir_%u", it->special_inum);
        const hfs_cat_item_t *target_dir = find_child_raw(hp, hp->priv_dir_data_cnid, dname);
        if (target_dir && target_dir->rec_type == 1U) {
            if (out_public_ino) {
                *out_public_ino = HFS_VDIR_TAG | ((uint64_t)it->cnid << 32) | (uint64_t)target_dir->cnid;
            }
            return target_dir;
        }
    }
    if (it->rec_type == 2U && it->fd_type == 0x686C6E6BU && it->fd_creator == 0x6866732BU && hp->priv_file_data_cnid != 0) {
        /* HFS+ file hard link -> "iNode<special_inum>" in HFS+ Private Data */
        char fname[64];
        snprintf(fname, sizeof(fname), "iNode%u", it->special_inum);
        const hfs_cat_item_t *target_file = find_child_raw(hp, hp->priv_file_data_cnid, fname);
        if (target_file && target_file->rec_type == 2U) {
            if (out_public_ino) *out_public_ino = it->cnid;
            return target_file;
        }
    }
    if (out_public_ino) *out_public_ino = it->cnid;
    return it;
}

static const hfs_cat_item_t *resolve_ino(const hfs_priv_t *hp, uint64_t ino) {
    if ((ino & HFS_VDIR_TAG) != 0) {
        uint32_t target_cnid = (uint32_t)(ino & 0xFFFFFFFFULL);
        return find_by_cnid(hp, target_cnid);
    }
    const hfs_cat_item_t *raw = find_by_cnid(hp, (uint32_t)ino);
    return resolve_item_target(hp, raw, NULL);
}

static aex_ftype_t item_ftype(const hfs_cat_item_t *it) {
    if (it->rec_type == 1U) return AEX_FT_DIR;
    if ((it->mode & S_IFMT) == S_IFLNK || (it->fd_type == 0x736C6E6BU && it->fd_creator == 0x72686170U)) {
        return AEX_FT_SYMLINK;
    }
    return AEX_FT_REG;
}

/* ---------------- Vtable Operations ---------------- */

static void hfs_close_priv(void *priv) {
    hfs_priv_t *hp = (hfs_priv_t *)priv;
    if (!hp) return;
    free(hp->items);
    free(hp);
}

static uint64_t hfs_root_ino(const void *priv) {
    (void)priv;
    return 2ULL; /* kHFSRootFolderID */
}

static int hfs_statfs(void *priv, uint64_t *total_bytes, uint64_t *used_bytes, uint32_t *block_size) {
    const hfs_priv_t *hp = (const hfs_priv_t *)priv;
    uint64_t tot = hp->total_blocks * hp->block_size;
    uint64_t fre = hp->free_blocks * hp->block_size;
    if (total_bytes) *total_bytes = tot;
    if (used_bytes) *used_bytes = (tot >= fre) ? (tot - fre) : 0ULL;
    if (block_size) *block_size = hp->block_size;
    return 0;
}

static int hfs_getattr(void *priv, uint64_t ino, aex_attr_t *out_attr) {
    const hfs_priv_t *hp = (const hfs_priv_t *)priv;
    const hfs_cat_item_t *it = resolve_ino(hp, ino);
    if (!it) return -ENOENT;

    memset(out_attr, 0, sizeof(*out_attr));
    out_attr->ino = ino;
    out_attr->ftype = item_ftype(it);
    if (out_attr->ftype == AEX_FT_DIR) {
        /* Strip restrictive Time Machine ACL / write bits, ensure clean 0555 read+traverse */
        out_attr->mode = S_IFDIR | 0555;
    } else if (out_attr->ftype == AEX_FT_SYMLINK) {
        out_attr->mode = S_IFLNK | 0777;
    } else {
        out_attr->mode = S_IFREG | 0444;
    }
    out_attr->uid = it->uid;
    out_attr->gid = it->gid;
    out_attr->nlink = it->nlink ? it->nlink : 1U;
    out_attr->size = it->data_fork.logical_size;
    out_attr->rsrc_size = it->rsrc_fork.logical_size;
    out_attr->crtime_sec = it->crtime;
    out_attr->mtime_sec = it->mtime;
    out_attr->ctime_sec = it->ctime;
    out_attr->atime_sec = it->atime;

    /* Check UF_COMPRESSED (0x20) decmpfs uncompressed size */
    if (!hp->is_classic && out_attr->ftype == AEX_FT_REG && (it->owner_flags & 0x20U) != 0) {
        uint8_t *xa = NULL;
        size_t xalen = 0;
        if (lookup_hfsplus_xattr(hp, it->cnid, "com.apple.decmpfs", &xa, &xalen) == 0) {
            if (xalen >= 16U && aex_le32(xa) == 0x636D7066U) {
                out_attr->size = aex_le64(xa + 8U);
            }
            free(xa);
        }
    }
    return 0;
}

static int hfs_readdir(void *priv, uint64_t dir_ino, aex_readdir_cb cb, void *user_ctx) {
    const hfs_priv_t *hp = (const hfs_priv_t *)priv;
    const hfs_cat_item_t *dir = resolve_ino(hp, dir_ino);
    if (!dir || dir->rec_type != 1U) return -ENOTDIR;

    for (size_t i = 0; i < hp->item_count; i++) {
        const hfs_cat_item_t *child = &hp->items[i];
        if (child->parent_cnid != dir->cnid) continue;
        if (child->is_hidden_meta) continue;
        if (!child->name[0]) continue;

        uint64_t pub_ino = 0;
        const hfs_cat_item_t *resolved = resolve_item_target(hp, child, &pub_ino);
        if (!resolved) continue;
        if (cb(user_ctx, child->name, pub_ino, item_ftype(resolved)) != 0) break;
    }
    return 0;
}

static int hfs_lookup(void *priv, uint64_t dir_ino, const char *name, uint64_t *out_ino) {
    const hfs_priv_t *hp = (const hfs_priv_t *)priv;
    const hfs_cat_item_t *dir = resolve_ino(hp, dir_ino);
    if (!dir || dir->rec_type != 1U) return -ENOTDIR;

    for (size_t i = 0; i < hp->item_count; i++) {
        const hfs_cat_item_t *child = &hp->items[i];
        if (child->parent_cnid != dir->cnid || child->is_hidden_meta) continue;
        int match = hp->case_sensitive
            ? (strcmp(child->name, name) == 0)
            : (aex_strcasecmp_utf8(child->name, name) == 0);
        if (match) {
            uint64_t pub_ino = 0;
            if (!resolve_item_target(hp, child, &pub_ino)) return -ENOENT;
            *out_ino = pub_ino;
            return 0;
        }
    }
    return -ENOENT;
}

static int hfs_read_data(
    void *priv,
    uint64_t ino,
    int is_rsrc,
    uint64_t offset,
    size_t length,
    void *buffer,
    size_t *out_read
) {
    const hfs_priv_t *hp = (const hfs_priv_t *)priv;
    const hfs_cat_item_t *it = resolve_ino(hp, ino);
    if (!it) return -ENOENT;
    if (it->rec_type == 1U) return -EISDIR;

    if (is_rsrc) {
        return read_fork_bytes(hp, it->cnid, 0xFFU, &it->rsrc_fork, offset, length, buffer, out_read);
    }

    /* Transparent HFS+ decmpfs decompression */
    if (!hp->is_classic && (it->owner_flags & 0x20U) != 0) {
        uint8_t *xa = NULL;
        size_t xalen = 0;
        if (lookup_hfsplus_xattr(hp, it->cnid, "com.apple.decmpfs", &xa, &xalen) == 0) {
            uint8_t *rbuf = NULL;
            size_t rlen = 0;
            if (it->rsrc_fork.logical_size > 0 && it->rsrc_fork.logical_size <= (64ULL << 20)) {
                rbuf = (uint8_t *)malloc((size_t)it->rsrc_fork.logical_size);
                if (rbuf) (void)read_fork_bytes(hp, it->cnid, 0xFFU, &it->rsrc_fork, 0, (size_t)it->rsrc_fork.logical_size, rbuf, &rlen);
            }
            uint8_t *decomp = NULL;
            size_t decomp_len = 0;
            int rc = aex_decmpfs_decompress(xa, xalen, rbuf, rlen, 0, &decomp, &decomp_len);
            free(xa);
            free(rbuf);
            if (rc == 0 && decomp) {
                if (offset >= decomp_len) {
                    *out_read = 0;
                } else {
                    size_t avail = decomp_len - (size_t)offset;
                    if (avail > length) avail = length;
                    memcpy(buffer, decomp + (size_t)offset, avail);
                    *out_read = avail;
                }
                free(decomp);
                return 0;
            }
            free(decomp);
        }
    }

    return read_fork_bytes(hp, it->cnid, 0x00U, &it->data_fork, offset, length, buffer, out_read);
}

static int hfs_readlink(void *priv, uint64_t ino, char *buffer, size_t buffer_cap, size_t *out_len) {
    const hfs_priv_t *hp = (const hfs_priv_t *)priv;
    const hfs_cat_item_t *it = resolve_ino(hp, ino);
    if (!it || item_ftype(it) != AEX_FT_SYMLINK) return -EINVAL;

    size_t got = 0;
    int rc = read_fork_bytes(hp, it->cnid, 0x00U, &it->data_fork, 0, buffer_cap - 1U, buffer, &got);
    if (rc != 0) return rc;
    buffer[got] = '\0';
    if (out_len) *out_len = got;
    return 0;
}

static const aex_fs_ops_t g_hfs_ops = {
    .close_priv     = hfs_close_priv,
    .root_ino       = hfs_root_ino,
    .list_snapshots = NULL,
    .statfs         = hfs_statfs,
    .getattr        = hfs_getattr,
    .readdir        = hfs_readdir,
    .lookup         = hfs_lookup,
    .read_data      = hfs_read_data,
    .readlink       = hfs_readlink,
};

/* ---------------- Probe & Open Entrypoints ---------------- */

int aex_hfs_probe_slice(const aex_slice_t *sl, aex_fs_kind_t *out_kind, char *out_label, size_t label_cap) {
    uint8_t vh[512];
    if (aex_slice_read(sl, 1024ULL, sizeof(vh), vh) != 0) return -EIO;
    uint16_t sig = aex_be16(vh);

    if (sig == 0x482BU || sig == 0x4858U) { /* 'H+' or 'HX' */
        uint32_t bsz = aex_be32(vh + 40U);
        if (bsz < 512U || (bsz & (bsz - 1U)) != 0) return -EINVAL;
        if (out_kind) *out_kind = AEX_FS_HFSPLUS;
        if (out_label && label_cap > 0) out_label[0] = '\0';
        return 0;
    }

    if (sig == 0x4244U) { /* 'BD' Classic HFS or HFS-wrapped HFS+ */
        uint32_t ablk_sz = aex_be32(vh + 20U);
        if (ablk_sz < 512U || (ablk_sz % 512U) != 0) return -EINVAL;
        uint16_t embed_sig = aex_be16(vh + 124U);
        if (out_kind) *out_kind = (embed_sig == 0x482BU) ? AEX_FS_HFSPLUS : AEX_FS_HFS;
        if (out_label && label_cap > 0) {
            uint8_t nlen = vh[36];
            if (nlen > 27U) nlen = 27U;
            aex_macroman_to_utf8(vh + 37U, nlen, out_label, label_cap);
        }
        return 0;
    }

    return -EINVAL;
}

int aex_hfs_open(aex_t *h) {
    uint8_t vh[512];
    int rc = aex_slice_read(&h->slice, 1024ULL, sizeof(vh), vh);
    if (rc != 0) return rc;

    hfs_priv_t *hp = (hfs_priv_t *)calloc(1, sizeof(hfs_priv_t));
    if (!hp) return -ENOMEM;
    hp->vol_slice = h->slice;

    uint16_t sig = aex_be16(vh);
    if (sig == 0x4244U && aex_be16(vh + 124U) == 0x482BU) {
        /* HFS-wrapped HFS+: advance vol_slice into embedded HFS+ extent */
        uint16_t al_bl_st = aex_be16(vh + 28U);
        uint32_t al_blk_sz = aex_be32(vh + 20U);
        uint16_t emb_start = aex_be16(vh + 126U);
        uint16_t emb_cnt = aex_be16(vh + 128U);
        uint64_t emb_off = (uint64_t)al_bl_st * 512ULL + (uint64_t)emb_start * al_blk_sz;
        uint64_t emb_sz = (uint64_t)emb_cnt * al_blk_sz;
        hp->vol_slice.offset += emb_off;
        hp->vol_slice.size = emb_sz;
        if (aex_slice_read(&hp->vol_slice, 1024ULL, sizeof(vh), vh) != 0) {
            free(hp);
            return -EIO;
        }
        sig = aex_be16(vh);
    }

    if (sig == 0x482BU || sig == 0x4858U) {
        hp->is_classic = 0;
        hp->block_size = aex_be32(vh + 40U);
        hp->total_blocks = aex_be32(vh + 44U);
        hp->free_blocks = aex_be32(vh + 48U);
        if (hp->block_size < 512U || (hp->block_size & (hp->block_size - 1U)) != 0) {
            free(hp);
            return -EINVAL;
        }
        parse_hfsplus_fork(vh + 192U, &hp->extents_file);
        parse_hfsplus_fork(vh + 272U, &hp->catalog_file);
        parse_hfsplus_fork(vh + 352U, &hp->attrs_file);
        (void)read_btree_header(hp, 3U, &hp->extents_file, &hp->ext_node_size, &hp->ext_first_leaf);
        if (read_btree_header(hp, 4U, &hp->catalog_file, &hp->cat_node_size, &hp->cat_first_leaf) != 0) {
            free(hp);
            return -EINVAL;
        }
        if (sig == 0x4858U) {
            /* Check HFSX keyCompareType at BTHeaderRec + 36 (offset 14 + 36 = 50): 0xBC = case-sensitive */
            uint8_t chdr[64];
            size_t got = 0;
            if (read_fork_bytes(hp, 4U, 0, &hp->catalog_file, 0, sizeof(chdr), chdr, &got) == 0 && got >= 52U) {
                hp->case_sensitive = (chdr[50] == 0xBCU) ? 1 : 0;
            }
        }
        (void)read_btree_header(hp, 8U, &hp->attrs_file, &hp->att_node_size, &hp->att_first_leaf);
        h->kind = AEX_FS_HFSPLUS;
    } else if (sig == 0x4244U) {
        hp->is_classic = 1;
        hp->block_size = aex_be32(vh + 20U);
        hp->total_blocks = aex_be16(vh + 18U);
        hp->free_blocks = aex_be16(vh + 34U);
        hp->alloc_base_off = (uint64_t)aex_be16(vh + 28U) * 512ULL;
        if (hp->block_size < 512U || (hp->block_size % 512U) != 0) {
            free(hp);
            return -EINVAL;
        }
        uint8_t nlen = vh[36];
        if (nlen > 27U) nlen = 27U;
        aex_macroman_to_utf8(vh + 37U, nlen, h->vol_name, sizeof(h->vol_name));

        parse_classic_ext_rec(vh + 134U, aex_be32(vh + 130U), hp->block_size, &hp->extents_file);
        parse_classic_ext_rec(vh + 150U, aex_be32(vh + 146U), hp->block_size, &hp->catalog_file);
        (void)read_btree_header(hp, 3U, &hp->extents_file, &hp->ext_node_size, &hp->ext_first_leaf);
        if (read_btree_header(hp, 4U, &hp->catalog_file, &hp->cat_node_size, &hp->cat_first_leaf) != 0) {
            free(hp);
            return -EINVAL;
        }
        h->kind = AEX_FS_HFS;
    } else {
        free(hp);
        return -EINVAL;
    }

    rc = load_catalog_leaves(hp, h->vol_name, sizeof(h->vol_name));
    if (rc != 0) {
        hfs_close_priv(hp);
        return rc;
    }
    if (!h->vol_name[0]) snprintf(h->vol_name, sizeof(h->vol_name), "Apple HFS Volume");

    h->ops = &g_hfs_ops;
    h->priv = hp;
    return 0;
}
