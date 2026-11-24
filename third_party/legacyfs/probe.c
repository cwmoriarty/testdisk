#include "internal.h"
#include <stdio.h>

static void fill_common(legacyfs_probe_info_t *out, legacyfs_kind_t kind, const char *ver) {
    memset(out, 0, sizeof(*out));
    const legacyfs_format_desc_t *desc = legacyfs_describe_kind(kind);
    out->kind = kind;
    out->can_mount_ro = desc->can_mount_ro;
    out->is_container = desc->is_container;
    snprintf(out->name, sizeof(out->name), "%s", desc->display_name);
    if (ver) {
        snprintf(out->version_detail, sizeof(out->version_detail), "%s", ver);
    }
}

static int try_read(legacyfs_read_fn fn, void *ctx, uint64_t part_size, uint64_t off, size_t len, void *buf) {
    if (part_size > 0 && (off > part_size || part_size - off < len)) return 0;
    return fn(ctx, off, len, buf) == 0;
}

/* ReiserFS 3.5 / 3.6 / Reiser4 at 64 KiB or 8 KiB */
static int probe_reiser(legacyfs_read_fn fn, void *ctx, uint64_t part_size, legacyfs_probe_info_t *out) {
    static const uint64_t offsets[2] = { 65536ULL, 8192ULL };
    uint8_t sb[256];

    for (int i = 0; i < 2; i++) {
        if (!try_read(fn, ctx, part_size, offsets[i], sizeof(sb), sb)) continue;

        if (offsets[i] == 65536ULL && memcmp(sb, "ReIsEr4", 7) == 0) {
            fill_common(out, LEGACYFS_KIND_REISER4, "4.0");
            lfs_format_uuid(sb + 16, out->uuid);
            lfs_copy_trimmed_label(sb + 32, 16, out->label, sizeof(out->label));
            out->block_size = 4096U;
            return 1;
        }

        const char *ver = NULL;
        int has_v2_fields = 0;
        if (memcmp(sb + 52, "ReIsErFs", 8) == 0) {
            ver = "3.5";
        } else if (memcmp(sb + 52, "ReIsEr2Fs", 9) == 0) {
            ver = "3.6";
            has_v2_fields = 1;
        } else if (memcmp(sb + 52, "ReIsEr3Fs", 9) == 0) {
            ver = "3.6-jr";
            has_v2_fields = 1;
        }
        if (!ver) continue;

        uint32_t blocks = lfs_le32(sb + 0);
        uint32_t free_blocks = lfs_le32(sb + 4);
        uint32_t root_block = lfs_le32(sb + 8);
        uint16_t bsize = lfs_le16(sb + 44);
        uint16_t fs_state = lfs_le16(sb + 50);
        if (bsize < 512 || bsize > 8192 || !lfs_is_pow2_u32(bsize)) continue;
        if (blocks < 16 || free_blocks > blocks || root_block == 0 || root_block >= blocks) continue;

        fill_common(out, LEGACYFS_KIND_REISERFS, ver);
        out->block_size = bsize;
        out->total_bytes = (uint64_t)blocks * (uint64_t)bsize;
        out->free_bytes = (uint64_t)free_blocks * (uint64_t)bsize;
        out->needs_recovery = (fs_state != 1) ? 1 : 0; /* REISERFS_VALID_FS == 1 */
        if (has_v2_fields) {
            lfs_format_uuid(sb + 84, out->uuid);
            lfs_copy_trimmed_label(sb + 100, 16, out->label, sizeof(out->label));
        }
        return 1;
    }
    return 0;
}

/* SquashFS 4.0 */
static int probe_squashfs(const uint8_t *head, size_t head_len, legacyfs_probe_info_t *out) {
    if (head_len < 96) return 0;
    if (lfs_le32(head) != 0x73717368U) return 0; /* "hsqs" */
    uint16_t s_major = lfs_le16(head + 28);
    uint16_t s_minor = lfs_le16(head + 30);
    uint32_t bsize = lfs_le32(head + 12);
    uint64_t bytes_used = lfs_le64(head + 40);
    if (s_major != 4 || bsize < 4096U || bsize > (1U << 20) || !lfs_is_pow2_u32(bsize) || bytes_used < 96) {
        return 0;
    }
    char ver[32];
    snprintf(ver, sizeof(ver), "%u.%u", s_major, s_minor);
    fill_common(out, LEGACYFS_KIND_SQUASHFS, ver);
    out->block_size = bsize;
    out->total_bytes = bytes_used;
    return 1;
}

/* CramFS (at offset 0 or 512) */
static int probe_cramfs(const uint8_t *head, size_t head_len, legacyfs_probe_info_t *out) {
    static const size_t offs[2] = { 0, 512 };
    for (int i = 0; i < 2; i++) {
        if (head_len < offs[i] + 76) continue;
        const uint8_t *sb = head + offs[i];
        if (lfs_le32(sb) != 0x28cd3d45U) continue;
        if (memcmp(sb + 16, "Compressed ROMFS", 16) != 0) continue;
        uint32_t size = lfs_le32(sb + 4);
        fill_common(out, LEGACYFS_KIND_CRAMFS, "2.0");
        out->block_size = 4096U;
        out->total_bytes = size;
        lfs_copy_trimmed_label(sb + 48, 16, out->label, sizeof(out->label));
        return 1;
    }
    return 0;
}

/* ROMFS (-rom1fs- at offset 0) */
static int probe_romfs(const uint8_t *head, size_t head_len, legacyfs_probe_info_t *out) {
    if (head_len < 32) return 0;
    if (memcmp(head, "-rom1fs-", 8) != 0) return 0;
    uint32_t full_size = lfs_be32(head + 8);
    if (full_size < 32) return 0;
    fill_common(out, LEGACYFS_KIND_ROMFS, "1.0");
    out->block_size = 1024U;
    out->total_bytes = full_size;
    lfs_copy_trimmed_label(head + 16, 16, out->label, sizeof(out->label));
    return 1;
}

/* EROFS at offset 1024 */
static int probe_erofs(const uint8_t *head, size_t head_len, legacyfs_probe_info_t *out) {
    if (head_len < 1024 + 128) return 0;
    const uint8_t *sb = head + 1024;
    if (lfs_le32(sb) != 0xE0F5E1E2U) return 0;
    uint8_t blkszbits = sb[12];
    if (blkszbits < 9 || blkszbits > 16) return 0;
    uint32_t bsize = 1U << blkszbits;
    uint32_t blocks = lfs_le32(sb + 36);
    fill_common(out, LEGACYFS_KIND_EROFS, "1.0");
    out->block_size = bsize;
    out->total_bytes = (uint64_t)blocks * (uint64_t)bsize;
    lfs_format_uuid(sb + 48, out->uuid);
    lfs_copy_trimmed_label(sb + 64, 16, out->label, sizeof(out->label));
    return 1;
}

/* Minix v1 / v2 / v3 at offset 1024 */
static int probe_minix(const uint8_t *head, size_t head_len, legacyfs_probe_info_t *out) {
    if (head_len < 1024 + 64) return 0;
    const uint8_t *sb = head + 1024;
    uint16_t m16 = lfs_le16(sb + 16);
    uint16_t m3_magic = lfs_le16(sb + 24);
    const char *ver = NULL;
    uint32_t bsize = 1024U;
    uint64_t zones = 0;

    if (m3_magic == 0x4D5AU) {
        uint16_t bsz = lfs_le16(sb + 28);
        if (bsz < 1024 || bsz > 8192 || !lfs_is_pow2_u32(bsz)) return 0;
        bsize = bsz;
        zones = lfs_le32(sb + 20);
        ver = "v3";
    } else if (m16 == 0x137FU || m16 == 0x138FU) {
        zones = lfs_le16(sb + 2);
        ver = (m16 == 0x138FU) ? "v1-30" : "v1-14";
    } else if (m16 == 0x2468U || m16 == 0x2478U) {
        zones = lfs_le32(sb + 20);
        ver = (m16 == 0x2478U) ? "v2-30" : "v2-14";
    }
    if (!ver || zones < 4) return 0;

    fill_common(out, LEGACYFS_KIND_MINIX, ver);
    out->block_size = bsize;
    out->total_bytes = zones * (uint64_t)bsize;
    return 1;
}

/* ISO9660 / UDF at 32 KiB */
static int probe_iso_udf(legacyfs_read_fn fn, void *ctx, uint64_t part_size, legacyfs_probe_info_t *out) {
    uint8_t pvd[2048];
    if (try_read(fn, ctx, part_size, 32768ULL, sizeof(pvd), pvd)) {
        if (pvd[0] == 1 && memcmp(pvd + 1, "CD001", 5) == 0 && pvd[6] == 1) {
            uint32_t space_size = lfs_le32(pvd + 80);
            uint16_t lb_size = lfs_le16(pvd + 128);
            if (lb_size == 0) lb_size = 2048U;
            fill_common(out, LEGACYFS_KIND_ISO9660, "ISO9660");
            out->block_size = lb_size;
            out->total_bytes = (uint64_t)space_size * (uint64_t)lb_size;
            lfs_copy_trimmed_label(pvd + 40, 32, out->label, sizeof(out->label));
            return 1;
        }
        if (memcmp(pvd + 1, "BEA01", 5) == 0 || memcmp(pvd + 1, "NSR02", 5) == 0 || memcmp(pvd + 1, "NSR03", 5) == 0) {
            fill_common(out, LEGACYFS_KIND_UDF, "UDF");
            out->block_size = 2048U;
            return 1;
        }
    }
    if (try_read(fn, ctx, part_size, 34816ULL, 64, pvd)) {
        if (memcmp(pvd + 1, "NSR02", 5) == 0 || memcmp(pvd + 1, "NSR03", 5) == 0) {
            fill_common(out, LEGACYFS_KIND_UDF, "UDF");
            out->block_size = 2048U;
            return 1;
        }
    }
    return 0;
}

/* UFS1 / UFS2 (BSD FFS) at 64K, 8K, 0K, or 256K */
static int probe_ufs(legacyfs_read_fn fn, void *ctx, uint64_t part_size, legacyfs_probe_info_t *out) {
    static const uint64_t sboffs[4] = { 65536ULL, 8192ULL, 0ULL, 262144ULL };
    uint8_t sb[1536];

    for (int i = 0; i < 4; i++) {
        if (!try_read(fn, ctx, part_size, sboffs[i], sizeof(sb), sb)) continue;
        uint32_t magic = lfs_le32(sb + 1372);
        if (magic != 0x00011954U && magic != 0x19540119U) continue;
        uint32_t bsize = lfs_le32(sb + 48);
        uint32_t fsize = lfs_le32(sb + 52);
        if (bsize < 4096U || bsize > 65536U || !lfs_is_pow2_u32(bsize)) continue;
        if (fsize < 512U || fsize > bsize || !lfs_is_pow2_u32(fsize)) continue;

        const char *ver = (magic == 0x19540119U) ? "UFS2" : "UFS1";
        uint64_t total_frags = (magic == 0x19540119U) ? lfs_le64(sb + 1088) : (uint64_t)lfs_le32(sb + 36);
        fill_common(out, LEGACYFS_KIND_UFS, ver);
        out->block_size = fsize;
        out->total_bytes = total_frags * (uint64_t)fsize;
        if (magic == 0x19540119U) {
            lfs_copy_trimmed_label(sb + 680, 32, out->label, sizeof(out->label));
        }
        return 1;
    }
    return 0;
}

/* IBM JFS at 32 KiB */
static int probe_jfs(legacyfs_read_fn fn, void *ctx, uint64_t part_size, legacyfs_probe_info_t *out) {
    uint8_t sb[256];
    if (!try_read(fn, ctx, part_size, 32768ULL, sizeof(sb), sb)) return 0;
    if (memcmp(sb, "JFS1", 4) != 0) return 0;
    uint32_t version = lfs_le32(sb + 4);
    uint32_t bsize = lfs_le32(sb + 16);
    uint32_t pbsize = lfs_le32(sb + 24);
    if (version == 0 || version > 4 || bsize < 512U || bsize > 65536U || !lfs_is_pow2_u32(bsize)) return 0;
    if (pbsize == 0) pbsize = 512U;
    uint64_t size_pblks = lfs_le64(sb + 8);
    fill_common(out, LEGACYFS_KIND_JFS, "JFS1");
    out->block_size = bsize;
    out->total_bytes = size_pblks * (uint64_t)pbsize;
    lfs_format_uuid(sb + 128, out->uuid);
    lfs_copy_trimmed_label(sb + 144, 16, out->label, sizeof(out->label));
    if (out->label[0] == '\0') {
        lfs_copy_trimmed_label(sb + 101, 11, out->label, sizeof(out->label));
    }
    return 1;
}

/* SysV / Xenix at 512 or 1024 */
static int probe_sysv(const uint8_t *head, size_t head_len, legacyfs_probe_info_t *out) {
    /* Standard System V magic 0xFD187E20 at superblock + 504 (offset 512 or 1024) */
    static const size_t sboffs[2] = { 512, 1024 };
    for (int i = 0; i < 2; i++) {
        if (head_len < sboffs[i] + 512) continue;
        const uint8_t *sb = head + sboffs[i];
        uint32_t magic = lfs_le32(sb + 504);
        if (magic != 0xFD187E20U) continue;
        uint32_t s_type = lfs_le32(sb + 508);
        uint32_t bsize = (s_type == 2) ? 1024U : ((s_type == 3) ? 2048U : 512U);
        uint32_t fsize = lfs_le32(sb + 4);
        if (fsize < 4) continue;
        fill_common(out, LEGACYFS_KIND_SYSV, "System V");
        out->block_size = bsize;
        out->total_bytes = (uint64_t)fsize * (uint64_t)bsize;
        lfs_copy_trimmed_label(sb + 492, 6, out->label, sizeof(out->label));
        return 1;
    }
    return 0;
}

/* Tier 2 detectors (containers, modern COW, retro, enterprise) */
static int probe_tier2(
    legacyfs_read_fn fn,
    void *ctx,
    uint64_t part_size,
    const uint8_t *head,
    size_t head_len,
    legacyfs_probe_info_t *out
) {
    /* LUKS1 / LUKS2 at offset 0 */
    if (head_len >= 256 && memcmp(head, "LUKS\xba\xbe", 6) == 0) {
        uint16_t ver = lfs_be16(head + 6);
        if (ver == 1) {
            fill_common(out, LEGACYFS_KIND_LUKS1, "1");
            lfs_copy_trimmed_label(head + 168, 40, out->uuid, sizeof(out->uuid));
            return 1;
        }
        if (ver == 2) {
            fill_common(out, LEGACYFS_KIND_LUKS2, "2");
            lfs_copy_trimmed_label(head + 168, 40, out->uuid, sizeof(out->uuid));
            lfs_copy_trimmed_label(head + 24, 48, out->label, sizeof(out->label));
            return 1;
        }
    }

    /* LVM2 Physical Volume at sector 1 (offset 512) */
    if (head_len >= 1024 && memcmp(head + 512, "LABELONE", 8) == 0 && memcmp(head + 512 + 24, "LVM2 001", 8) == 0) {
        fill_common(out, LEGACYFS_KIND_LVM2, "LVM2");
        lfs_copy_trimmed_label(head + 512 + 32, 32, out->uuid, sizeof(out->uuid));
        return 1;
    }

    /* Linux MD RAID 1.x (at 4 KiB or 0 KiB) */
    if (head_len >= 4096 + 256 && lfs_le32(head + 4096) == 0xa92b4efcU) {
        fill_common(out, LEGACYFS_KIND_LINUX_RAID, "1.2");
        lfs_format_uuid(head + 4096 + 16, out->uuid);
        lfs_copy_trimmed_label(head + 4096 + 32, 32, out->label, sizeof(out->label));
        return 1;
    }
    if (head_len >= 256 && lfs_le32(head) == 0xa92b4efcU) {
        fill_common(out, LEGACYFS_KIND_LINUX_RAID, "1.1");
        lfs_format_uuid(head + 16, out->uuid);
        lfs_copy_trimmed_label(head + 32, 32, out->label, sizeof(out->label));
        return 1;
    }

    /* Linux Swap at page_size - 10 (4086 or 8182) */
    if (head_len >= 4096 && (memcmp(head + 4086, "SWAPSPACE2", 10) == 0 || memcmp(head + 4086, "SWAP-SPACE", 10) == 0)) {
        fill_common(out, LEGACYFS_KIND_LINUX_SWAP, "2");
        out->block_size = 4096U;
        lfs_format_uuid(head + 1036, out->uuid);
        lfs_copy_trimmed_label(head + 1052, 16, out->label, sizeof(out->label));
        return 1;
    }

    /* XFS at offset 0 */
    if (head_len >= 256 && memcmp(head, "XFSB", 4) == 0) {
        uint32_t bsize = lfs_be32(head + 4);
        if (bsize >= 512U && bsize <= 65536U && lfs_is_pow2_u32(bsize)) {
            fill_common(out, LEGACYFS_KIND_XFS, "XFS");
            out->block_size = bsize;
            out->total_bytes = lfs_be64(head + 8) * (uint64_t)bsize;
            lfs_format_uuid(head + 32, out->uuid);
            lfs_copy_trimmed_label(head + 108, 12, out->label, sizeof(out->label));
            return 1;
        }
    }

    /* F2FS at offset 1024 */
    if (head_len >= 1536 && lfs_le32(head + 1024) == 0xF2F52010U) {
        fill_common(out, LEGACYFS_KIND_F2FS, "F2FS");
        out->block_size = 4096U;
        lfs_format_uuid(head + 1024 + 108, out->uuid);
        return 1;
    }

    /* NILFS2 at offset 1024 (s_magic = 0x3434 at +6) */
    if (head_len >= 1536 && lfs_le16(head + 1024 + 6) == 0x3434U && lfs_le32(head + 1024) <= 4U) {
        uint32_t log_bsize = lfs_le32(head + 1024 + 24);
        if (log_bsize <= 6) {
            fill_common(out, LEGACYFS_KIND_NILFS2, "2");
            out->block_size = 1024U << log_bsize;
            lfs_format_uuid(head + 1024 + 152, out->uuid);
            lfs_copy_trimmed_label(head + 1024 + 168, 80, out->label, sizeof(out->label));
            return 1;
        }
    }

    /* BCacheFS at offset 4096 (16-byte magic UUID c68573f6-66ce-90a9-d96a-60cf803df7ef at +24) */
    static const uint8_t bcache_magic[16] = {
        0xc6, 0x85, 0x73, 0xf6, 0x66, 0xce, 0x90, 0xa9,
        0xd9, 0x6a, 0x60, 0xcf, 0x80, 0x3d, 0xf7, 0xef
    };
    if (head_len >= 4096 + 168 && memcmp(head + 4096 + 24, bcache_magic, 16) == 0) {
        fill_common(out, LEGACYFS_KIND_BCACHEFS, "BCacheFS");
        lfs_format_uuid(head + 4096 + 40, out->uuid);
        lfs_copy_trimmed_label(head + 4096 + 56, 32, out->label, sizeof(out->label));
        return 1;
    }

    /* BeFS / Haiku BFS at offset 512 */
    if (head_len >= 1024 && (lfs_le32(head + 512 + 32) == 0x42465331U || lfs_be32(head + 512 + 32) == 0x42465331U)) {
        fill_common(out, LEGACYFS_KIND_BEFS, "BFS1");
        lfs_copy_trimmed_label(head + 512, 32, out->label, sizeof(out->label));
        return 1;
    }

    /* Classic Mac HFS ("BD" at offset 1024, non-HFS+ wrapper check) */
    if (head_len >= 1200 && lfs_be16(head + 1024) == 0x4244U && lfs_be16(head + 1024 + 124) != 0x482BU) {
        uint32_t blk_sz = lfs_be32(head + 1024 + 20);
        if (blk_sz >= 512U && (blk_sz % 512U) == 0) {
            fill_common(out, LEGACYFS_KIND_HFS, "HFS");
            out->block_size = blk_sz;
            uint8_t name_len = head[1024 + 36];
            if (name_len > 0 && name_len <= 27) {
                lfs_copy_trimmed_label(head + 1024 + 37, name_len, out->label, sizeof(out->label));
            }
            return 1;
        }
    }

    /* Amiga AFFS ("DOS\0".."DOS\7" at offset 0 with non-zero rootblock pointer check) */
    if (head_len >= 512 && memcmp(head, "DOS", 3) == 0 && head[3] <= 7 && lfs_be32(head + 8) != 0) {
        fill_common(out, LEGACYFS_KIND_AFFS, "AFFS");
        out->block_size = 512U;
        return 1;
    }

    /* Microsoft ReFS ("ReFS" at offset 3) */
    if (head_len >= 512 && memcmp(head + 3, "ReFS\0\0\0\0", 8) == 0) {
        fill_common(out, LEGACYFS_KIND_REFS, "ReFS");
        return 1;
    }

    /* Wii WBFS ("WBFS" at offset 0) */
    if (head_len >= 512 && memcmp(head, "WBFS", 4) == 0) {
        fill_common(out, LEGACYFS_KIND_WBFS, "WBFS");
        return 1;
    }

    /* Xbox FATX ("FATX" at offset 0) */
    if (head_len >= 512 && memcmp(head, "FATX", 4) == 0) {
        fill_common(out, LEGACYFS_KIND_FATX, "FATX");
        return 1;
    }

    /* JFFS2 (0x1985 node magic + valid nodetype 0xE001/0xE002/0x2003) */
    if (head_len >= 64 && lfs_le16(head) == 0x1985U) {
        uint16_t ntype = lfs_le16(head + 2);
        if (ntype == 0xE001U || ntype == 0xE002U || ntype == 0x2003U) {
            fill_common(out, LEGACYFS_KIND_JFFS2, "JFFS2");
            return 1;
        }
    }

    /* UBIFS (0x06101831 at offset 0, node_type 6 = superblock) */
    if (head_len >= 64 && lfs_le32(head) == 0x06101831U && head[16] == 6) {
        fill_common(out, LEGACYFS_KIND_UBIFS, "UBIFS");
        return 1;
    }

    /* QNX4 (0x002F at offset 512) & QNX6 (0x68191122 at offset 4096) */
    if (head_len >= 4096 + 64 && lfs_le32(head + 4096) == 0x68191122U) {
        fill_common(out, LEGACYFS_KIND_QNX6, "QNX6");
        lfs_format_uuid(head + 4096 + 4, out->uuid);
        return 1;
    }
    if (head_len >= 1024 && lfs_le16(head + 512) == 0x002FU && memcmp(head + 512 + 4, "QNX4", 4) == 0) {
        fill_common(out, LEGACYFS_KIND_QNX4, "QNX4");
        return 1;
    }

    /* OCFS2 ("OCFSV2" at 1K, 2K, 4K, or 8K) */
    static const size_t ocfs_offs[4] = { 1024, 2048, 4096, 8192 };
    for (int i = 0; i < 4; i++) {
        if (head_len >= ocfs_offs[i] + 256 && memcmp(head + ocfs_offs[i], "OCFSV2", 6) == 0) {
            fill_common(out, LEGACYFS_KIND_OCFS2, "OCFS2");
            lfs_copy_trimmed_label(head + ocfs_offs[i] + 104, 64, out->label, sizeof(out->label));
            lfs_format_uuid(head + ocfs_offs[i] + 168, out->uuid);
            return 1;
        }
    }

    /* HPFS (0xF995E849 at sector 16 = offset 8192) */
    if (head_len >= 8192 + 64 && lfs_le32(head + 8192) == 0xF995E849U && lfs_le32(head + 8192 + 4) == 0xFA53E9C5U) {
        fill_common(out, LEGACYFS_KIND_HPFS, "HPFS");
        out->block_size = 512U;
        return 1;
    }

    /* 64 KiB probes: Btrfs and GFS2 */
    uint8_t buf64k[1024];
    if (try_read(fn, ctx, part_size, 65536ULL, sizeof(buf64k), buf64k)) {
        if (memcmp(buf64k + 64, "_BHRfS_M", 8) == 0) {
            fill_common(out, LEGACYFS_KIND_BTRFS, "Btrfs");
            out->block_size = lfs_le32(buf64k + 144);
            out->total_bytes = lfs_le64(buf64k + 112);
            lfs_format_uuid(buf64k + 32, out->uuid);
            lfs_copy_trimmed_label(buf64k + 299, 256, out->label, sizeof(out->label));
            return 1;
        }
        if (lfs_be32(buf64k) == 0x01161970U && lfs_be32(buf64k + 4) == 1U) {
            fill_common(out, LEGACYFS_KIND_GFS2, "GFS2");
            out->block_size = lfs_be32(buf64k + 36);
            lfs_copy_trimmed_label(buf64k + 104, 64, out->label, sizeof(out->label));
            return 1;
        }
    }

    /* ZFS vdev uberblock at 128 KiB (offset 131072) */
    uint8_t zbuf[1024];
    if (try_read(fn, ctx, part_size, 131072ULL, sizeof(zbuf), zbuf)) {
        if (lfs_le64(zbuf) == 0x00bab10cULL || lfs_be64(zbuf) == 0x00bab10cULL) {
            fill_common(out, LEGACYFS_KIND_ZFS, "ZFS");
            return 1;
        }
    }

    /* VMware VMFS at 1 MiB (offset 1048576) */
    uint8_t vbuf[64];
    if (try_read(fn, ctx, part_size, 1048576ULL, sizeof(vbuf), vbuf)) {
        if (lfs_le32(vbuf) == 0x2fabf15eU || lfs_le32(vbuf) == 0xc001d00dU) {
            fill_common(out, LEGACYFS_KIND_VMFS, "VMFS");
            return 1;
        }
    }

    return 0;
}

int legacyfs_probe_io(
    legacyfs_read_fn read_fn,
    void *io_ctx,
    uint64_t partition_size,
    legacyfs_probe_info_t *out_info
) {
    if (!read_fn || !out_info) return -EINVAL;
    memset(out_info, 0, sizeof(*out_info));

    /* Read up to 12 KiB from the start in realistic decreasing sizes so small images succeed too. */
    uint8_t head[12288];
    memset(head, 0, sizeof(head));
    size_t head_got = 0;
    static const size_t sizes[4] = { 12288, 4096, 2048, 512 };
    for (int i = 0; i < 4; i++) {
        if (try_read(read_fn, io_ctx, partition_size, 0, sizes[i], head)) {
            head_got = sizes[i];
            break;
        }
    }
    if (head_got == 0) {
        return -EIO;
    }

    /* Tier 1 mountable formats first */
    if (probe_reiser(read_fn, io_ctx, partition_size, out_info)) return 0;
    if (probe_squashfs(head, head_got, out_info)) return 0;
    if (probe_cramfs(head, head_got, out_info)) return 0;
    if (probe_romfs(head, head_got, out_info)) return 0;
    if (probe_erofs(head, head_got, out_info)) return 0;
    if (probe_minix(head, head_got, out_info)) return 0;
    if (probe_jfs(read_fn, io_ctx, partition_size, out_info)) return 0;
    if (probe_ufs(read_fn, io_ctx, partition_size, out_info)) return 0;
    if (probe_iso_udf(read_fn, io_ctx, partition_size, out_info)) return 0;
    if (probe_sysv(head, head_got, out_info)) return 0;

    /* Tier 2 identification formats */
    if (probe_tier2(read_fn, io_ctx, partition_size, head, head_got, out_info)) return 0;

    return -ENOENT;
}
