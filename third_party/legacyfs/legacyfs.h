#ifndef LEGACYFS_H
#define LEGACYFS_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define LEGACYFS_VERSION "0.2.0"

/* Read callback: returns 0 on full read of `length` bytes at `offset`, or positive errno on error. */
typedef int (*legacyfs_read_fn)(void *io_ctx, uint64_t offset, size_t length, void *buffer);

typedef enum {
    LEGACYFS_KIND_UNKNOWN = 0,

    /* Tier 1: Full read-only mount and file extraction supported */
    LEGACYFS_KIND_REISERFS = 1,
    LEGACYFS_KIND_MINIX = 2,
    LEGACYFS_KIND_CRAMFS = 3,
    LEGACYFS_KIND_ROMFS = 4,
    LEGACYFS_KIND_ISO9660 = 5,
    LEGACYFS_KIND_SQUASHFS = 6,
    LEGACYFS_KIND_EROFS = 7,
    LEGACYFS_KIND_UFS = 8,
    LEGACYFS_KIND_JFS = 9,
    LEGACYFS_KIND_SYSV = 10,

    /* Tier 2: Superblock and storage-container identification */
    LEGACYFS_KIND_REISER4 = 11,
    LEGACYFS_KIND_BTRFS = 12,
    LEGACYFS_KIND_XFS = 13,
    LEGACYFS_KIND_F2FS = 14,
    LEGACYFS_KIND_NILFS2 = 15,
    LEGACYFS_KIND_ZFS = 16,
    LEGACYFS_KIND_GFS2 = 17,
    LEGACYFS_KIND_OCFS2 = 18,
    LEGACYFS_KIND_BCACHEFS = 19,
    LEGACYFS_KIND_BEFS = 20,
    LEGACYFS_KIND_HPFS = 21,
    LEGACYFS_KIND_AFFS = 22,
    LEGACYFS_KIND_HFS = 23,
    LEGACYFS_KIND_UDF = 24,
    LEGACYFS_KIND_VMFS = 25,
    LEGACYFS_KIND_REFS = 26,
    LEGACYFS_KIND_WBFS = 27,
    LEGACYFS_KIND_FATX = 28,
    LEGACYFS_KIND_QNX4 = 29,
    LEGACYFS_KIND_QNX6 = 30,
    LEGACYFS_KIND_JFFS2 = 31,
    LEGACYFS_KIND_UBIFS = 32,
    LEGACYFS_KIND_LUKS1 = 33,
    LEGACYFS_KIND_LUKS2 = 34,
    LEGACYFS_KIND_LVM2 = 35,
    LEGACYFS_KIND_LINUX_RAID = 36,
    LEGACYFS_KIND_LINUX_SWAP = 37,

    LEGACYFS_KIND_COUNT = 38
} legacyfs_kind_t;

typedef enum {
    LEGACYFS_FT_UNKNOWN = 0,
    LEGACYFS_FT_REG = 1,
    LEGACYFS_FT_DIR = 2,
    LEGACYFS_FT_SYMLINK = 3,
    LEGACYFS_FT_CHRDEV = 4,
    LEGACYFS_FT_BLKDEV = 5,
    LEGACYFS_FT_FIFO = 6,
    LEGACYFS_FT_SOCK = 7
} legacyfs_ftype_t;

typedef struct {
    legacyfs_kind_t kind;
    int can_mount_ro;
    int is_container;
    int needs_recovery;
    uint32_t block_size;
    uint64_t total_bytes;
    uint64_t free_bytes;
    char name[32];
    char version_detail[32];
    char label[128];
    char uuid[64];
} legacyfs_probe_info_t;

typedef struct {
    legacyfs_kind_t kind;
    const char *short_name;
    const char *display_name;
    const char *fuse_binary;
    int can_mount_ro;
    int is_container;
} legacyfs_format_desc_t;

typedef struct {
    uint64_t ino;
    uint32_t mode;       /* Full POSIX st_mode bits (S_IFREG/S_IFDIR/S_IFLNK | 07777) */
    uint32_t uid;
    uint32_t gid;
    uint32_t nlink;
    uint64_t size;
    uint64_t blocks_512;
    int64_t atime_sec;
    int64_t mtime_sec;
    int64_t ctime_sec;
    legacyfs_ftype_t ftype;
} legacyfs_attr_t;

typedef struct {
    uint32_t block_size;
    uint64_t total_blocks;
    uint64_t free_blocks;
    uint64_t total_inodes;
    uint64_t free_inodes;
    uint32_t namemax;
} legacyfs_statfs_t;

/* Return 0 to continue iteration, non-zero to stop early. */
typedef int (*legacyfs_readdir_cb)(
    void *user_ctx,
    const char *name,
    uint64_t ino,
    legacyfs_ftype_t ftype
);

typedef struct legacyfs_handle legacyfs_t;

const char *legacyfs_version(void);
size_t legacyfs_supported_formats(const legacyfs_format_desc_t **out_table);
const legacyfs_format_desc_t *legacyfs_describe_kind(legacyfs_kind_t kind);
legacyfs_kind_t legacyfs_kind_from_name(const char *name);

/* Superblock and container probing (works on all 37 formats). Returns 0 when recognized, negative errno otherwise. */
int legacyfs_probe_io(
    legacyfs_read_fn read_fn,
    void *io_ctx,
    uint64_t partition_size,
    legacyfs_probe_info_t *out_info
);
int legacyfs_probe_path(const char *path, legacyfs_probe_info_t *out_info);

/* Read-only filesystem mount and traversal (works on all Tier 1 formats). Returns 0 on success, negative errno otherwise. */
int legacyfs_open_io(
    legacyfs_read_fn read_fn,
    void *io_ctx,
    uint64_t partition_size,
    legacyfs_kind_t forced_kind,
    legacyfs_t **out_fs
);
int legacyfs_open_path(const char *path, legacyfs_kind_t forced_kind, legacyfs_t **out_fs);
void legacyfs_close(legacyfs_t *fs);

legacyfs_kind_t legacyfs_get_kind(const legacyfs_t *fs);
const legacyfs_probe_info_t *legacyfs_get_info(const legacyfs_t *fs);
uint64_t legacyfs_root_ino(const legacyfs_t *fs);

int legacyfs_statfs(legacyfs_t *fs, legacyfs_statfs_t *out_stat);
int legacyfs_getattr(legacyfs_t *fs, uint64_t ino, legacyfs_attr_t *out_attr);
int legacyfs_readdir(legacyfs_t *fs, uint64_t dir_ino, legacyfs_readdir_cb cb, void *user_ctx);
int legacyfs_lookup(legacyfs_t *fs, uint64_t dir_ino, const char *name, uint64_t *out_ino);
int legacyfs_lookup_path(legacyfs_t *fs, const char *path, uint64_t *out_ino);
int legacyfs_read(legacyfs_t *fs, uint64_t ino, uint64_t offset, size_t length, void *buffer, size_t *out_read);
int legacyfs_readlink(legacyfs_t *fs, uint64_t ino, char *buffer, size_t buffer_size, size_t *out_len);

#ifdef __cplusplus
}
#endif

#endif /* LEGACYFS_H */
