#ifndef APPLE_EXPLORER_H
#define APPLE_EXPLORER_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define AEX_VERSION "0.1.0"

typedef enum {
    AEX_CONTAINER_RAW          = 0,
    AEX_CONTAINER_SPARSEBUNDLE = 1, /* .sparsebundle and .backupbundle */
    AEX_CONTAINER_SPARSEIMAGE  = 2, /* .sparseimage (sprs) */
    AEX_CONTAINER_UDIF_DMG     = 3  /* UDIF .dmg (koly + blkx) */
} aex_container_kind_t;

typedef enum {
    AEX_FS_UNKNOWN  = 0,
    AEX_FS_HFS      = 1, /* Classic HFS ('BD') */
    AEX_FS_HFSPLUS  = 2, /* HFS+ ('H+') and HFSX ('HX') */
    AEX_FS_APFS     = 3  /* APFS ('NXSB' + 'APSB') */
} aex_fs_kind_t;

typedef enum {
    AEX_FT_UNKNOWN = 0,
    AEX_FT_REG     = 1,
    AEX_FT_DIR     = 2,
    AEX_FT_SYMLINK = 3
} aex_ftype_t;

typedef struct {
    uint32_t      index;
    uint64_t      offset_bytes;
    uint64_t      size_bytes;
    aex_fs_kind_t detected_fs;
    char          scheme[16];  /* "GPT", "APM", "MBR", or "Whole" */
    char          type_str[64];
    char          name[128];
} aex_partition_desc_t;

typedef struct {
    uint32_t      index;
    aex_fs_kind_t kind;
    int           is_encrypted;
    int           is_time_machine;
    uint32_t      snapshot_count;
    uint64_t      total_bytes;
    uint64_t      used_bytes;
    char          name[128];
    char          uuid[64];
    char          role[32];
} aex_volume_desc_t;

typedef struct {
    uint64_t xid;
    int64_t  timestamp_sec;
    char     name[256];
} aex_snapshot_desc_t;

typedef struct {
    aex_container_kind_t container_kind;
    int                  container_encrypted;
    uint64_t             virtual_size;
    uint32_t             band_size;
    uint32_t             partition_count;
    uint32_t             volume_count;
    aex_fs_kind_t        primary_fs;
    int                  has_backups_db;
    int                  has_apfs_snapshots;
    char                 primary_label[128];
} aex_probe_info_t;

typedef struct {
    uint64_t    ino;
    uint32_t    mode;
    uint32_t    uid;
    uint32_t    gid;
    uint32_t    nlink;
    uint64_t    size;
    uint64_t    rsrc_size;
    int64_t     atime_sec;
    int64_t     mtime_sec;
    int64_t     ctime_sec;
    int64_t     crtime_sec;
    aex_ftype_t ftype;
} aex_attr_t;

typedef struct {
    int         partition_index; /* -1 = auto-select first Apple partition */
    int         volume_index;    /* -1 = auto-select primary/backup volume */
    const char *snapshot_name;   /* NULL = live volume (plus synthetic /Snapshots & /Backups trees) */
    const char *password;        /* Optional passphrase for encrypted .sparsebundle/.dmg or FileVault 2 */
} aex_open_options_t;

typedef int (*aex_read_fn)(void *io_ctx, uint64_t offset, size_t length, void *buffer);

/* Return 0 to continue iteration, non-zero to stop early. */
typedef int (*aex_readdir_cb)(
    void *user_ctx,
    const char *name,
    uint64_t ino,
    aex_ftype_t ftype
);

typedef struct aex_stream aex_stream_t;
typedef struct aex_handle aex_t;

const char *aex_version(void);
const char *aex_strerror(int err_code);

/* Container / Disk Image / Device Stream API */
int aex_stream_open_path(const char *path, const char *password, aex_stream_t **out_stream);
int aex_stream_open_io(aex_read_fn read_fn, void *io_ctx, uint64_t size_bytes, aex_stream_t **out_stream);
void aex_stream_close(aex_stream_t *stream);
uint64_t aex_stream_size(const aex_stream_t *stream);
aex_container_kind_t aex_stream_kind(const aex_stream_t *stream);
int aex_stream_read(aex_stream_t *stream, uint64_t offset, size_t length, void *buffer);

/* Probing, Partition Discovery, Volume & Snapshot Enumeration */
int aex_probe_path(const char *path, const char *password, aex_probe_info_t *out_info);
int aex_list_partitions(aex_stream_t *stream, aex_partition_desc_t *out_parts, size_t max_parts, size_t *out_count);
int aex_list_volumes_path(const char *path, const char *password, aex_volume_desc_t *out_vols, size_t max_vols, size_t *out_count);

/* Filesystem Open & Traversal API (Classic HFS, HFS+/HFSX + Backups.backupdb, APFS + FileVault 2 + Snapshots) */
int aex_open_path(const char *path, const aex_open_options_t *opts, aex_t **out_fs);
int aex_open_io(aex_read_fn read_fn, void *io_ctx, uint64_t size_bytes, const aex_open_options_t *opts, aex_t **out_fs);
void aex_close(aex_t *fs);

aex_fs_kind_t aex_fs_kind(const aex_t *fs);
const char *aex_volume_name(const aex_t *fs);
uint64_t aex_root_ino(const aex_t *fs);
int aex_list_snapshots(aex_t *fs, aex_snapshot_desc_t *out_snaps, size_t max_snaps, size_t *out_count);

int aex_statfs(aex_t *fs, uint64_t *total_bytes, uint64_t *used_bytes, uint32_t *block_size);
int aex_getattr(aex_t *fs, uint64_t ino, aex_attr_t *out_attr);
int aex_readdir(aex_t *fs, uint64_t dir_ino, aex_readdir_cb cb, void *user_ctx);
int aex_lookup(aex_t *fs, uint64_t dir_ino, const char *name, uint64_t *out_ino);
int aex_lookup_path(aex_t *fs, const char *path, uint64_t *out_ino);
int aex_read(aex_t *fs, uint64_t ino, uint64_t offset, size_t length, void *buffer, size_t *out_read);
int aex_read_rsrc(aex_t *fs, uint64_t ino, uint64_t offset, size_t length, void *buffer, size_t *out_read);
int aex_readlink(aex_t *fs, uint64_t ino, char *buffer, size_t buffer_cap, size_t *out_len);

/* Recursive File & Directory Tree Extraction Helper */
int aex_extract_path(aex_t *fs, const char *src_path, const char *dest_host_path);

#ifdef __cplusplus
}
#endif

#endif /* APPLE_EXPLORER_H */
