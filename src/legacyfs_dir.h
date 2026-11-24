#ifndef _LEGACYFS_DIR_H
#define _LEGACYFS_DIR_H
#ifdef __cplusplus
extern "C" {
#endif

dir_partition_t dir_partition_legacyfs_init(disk_t *disk_car, const partition_t *partition, dir_data_t *dir_data, const int verbose);
int is_legacyfs_browsable(const partition_t *partition);
const char *td_legacyfs_version(void);

#ifdef __cplusplus
}
#endif
#endif
