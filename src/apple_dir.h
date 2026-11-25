#ifndef _APPLE_DIR_H
#define _APPLE_DIR_H
#ifdef __cplusplus
extern "C" {
#endif

dir_partition_t dir_partition_apple_init(disk_t *disk_car, const partition_t *partition, dir_data_t *dir_data, const int verbose);
int is_apple_browsable(const partition_t *partition);
const char *td_apple_explorer_version(void);

#ifdef __cplusplus
}
#endif
#endif
