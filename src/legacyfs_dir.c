#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <stdio.h>
#ifdef HAVE_STDLIB_H
#include <stdlib.h>
#endif
#ifdef HAVE_STRING_H
#include <string.h>
#endif
#ifdef HAVE_ERRNO_H
#include <errno.h>
#endif

#include "types.h"
#include "common.h"
#include "intrf.h"
#include "dir.h"
#include "legacyfs_dir.h"
#include "log.h"
#include "setdate.h"

#ifdef HAVE_LIBLEGACYFS
#include "legacyfs.h"

struct legacyfs_dir_state
{
  disk_t *disk_car;
  const partition_t *partition;
  legacyfs_t *fs;
  uint64_t *ino_slots;
  uint32_t *parent_slots;
  uint32_t slot_count;
  uint32_t slot_cap;
};

static int legacyfs_td_read_cb(void *io_ctx, uint64_t offset, size_t length, void *buffer)
{
  const struct legacyfs_dir_state *ls = (const struct legacyfs_dir_state *)io_ctx;
  uint64_t abs_off;
  unsigned int sector_sz;

  if (ls == NULL || ls->disk_car == NULL || ls->partition == NULL || buffer == NULL)
    return EINVAL;
  if (length == 0)
    return 0;
  if (ls->partition->part_size > 0 &&
      (offset > ls->partition->part_size || ls->partition->part_size - offset < (uint64_t)length))
    return EIO;

  abs_off = ls->partition->part_offset + offset;
  sector_sz = (ls->disk_car->sector_size >= 512U) ? ls->disk_car->sector_size : 512U;

  if ((abs_off % sector_sz) == 0 && (length % sector_sz) == 0)
  {
    if ((size_t)ls->disk_car->pread(ls->disk_car, buffer, (unsigned int)length, abs_off) != length)
      return EIO;
    return 0;
  }

  {
    const uint64_t aligned_start = (abs_off / sector_sz) * sector_sz;
    const uint64_t end = abs_off + (uint64_t)length;
    const uint64_t aligned_end = ((end + sector_sz - 1ULL) / sector_sz) * sector_sz;
    const size_t aligned_len = (size_t)(aligned_end - aligned_start);
    unsigned char *bounce = (unsigned char *)MALLOC(aligned_len);
    const ssize_t got = ls->disk_car->pread(ls->disk_car, bounce, (unsigned int)aligned_len, aligned_start);
    const size_t head_skip = (size_t)(abs_off - aligned_start);

    if (got < 0 || (size_t)got < head_skip + length)
    {
      free(bounce);
      return EIO;
    }
    memcpy(buffer, bounce + head_skip, length);
    free(bounce);
    return 0;
  }
}

static uint32_t intern_lfs_ino(struct legacyfs_dir_state *ls, uint64_t lfs_ino, uint32_t parent_slot)
{
  uint32_t i;
  for (i = 2; i < ls->slot_count; i++)
  {
    if (ls->ino_slots[i] == lfs_ino)
      return i;
  }
  if (ls->slot_count >= ls->slot_cap)
  {
    const uint32_t new_cap = (ls->slot_cap == 0) ? 256U : (ls->slot_cap * 2U);
    uint64_t *new_inos = (uint64_t *)realloc(ls->ino_slots, (size_t)new_cap * sizeof(uint64_t));
    uint32_t *new_parents = (uint32_t *)realloc(ls->parent_slots, (size_t)new_cap * sizeof(uint32_t));
    if (new_inos == NULL || new_parents == NULL)
    {
      free(new_inos);
      free(new_parents);
      return 2U;
    }
    ls->ino_slots = new_inos;
    ls->parent_slots = new_parents;
    ls->slot_cap = new_cap;
  }
  {
    const uint32_t slot = ls->slot_count++;
    ls->ino_slots[slot] = lfs_ino;
    ls->parent_slots[slot] = (parent_slot >= 2U) ? parent_slot : 2U;
    return slot;
  }
}

static uint64_t slot_to_lfs_ino(const struct legacyfs_dir_state *ls, unsigned long int slot)
{
  if (slot >= 2UL && slot < (unsigned long int)ls->slot_count)
    return ls->ino_slots[slot];
  return legacyfs_root_ino(ls->fs);
}

static uint32_t translate_lfs_mode(const legacyfs_attr_t *attr)
{
  uint32_t perm = attr->mode & 07777U;
  switch (attr->ftype)
  {
    case LEGACYFS_FT_DIR:
      return LINUX_S_IFDIR | (perm ? perm : 0755U);
    case LEGACYFS_FT_SYMLINK:
      return LINUX_S_IFLNK | (perm ? perm : 0777U);
    case LEGACYFS_FT_CHRDEV:
      return LINUX_S_IFCHR | perm;
    case LEGACYFS_FT_BLKDEV:
      return LINUX_S_IFBLK | perm;
    case LEGACYFS_FT_FIFO:
      return LINUX_S_IFIFO | perm;
    case LEGACYFS_FT_SOCK:
      return LINUX_S_IFSOCK | perm;
    case LEGACYFS_FT_REG:
    default:
      return LINUX_S_IFREG | (perm ? perm : 0644U);
  }
}

static void append_file_entry(
    file_info_t *dir_list,
    const char *name,
    uint32_t slot_ino,
    const legacyfs_attr_t *attr)
{
  file_info_t *entry = (file_info_t *)MALLOC(sizeof(*entry));
  const size_t nlen = strlen(name);
  entry->name = (char *)MALLOC(nlen + 1U);
  memcpy(entry->name, name, nlen + 1U);
  entry->st_ino = slot_ino;
  entry->st_mode = translate_lfs_mode(attr);
  entry->st_uid = attr->uid;
  entry->st_gid = attr->gid;
  entry->st_size = attr->size;
  entry->td_atime = (time_t)attr->atime_sec;
  entry->td_mtime = (time_t)attr->mtime_sec;
  entry->td_ctime = (time_t)attr->ctime_sec;
  entry->status = 0;
  td_list_add_tail(&entry->list, &dir_list->list);
}

struct lfs_readdir_pack
{
  struct legacyfs_dir_state *ls;
  uint32_t dir_slot;
  file_info_t *dir_list;
};

static int lfs_dir_visitor(void *user_ctx, const char *name, uint64_t child_ino, legacyfs_ftype_t ftype)
{
  struct lfs_readdir_pack *pack = (struct lfs_readdir_pack *)user_ctx;
  legacyfs_attr_t attr;
  uint32_t child_slot;

  (void)ftype;
  if (pack == NULL || name == NULL || name[0] == '\0')
    return 0;
  if (strcmp(name, ".") == 0 || strcmp(name, "..") == 0)
    return 0;

  memset(&attr, 0, sizeof(attr));
  if (legacyfs_getattr(pack->ls->fs, child_ino, &attr) != 0)
  {
    attr.ino = child_ino;
    attr.ftype = ftype;
    attr.mode = (ftype == LEGACYFS_FT_DIR) ? (LINUX_S_IFDIR | 0755U) : (LINUX_S_IFREG | 0644U);
  }
  child_slot = intern_lfs_ino(pack->ls, child_ino, pack->dir_slot);
  append_file_entry(pack->dir_list, name, child_slot, &attr);
  return 0;
}

static int legacyfs_get_dir(
    disk_t *disk_car,
    const partition_t *partition,
    dir_data_t *dir_data,
    const unsigned long int first_inode,
    file_info_t *dir_list)
{
  struct legacyfs_dir_state *ls = (struct legacyfs_dir_state *)dir_data->private_dir_data;
  const uint32_t cur_slot = (first_inode >= 2UL && first_inode < (unsigned long int)ls->slot_count)
      ? (uint32_t)first_inode : 2U;
  const uint32_t parent_slot = ls->parent_slots[cur_slot];
  const uint64_t dir_ino = slot_to_lfs_ino(ls, cur_slot);
  const uint64_t parent_ino = slot_to_lfs_ino(ls, parent_slot);
  legacyfs_attr_t dot_attr;
  legacyfs_attr_t dotdot_attr;
  struct lfs_readdir_pack pack;

  (void)disk_car;
  (void)partition;

  memset(&dot_attr, 0, sizeof(dot_attr));
  if (legacyfs_getattr(ls->fs, dir_ino, &dot_attr) != 0)
  {
    dot_attr.ftype = LEGACYFS_FT_DIR;
    dot_attr.mode = LINUX_S_IFDIR | 0755U;
  }
  append_file_entry(dir_list, ".", cur_slot, &dot_attr);

  memset(&dotdot_attr, 0, sizeof(dotdot_attr));
  if (legacyfs_getattr(ls->fs, parent_ino, &dotdot_attr) != 0)
  {
    dotdot_attr.ftype = LEGACYFS_FT_DIR;
    dotdot_attr.mode = LINUX_S_IFDIR | 0755U;
  }
  append_file_entry(dir_list, "..", parent_slot, &dotdot_attr);

  pack.ls = ls;
  pack.dir_slot = cur_slot;
  pack.dir_list = dir_list;
  if (legacyfs_readdir(ls->fs, dir_ino, &lfs_dir_visitor, &pack) != 0)
    return -1;
  return 0;
}

static copy_file_t legacyfs_copy_file(
    disk_t *disk_car,
    const partition_t *partition,
    dir_data_t *dir_data,
    const file_info_t *file)
{
  struct legacyfs_dir_state *ls = (struct legacyfs_dir_state *)dir_data->private_dir_data;
  const uint64_t lfs_ino = slot_to_lfs_ino(ls, file->st_ino);
  char *new_file = NULL;
  FILE *f_out;
  unsigned char *buf;
  uint64_t off = 0;
  uint64_t max_size = file->st_size;
  copy_file_t status = CP_OK;

  (void)disk_car;

  /* Guard against damaged inodes reporting an astronomical sparse size on a small partition */
  if (partition != NULL && partition->part_size > 0 &&
      max_size > partition->part_size * 16ULL && max_size > (256ULL << 20))
  {
    log_error("legacyfs_copy_file: clamping implausible size %llu on %s\n",
        (unsigned long long)max_size, dir_data->current_directory);
    max_size = partition->part_size * 16ULL;
  }

  f_out = fopen_local(&new_file, dir_data->local_dir, dir_data->current_directory);
  if (f_out == NULL)
  {
    log_critical("Can't create file %s: %s\n", new_file, strerror(errno));
    free(new_file);
    return CP_CREATE_FAILED;
  }

  buf = (unsigned char *)MALLOC(65536U);
  while (off < max_size)
  {
    size_t got = 0;
    const size_t want = (max_size - off > 65536ULL) ? 65536U : (size_t)(max_size - off);
    const int rc = legacyfs_read(ls->fs, lfs_ino, off, want, buf, &got);
    if (rc != 0)
    {
      log_error("legacyfs_read failed on %s (rc=%d)\n", dir_data->current_directory, rc);
      status = CP_READ_FAILED;
      break;
    }
    if (got == 0)
      break;
    if (fwrite(buf, 1, got, f_out) != got)
    {
      log_error("legacyfs_copy_file: write failed on %s\n", new_file);
      status = CP_NOSPACE;
      break;
    }
    off += (uint64_t)got;
  }

  free(buf);
  if (fclose(f_out) != 0 && status == CP_OK)
    status = CP_CLOSE_FAILED;
  set_date(new_file, file->td_atime, file->td_mtime);
  (void)set_mode(new_file, file->st_mode);
  free(new_file);
  return status;
}

static void dir_partition_legacyfs_close(dir_data_t *dir_data)
{
  struct legacyfs_dir_state *ls = (struct legacyfs_dir_state *)dir_data->private_dir_data;
  if (ls == NULL)
    return;
  if (ls->fs != NULL)
    legacyfs_close(ls->fs);
  free(ls->ino_slots);
  free(ls->parent_slots);
  free(ls);
  dir_data->private_dir_data = NULL;
}
#endif /* HAVE_LIBLEGACYFS */

int is_legacyfs_browsable(const partition_t *partition)
{
#ifdef HAVE_LIBLEGACYFS
  if (partition == NULL)
    return 0;
  switch (partition->upart_type)
  {
    case UP_BTRFS:
    case UP_CRAMFS:
    case UP_FREEBSD:
    case UP_ISO:
    case UP_JFS:
    case UP_OPENBSD:
    case UP_RFS:
    case UP_RFS2:
    case UP_RFS3:
    case UP_SUN:
    case UP_SYSV4:
    case UP_UFS:
    case UP_UFS2:
    case UP_UFS_LE:
    case UP_UFS2_LE:
    case UP_XFS:
    case UP_XFS2:
    case UP_XFS3:
    case UP_XFS4:
    case UP_XFS5:
      return 1;
    default:
      return 0;
  }
#else
  (void)partition;
  return 0;
#endif
}

dir_partition_t dir_partition_legacyfs_init(
    disk_t *disk_car,
    const partition_t *partition,
    dir_data_t *dir_data,
    const int verbose)
{
#ifdef HAVE_LIBLEGACYFS
  struct legacyfs_dir_state *ls;
  int rc;

  if (disk_car == NULL || partition == NULL || dir_data == NULL)
    return DIR_PART_EIO;

  ls = (struct legacyfs_dir_state *)MALLOC(sizeof(*ls));
  memset(ls, 0, sizeof(*ls));
  ls->disk_car = disk_car;
  ls->partition = partition;

  rc = legacyfs_open_io(&legacyfs_td_read_cb, ls, partition->part_size, LEGACYFS_KIND_UNKNOWN, &ls->fs);
  if (rc != 0 || ls->fs == NULL)
  {
    free(ls);
    return (rc == -ENOTSUP || rc == -EINVAL) ? DIR_PART_ENOIMP : DIR_PART_EIO;
  }

  ls->slot_cap = 256U;
  ls->ino_slots = (uint64_t *)calloc(ls->slot_cap, sizeof(uint64_t));
  ls->parent_slots = (uint32_t *)calloc(ls->slot_cap, sizeof(uint32_t));
  if (ls->ino_slots == NULL || ls->parent_slots == NULL)
  {
    legacyfs_close(ls->fs);
    free(ls->ino_slots);
    free(ls->parent_slots);
    free(ls);
    return DIR_PART_EIO;
  }
  ls->slot_count = 2U;
  intern_lfs_ino(ls, legacyfs_root_ino(ls->fs), 2U);

  strncpy(dir_data->current_directory, "/", sizeof(dir_data->current_directory));
  dir_data->current_directory[sizeof(dir_data->current_directory) - 1U] = '\0';
  dir_data->current_inode = 2UL;
  dir_data->param = 0;
  dir_data->verbose = verbose;
  dir_data->capabilities = 0;
  dir_data->get_dir = &legacyfs_get_dir;
  dir_data->copy_file = &legacyfs_copy_file;
  dir_data->close = &dir_partition_legacyfs_close;
  dir_data->local_dir = NULL;
  dir_data->private_dir_data = ls;
  return DIR_PART_OK;
#else
  (void)disk_car;
  (void)partition;
  (void)dir_data;
  (void)verbose;
  return DIR_PART_ENOSYS;
#endif
}

const char *td_legacyfs_version(void)
{
#ifdef HAVE_LIBLEGACYFS
  return legacyfs_version();
#else
  return "none";
#endif
}
