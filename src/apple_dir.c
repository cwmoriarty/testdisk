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
#include "guid_cmp.h"
#include "intrf.h"
#include "dir.h"
#include "list_sort.h"
#include "apple_dir.h"
#include "log.h"
#include "setdate.h"

#ifdef HAVE_LIBAPPLEEXPLORER
#include "apple_explorer.h"

struct apple_dir_state
{
  disk_t *disk_car;
  const partition_t *partition;
  uint64_t slice_size;
  aex_t *fs;
  uint64_t *ino_slots;
  uint32_t *parent_slots;
  uint32_t slot_count;
  uint32_t slot_cap;
};

static int apple_td_read_cb(void *io_ctx, uint64_t offset, size_t length, void *buffer)
{
  const struct apple_dir_state *as = (const struct apple_dir_state *)io_ctx;
  uint64_t abs_off;
  unsigned int sector_sz;

  if (as == NULL || as->disk_car == NULL || as->partition == NULL || buffer == NULL)
    return -EINVAL;
  if (length == 0)
    return 0;
  if (as->slice_size > 0 &&
      (offset > as->slice_size || as->slice_size - offset < (uint64_t)length))
    return -EIO;

  abs_off = as->partition->part_offset + offset;
  sector_sz = (as->disk_car->sector_size >= 512U) ? as->disk_car->sector_size : 512U;

  if ((abs_off % sector_sz) == 0 && (length % sector_sz) == 0)
  {
    if ((size_t)as->disk_car->pread(as->disk_car, buffer, (unsigned int)length, abs_off) != length)
      return -EIO;
    return 0;
  }

  {
    const uint64_t aligned_start = (abs_off / sector_sz) * sector_sz;
    const uint64_t end = abs_off + (uint64_t)length;
    const uint64_t aligned_end = ((end + sector_sz - 1ULL) / sector_sz) * sector_sz;
    const size_t aligned_len = (size_t)(aligned_end - aligned_start);
    unsigned char *bounce = (unsigned char *)MALLOC(aligned_len);
    const ssize_t got = as->disk_car->pread(as->disk_car, bounce, (unsigned int)aligned_len, aligned_start);
    const size_t head_skip = (size_t)(abs_off - aligned_start);

    if (got < 0 || (size_t)got < head_skip + length)
    {
      free(bounce);
      return -EIO;
    }
    memcpy(buffer, bounce + head_skip, length);
    free(bounce);
    return 0;
  }
}

static uint32_t intern_aex_ino(struct apple_dir_state *as, uint64_t aex_ino, uint32_t parent_slot)
{
  uint32_t i;
  for (i = 2; i < as->slot_count; i++)
  {
    if (as->ino_slots[i] == aex_ino)
    {
      if (i > 2U && parent_slot >= 2U && i != parent_slot)
        as->parent_slots[i] = parent_slot;
      return i;
    }
  }
  if (as->slot_count >= as->slot_cap)
  {
    const uint32_t new_cap = (as->slot_cap == 0) ? 256U : (as->slot_cap * 2U);
    uint64_t *new_inos = (uint64_t *)realloc(as->ino_slots, (size_t)new_cap * sizeof(uint64_t));
    uint32_t *new_parents;
    if (new_inos == NULL)
      return 2U;
    as->ino_slots = new_inos;
    new_parents = (uint32_t *)realloc(as->parent_slots, (size_t)new_cap * sizeof(uint32_t));
    if (new_parents == NULL)
      return 2U;
    as->parent_slots = new_parents;
    as->slot_cap = new_cap;
  }
  {
    const uint32_t slot = as->slot_count++;
    as->ino_slots[slot] = aex_ino;
    as->parent_slots[slot] = (parent_slot >= 2U) ? parent_slot : 2U;
    return slot;
  }
}

static uint64_t slot_to_aex_ino(const struct apple_dir_state *as, unsigned long int slot)
{
  if (slot >= 2UL && slot < (unsigned long int)as->slot_count)
    return as->ino_slots[slot];
  return aex_root_ino(as->fs);
}

static uint32_t translate_aex_mode(const aex_attr_t *attr)
{
  const uint32_t perm = attr->mode & 07777U;
  switch (attr->ftype)
  {
    case AEX_FT_DIR:
      return LINUX_S_IFDIR | (perm ? perm : 0755U);
    case AEX_FT_SYMLINK:
      return LINUX_S_IFLNK | (perm ? perm : 0777U);
    case AEX_FT_REG:
    case AEX_FT_UNKNOWN:
    default:
      return LINUX_S_IFREG | (perm ? perm : 0644U);
  }
}

static void append_apple_file_entry(
    file_info_t *dir_list,
    const char *name,
    uint32_t slot_ino,
    const aex_attr_t *attr)
{
  file_info_t *entry = (file_info_t *)MALLOC(sizeof(*entry));
  const size_t nlen = strlen(name);
  const int64_t mtime_val = (attr->mtime_sec != 0) ? attr->mtime_sec : attr->crtime_sec;
  const int64_t atime_val = (attr->atime_sec != 0) ? attr->atime_sec : mtime_val;
  const int64_t ctime_val = (attr->ctime_sec != 0) ? attr->ctime_sec : mtime_val;

  entry->name = (char *)MALLOC(nlen + 1U);
  memcpy(entry->name, name, nlen + 1U);
  entry->st_ino = slot_ino;
  entry->st_mode = translate_aex_mode(attr);
  entry->st_uid = attr->uid;
  entry->st_gid = attr->gid;
  entry->st_size = attr->size;
  entry->td_atime = (time_t)atime_val;
  entry->td_mtime = (time_t)mtime_val;
  entry->td_ctime = (time_t)ctime_val;
  entry->status = 0;
  td_list_add_tail(&entry->list, &dir_list->list);
}

struct apple_readdir_pack
{
  struct apple_dir_state *as;
  uint32_t dir_slot;
  file_info_t *dir_list;
};

static int apple_dir_visitor(void *user_ctx, const char *name, uint64_t child_ino, aex_ftype_t ftype)
{
  struct apple_readdir_pack *pack = (struct apple_readdir_pack *)user_ctx;
  aex_attr_t attr;
  uint32_t child_slot;

  if (pack == NULL || name == NULL || name[0] == '\0')
    return 0;
  if (strcmp(name, ".") == 0 || strcmp(name, "..") == 0)
    return 0;

  memset(&attr, 0, sizeof(attr));
  if (aex_getattr(pack->as->fs, child_ino, &attr) != 0)
  {
    attr.ino = child_ino;
    attr.ftype = ftype;
    if (ftype == AEX_FT_DIR)
      attr.mode = LINUX_S_IFDIR | 0755U;
    else if (ftype == AEX_FT_SYMLINK)
      attr.mode = LINUX_S_IFLNK | 0777U;
    else
      attr.mode = LINUX_S_IFREG | 0644U;
  }
  child_slot = intern_aex_ino(pack->as, child_ino, pack->dir_slot);
  append_apple_file_entry(pack->dir_list, name, child_slot, &attr);
  return 0;
}

static int apple_get_dir(
    disk_t *disk_car,
    const partition_t *partition,
    dir_data_t *dir_data,
    const unsigned long int first_inode,
    file_info_t *dir_list)
{
  struct apple_dir_state *as = (struct apple_dir_state *)dir_data->private_dir_data;
  const uint32_t cur_slot = (first_inode >= 2UL && first_inode < (unsigned long int)as->slot_count)
      ? (uint32_t)first_inode : 2U;
  const uint32_t parent_slot = as->parent_slots[cur_slot];
  const uint64_t dir_ino = slot_to_aex_ino(as, cur_slot);
  const uint64_t parent_ino = slot_to_aex_ino(as, parent_slot);
  aex_attr_t dot_attr;
  aex_attr_t dotdot_attr;
  struct apple_readdir_pack pack;

  (void)disk_car;
  (void)partition;

  memset(&dot_attr, 0, sizeof(dot_attr));
  if (aex_getattr(as->fs, dir_ino, &dot_attr) != 0)
  {
    dot_attr.ftype = AEX_FT_DIR;
    dot_attr.mode = LINUX_S_IFDIR | 0755U;
  }
  append_apple_file_entry(dir_list, ".", cur_slot, &dot_attr);

  memset(&dotdot_attr, 0, sizeof(dotdot_attr));
  if (aex_getattr(as->fs, parent_ino, &dotdot_attr) != 0)
  {
    dotdot_attr.ftype = AEX_FT_DIR;
    dotdot_attr.mode = LINUX_S_IFDIR | 0755U;
  }
  append_apple_file_entry(dir_list, "..", parent_slot, &dotdot_attr);

  pack.as = as;
  pack.dir_slot = cur_slot;
  pack.dir_list = dir_list;
  if (aex_readdir(as->fs, dir_ino, &apple_dir_visitor, &pack) != 0)
    return -1;
  td_list_sort(&dir_list->list, filesort);
  return 0;
}

static copy_file_t apple_copy_file(
    disk_t *disk_car,
    const partition_t *partition,
    dir_data_t *dir_data,
    const file_info_t *file)
{
  struct apple_dir_state *as = (struct apple_dir_state *)dir_data->private_dir_data;
  const uint64_t aex_ino = slot_to_aex_ino(as, file->st_ino);
  char *new_file = NULL;
  FILE *f_out;
  unsigned char *buf;
  uint64_t off = 0;
  uint64_t max_size = file->st_size;
  copy_file_t status = CP_OK;

  (void)disk_car;
  (void)partition;

  /* Guard against damaged inodes reporting an astronomical sparse size on a small partition */
  if (as->slice_size > 0 &&
      max_size > as->slice_size * 16ULL && max_size > (256ULL << 20))
  {
    log_error("apple_copy_file: clamping implausible size %llu on %s\n",
        (unsigned long long)max_size, dir_data->current_directory);
    max_size = as->slice_size * 16ULL;
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
    const int rc = aex_read(as->fs, aex_ino, off, want, buf, &got);
    if (rc != 0)
    {
      log_error("aex_read failed on %s (rc=%d)\n", dir_data->current_directory, rc);
      status = CP_READ_FAILED;
      break;
    }
    if (got == 0)
      break;
    if (fwrite(buf, 1, got, f_out) != got)
    {
      log_error("apple_copy_file: write failed on %s\n", new_file);
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

static void dir_partition_apple_close(dir_data_t *dir_data)
{
  struct apple_dir_state *as = (struct apple_dir_state *)dir_data->private_dir_data;
  if (as == NULL)
    return;
  if (as->fs != NULL)
    aex_close(as->fs);
  free(as->ino_slots);
  free(as->parent_slots);
  free(as);
  dir_data->private_dir_data = NULL;
}
#endif /* HAVE_LIBAPPLEEXPLORER */

int is_apple_browsable(const partition_t *partition)
{
#ifdef HAVE_LIBAPPLEEXPLORER
  if (partition == NULL)
    return 0;
  switch (partition->upart_type)
  {
    case UP_APFS:
    case UP_HFS:
    case UP_HFSP:
    case UP_HFSX:
      return 1;
    default:
      break;
  }
  if (partition->part_type_i386 == P_HFS ||
      partition->part_type_i386 == P_HFSP ||
      partition->part_type_mac == PMAC_HFS ||
      guid_cmp(partition->part_type_gpt, GPT_ENT_TYPE_MAC_HFS) == 0 ||
      guid_cmp(partition->part_type_gpt, GPT_ENT_TYPE_MAC_APFS) == 0)
    return 1;
  return 0;
#else
  (void)partition;
  return 0;
#endif
}

dir_partition_t dir_partition_apple_init(
    disk_t *disk_car,
    const partition_t *partition,
    dir_data_t *dir_data,
    const int verbose)
{
#ifdef HAVE_LIBAPPLEEXPLORER
  struct apple_dir_state *as;
  int rc;

  if (disk_car == NULL || partition == NULL || dir_data == NULL)
    return DIR_PART_EIO;

  as = (struct apple_dir_state *)MALLOC(sizeof(*as));
  memset(as, 0, sizeof(*as));
  as->disk_car = disk_car;
  as->partition = partition;
  if (partition->part_size > 0)
    as->slice_size = partition->part_size;
  else if (disk_car->disk_size > partition->part_offset)
    as->slice_size = disk_car->disk_size - partition->part_offset;

  rc = aex_open_io(&apple_td_read_cb, as, as->slice_size, NULL, &as->fs);
  if (rc != 0 || as->fs == NULL)
  {
    const int explicit_apple = (partition->upart_type == UP_APFS ||
        partition->upart_type == UP_HFS ||
        partition->upart_type == UP_HFSP ||
        partition->upart_type == UP_HFSX);
    free(as);
    if (explicit_apple)
      return DIR_PART_EIO;
    return (rc == -ENOTSUP || rc == -EINVAL || rc == -ENOENT) ? DIR_PART_ENOIMP : DIR_PART_EIO;
  }

  as->slot_cap = 256U;
  as->ino_slots = (uint64_t *)calloc(as->slot_cap, sizeof(uint64_t));
  as->parent_slots = (uint32_t *)calloc(as->slot_cap, sizeof(uint32_t));
  if (as->ino_slots == NULL || as->parent_slots == NULL)
  {
    aex_close(as->fs);
    free(as->ino_slots);
    free(as->parent_slots);
    free(as);
    return DIR_PART_EIO;
  }
  as->slot_count = 2U;
  intern_aex_ino(as, aex_root_ino(as->fs), 2U);

  strncpy(dir_data->current_directory, "/", sizeof(dir_data->current_directory));
  dir_data->current_directory[sizeof(dir_data->current_directory) - 1U] = '\0';
  dir_data->current_inode = 2UL;
  dir_data->param = 0;
  dir_data->verbose = verbose;
  dir_data->capabilities = 0;
  dir_data->get_dir = &apple_get_dir;
  dir_data->copy_file = &apple_copy_file;
  dir_data->close = &dir_partition_apple_close;
  dir_data->local_dir = NULL;
  dir_data->private_dir_data = as;
  return DIR_PART_OK;
#else
  (void)disk_car;
  (void)partition;
  (void)dir_data;
  (void)verbose;
  return DIR_PART_ENOSYS;
#endif
}

const char *td_apple_explorer_version(void)
{
#ifdef HAVE_LIBAPPLEEXPLORER
  return aex_version();
#else
  return "none";
#endif
}
