/*
    File: rollback.c

    Safety Rollback Journal and Recovery Engine for TestDisk-NG
    Automated pre-write snapshot capture and --undo command restoration.

    Copyright (C) 1998-2024 Christophe GRENIER <grenier@cgsecurity.org>
    https://www.cgsecurity.org
    Modernization & Rollback Engine (C) November 2026 Christopher W Moriarty <oss@cwmoriarty.com>

    This software is free software; you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation; either version 2 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.
*/

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <errno.h>
#include <fcntl.h>
#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif
#ifdef __APPLE__
#include <sys/ioctl.h>
#include <sys/disk.h>
#endif

#include "types.h"
#include "common.h"
#include "crc.h"
#include "log.h"
#include "rollback.h"

static void sanitize_dev_name(const char *dev, char *out, size_t out_sz)
{
  if(dev == NULL || *dev == '\0')
  {
    strncpy(out, "disk", out_sz - 1);
    out[out_sz - 1] = '\0';
    return;
  }

  /* Strip leading /dev/r or /dev/ */
  const char *p = dev;
  if(strncmp(p, "/dev/r", 6) == 0)
    p += 6;
  else if(strncmp(p, "/dev/", 5) == 0)
    p += 5;
  else if(strncmp(p, "\\\\.\\", 4) == 0)
    p += 4;

  size_t j = 0;
  for(size_t i = 0; p[i] != '\0' && j < out_sz - 1; i++)
  {
    char c = p[i];
    if((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '-' || c == '_')
    {
      out[j++] = c;
    }
    else
    {
      out[j++] = '_';
    }
  }
  out[j] = '\0';
}

int safety_rollback_backup(disk_t *disk_car, const char *action_desc, char *out_journal_path, size_t path_max)
{
  if(disk_car == NULL || disk_car->pread == NULL || disk_car->sector_size == 0 ||
     disk_car->disk_size < disk_car->sector_size ||
     (disk_car->disk_real_size > 0 && disk_car->disk_real_size < disk_car->sector_size))
  {
    log_error("[SAFETY ROLLBACK] Invalid disk structure, cannot capture snapshot.\n");
    return -1;
  }

  const unsigned int ss = disk_car->sector_size;
  const uint32_t head_bytes = TD_UNDO_HEAD_SECTORS * ss;
  uint32_t chunk0_sz = (disk_car->disk_size < head_bytes) ? (uint32_t)disk_car->disk_size : head_bytes;

  unsigned char *chunk0_buf = (unsigned char *)malloc(chunk0_sz);
  if(chunk0_buf == NULL)
  {
    log_error("[SAFETY ROLLBACK] Memory allocation failed for head snapshot.\n");
    return -2;
  }

  /* Read Chunk 0: Head of disk */
  int r0 = disk_car->pread(disk_car, chunk0_buf, chunk0_sz, 0);
  if(r0 != (int)chunk0_sz)
  {
    log_error("[SAFETY ROLLBACK] Failed to read head sectors for backup (got %d / %u bytes): %s\n",
              r0, chunk0_sz, strerror(errno));
    free(chunk0_buf);
    return -3;
  }

  /* Check if tail chunk is applicable (disk larger than head + tail) */
  const uint32_t tail_bytes = TD_UNDO_TAIL_SECTORS * ss;
  unsigned char *chunk1_buf = NULL;
  uint64_t chunk1_offset = 0;
  uint32_t chunk1_sz = 0;
  uint32_t num_chunks = 1;

  if(disk_car->disk_size > (uint64_t)(chunk0_sz + tail_bytes))
  {
    chunk1_sz = tail_bytes;
    chunk1_offset = disk_car->disk_size - tail_bytes;
    chunk1_buf = (unsigned char *)malloc(chunk1_sz);
    if(chunk1_buf != NULL)
    {
      int r1 = disk_car->pread(disk_car, chunk1_buf, chunk1_sz, chunk1_offset);
      if(r1 == (int)chunk1_sz)
      {
        num_chunks = 2;
      }
      else
      {
        log_warning("[SAFETY ROLLBACK] Could not read tail sectors for secondary GPT backup; continuing with head chunk.\n");
        free(chunk1_buf);
        chunk1_buf = NULL;
        chunk1_sz = 0;
        chunk1_offset = 0;
      }
    }
  }

  /* Generate filename */
  char clean_dev[64];
  sanitize_dev_name(disk_car->device, clean_dev, sizeof(clean_dev));

  time_t now = time(NULL);
  struct tm tm_info;
  localtime_r(&now, &tm_info);
  char time_str[32];
  strftime(time_str, sizeof(time_str), "%Y%m%d_%H%M%S", &tm_info);

  char filename[256];
  snprintf(filename, sizeof(filename), "testdisk_undo_%s_%s.bin", clean_dev, time_str);

  FILE *fp = fopen(filename, "wb");
  if(fp == NULL)
  {
    log_error("[SAFETY ROLLBACK] Failed to create journal file '%s': %s\n", filename, strerror(errno));
    free(chunk0_buf);
    if(chunk1_buf)
      free(chunk1_buf);
    return -4;
  }

  /* Build Header */
  td_rollback_header_t hdr;
  memset(&hdr, 0, sizeof(hdr));
  memcpy(hdr.magic, TD_UNDO_MAGIC, TD_UNDO_MAGIC_LEN);
  hdr.timestamp = (uint64_t)now;
  hdr.disk_size = disk_car->disk_size;
  hdr.sector_size = ss;
  if(disk_car->device)
    strncpy(hdr.device, disk_car->device, sizeof(hdr.device) - 1);
  if(disk_car->model)
    strncpy(hdr.model, disk_car->model, sizeof(hdr.model) - 1);
  if(action_desc)
    strncpy(hdr.action_desc, action_desc, sizeof(hdr.action_desc) - 1);
  else
    strncpy(hdr.action_desc, "Write Partition Table", sizeof(hdr.action_desc) - 1);

  hdr.num_chunks = num_chunks;
  /* Calculate CRC32 over header fields up to header_crc32 */
  hdr.header_crc32 = get_crc32(&hdr, (unsigned int)offsetof(td_rollback_header_t, header_crc32), 0xFFFFFFFF);

  /* Write Header */
  if(fwrite(&hdr, sizeof(hdr), 1, fp) != 1)
  {
    log_error("[SAFETY ROLLBACK] Failed writing header to journal.\n");
    fclose(fp);
    free(chunk0_buf);
    if(chunk1_buf) free(chunk1_buf);
    return -5;
  }

  /* Write Chunk 0 */
  td_rollback_chunk_hdr_t ch0;
  ch0.offset_bytes = 0;
  ch0.size_bytes = chunk0_sz;
  ch0.chunk_crc32 = get_crc32(chunk0_buf, chunk0_sz, 0xFFFFFFFF);

  if(fwrite(&ch0, sizeof(ch0), 1, fp) != 1 || fwrite(chunk0_buf, chunk0_sz, 1, fp) != 1)
  {
    log_error("[SAFETY ROLLBACK] Failed writing chunk 0 data.\n");
    fclose(fp);
    free(chunk0_buf);
    if(chunk1_buf) free(chunk1_buf);
    return -6;
  }
  free(chunk0_buf);

  /* Write Chunk 1 if present */
  if(num_chunks > 1 && chunk1_buf != NULL)
  {
    td_rollback_chunk_hdr_t ch1;
    ch1.offset_bytes = chunk1_offset;
    ch1.size_bytes = chunk1_sz;
    ch1.chunk_crc32 = get_crc32(chunk1_buf, chunk1_sz, 0xFFFFFFFF);

    if(fwrite(&ch1, sizeof(ch1), 1, fp) != 1 || fwrite(chunk1_buf, chunk1_sz, 1, fp) != 1)
    {
      log_error("[SAFETY ROLLBACK] Failed writing chunk 1 data.\n");
      fclose(fp);
      free(chunk1_buf);
      return -7;
    }
    free(chunk1_buf);
  }

  fflush(fp);
#if defined(HAVE_FSYNC)
  fsync(fileno(fp));
#endif
  fclose(fp);

  if(out_journal_path != NULL && path_max > 0)
  {
    strncpy(out_journal_path, filename, path_max - 1);
    out_journal_path[path_max - 1] = '\0';
  }

  log_info("[SAFETY ROLLBACK] Created snapshot: %s (%u chunks saved)\n", filename, num_chunks);
  log_info("[SAFETY ROLLBACK] To undo changes, run: testdisk-ng --undo %s\n", filename);

  return 0;
}

int rollback_create_snapshot(disk_t *disk_car, const char *action_desc, char *out_journal_path, size_t path_max)
{
  return safety_rollback_backup(disk_car, action_desc, out_journal_path, path_max);
}

int testdisk_rollback_restore(const char *undo_filename, const char *override_device, int non_interactive)
{
  if(undo_filename == NULL || *undo_filename == '\0')
  {
    fprintf(stderr, "Error: No rollback journal file specified.\n");
    return -1;
  }

  FILE *fp = fopen(undo_filename, "rb");
  if(fp == NULL)
  {
    fprintf(stderr, "Error: Cannot open rollback journal '%s': %s\n", undo_filename, strerror(errno));
    return -2;
  }

  td_rollback_header_t hdr;
  if(fread(&hdr, sizeof(hdr), 1, fp) != 1)
  {
    fprintf(stderr, "Error: Corrupted journal '%s' (truncated header).\n", undo_filename);
    fclose(fp);
    return -3;
  }

  /* Verify Magic */
  if(memcmp(hdr.magic, TD_UNDO_MAGIC, TD_UNDO_MAGIC_LEN) != 0)
  {
    fprintf(stderr, "Error: '%s' is not a valid TestDisk safety rollback journal (invalid magic).\n", undo_filename);
    fclose(fp);
    return -4;
  }

  /* Verify Header CRC32 */
  uint32_t expected_crc = get_crc32(&hdr, (unsigned int)offsetof(td_rollback_header_t, header_crc32), 0xFFFFFFFF);
  if(hdr.header_crc32 != expected_crc)
  {
    fprintf(stderr, "Error: Rollback journal header checksum failure (header corrupted)!\n");
    fclose(fp);
    return -5;
  }

  if(hdr.num_chunks == 0 || hdr.num_chunks > TD_ROLLBACK_MAX_CHUNKS)
  {
    fprintf(stderr, "Error: Invalid number of chunks in rollback journal: %u\n", hdr.num_chunks);
    fclose(fp);
    return -6;
  }

  /* Read and verify chunks into memory */
  typedef struct {
    td_rollback_chunk_hdr_t chunk_hdr;
    unsigned char *data;
  } loaded_chunk_t;

  loaded_chunk_t chunks[TD_ROLLBACK_MAX_CHUNKS];
  memset(chunks, 0, sizeof(chunks));

  for(uint32_t i = 0; i < hdr.num_chunks; i++)
  {
    if(fread(&chunks[i].chunk_hdr, sizeof(td_rollback_chunk_hdr_t), 1, fp) != 1)
    {
      fprintf(stderr, "Error: Failed to read chunk header #%u.\n", i);
      fclose(fp);
      return -7;
    }

    uint32_t sz = chunks[i].chunk_hdr.size_bytes;
    if(sz == 0 || sz > (1024 * 1024 * 64)) /* Sanity limit: 64MB */
    {
      fprintf(stderr, "Error: Invalid chunk size %u in chunk #%u.\n", sz, i);
      fclose(fp);
      return -8;
    }

    chunks[i].data = (unsigned char *)malloc(sz);
    if(chunks[i].data == NULL)
    {
      fprintf(stderr, "Error: Out of memory reading chunk #%u.\n", i);
      fclose(fp);
      return -9;
    }

    if(fread(chunks[i].data, sz, 1, fp) != 1)
    {
      fprintf(stderr, "Error: Truncated data in chunk #%u.\n", i);
      fclose(fp);
      for(uint32_t k = 0; k <= i; k++) free(chunks[k].data);
      return -10;
    }

    /* Verify chunk CRC */
    uint32_t c_crc = get_crc32(chunks[i].data, sz, 0xFFFFFFFF);
    if(c_crc != chunks[i].chunk_hdr.chunk_crc32)
    {
      fprintf(stderr, "Error: Checksum mismatch in chunk #%u! Journal data is corrupted.\n", i);
      fclose(fp);
      for(uint32_t k = 0; k <= i; k++) free(chunks[k].data);
      return -11;
    }
  }
  fclose(fp);

  /* Determine target device */
  const char *target_dev = (override_device != NULL && *override_device != '\0') ? override_device : hdr.device;
  if(target_dev == NULL || *target_dev == '\0')
  {
    fprintf(stderr, "Error: No target device recorded in journal and none provided on CLI.\n");
    for(uint32_t k = 0; k < hdr.num_chunks; k++) free(chunks[k].data);
    return -12;
  }

  /* Display restore summary */
  time_t snap_time = (time_t)hdr.timestamp;
  struct tm tm_snap;
  gmtime_r(&snap_time, &tm_snap);
  char time_buf[64];
  strftime(time_buf, sizeof(time_buf), "%Y-%m-%d %H:%M:%S UTC", &tm_snap);

  printf("\n");
  printf("========================================================================\n");
  printf("              TESTDISK-NG SAFETY ROLLBACK RESTORE ENGINE                \n");
  printf("========================================================================\n");
  printf(" Journal File:    %s\n", undo_filename);
  printf(" Snapshot Taken:  %s\n", time_buf);
  printf(" Action Saved:    %s\n", hdr.action_desc);
  printf(" Recorded Device: %s\n", hdr.device);
  printf(" Recorded Model:  %s\n", hdr.model[0] ? hdr.model : "N/A");
  printf(" Disk Capacity:   %llu bytes (sector size: %u bytes)\n",
         (unsigned long long)hdr.disk_size, hdr.sector_size);
  printf(" Target Device:   %s%s\n", target_dev, (override_device ? " (CLI override)" : ""));
  printf(" Chunks to Write: %u chunks\n", hdr.num_chunks);
  for(uint32_t i = 0; i < hdr.num_chunks; i++)
  {
    printf("   Chunk %u:       offset %llu bytes (%llu sectors), size %u bytes\n",
           i, (unsigned long long)chunks[i].chunk_hdr.offset_bytes,
           (unsigned long long)(chunks[i].chunk_hdr.offset_bytes / hdr.sector_size),
           chunks[i].chunk_hdr.size_bytes);
  }
  printf("========================================================================\n\n");

  if(!non_interactive)
  {
    printf("WARNING: This will overwrite sectors on '%s' with the saved snapshot.\n", target_dev);
    printf("Are you sure you want to proceed with the rollback? (Y/N): ");
    fflush(stdout);

    char resp[32];
    if(fgets(resp, sizeof(resp), stdin) == NULL || (resp[0] != 'y' && resp[0] != 'Y'))
    {
      printf("Restore aborted by user. No disk modifications were made.\n");
      for(uint32_t k = 0; k < hdr.num_chunks; k++) free(chunks[k].data);
      return 0;
    }
  }

  /* Open target device with direct sync */
  int fd = open(target_dev, O_RDWR | O_SYNC);
  if(fd < 0)
  {
    fprintf(stderr, "\nError: Cannot open target device '%s' for writing: %s\n", target_dev, strerror(errno));
#if defined(HAVE_GETEUID) && !defined(__CYGWIN__) && !defined(__MINGW32__) && !defined(DJGPP)
    if(geteuid() != 0)
    {
      fprintf(stderr, "Hint: Restoring partition sectors requires root privileges. Run with: sudo testdisk-ng --undo %s\n", undo_filename);
    }
#endif
    for(uint32_t k = 0; k < hdr.num_chunks; k++) free(chunks[k].data);
    return -13;
  }

  printf("\nRestoring sectors...\n");
  for(uint32_t i = 0; i < hdr.num_chunks; i++)
  {
    uint64_t off = chunks[i].chunk_hdr.offset_bytes;
    uint32_t sz = chunks[i].chunk_hdr.size_bytes;

    ssize_t written = pwrite(fd, chunks[i].data, sz, off);
    if(written != (ssize_t)sz)
    {
      fprintf(stderr, "Error: Failed writing chunk %u to LBA offset %llu: %s\n",
              i, (unsigned long long)(off / hdr.sector_size), strerror(errno));
      close(fd);
      for(uint32_t k = 0; k < hdr.num_chunks; k++) free(chunks[k].data);
      return -14;
    }
    printf("  [OK] Restored chunk %u (%u bytes at offset %llu)\n", i, sz, (unsigned long long)off);
  }

  /* Flush buffers to physical disk */
#if defined(HAVE_FSYNC)
  fsync(fd);
#endif
#ifdef __APPLE__
  fcntl(fd, F_FULLFSYNC);
#endif
  close(fd);

  for(uint32_t k = 0; k < hdr.num_chunks; k++)
    free(chunks[k].data);

  printf("\n========================================================================\n");
  printf(" SUCCESS: Rollback completed successfully!\n");
  printf(" All critical partition table sectors on '%s' have been reverted\n", target_dev);
  printf(" to their exact state prior to '%s'.\n", hdr.action_desc);
  printf(" Please disconnect/reconnect the drive or reboot to reload partitions.\n");
  printf("========================================================================\n\n");

  return 0;
}
