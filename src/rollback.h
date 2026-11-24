/*
    File: rollback.h

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

#ifndef _ROLLBACK_H
#define _ROLLBACK_H

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif
#include <stdint.h>
#include <stddef.h>
#include "types.h"
#include "common.h"

#define TD_UNDO_MAGIC "TDUNDO01"
#define TD_UNDO_MAGIC_LEN 8

/* Maximum sectors captured in head chunk (LBA 0 to LBA 63) */
#define TD_UNDO_HEAD_SECTORS 64
/* Maximum sectors captured in tail chunk (backup GPT at end of disk) */
#define TD_UNDO_TAIL_SECTORS 64

#define TD_ROLLBACK_MAX_CHUNKS 8

typedef struct {
  char magic[8];              /* "TDUNDO01" */
  uint64_t timestamp;         /* Seconds since unix epoch */
  uint64_t disk_size;         /* Total capacity in bytes */
  uint32_t sector_size;       /* Logical sector size in bytes */
  char device[128];           /* Device path (e.g. /dev/rdisk2 or /dev/sdb) */
  char model[64];             /* Drive model description */
  char action_desc[64];       /* Reason for snapshot (e.g. "Write Partition Table") */
  uint32_t num_chunks;        /* Number of chunks saved */
  uint32_t header_crc32;      /* CRC32 of preceding fields */
} td_rollback_header_t;

typedef struct {
  uint64_t offset_bytes;      /* Byte offset on disk */
  uint32_t size_bytes;        /* Chunk size in bytes */
  uint32_t chunk_crc32;       /* CRC32 of chunk data */
} td_rollback_chunk_hdr_t;

/* Creates an automated safety rollback journal file before destructive partition writes.
 * Returns 0 on success (journal written and flushed), negative value on error.
 * If out_journal_path is non-null, the written filename is copied there. */
int safety_rollback_backup(disk_t *disk_car, const char *action_desc, char *out_journal_path, size_t path_max);
int rollback_create_snapshot(disk_t *disk_car, const char *action_desc, char *out_journal_path, size_t path_max);

/* Restores partition table and boot sectors from a safety rollback journal file.
 * Returns 0 on success, negative value on error. */
int testdisk_rollback_restore(const char *undo_filename, const char *override_device, int non_interactive);

#endif /* _ROLLBACK_H */
