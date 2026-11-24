/*

    File: file_zst.c

    Copyright (C) 2026 Christopher W Moriarty <oss@cwmoriarty.com>

    This software is free software; you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation; either version 2 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License along
    with this program; if not, write the Free Software Foundation, Inc., 51
    Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.

 */

#if !defined(SINGLE_FORMAT) || defined(SINGLE_FORMAT_zst)
#ifdef HAVE_CONFIG_H
#include <config.h>
#endif
#ifdef HAVE_STRING_H
#include <string.h>
#endif
#include <stdio.h>
#include "types.h"
#include "filegen.h"
#include "common.h"

/* Zstandard maximum block size is 128 KiB per RFC 8878 Section 3.1.1.2 */
#define ZSTD_MAX_BLOCK_SIZE (128U * 1024U)

static void register_header_check_zst(file_stat_t *file_stat);

const file_hint_t file_hint_zst = {
  .extension = "zst",
  .description = "Zstandard compressed archive",
  .max_filesize = PHOTOREC_MAX_FILE_SIZE,
  .recover = 1,
  .enable_by_default = 1,
  .register_header_check = &register_header_check_zst
};

static unsigned int zstd_frame_header_size(const unsigned char fhd)
{
  static const unsigned int dict_id_sizes[4] = { 0U, 1U, 2U, 4U };
  const unsigned int fcs_flag = (fhd >> 6) & 3U;
  const unsigned int single_segment = (fhd >> 5) & 1U;
  const unsigned int dict_id_flag = fhd & 3U;
  const unsigned int window_desc_len = single_segment ? 0U : 1U;
  unsigned int fcs_len = 0U;

  if(fcs_flag == 0U)
    fcs_len = single_segment ? 1U : 0U;
  else if(fcs_flag == 1U)
    fcs_len = 2U;
  else if(fcs_flag == 2U)
    fcs_len = 4U;
  else
    fcs_len = 8U;

  return 4U + 1U + window_desc_len + dict_id_sizes[dict_id_flag] + fcs_len;
}

static data_check_t data_check_zst(const unsigned char *buffer, const unsigned int buffer_size, file_recovery_t *file_recovery)
{
  while(file_recovery->calculated_file_size + buffer_size / 2 >= file_recovery->file_size &&
        file_recovery->calculated_file_size + 3ULL <= file_recovery->file_size + buffer_size / 2)
  {
    const unsigned int i = (unsigned int)(file_recovery->calculated_file_size + buffer_size / 2 - file_recovery->file_size);
    uint32_t bh;
    unsigned int last_block;
    unsigned int block_type;
    uint32_t block_size;
    uint64_t payload_bytes;

    if(i + 3U > buffer_size)
      return DC_CONTINUE;

    bh = (uint32_t)buffer[i] | ((uint32_t)buffer[i + 1U] << 8) | ((uint32_t)buffer[i + 2U] << 16);
    last_block = bh & 1U;
    block_type = (bh >> 1) & 3U;
    block_size = bh >> 3;

    /* Block_Type 3 is reserved and invalid; compressed blocks must be non-empty and <= 128 KiB */
    if(block_type == 3U)
      return DC_STOP;
    if(block_type == 2U && (block_size == 0U || block_size > ZSTD_MAX_BLOCK_SIZE))
      return DC_STOP;
    if(block_type == 0U && block_size > ZSTD_MAX_BLOCK_SIZE)
      return DC_STOP;

    /* RLE_Block (type 1) stores a single byte on disk regardless of regenerated Block_Size */
    payload_bytes = (block_type == 1U) ? 1ULL : (uint64_t)block_size;
    file_recovery->calculated_file_size += 3ULL + payload_bytes;

    if(last_block != 0U)
    {
      if((file_recovery->data_check_tmp & 1U) != 0U)
        file_recovery->calculated_file_size += 4ULL;
      if(file_recovery->calculated_file_size >= PHOTOREC_MAX_FILE_SIZE)
        return DC_STOP;
      file_recovery->data_check = &data_check_size;
      return data_check_size(buffer, buffer_size, file_recovery);
    }

    if(file_recovery->calculated_file_size >= PHOTOREC_MAX_FILE_SIZE)
      return DC_STOP;
  }
  return DC_CONTINUE;
}

static int header_check_zst(const unsigned char *buffer, const unsigned int buffer_size, const unsigned int safe_header_only, const file_recovery_t *file_recovery, file_recovery_t *file_recovery_new)
{
  unsigned char fhd;
  unsigned int hdr_size;
  uint32_t bh;
  unsigned int block_type;
  uint32_t block_size;

  (void)safe_header_only;
  if(buffer_size < 9U)
    return 0;

  fhd = buffer[4];
  /* Reserved bit 3 of Frame_Header_Descriptor must be zero */
  if((fhd & 0x08U) != 0U)
    return 0;

  hdr_size = zstd_frame_header_size(fhd);
  if(buffer_size < hdr_size + 3U)
    return 0;

  bh = (uint32_t)buffer[hdr_size] |
       ((uint32_t)buffer[hdr_size + 1U] << 8) |
       ((uint32_t)buffer[hdr_size + 2U] << 16);
  block_type = (bh >> 1) & 3U;
  block_size = bh >> 3;

  if(block_type == 3U)
    return 0;
  if(block_type == 2U && (block_size == 0U || block_size > ZSTD_MAX_BLOCK_SIZE))
    return 0;
  if(block_type == 0U && block_size > ZSTD_MAX_BLOCK_SIZE)
    return 0;

  if(file_recovery->file_stat != NULL &&
     file_recovery->file_stat->file_hint == &file_hint_zst &&
     file_recovery->data_check != NULL &&
     file_recovery->file_size < file_recovery->calculated_file_size)
  {
    header_ignored(file_recovery_new);
    return 0;
  }

  reset_file_recovery(file_recovery_new);
  file_recovery_new->extension = file_hint_zst.extension;
  if(file_recovery_new->blocksize < 16U)
  {
    file_recovery_new->min_filesize = (uint64_t)hdr_size + 3ULL;
    return 1;
  }
  file_recovery_new->calculated_file_size = hdr_size;
  file_recovery_new->data_check_tmp = (fhd >> 2) & 1U;
  file_recovery_new->data_check = &data_check_zst;
  file_recovery_new->file_check = &file_check_size;
  return 1;
}

static void register_header_check_zst(file_stat_t *file_stat)
{
  static const unsigned char zst_magic[4] = { 0x28, 0xb5, 0x2f, 0xfd };
  register_header_check(0, zst_magic, sizeof(zst_magic), &header_check_zst, file_stat);
}
#endif
