/*

    File: file_lz4.c

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

#if !defined(SINGLE_FORMAT) || defined(SINGLE_FORMAT_lz4)
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

static void register_header_check_lz4(file_stat_t *file_stat);

const file_hint_t file_hint_lz4 = {
  .extension = "lz4",
  .description = "LZ4 frame compressed archive",
  .max_filesize = PHOTOREC_MAX_FILE_SIZE,
  .recover = 1,
  .enable_by_default = 1,
  .register_header_check = &register_header_check_lz4
};

static uint32_t lz4_max_block_bytes(const unsigned int bd_code)
{
  switch(bd_code & 7U)
  {
    case 4U:
      return 64U * 1024U;
    case 5U:
      return 256U * 1024U;
    case 6U:
      return 1024U * 1024U;
    case 7U:
      return 4U * 1024U * 1024U;
    default:
      return 0U;
  }
}

static data_check_t data_check_lz4(const unsigned char *buffer, const unsigned int buffer_size, file_recovery_t *file_recovery)
{
  const unsigned int b_checksum = file_recovery->data_check_tmp & 1U;
  const unsigned int c_checksum = (file_recovery->data_check_tmp >> 1) & 1U;
  const uint32_t max_bsz = lz4_max_block_bytes((file_recovery->data_check_tmp >> 4) & 7U);

  while(file_recovery->calculated_file_size + buffer_size / 2 >= file_recovery->file_size &&
        file_recovery->calculated_file_size + 4ULL <= file_recovery->file_size + buffer_size / 2)
  {
    const unsigned int i = (unsigned int)(file_recovery->calculated_file_size + buffer_size / 2 - file_recovery->file_size);
    uint32_t raw_bsz;
    uint32_t data_len;

    if(i + 4U > buffer_size)
      return DC_CONTINUE;

    raw_bsz = (uint32_t)buffer[i] |
              ((uint32_t)buffer[i + 1U] << 8) |
              ((uint32_t)buffer[i + 2U] << 16) |
              ((uint32_t)buffer[i + 3U] << 24);

    if(raw_bsz == 0U)
    {
      file_recovery->calculated_file_size += 4ULL + (c_checksum ? 4ULL : 0ULL);
      if(file_recovery->calculated_file_size >= PHOTOREC_MAX_FILE_SIZE)
        return DC_STOP;
      file_recovery->data_check = &data_check_size;
      return data_check_size(buffer, buffer_size, file_recovery);
    }

    data_len = raw_bsz & 0x7FFFFFFFU;
    if(data_len == 0U || data_len > max_bsz)
      return DC_STOP;

    file_recovery->calculated_file_size += 4ULL + (uint64_t)data_len + (b_checksum ? 4ULL : 0ULL);
    if(file_recovery->calculated_file_size >= PHOTOREC_MAX_FILE_SIZE)
      return DC_STOP;
  }
  return DC_CONTINUE;
}

static int header_check_lz4(const unsigned char *buffer, const unsigned int buffer_size, const unsigned int safe_header_only, const file_recovery_t *file_recovery, file_recovery_t *file_recovery_new)
{
  unsigned char flg;
  unsigned char bd;
  unsigned int bd_code;
  unsigned int hdr_size;
  uint32_t first_bsz;
  uint32_t max_bsz;

  (void)safe_header_only;
  if(buffer_size < 11U)
    return 0;

  flg = buffer[4];
  bd = buffer[5];
  /* Version bits [7:6] must equal 01; reserved bit 1 must equal 0 */
  if(((flg >> 6) & 3U) != 1U || (flg & 2U) != 0U)
    return 0;

  bd_code = (bd >> 4) & 7U;
  /* Block MaxSize code must be 4..7 and reserved BD bits must be 0 */
  if(bd_code < 4U || (bd & 0x8FU) != 0U)
    return 0;

  hdr_size = 7U + (((flg >> 3) & 1U) ? 8U : 0U) + ((flg & 1U) ? 4U : 0U);
  if(buffer_size < hdr_size + 4U)
    return 0;

  first_bsz = (uint32_t)buffer[hdr_size] |
              ((uint32_t)buffer[hdr_size + 1U] << 8) |
              ((uint32_t)buffer[hdr_size + 2U] << 16) |
              ((uint32_t)buffer[hdr_size + 3U] << 24);
  max_bsz = lz4_max_block_bytes(bd_code);
  if(first_bsz != 0U)
  {
    const uint32_t first_len = first_bsz & 0x7FFFFFFFU;
    if(first_len == 0U || first_len > max_bsz)
      return 0;
  }

  if(file_recovery->file_stat != NULL &&
     file_recovery->file_stat->file_hint == &file_hint_lz4 &&
     file_recovery->data_check != NULL &&
     file_recovery->file_size < file_recovery->calculated_file_size)
  {
    header_ignored(file_recovery_new);
    return 0;
  }

  reset_file_recovery(file_recovery_new);
  file_recovery_new->extension = file_hint_lz4.extension;
  if(file_recovery_new->blocksize < 16U)
  {
    file_recovery_new->min_filesize = (uint64_t)hdr_size + 4ULL;
    return 1;
  }
  file_recovery_new->calculated_file_size = hdr_size;
  file_recovery_new->data_check_tmp =
      (((flg >> 4) & 1U)) |
      ((((flg >> 2) & 1U)) << 1) |
      (bd_code << 4);
  file_recovery_new->data_check = &data_check_lz4;
  file_recovery_new->file_check = &file_check_size;
  return 1;
}

static void register_header_check_lz4(file_stat_t *file_stat)
{
  static const unsigned char lz4_magic[4] = { 0x04, 0x22, 0x4d, 0x18 };
  register_header_check(0, lz4_magic, sizeof(lz4_magic), &header_check_lz4, file_stat);
}
#endif
