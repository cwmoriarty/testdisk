/*

    File: file_ivf.c

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

#if !defined(SINGLE_FORMAT) || defined(SINGLE_FORMAT_ivf)
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

#define IVF_MAX_FRAME_SIZE (64U * 1024U * 1024U)

static void register_header_check_ivf(file_stat_t *file_stat);

const file_hint_t file_hint_ivf = {
  .extension = "ivf",
  .description = "AV1/VP9/VP8 IVF video stream",
  .max_filesize = PHOTOREC_MAX_FILE_SIZE,
  .recover = 1,
  .enable_by_default = 1,
  .register_header_check = &register_header_check_ivf
};

static data_check_t data_check_ivf(const unsigned char *buffer, const unsigned int buffer_size, file_recovery_t *file_recovery)
{
  while(file_recovery->calculated_file_size + buffer_size / 2 >= file_recovery->file_size &&
        file_recovery->calculated_file_size + 12ULL <= file_recovery->file_size + buffer_size / 2)
  {
    const unsigned int i = (unsigned int)(file_recovery->calculated_file_size + buffer_size / 2 - file_recovery->file_size);
    uint32_t frame_size;

    if(i + 12U > buffer_size)
      return DC_CONTINUE;

    frame_size = (uint32_t)buffer[i] |
                 ((uint32_t)buffer[i + 1U] << 8) |
                 ((uint32_t)buffer[i + 2U] << 16) |
                 ((uint32_t)buffer[i + 3U] << 24);

    if(frame_size == 0U || frame_size > IVF_MAX_FRAME_SIZE)
    {
      if(file_recovery->data_check_tmp == 0U)
      {
        file_recovery->data_check = &data_check_size;
        return data_check_size(buffer, buffer_size, file_recovery);
      }
      return DC_STOP;
    }

    file_recovery->calculated_file_size += 12ULL + (uint64_t)frame_size;
    if(file_recovery->calculated_file_size >= PHOTOREC_MAX_FILE_SIZE)
      return DC_STOP;

    if(file_recovery->data_check_tmp > 0U)
    {
      file_recovery->data_check_tmp--;
      if(file_recovery->data_check_tmp == 0U)
      {
        file_recovery->data_check = &data_check_size;
        return data_check_size(buffer, buffer_size, file_recovery);
      }
    }
  }
  return DC_CONTINUE;
}

static int header_check_ivf(const unsigned char *buffer, const unsigned int buffer_size, const unsigned int safe_header_only, const file_recovery_t *file_recovery, file_recovery_t *file_recovery_new)
{
  uint16_t version;
  uint16_t hdr_len;
  uint16_t width;
  uint16_t height;
  uint32_t num_frames;

  (void)safe_header_only;
  if(buffer_size < 32U)
    return 0;

  version = (uint16_t)buffer[4] | ((uint16_t)buffer[5] << 8);
  hdr_len = (uint16_t)buffer[6] | ((uint16_t)buffer[7] << 8);
  if(version != 0U || hdr_len != 32U)
    return 0;

  if(memcmp(&buffer[8], "AV01", 4) != 0 &&
     memcmp(&buffer[8], "VP90", 4) != 0 &&
     memcmp(&buffer[8], "VP80", 4) != 0)
    return 0;

  width = (uint16_t)buffer[12] | ((uint16_t)buffer[13] << 8);
  height = (uint16_t)buffer[14] | ((uint16_t)buffer[15] << 8);
  if(width == 0U || height == 0U)
    return 0;

  num_frames = (uint32_t)buffer[24] |
               ((uint32_t)buffer[25] << 8) |
               ((uint32_t)buffer[26] << 16) |
               ((uint32_t)buffer[27] << 24);

  if(file_recovery->file_stat != NULL &&
     file_recovery->file_stat->file_hint == &file_hint_ivf &&
     file_recovery->data_check != NULL &&
     file_recovery->file_size < file_recovery->calculated_file_size)
  {
    header_ignored(file_recovery_new);
    return 0;
  }

  reset_file_recovery(file_recovery_new);
  file_recovery_new->extension = file_hint_ivf.extension;
  if(file_recovery_new->blocksize < 16U)
  {
    file_recovery_new->min_filesize = 32ULL;
    return 1;
  }
  file_recovery_new->calculated_file_size = 32ULL;
  file_recovery_new->data_check_tmp = num_frames;
  file_recovery_new->data_check = &data_check_ivf;
  file_recovery_new->file_check = &file_check_size;
  return 1;
}

static void register_header_check_ivf(file_stat_t *file_stat)
{
  static const unsigned char ivf_magic[8] = { 'D', 'K', 'I', 'F', 0x00, 0x00, 0x20, 0x00 };
  register_header_check(0, ivf_magic, sizeof(ivf_magic), &header_check_ivf, file_stat);
}
#endif
