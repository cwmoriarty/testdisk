/*

    File: file_raf.c

    Copyright (C) 1998-2005,2007-2011 Christophe GRENIER <grenier@cgsecurity.org>
  
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

#if !defined(SINGLE_FORMAT) || defined(SINGLE_FORMAT_raf)
#ifdef HAVE_CONFIG_H
#include <config.h>
#endif
#ifdef HAVE_STRING_H
#include <string.h>
#endif
#include <stdio.h>
#include <ctype.h>
#include <time.h>
#include "types.h"
#include "common.h"
#include "setdate.h"
#include "filegen.h"

/*@ requires valid_register_header_check(file_stat); */
static void register_header_check_raf(file_stat_t *file_stat);

const file_hint_t file_hint_raf= {
  .extension="raf",
  .description="Raw Fujifilm picture",
  .max_filesize=PHOTOREC_MAX_FILE_SIZE,
  .recover=1,
  .enable_by_default=1,
  .register_header_check=&register_header_check_raf
};

/* Documentation source: https://libopenraw.pages.freedesktop.org/formats/raf/ */
struct header_raf
{
  char magic[16];
  char unk1[4];		/* 0201 */
  char unk2[8];		/* FF393103 */
  char model[32];	/* ie. FinePix E900 */
  char dir_version[4];	/* 0100 or 0159 */
  char unk3[20];
  uint32_t jpg_offset;
  uint32_t jpg_size;
  uint32_t cfa_header_offset;
  uint32_t cfa_header_size;
  uint32_t cfa_offset;
  uint32_t cfa_size;
} __attribute__ ((gcc_struct, __packed__));

static void file_rename_raf(file_recovery_t *file_recovery)
{
  FILE *file;
  struct header_raf hdr;
  char model_str[64] = "";
  char date_str[32] = "";
  size_t k, m;

  if((file = fopen(file_recovery->filename, "rb")) == NULL)
    return;
  if(fread(&hdr, sizeof(hdr), 1, file) != 1)
  {
    fclose(file);
    return;
  }

  k = 0; m = 0;
  while(k < sizeof(hdr.model) && hdr.model[k] != '\0' && m < sizeof(model_str) - 1)
  {
    const char c = hdr.model[k++];
    if(isalnum((unsigned char)c) || c == '_' || c == '-')
      model_str[m++] = c;
    else if(c == ' ' && m > 0 && model_str[m-1] != '_')
      model_str[m++] = '_';
  }
  while(m > 0 && model_str[m-1] == '_') m--;
  model_str[m] = '\0';

  if(be32(hdr.jpg_offset) >= sizeof(hdr) && be32(hdr.jpg_size) >= 32)
  {
    if(fseek(file, be32(hdr.jpg_offset), SEEK_SET) == 0)
    {
      unsigned char jbuf[65536];
      const size_t jn = fread(jbuf, 1, sizeof(jbuf), file);
      if(jn >= 32 && jbuf[0] == 0xFF && jbuf[1] == 0xD8)
      {
        size_t pos = 2;
        while(pos + 4 < jn && jbuf[pos] == 0xFF)
        {
          const unsigned char marker = jbuf[pos + 1];
          size_t len;
          if(marker == 0xDA || marker == 0xD9)
            break;
          len = ((size_t)jbuf[pos + 2] << 8) | jbuf[pos + 3];
          if(len < 2 || pos + 2 + len > jn)
            break;
          if(marker == 0xE1 && len >= 14 && memcmp(&jbuf[pos + 4], "Exif\0\0", 6) == 0)
          {
            const unsigned char *tiff_base = &jbuf[pos + 10];
            const size_t tiff_len = len - 8;
            if(tiff_len >= 14)
            {
              const int is_le = (tiff_base[0] == 'I' && tiff_base[1] == 'I');
              size_t off;
              for(off = 0; off + 12 <= tiff_len; off++)
              {
                const uint16_t tag = is_le ? (tiff_base[off] | ((uint16_t)tiff_base[off+1] << 8)) :
                                             (((uint16_t)tiff_base[off] << 8) | tiff_base[off+1]);
                const uint16_t type = is_le ? (tiff_base[off+2] | ((uint16_t)tiff_base[off+3] << 8)) :
                                              (((uint16_t)tiff_base[off+2] << 8) | tiff_base[off+3]);
                const uint32_t count = is_le ? ((uint32_t)tiff_base[off+4] | ((uint32_t)tiff_base[off+5] << 8) | ((uint32_t)tiff_base[off+6] << 16) | ((uint32_t)tiff_base[off+7] << 24)) :
                                               (((uint32_t)tiff_base[off+4] << 24) | ((uint32_t)tiff_base[off+5] << 16) | ((uint32_t)tiff_base[off+6] << 8) | (uint32_t)tiff_base[off+7]);
                const uint32_t val_off = is_le ? ((uint32_t)tiff_base[off+8] | ((uint32_t)tiff_base[off+9] << 8) | ((uint32_t)tiff_base[off+10] << 16) | ((uint32_t)tiff_base[off+11] << 24)) :
                                                 (((uint32_t)tiff_base[off+8] << 24) | ((uint32_t)tiff_base[off+9] << 16) | ((uint32_t)tiff_base[off+10] << 8) | (uint32_t)tiff_base[off+11]);
                if(type == 2 && count >= 19 && count < 64 && (tag == 0x9003 || tag == 0x0132))
                {
                  const char *str_val = (count <= 4) ? (const char *)&tiff_base[off + 8] :
                                        (val_off + count <= tiff_len ? (const char *)&tiff_base[val_off] : NULL);
                  if(str_val != NULL && isdigit((unsigned char)str_val[0]) && str_val[4] == ':')
                  {
                    snprintf(date_str, sizeof(date_str), "%c%c%c%c%c%c%c%c_%c%c%c%c%c%c",
                             str_val[0], str_val[1], str_val[2], str_val[3],
                             str_val[5], str_val[6], str_val[8], str_val[9],
                             str_val[11], str_val[12], str_val[14], str_val[15],
                             str_val[17], str_val[18]);
                    break;
                  }
                }
              }
            }
            break;
          }
          pos += 2 + len;
        }
      }
    }
  }
  fclose(file);

  if(date_str[0] != '\0')
  {
    struct tm tm_date;
    time_t t;
    char prefix[128];
    memset(&tm_date, 0, sizeof(tm_date));
    if(sscanf(date_str, "%4d%2d%2d_%2d%2d%2d",
              &tm_date.tm_year, &tm_date.tm_mon, &tm_date.tm_mday,
              &tm_date.tm_hour, &tm_date.tm_min, &tm_date.tm_sec) == 6)
    {
      tm_date.tm_year -= 1900;
      tm_date.tm_mon -= 1;
      t = mktime(&tm_date);
      if(t != (time_t)-1)
        set_date(file_recovery->filename, t, t);
    }
    if(model_str[0] != '\0')
      snprintf(prefix, sizeof(prefix), "%s_%s", date_str, model_str);
    else
      snprintf(prefix, sizeof(prefix), "%s", date_str);
    file_rename(file_recovery, prefix, strlen(prefix), 0, NULL, 1);
  }
  else if(model_str[0] != '\0')
  {
    file_rename(file_recovery, model_str, strlen(model_str), 0, NULL, 1);
  }
}

/*@
  @ requires buffer_size >= sizeof(struct header_raf);
  @ requires separation: \separated(&file_hint_raf, buffer+(..), file_recovery, file_recovery_new);
  @ requires valid_header_check_param(buffer, buffer_size, safe_header_only, file_recovery, file_recovery_new);
  @ ensures  valid_header_check_result(\result, file_recovery_new);
  @ assigns  *file_recovery_new;
  @*/
static int header_check_raf(const unsigned char *buffer, const unsigned int buffer_size, const unsigned int safe_header_only, const file_recovery_t *file_recovery, file_recovery_t *file_recovery_new)
{
  const struct header_raf *raf=(const struct header_raf *)buffer;
  /*@ assert \valid_read(raf); */
  /* Fuji */
  const unsigned int cfa_header_offset=be32(raf->cfa_header_offset);
  const unsigned int cfa_header_size=be32(raf->cfa_header_size);
  const unsigned int cfa_offset=be32(raf->cfa_offset);
  const unsigned int cfa_size=be32(raf->cfa_size);
  const unsigned int jpg_offset=be32(raf->jpg_offset);
  const unsigned int jpg_size=be32(raf->jpg_size);
  uint64_t size=0;
  if(jpg_size > 0)
  {
    const uint64_t tmp=(uint64_t)jpg_offset + jpg_size;
    if(jpg_offset<sizeof(struct header_raf))
      return 0;
    if(tmp > size)
      size=tmp;
  }
  if(cfa_size > 0)
  {
    const uint64_t tmp=(uint64_t)cfa_offset + cfa_size;
    if(cfa_offset<sizeof(struct header_raf))
      return 0;
    if(size < tmp)
      size=tmp;
  }
  if(cfa_header_size > 0)
  {
    const uint64_t tmp=(uint64_t)cfa_header_offset + cfa_header_size;
    if(cfa_header_offset<sizeof(struct header_raf))
      return 0;
    if(size < tmp)
      size=tmp;
  }
  if(size < sizeof(struct header_raf))
    return 0;
  reset_file_recovery(file_recovery_new);
  file_recovery_new->extension=file_hint_raf.extension;
  file_recovery_new->calculated_file_size=size;
  /* The size is bigger than calculated_file_size */
  file_recovery_new->file_check=&file_check_size_min;
  file_recovery_new->file_rename=&file_rename_raf;
  return 1;
}

static void register_header_check_raf(file_stat_t *file_stat)
{
  register_header_check(0, "FUJIFILMCCD-RAW ", 16, &header_check_raf, file_stat);
}
#endif
