/*

    File: file_png.c

    Copyright (C) 1998-2009 Christophe GRENIER <grenier@cgsecurity.org>
    Thanks to Holger Klemm for JNG (JPEG Network Graphics) and
    MNG (Multiple-Image Network Graphics) support (2006)
  
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
/*
   MNG (Multiple-image Network Graphics) Format
   http://www.libpng.org/pub/mng/spec/
*/

#if !defined(SINGLE_FORMAT) || defined(SINGLE_FORMAT_png)
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

extern const file_hint_t file_hint_doc;

/*@ requires valid_register_header_check(file_stat); */
static void register_header_check_png(file_stat_t *file_stat);

const file_hint_t file_hint_png= {
  .extension="png",
  .description="Portable/JPEG/Multiple-Image Network Graphics",
  .max_filesize=PHOTOREC_MAX_FILE_SIZE,
  .recover=1,
  .enable_by_default=1,
  .register_header_check=&register_header_check_png
};

struct png_chunk
{
  uint32_t length;
  uint32_t type;
#if 0
  char data[0];
#endif
  /* data is followed by uint32_t crc; */
} __attribute__ ((gcc_struct, __packed__));

struct png_ihdr
{
  uint32_t width;
  uint32_t height;
  uint8_t  bit_depth;
  uint8_t  color_type;
  uint8_t  compression;
  uint8_t  filter;
  uint8_t  interlace;
} __attribute__ ((gcc_struct, __packed__));

/* png_check_ihdr: return 1 if valid */
/*@
  @ requires \valid_read(ihdr);
  @ requires \initialized(ihdr);
  @ terminates \true;
  @ ensures  \result == 0 || \result == 1;
  @ assigns  \nothing;
  @ */
static int png_check_ihdr(const struct png_ihdr *ihdr)
{
  if(be32(ihdr->width)==0 || be32(ihdr->height)==0)
    return 0;
  switch(ihdr->color_type)
  {
    case 0:	/* Greyscale */
      if(ihdr->bit_depth!=1 && ihdr->bit_depth!=2 && ihdr->bit_depth!=4 && ihdr->bit_depth!=8 && ihdr->bit_depth!=16)
	return 0;
      break;
    case 3:	/* Indexed-colour*/
      if(ihdr->bit_depth!=1 && ihdr->bit_depth!=2 && ihdr->bit_depth!=4 && ihdr->bit_depth!=8)
	return 0;
      break;
    case 2:	/* Truecolour */
    case 4:	/* Greyscale with alpha */
    case 6:	/* Truecolour with alpha */
      if(ihdr->bit_depth!=8 && ihdr->bit_depth!=16)
	return 0;
      break;
    default:
      return 0;
  }
  return 1;
}

/*@
  @ requires fr->file_check == &file_check_png;
  @ requires valid_file_check_param(fr);
  @ ensures  valid_file_check_result(fr);
  @ assigns *fr->handle, errno, fr->file_size;
  @ assigns Frama_C_entropy_source;
  @*/
static void file_check_png(file_recovery_t *fr)
{
  if(fr->file_size<fr->calculated_file_size)
  {
    fr->file_size=0;
    return ;
  }
  fr->file_size=8;
  /*@
    @ loop invariant valid_file_recovery(fr);
    @ loop invariant fr->file_size < 0x8000000000000000;
    @ loop assigns *fr->handle, errno, fr->file_size;
    @ loop assigns Frama_C_entropy_source;
    @ loop variant 0x8000000000000000 - fr->file_size;
    @*/
  while(1)
  {
    char buffer[8];
    const struct png_chunk *chunk=(const struct png_chunk *)&buffer;
    uint32_t length;
    if(my_fseek(fr->handle, fr->file_size, SEEK_SET) < 0 ||
	fread(&buffer, sizeof(buffer), 1, fr->handle) != 1)
    {
      fr->file_size=0;
      return ;
    }
#ifdef __FRAMAC__
    Frama_C_make_unknown(&buffer, sizeof(buffer));
#endif
    length = be32(chunk->length);
    fr->file_size+=(uint64_t)12 + length;
    if(fr->file_size >= 0x8000000000000000)
      return ;
    if(memcmp(&buffer[4], "IEND", 4)==0)
      return ;
    if(memcmp(&buffer[4], "IHDR", 4) == 0)
    {
      char buf_ihdr[sizeof(struct png_ihdr)];
      const struct png_ihdr *ihdr=(const struct png_ihdr *)&buf_ihdr;
      if(fread(&buf_ihdr, sizeof(buf_ihdr), 1, fr->handle) != 1)
      {
	fr->file_size=0;
	return ;
      }
#ifdef __FRAMAC__
      Frama_C_make_unknown(&buf_ihdr, sizeof(buf_ihdr));
#endif
      if(png_check_ihdr(ihdr)==0)
      {
	fr->file_size=0;
	return ;
      }
    }
  }
}

/*@
  @ requires file_recovery->data_check==&data_check_mng;
  @ requires valid_data_check_param(buffer, buffer_size, file_recovery);
  @ ensures  valid_data_check_result(\result, file_recovery);
  @ assigns  file_recovery->calculated_file_size, file_recovery->offset_ok, file_recovery->offset_error;
  @*/
static data_check_t data_check_mng(const unsigned char *buffer, const unsigned int buffer_size, file_recovery_t *file_recovery)
{
  static const unsigned char mng_footer[4]= {'M','E','N','D'};
  /*@ assert file_recovery->calculated_file_size <= PHOTOREC_MAX_FILE_SIZE; */
  /*@ assert file_recovery->file_size <= PHOTOREC_MAX_FILE_SIZE; */
  /*@
    @ loop assigns file_recovery->calculated_file_size, file_recovery->offset_ok;
    @ loop variant file_recovery->file_size + buffer_size/2 - (file_recovery->calculated_file_size + 8);
    @*/
  while(file_recovery->calculated_file_size + buffer_size/2  >= file_recovery->file_size &&
      file_recovery->calculated_file_size + 8 <= file_recovery->file_size + buffer_size/2)
  {
    const unsigned int i=file_recovery->calculated_file_size + buffer_size/2 - file_recovery->file_size;
    /*@ assert 0 <= i <= buffer_size - 8 ; */
    const struct png_chunk *chunk=(const struct png_chunk *)&buffer[i];
    const uint32_t length=be32(chunk->length);
    if(memcmp(&buffer[i+4], mng_footer, sizeof(mng_footer))==0)
    {
      file_recovery->calculated_file_size+=(uint64_t)12 + length;
      return DC_STOP;
    }
    if( !((isupper(buffer[i+4]) || islower(buffer[i+4])) &&
	  (isupper(buffer[i+5]) || islower(buffer[i+5])) &&
	  (isupper(buffer[i+6]) || islower(buffer[i+6])) &&
	  (isupper(buffer[i+7]) || islower(buffer[i+7]))))
    {
      file_recovery->offset_error=file_recovery->calculated_file_size+7;
      return DC_ERROR;
    }
    file_recovery->offset_ok=file_recovery->calculated_file_size+7;
    file_recovery->calculated_file_size+=(uint64_t)12 + length;
  }
  return DC_CONTINUE;
}

/*@
  @ requires file_recovery->data_check==&data_check_png;
  @ requires valid_data_check_param(buffer, buffer_size, file_recovery);
  @ ensures  valid_data_check_result(\result, file_recovery);
  @ assigns  file_recovery->calculated_file_size, file_recovery->offset_ok, file_recovery->offset_error;
  @*/
static data_check_t data_check_png(const unsigned char *buffer, const unsigned int buffer_size, file_recovery_t *file_recovery)
{
  /*@ assert file_recovery->calculated_file_size <= PHOTOREC_MAX_FILE_SIZE; */
  /*@ assert file_recovery->file_size <= PHOTOREC_MAX_FILE_SIZE; */
  /*@
    @ loop assigns file_recovery->calculated_file_size, file_recovery->offset_ok;
    @ loop variant file_recovery->file_size + buffer_size/2 - (file_recovery->calculated_file_size + 8);
    @*/
  while(file_recovery->calculated_file_size + buffer_size/2  >= file_recovery->file_size &&
      file_recovery->calculated_file_size + 8 <= file_recovery->file_size + buffer_size/2)
  {
    const unsigned int i=file_recovery->calculated_file_size + buffer_size/2 - file_recovery->file_size;
    /*@ assert 0 <= i <= buffer_size - 8 ; */
    const struct png_chunk *chunk=(const struct png_chunk *)&buffer[i];
    const uint32_t length=be32(chunk->length);
    if(memcmp(&buffer[i+4], "IEND", 4)==0)
    {
      file_recovery->calculated_file_size+=(uint64_t)12 + length;
      return DC_STOP;
    }
// PNG chunk code
// IDAT IHDR PLTE bKGD cHRM fRAc gAMA gIFg gIFt gIFx hIST iCCP
// iTXt oFFs pCAL pHYs sBIT sCAL sPLT sRGB sTER tEXt tRNS zTXt
    if( !((isupper(buffer[i+4]) || islower(buffer[i+4])) &&
	  (isupper(buffer[i+5]) || islower(buffer[i+5])) &&
	  (isupper(buffer[i+6]) || islower(buffer[i+6])) &&
	  (isupper(buffer[i+7]) || islower(buffer[i+7]))))
    {
      file_recovery->offset_error=file_recovery->calculated_file_size+7;
      return DC_ERROR;
    }
    file_recovery->offset_ok=file_recovery->calculated_file_size+7;
    file_recovery->calculated_file_size+=(uint64_t)12 + length;
  }
  return DC_CONTINUE;
}

/*@
  @ requires buffer_size >= 16;
  @ requires separation: \separated(&file_hint_png, buffer+(..), file_recovery, file_recovery_new);
  @ requires valid_header_check_param(buffer, buffer_size, safe_header_only, file_recovery, file_recovery_new);
  @ ensures  valid_header_check_result(\result, file_recovery_new);
  @ assigns  *file_recovery_new;
  @*/
static int header_check_jng(const unsigned char *buffer, const unsigned int buffer_size, const unsigned int safe_header_only, const file_recovery_t *file_recovery, file_recovery_t *file_recovery_new)
{
  if( !((isupper(buffer[8+4]) || islower(buffer[8+4])) &&
	(isupper(buffer[8+5]) || islower(buffer[8+5])) &&
	(isupper(buffer[8+6]) || islower(buffer[8+6])) &&
	(isupper(buffer[8+7]) || islower(buffer[8+7]))))
    return 0;
  reset_file_recovery(file_recovery_new);
  file_recovery_new->extension="jng";
  file_recovery_new->min_filesize=16;
  if(file_recovery_new->blocksize < 8)
  {
    /*@ assert valid_file_recovery(file_recovery_new); */
    return 1;
  }
  file_recovery_new->calculated_file_size=8;
  file_recovery_new->data_check=&data_check_png;
  file_recovery_new->file_check=&file_check_size;
  /*@ assert valid_file_recovery(file_recovery_new); */
  return 1;
}

/*@
  @ requires buffer_size >= 16;
  @ requires separation: \separated(&file_hint_png, buffer+(..), file_recovery, file_recovery_new);
  @ requires valid_header_check_param(buffer, buffer_size, safe_header_only, file_recovery, file_recovery_new);
  @ ensures  valid_header_check_result(\result, file_recovery_new);
  @ assigns  *file_recovery_new;
  @*/
static int header_check_mng(const unsigned char *buffer, const unsigned int buffer_size, const unsigned int safe_header_only, const file_recovery_t *file_recovery, file_recovery_t *file_recovery_new)
{
  if( !((isupper(buffer[8+4]) || islower(buffer[8+4])) &&
	(isupper(buffer[8+5]) || islower(buffer[8+5])) &&
	(isupper(buffer[8+6]) || islower(buffer[8+6])) &&
	(isupper(buffer[8+7]) || islower(buffer[8+7]))))
    return 0;
  reset_file_recovery(file_recovery_new);
  file_recovery_new->extension="mng";
  file_recovery_new->min_filesize=16;
  if(file_recovery_new->blocksize < 8)
  {
    /*@ assert valid_file_recovery(file_recovery_new); */
    return 1;
  }
  file_recovery_new->calculated_file_size=8;
  file_recovery_new->data_check=&data_check_mng;
  file_recovery_new->file_check=&file_check_size;
  /*@ assert valid_file_recovery(file_recovery_new); */
  return 1;
}

static void file_rename_png(file_recovery_t *file_recovery)
{
  FILE *file;
  unsigned char buffer[65536];
  size_t n;
  size_t pos;
  char date_str[32] = "";
  char model_str[64] = "";

  if((file = fopen(file_recovery->filename, "rb")) == NULL)
    return;
  n = fread(buffer, 1, sizeof(buffer), file);
  fclose(file);

  if(n < 32 || memcmp(buffer, "\x89PNG\r\n\x1a\n", 8) != 0)
    return;

  pos = 8;
  while(pos + 12 <= n)
  {
    const uint32_t chunk_len = ((uint32_t)buffer[pos] << 24) | ((uint32_t)buffer[pos+1] << 16) | ((uint32_t)buffer[pos+2] << 8) | buffer[pos+3];
    const unsigned char *chunk_type = &buffer[pos + 4];
    const unsigned char *chunk_data = &buffer[pos + 8];

    if(pos + 12 + chunk_len > n)
      break;

    if(memcmp(chunk_type, "tIME", 4) == 0 && chunk_len >= 7)
    {
      const uint16_t year = ((uint16_t)chunk_data[0] << 8) | chunk_data[1];
      const uint8_t mon = chunk_data[2];
      const uint8_t day = chunk_data[3];
      const uint8_t hour = chunk_data[4];
      const uint8_t min = chunk_data[5];
      const uint8_t sec = chunk_data[6];
      if(year >= 1990 && year <= 2050 && mon >= 1 && mon <= 12 && day >= 1 && day <= 31 && hour < 24 && min < 60 && sec <= 60)
      {
        struct tm tm_date;
        time_t t;
        memset(&tm_date, 0, sizeof(tm_date));
        tm_date.tm_year = year - 1900;
        tm_date.tm_mon = mon - 1;
        tm_date.tm_mday = day;
        tm_date.tm_hour = hour;
        tm_date.tm_min = min;
        tm_date.tm_sec = sec;
        t = mktime(&tm_date);
        if(t != (time_t)-1)
        {
          snprintf(date_str, sizeof(date_str), "%04d%02d%02d_%02d%02d%02d",
                   year, mon, day, hour, min, sec);
          set_date(file_recovery->filename, t, t);
          break;
        }
      }
    }
    else if(memcmp(chunk_type, "eXIf", 4) == 0 && chunk_len >= 14)
    {
      const unsigned char *exif_buf = chunk_data;
      size_t exif_len = chunk_len;
      if(exif_len >= 6 && memcmp(exif_buf, "Exif\0\0", 6) == 0)
      {
        exif_buf += 6;
        exif_len -= 6;
      }
      if(exif_len >= 14)
      {
        const int is_le = (exif_buf[0] == 'I' && exif_buf[1] == 'I');
        size_t off;
        for(off = 0; off + 12 <= exif_len; off++)
        {
          const uint16_t tag = is_le ? (exif_buf[off] | ((uint16_t)exif_buf[off+1] << 8)) :
                                       (((uint16_t)exif_buf[off] << 8) | exif_buf[off+1]);
          const uint16_t type = is_le ? (exif_buf[off+2] | ((uint16_t)exif_buf[off+3] << 8)) :
                                        (((uint16_t)exif_buf[off+2] << 8) | exif_buf[off+3]);
          const uint32_t count = is_le ? ((uint32_t)exif_buf[off+4] | ((uint32_t)exif_buf[off+5] << 8) | ((uint32_t)exif_buf[off+6] << 16) | ((uint32_t)exif_buf[off+7] << 24)) :
                                         (((uint32_t)exif_buf[off+4] << 24) | ((uint32_t)exif_buf[off+5] << 16) | ((uint32_t)exif_buf[off+6] << 8) | (uint32_t)exif_buf[off+7]);
          const uint32_t val_off = is_le ? ((uint32_t)exif_buf[off+8] | ((uint32_t)exif_buf[off+9] << 8) | ((uint32_t)exif_buf[off+10] << 16) | ((uint32_t)exif_buf[off+11] << 24)) :
                                           (((uint32_t)exif_buf[off+8] << 24) | ((uint32_t)exif_buf[off+9] << 16) | ((uint32_t)exif_buf[off+10] << 8) | (uint32_t)exif_buf[off+11]);
          if(type == 2 && count > 1 && count < 64)
          {
            const char *str_val = NULL;
            if(count <= 4) str_val = (const char *)&exif_buf[off + 8];
            else if(val_off + count <= exif_len) str_val = (const char *)&exif_buf[val_off];
            if(str_val != NULL)
            {
              if((tag == 0x9003 || tag == 0x0132) && date_str[0] == '\0')
              {
                if(count >= 19 && isdigit((unsigned char)str_val[0]) && isdigit((unsigned char)str_val[1]) &&
                   isdigit((unsigned char)str_val[2]) && isdigit((unsigned char)str_val[3]) && str_val[4] == ':')
                {
                  snprintf(date_str, sizeof(date_str), "%c%c%c%c%c%c%c%c_%c%c%c%c%c%c",
                           str_val[0], str_val[1], str_val[2], str_val[3],
                           str_val[5], str_val[6], str_val[8], str_val[9],
                           str_val[11], str_val[12], str_val[14], str_val[15],
                           str_val[17], str_val[18]);
                }
              }
              else if(tag == 0x0110 && model_str[0] == '\0')
              {
                size_t k = 0, m = 0;
                while(k < count && str_val[k] != '\0' && m < sizeof(model_str) - 1)
                {
                  const char c = str_val[k++];
                  if(isalnum((unsigned char)c) || c == '_' || c == '-') model_str[m++] = c;
                  else if(c == ' ' && m > 0 && model_str[m-1] != '_') model_str[m++] = '_';
                }
                while(m > 0 && model_str[m-1] == '_') m--;
                model_str[m] = '\0';
              }
            }
          }
        }
      }
      if(date_str[0] != '\0')
        break;
    }
    else if(memcmp(chunk_type, "IEND", 4) == 0)
    {
      break;
    }

    pos += 12 + chunk_len;
  }

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
}

/*@
  @ requires buffer_size >= 16 + sizeof(struct png_ihdr);
  @ requires separation: \separated(&file_hint_png, buffer+(..), file_recovery, file_recovery_new);
  @ requires valid_header_check_param(buffer, buffer_size, safe_header_only, file_recovery, file_recovery_new);
  @ ensures  valid_header_check_result(\result, file_recovery_new);
  @ assigns  *file_recovery_new;
  @*/
static int header_check_png(const unsigned char *buffer, const unsigned int buffer_size, const unsigned int safe_header_only, const file_recovery_t *file_recovery, file_recovery_t *file_recovery_new)
{
  if( !((isupper(buffer[8+4]) || islower(buffer[8+4])) &&
	(isupper(buffer[8+5]) || islower(buffer[8+5])) &&
	(isupper(buffer[8+6]) || islower(buffer[8+6])) &&
	(isupper(buffer[8+7]) || islower(buffer[8+7]))))
    return 0;
  if(memcmp(&buffer[8+4], "IHDR", 4) == 0 &&
      png_check_ihdr((const struct png_ihdr *)&buffer[16])==0)
    return 0;
#if !defined(SINGLE_FORMAT)
  /* SolidWorks files contain a png */
  if(file_recovery->file_stat!=NULL &&
      file_recovery->file_stat->file_hint==&file_hint_doc)
  {
    if(header_ignored_adv(file_recovery, file_recovery_new)==0)
      return 0;
  }
#endif
  reset_file_recovery(file_recovery_new);
  file_recovery_new->extension=file_hint_png.extension;
  file_recovery_new->min_filesize=16;
  if(file_recovery_new->blocksize < 8)
  {
    /*@ assert valid_file_recovery(file_recovery_new); */
    return 1;
  }
  file_recovery_new->calculated_file_size=8;
  file_recovery_new->data_check=&data_check_png;
  file_recovery_new->file_check=&file_check_png;
  file_recovery_new->file_rename=&file_rename_png;
  /*@ assert valid_file_recovery(file_recovery_new); */
  return 1;
}

static void register_header_check_png(file_stat_t *file_stat)
{
  static const unsigned char jng_header[8]= { 0x8b, 'J', 'N','G', 0x0d, 0x0a, 0x1a, 0x0a};
  static const unsigned char mng_header[8]= { 0x8a, 'M', 'N','G', 0x0d, 0x0a, 0x1a, 0x0a};
  static const unsigned char png_header[8]= { 0x89, 'P', 'N','G', 0x0d, 0x0a, 0x1a, 0x0a};
  register_header_check(0, jng_header, sizeof(jng_header), &header_check_jng, file_stat);
  register_header_check(0, mng_header, sizeof(mng_header), &header_check_mng, file_stat);
  register_header_check(0, png_header, sizeof(png_header), &header_check_png, file_stat);
}
#endif
