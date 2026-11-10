/*

    File: file_tiff.c

    Copyright (C) 1998-2005,2007-2009 Christophe GRENIER <grenier@cgsecurity.org>
  
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

#if !defined(SINGLE_FORMAT) || defined(SINGLE_FORMAT_tiff) || defined(SINGLE_FORMAT_jpg) || defined(SINGLE_FORMAT_rw2) || defined(SINGLE_FORMAT_orf) || defined(SINGLE_FORMAT_wdp)
#ifdef HAVE_CONFIG_H
#include <config.h>
#endif
#ifdef HAVE_STRING_H
#include <string.h>
#endif
#ifdef HAVE_TIME_H
#include <time.h>
#endif
#ifdef HAVE_STDLIB_H
#include <stdlib.h>
#endif
#include <stdio.h>
#include <ctype.h>
#include "types.h"
#include "filegen.h"
#include "common.h"
#include "file_tiff.h"
#include "setdate.h"
#include "log.h"
#if defined(__FRAMAC__)
#include "__fc_builtin.h"
#endif


static void register_header_check_tiff(file_stat_t *file_stat);

const file_hint_t file_hint_tiff= {
  .extension="tif",
  .description="Tag Image File Format and some raw file formats (pef/nef/dcr/sr2/cr2)",
  .max_filesize=1024*1024*1024,
  .recover=1,
  .enable_by_default=1,
  .register_header_check=&register_header_check_tiff
};

unsigned int tiff_type2size(const unsigned int type)
{
  switch(type)
  {
    case 1:	/* TIFF_BYTE	*/
    case 2:	/* TIFF_ASCII	*/
    case 6:	/* TIFF_SBYTE	*/
    case 7:	/* TIFF_UNDEFINED */
      return 1;
    case 3:	/* TIFF_SHORT	*/
    case 8:	/* TIFF_SSHORT	*/
      return 2;
    case 4:	/* TIFF_LONG	*/
    case 9:	/* TIFF_SLONG	*/
    case 11:	/* TIFF_FLOAT	*/
    case 13:	/* TIFF_IFD	*/
      return 4;
    case 5:	/* TIFF_RATIONAL */
    case 10:	/* TIFF_SRATIONAL */
    case 12:	/* TIFF_DOUBLE	*/
    case 16:	/* TIFF_LONG8	*/
    case 17:	/* TIFF_SLONG8	*/
    case 18:	/* TIFF_IFD8	*/
      return 8;
#if 0
    case 14:	/* TIFF_UNICODE	*/
    case 15:	/* TIFF_COMPLEX */
#endif
    default:
      return 1;
  }
}

#ifdef DEBUG_TIFF
const char *tag_name(unsigned int tag)
{
  switch(tag)
  {
    case TIFFTAG_IMAGEDESCRIPTION:
      return "IMAGEDESCRIPTION";
    case TIFFTAG_MAKE:
      return "MAKE";
    case TIFFTAG_MODEL:
      return "TIFFTAG_MODEL";
    case TIFFTAG_SUBIFD:
      return "SUBIFD";
    case TIFFTAG_EXIFIFD:
       return "EXIFIFD";
    case TIFFTAG_STRIPOFFSETS:
       return "STRIPOFFSETS";
    case TIFFTAG_STRIPBYTECOUNTS:
       return "STRIPBYTECOUNTS";
    case TIFFTAG_KODAKIFD:
       return "KODAKIFD";
    case TIFFTAG_JPEGIFOFFSET:
       return "JPEGIFOFFSET";
    case TIFFTAG_JPEGIFBYTECOUNT:
       return "JPEGIFBYTECOUNT";
    case TIFFTAG_DNGPRIVATEDATA:
       return "DNGPRIVATEDATA";
    case EXIFTAG_MAKERNOTE:
       return "EXIFTAG_MAKERNOTE";
    case TIFFTAG_PRINTIM:
       return "PrintIM";
    case TIFFTAG_IMAGEOFFSET:
       return "IMAGEOFFSET";
    case TIFFTAG_IMAGEBYTECOUNT:
       return "IMAGEBYTECOUNT";
    case TIFFTAG_ALPHAOFFSET:
       return "ALPHAOFFSET";
    case TIFFTAG_ALPHABYTECOUNT:
       return "ALPHABYTECOUNT";
    case TIFFTAG_TILEOFFSETS:
       return "TileOffsets";
    case TIFFTAG_TILEBYTECOUNTS:
       return "TileByteCounts";
    default:
      return "";
  }
}
#endif

unsigned int find_tag_from_tiff_header(const unsigned char*buffer, const unsigned int buffer_size, const unsigned int tag, const unsigned char **potential_error)
{
  const TIFFHeader *tiff=(const TIFFHeader *)buffer;
  /*@ assert sizeof(TIFFHeader) <= sizeof(struct ifd_header); */
  if(buffer_size < sizeof(struct ifd_header))
    return 0;
  /*@ assert buffer_size >= sizeof(TIFFHeader); */
  /*@ assert buffer_size >= sizeof(struct ifd_header); */
  /*@ assert \valid_read(tiff); */
#ifndef MAIN_tiff_le
  if(tiff->tiff_magic==TIFF_BIGENDIAN)
    return find_tag_from_tiff_header_be(buffer, buffer_size, tag, potential_error);
#endif
#ifndef MAIN_tiff_be
  if(tiff->tiff_magic==TIFF_LITTLEENDIAN)
    return find_tag_from_tiff_header_le(buffer, buffer_size, tag, potential_error);
#endif
  return 0;
}

time_t get_date_from_tiff_header(const unsigned char *buffer, const unsigned int buffer_size)
{
  const unsigned char *potential_error=NULL;
  unsigned int date_asc=0;
  time_t tmp;
  /*@ assert \valid_read(buffer+(0..buffer_size-1)); */
  /*@ assert sizeof(TIFFHeader) <= sizeof(struct ifd_header); */
  if(buffer_size < sizeof(struct ifd_header) || buffer_size < 19)
    return (time_t)0;
  /*@ assert buffer_size >= sizeof(TIFFHeader); */
  /*@ assert buffer_size >= sizeof(struct ifd_header); */
  /* DateTimeOriginal */
  date_asc=find_tag_from_tiff_header(buffer, buffer_size, 0x9003, &potential_error);
  /* DateTimeDigitalized*/
  if(date_asc==0 || date_asc >  buffer_size - 19)
    date_asc=find_tag_from_tiff_header(buffer, buffer_size, 0x9004, &potential_error);
  if(date_asc==0 || date_asc >  buffer_size - 19)
    date_asc=find_tag_from_tiff_header(buffer, buffer_size, 0x132, &potential_error);
  if(date_asc==0 || date_asc >  buffer_size - 19)
    return (time_t)0;
  tmp=get_time_from_YYYY_MM_DD_HH_MM_SS(&buffer[date_asc]);
  /*@ assert \valid_read(buffer+(0..buffer_size-1)); */
  return tmp;
}

void file_rename_tiff(file_recovery_t *file_recovery)
{
  FILE *file;
  unsigned char buffer[65536];
  size_t n;
  char date_str[32] = "";
  char model_str[64] = "";
  char prefix[128];
  int is_le = 0;
  size_t off;

  if((file = fopen(file_recovery->filename, "rb")) == NULL)
    return;
  n = fread(buffer, 1, sizeof(buffer), file);
  fclose(file);

  if(n < 16)
    return;

  if(buffer[0] == 'I' && buffer[1] == 'I')
    is_le = 1;
  else if(buffer[0] == 'M' && buffer[1] == 'M')
    is_le = 0;
  else
    return;

  for(off = 0; off + 12 <= n; off++)
  {
    uint16_t tag = is_le ? (buffer[off] | ((uint16_t)buffer[off+1] << 8)) :
                           (((uint16_t)buffer[off] << 8) | buffer[off+1]);
    uint16_t type = is_le ? (buffer[off+2] | ((uint16_t)buffer[off+3] << 8)) :
                            (((uint16_t)buffer[off+2] << 8) | buffer[off+3]);
    uint32_t count = is_le ? ((uint32_t)buffer[off+4] | ((uint32_t)buffer[off+5] << 8) | ((uint32_t)buffer[off+6] << 16) | ((uint32_t)buffer[off+7] << 24)) :
                             (((uint32_t)buffer[off+4] << 24) | ((uint32_t)buffer[off+5] << 16) | ((uint32_t)buffer[off+6] << 8) | (uint32_t)buffer[off+7]);
    uint32_t val_off = is_le ? ((uint32_t)buffer[off+8] | ((uint32_t)buffer[off+9] << 8) | ((uint32_t)buffer[off+10] << 16) | ((uint32_t)buffer[off+11] << 24)) :
                               (((uint32_t)buffer[off+8] << 24) | ((uint32_t)buffer[off+9] << 16) | ((uint32_t)buffer[off+10] << 8) | (uint32_t)buffer[off+11]);

    if(type == 2 && count > 1 && count < 64)
    {
      const char *str_val = NULL;
      if(count <= 4)
        str_val = (const char *)&buffer[off + 8];
      else if(val_off + count <= n)
        str_val = (const char *)&buffer[val_off];

      if(str_val != NULL)
      {
        if((tag == 0x9003 || tag == 0x0132) && date_str[0] == '\0')
        {
          if(count >= 19 && isdigit((unsigned char)str_val[0]) && isdigit((unsigned char)str_val[1]) &&
             isdigit((unsigned char)str_val[2]) && isdigit((unsigned char)str_val[3]) && str_val[4] == ':')
          {
            snprintf(date_str, sizeof(date_str), "%c%c%c%c%c%c%c%c_%c%c%c%c%c%c",
                     str_val[0], str_val[1], str_val[2], str_val[3],
                     str_val[5], str_val[6],
                     str_val[8], str_val[9],
                     str_val[11], str_val[12],
                     str_val[14], str_val[15],
                     str_val[17], str_val[18]);
          }
        }
        else if(tag == 0x0110 && model_str[0] == '\0')
        {
          size_t k = 0, m = 0;
          while(k < count && str_val[k] != '\0' && m < sizeof(model_str) - 1)
          {
            char c = str_val[k++];
            if(isalnum((unsigned char)c) || c == '_' || c == '-')
              model_str[m++] = c;
            else if(c == ' ' && m > 0 && model_str[m-1] != '_')
              model_str[m++] = '_';
          }
          while(m > 0 && model_str[m-1] == '_') m--;
          model_str[m] = '\0';
        }
      }
    }
  }

  if(date_str[0] != '\0')
  {
    struct tm tm_date;
    time_t t;
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

static void register_header_check_tiff(file_stat_t *file_stat)
{
  static const unsigned char tiff_header_be[4]= { 'M','M',0x00, 0x2a};
  static const unsigned char tiff_header_le[4]= { 'I','I',0x2a, 0x00};
#if !defined(SINGLE_FORMAT_jpg) && !defined(SINGLE_FORMAT_rw2) && !defined(SINGLE_FORMAT_orf) && !defined(SINGLE_FORMAT_wdp)
#if !defined(MAIN_tiff_le) && !defined(MAIN_jpg)
  register_header_check(0, tiff_header_be, sizeof(tiff_header_be), &header_check_tiff_be, file_stat);
#endif
#if !defined(MAIN_tiff_be) && !defined(MAIN_jpg)
  register_header_check(0, tiff_header_le, sizeof(tiff_header_le), &header_check_tiff_le, file_stat);
#endif
#endif
}
#endif
