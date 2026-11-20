/*

    File: phnc.c

    Copyright (C) 1998-2009 Christophe GRENIER <grenier@cgsecurity.org>

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

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#if defined(DISABLED_FOR_FRAMAC)
#undef HAVE_NCURSES
#endif

#ifdef HAVE_NCURSES
#include <stdio.h>
#ifdef HAVE_STDLIB_H
#include <stdlib.h>
#endif
#ifdef HAVE_STRING_H
#include <string.h>
#endif
#include "types.h"
#include "common.h"
#include "intrf.h"
#include "intrfn.h"
#include "filegen.h"
#include "photorec.h"
#include "phnc.h"

void photorec_info(WINDOW *window, const file_stat_t *file_stats)
{
  unsigned int i, nbr;
  unsigned int total_img = 0, total_vid = 0, total_doc = 0, total_arc = 0, total_other = 0;
  file_stat_t *new_file_stats;
  int start_y = 15;
  int box_h = LINES - start_y - 2;
  int col_w;

  if(file_stats == NULL || box_h < 4)
    return;

  for(i = 0; file_stats[i].file_hint != NULL; i++);
  nbr = i;
  if(nbr == 0)
    return;

  tui_draw_box(window, start_y, 0, box_h, COLS, "Carved File Types Breakdown", 5);

  /* Compute category sums */
  for(i = 0; i < nbr; i++)
  {
    if(file_stats[i].recovered > 0 && file_stats[i].file_hint != NULL && file_stats[i].file_hint->extension != NULL)
    {
      char badge[16];
      int cpair = 5;
      tui_get_file_badge(file_stats[i].file_hint->extension, 0, badge, sizeof(badge), &cpair);
      if(cpair == 2) total_img += file_stats[i].recovered;
      else if(cpair == 6) total_vid += file_stats[i].recovered;
      else if(cpair == 4) total_doc += file_stats[i].recovered;
      else if(cpair == 1) total_arc += file_stats[i].recovered;
      else total_other += file_stats[i].recovered;
    }
  }

  /* Summary Row */
  wmove(window, start_y + 1, 2);
  wclrtoeol(window);
  mvwprintw(window, start_y + 1, 2, "Images: %u   Videos: %u   Docs: %u   Archives: %u   Other: %u",
            total_img, total_vid, total_doc, total_arc, total_other);

  /* Top file extensions */
  new_file_stats = (file_stat_t*)MALLOC(nbr * sizeof(file_stat_t));
  memcpy(new_file_stats, file_stats, nbr * sizeof(file_stat_t));
  qsort(new_file_stats, nbr, sizeof(file_stat_t), sorfile_stat_ts);

  col_w = (COLS - 6) / 3;
  if(col_w < 20) col_w = 20;

  for(i = 0; i < nbr && new_file_stats[i].recovered > 0; i++)
  {
    int row = i % (box_h - 3);
    int col = i / (box_h - 3);
    int print_x = 2 + col * col_w;
    int print_y = start_y + 2 + row;
    char badge[16];
    int cpair = 7;

    if(col >= 3 || print_y >= start_y + box_h - 1)
      break;

    tui_get_file_badge(new_file_stats[i].file_hint->extension, 0, badge, sizeof(badge), &cpair);

    wmove(window, print_y, print_x);
    if(cpair == 3 && has_colors())
      wattron(window, COLOR_PAIR(3));
    wprintw(window, "%-6s ", badge);
    if(cpair == 3 && has_colors())
      wattroff(window, COLOR_PAIR(3));
    wprintw(window, "%-7s: %5u",
            (new_file_stats[i].file_hint->extension ? new_file_stats[i].file_hint->extension : "???"),
            new_file_stats[i].recovered);
  }
  free(new_file_stats);
}

pstatus_t photorec_progressbar(WINDOW *window, const unsigned int pass, const struct ph_param *params, const uint64_t offset, const time_t current_time)
{
  const partition_t *partition = params->partition;
  const unsigned int sector_size = params->disk->sector_size;
  int key_action;
  uint64_t bytes_done = 0;
  double pct = 0.0;
  double speed_mb_s = 0.0;
  time_t elapsed_time = 0;
  time_t eta = 0;
  int block_map_h = (LINES > 28 ? 3 : 2);

  if(partition->part_size > 0 && offset >= partition->part_offset)
  {
    bytes_done = offset - partition->part_offset;
    pct = ((double)bytes_done * 100.0) / (double)partition->part_size;
    if(pct > 100.0) pct = 100.0;
    if(pct < 0.0) pct = 0.0;
  }

  if(current_time > params->real_start_time)
  {
    elapsed_time = current_time - params->real_start_time;
    if(elapsed_time > 0)
      speed_mb_s = (double)bytes_done / (1024.0 * 1024.0 * (double)elapsed_time);
    if(offset > partition->part_offset && bytes_done > 0)
    {
      eta = (partition->part_size - bytes_done) * elapsed_time / bytes_done;
    }
  }

  tui_draw_header(window, "PhotoRec-NG", "Recovery Dashboard");

  /* Top Box: Telemetry and Sector Block Map */
  tui_draw_box(window, 5, 0, 9, COLS, "Scan Progress & Telemetry", 3);

  /* Row 6: Pass & Destination */
  wmove(window, 6, 2);
  wclrtoeol(window);
  mvwprintw(window, 6, 2, "Pass %u (Blocksize: %u B)  •  Destination: %.*s",
            pass, params->blocksize, (COLS > 60 ? COLS - 50 : 20), params->recup_dir);

  /* Row 7: Progress Bar & Speed */
  wmove(window, 7, 2);
  wclrtoeol(window);
  {
    const int bar_w = (COLS > 80 ? 40 : 25);
    int filled = (int)(pct * (double)bar_w / 100.0);
    int b;
    if(filled > bar_w) filled = bar_w;
    if(filled < 0) filled = 0;

    mvwprintw(window, 7, 2, "Progress: [");
    if(has_colors())
      wbkgdset(window, ' ' | A_BOLD | COLOR_PAIR(3));
    for(b = 0; b < filled; b++)
      waddch(window, '=');
    if(filled < bar_w)
      waddch(window, '>');
    for(b = filled + 1; b < bar_w; b++)
      waddch(window, ' ');
    if(has_colors())
      wbkgdset(window, ' ' | COLOR_PAIR(0));
    wprintw(window, "] %5.1f%%   Speed: %5.1f MB/s", pct, speed_mb_s);
  }

  /* Rows 8 to 8 + block_map_h: Visual Block Map */
  tui_draw_block_map(window, 8, 2, COLS - 4, block_map_h, pct);

  /* Row 12: Timing & Sectors */
  wmove(window, 8 + block_map_h + 1, 2);
  wclrtoeol(window);
  mvwprintw(window, 8 + block_map_h + 1, 2,
            "Elapsed: %02uh%02um%02us   ETA: %02uh%02um%02us   Sectors: %llu/%llu   Files Carved: ",
            (unsigned)(elapsed_time / 3600), (unsigned)((elapsed_time / 60) % 60), (unsigned)(elapsed_time % 60),
            (unsigned)(eta / 3600), (unsigned)((eta / 60) % 60), (unsigned)(eta % 60),
            (unsigned long long)((offset - partition->part_offset) / sector_size),
            (unsigned long long)(partition->part_size / sector_size));
  if(has_colors()) wattron(window, COLOR_PAIR(2) | A_BOLD);
  wprintw(window, "%u", params->file_nbr);
  if(has_colors()) wattroff(window, COLOR_PAIR(2) | A_BOLD);

  /* Carved Files Breakdown Box */
  photorec_info(window, params->file_stats);

  /* Hotkey footer */
  tui_draw_footer(window, "[Space / P] Pause/Resume   [Enter / S] Stop Carving   [?] Help");

  wrefresh(window);

  key_action = check_enter_key_or_s(window);
  if(key_action == 1)
    return PSTATUS_STOP;
  if(key_action == 4)
  {
    /* Paused Modal */
    int modal_w = 64;
    int modal_h = 5;
    int modal_x = (COLS - modal_w) / 2;
    int modal_y = (LINES - modal_h) / 2;
    if(modal_x < 0) modal_x = 0;
    if(modal_w > COLS) modal_w = COLS;

    tui_draw_box(window, modal_y, modal_x, modal_h, modal_w, "RECOVERY PAUSED", 1);
    mvwprintw(window, modal_y + 2, modal_x + 4, "  Press [Space] or [P] to Resume, or [S] to Stop  ");
    wrefresh(window);

    while(1)
    {
      const int ch = wgetch(window);
      if(ch == ' ' || ch == 'p' || ch == 'P' || ch == '\n' || ch == '\r')
        break;
      if(ch == 'q' || ch == 'Q' || ch == 's' || ch == 'S')
        return PSTATUS_STOP;
    }
  }
  return PSTATUS_OK;
}
#endif
