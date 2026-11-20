/*

    File: pdiskseln.c

    Copyright (C) 1998-2008 Christophe GRENIER <grenier@cgsecurity.org>

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

#if defined(__CYGWIN__) || defined(__MINGW32__) || defined(DJGPP) || !defined(HAVE_GETEUID)
#undef SUDO_BIN
#endif

#if defined(DISABLED_FOR_FRAMAC)
#undef HAVE_NCURSES
#endif

#include <stdio.h>
#ifdef HAVE_STDLIB_H
#include <stdlib.h>
#endif
#ifdef HAVE_UNISTD_H
#include <unistd.h>	/* geteuid */
#endif
#ifdef HAVE_STRING_H
#include <string.h>
#endif
#include "types.h"
#include "common.h"
#include "intrf.h"
#if defined(HAVE_NCURSES)
#include "intrfn.h"
#endif
#include "dir.h"
#include "list.h"
#include "filegen.h"
#include "photorec.h"
#include "sessionp.h"
#include "partauto.h"
#include "log.h"
#include "pdisksel.h"
#include "pdiskseln.h"
#include "ppartseln.h"
#include "hidden.h"
#include "hiddenn.h"
#include "nodisk.h"
#include "chgarch.h"
#include "chgarchn.h"
#include "autoset.h"

#if defined(HAVE_NCURSES)
#define NBR_DISK_MAX 		(LINES-6-8)
#define INTER_DISK_X		0
#define INTER_DISK_Y		(8+NBR_DISK_MAX)
#define INTER_NOTE_Y		(LINES-4)
#endif

extern const arch_fnct_t arch_none;


#if defined(HAVE_NCURSES)
static int disk_matches_filter(const disk_t *disk, const char *query)
{
  if(query == NULL || *query == '\0')
    return 1;
  if(disk == NULL)
    return 0;
  if(disk->device && strcasestr(disk->device, query) != NULL)
    return 1;
  if(disk->model && strcasestr(disk->model, query) != NULL)
    return 1;
  if(disk->description_txt[0] != '\0' && strcasestr(disk->description_txt, query) != NULL)
    return 1;
  if(disk->description_short_txt[0] != '\0' && strcasestr(disk->description_short_txt, query) != NULL)
    return 1;
  if(disk->bus_type && strcasestr(disk->bus_type, query) != NULL)
    return 1;
  if(disk->serial_no && strcasestr(disk->serial_no, query) != NULL)
    return 1;
  return 0;
}

static void draw_media_inspector(WINDOW *win, int top_y, int left_x, int box_h, int box_w, const disk_t *disk)
{
  char size_str[32];
  char badge[16];
  int badge_color = 3;
  int cur_y = top_y + 1;
  const int inner_w = box_w - 4;
  int sep_i;

  tui_draw_box(win, top_y, left_x, box_h, box_w, "Live Media Inspector", 3);

  if(disk == NULL)
  {
    mvwprintw(win, cur_y, left_x + 2, "No media selected");
    return;
  }

  tui_get_disk_badge(disk, badge, sizeof(badge), &badge_color);
  tui_format_size(disk->disk_size, size_str, sizeof(size_str));

  /* Device and Badge */
  mvwprintw(win, cur_y++, left_x + 2, "Device:       %-16s ", (disk->device ? disk->device : "Unknown"));
  if(has_colors())
    wattron(win, COLOR_PAIR(badge_color) | A_BOLD);
  wprintw(win, "%s", badge);
  if(has_colors())
    wattroff(win, COLOR_PAIR(badge_color) | A_BOLD);

  /* Model */
  mvwprintw(win, cur_y++, left_x + 2, "Model:        %.*s", inner_w - 14,
            (disk->model && disk->model[0] != '\0' ? disk->model : "Generic Storage Device"));

  /* Protocol / Bus */
  mvwprintw(win, cur_y++, left_x + 2, "Protocol:     %s",
            (disk->bus_type && disk->bus_type[0] != '\0' ? disk->bus_type : (disk->is_usb_adapter ? "USB Storage" : "Standard Block Device")));

  /* Media Type */
  mvwprintw(win, cur_y++, left_x + 2, "Media Type:   %s",
            (disk->medium_type ? disk->medium_type : (disk->is_ssd ? "Solid State Drive (SSD)" : "Direct-Access Block Media")));

  /* Capacity */
  mvwprintw(win, cur_y++, left_x + 2, "Capacity:     %s (%llu bytes)",
            size_str, (unsigned long long)disk->disk_size);

  /* Sector Sizing */
  mvwprintw(win, cur_y++, left_x + 2, "Sector Sizing:%u bytes logical / %u physical",
            disk->sector_size, (disk->sector_size == 4096 ? 4096 : 512));

  /* Total Sectors */
  if(disk->sector_size > 0)
  {
    mvwprintw(win, cur_y++, left_x + 2, "Total Sectors:%llu sectors",
              (unsigned long long)(disk->disk_size / disk->sector_size));
  }

  /* Geometry CHS */
  mvwprintw(win, cur_y++, left_x + 2, "Geometry:     %lu cyl / %u heads / %u sec",
            disk->geom.cylinders, disk->geom.heads_per_cylinder, disk->geom.sectors_per_head);

  /* Serial Number */
  if(disk->serial_no && disk->serial_no[0] != '\0')
  {
    mvwprintw(win, cur_y, left_x + 2, "Serial No:    ");
    if(has_colors())
      wattron(win, COLOR_PAIR(2));
    wprintw(win, "%.*s", inner_w - 14, disk->serial_no);
    if(has_colors())
      wattroff(win, COLOR_PAIR(2));
    cur_y++;
  }

  /* Firmware */
  if(disk->fw_rev && disk->fw_rev[0] != '\0')
  {
    mvwprintw(win, cur_y++, left_x + 2, "Firmware Rev: %.*s", inner_w - 14, disk->fw_rev);
  }

  /* Divider */
  if(cur_y < top_y + box_h - 5)
  {
    wmove(win, cur_y++, left_x + 1);
    if(has_colors())
      wattron(win, COLOR_PAIR(5));
    for(sep_i = 0; sep_i < box_w - 2; sep_i++)
      waddch(win, ACS_HLINE);
    if(has_colors())
      wattroff(win, COLOR_PAIR(5));
  }

  /* Privilege & Status */
#if defined(HAVE_GETEUID) && !defined(__CYGWIN__) && !defined(__MINGW32__) && !defined(DJGPP)
  if(geteuid() != 0)
  {
    mvwprintw(win, cur_y, left_x + 2, "Privileges:   ");
    if(has_colors())
      wattron(win, COLOR_PAIR(1) | A_BOLD);
    wprintw(win, "NON-ROOT (Run sudo for full access)");
    if(has_colors())
      wattroff(win, COLOR_PAIR(1) | A_BOLD);
    cur_y++;
  }
  else
#endif
  {
    mvwprintw(win, cur_y, left_x + 2, "Privileges:   ");
    if(has_colors())
      wattron(win, COLOR_PAIR(2));
    wprintw(win, "Root Access (Raw device verified)");
    if(has_colors())
      wattroff(win, COLOR_PAIR(2));
    cur_y++;
  }

  /* Partition Architecture */
  if(disk->arch != NULL && disk->arch->part_name != NULL)
  {
    mvwprintw(win, cur_y++, left_x + 2, "Partition Map:%s", disk->arch->part_name);
  }

  /* S.M.A.R.T. Health Diagnostics */
  if(disk->smart_status != NULL && cur_y < top_y + box_h - 2)
  {
    mvwprintw(win, cur_y, left_x + 2, "SMART Health: ");
    if(disk->smart_healthy > 0)
    {
      if(has_colors()) wattron(win, COLOR_PAIR(2) | A_BOLD);
      wprintw(win, "%s", disk->smart_status);
      if(has_colors()) wattroff(win, COLOR_PAIR(2) | A_BOLD);
    }
    else if(disk->smart_healthy < 0)
    {
      if(has_colors()) wattron(win, COLOR_PAIR(1) | A_BOLD);
      wprintw(win, "%s", disk->smart_status);
      if(has_colors()) wattroff(win, COLOR_PAIR(1) | A_BOLD);
    }
    else
    {
      if(has_colors()) wattron(win, COLOR_PAIR(7));
      wprintw(win, "%s", disk->smart_status);
      if(has_colors()) wattroff(win, COLOR_PAIR(7));
    }
    cur_y++;
  }

  /* Recommended Action */
  if(cur_y < top_y + box_h - 2)
  {
    cur_y = top_y + box_h - 2;
    mvwprintw(win, cur_y, left_x + 2, "Action:       ");
    if(has_colors())
      wattron(win, COLOR_PAIR(3) | A_BOLD);
    wprintw(win, "Press [Enter] to carve and recover files");
    if(has_colors())
      wattroff(win, COLOR_PAIR(3) | A_BOLD);
  }
}

static int photorec_disk_selection_ncurses(struct ph_param *params, struct ph_options *options, const list_disk_t *list_disk, alloc_data_t *list_search_space)
{
  int pos_num = 0;
  int offset = 0;
  char filter_str[64] = "";
  int filter_mode = 0;
  const list_disk_t *element_disk;
  const list_disk_t *current_disk = list_disk;
  const list_disk_t *matched_disks[256];
  int match_count = 0;

  if(list_disk == NULL)
  {
    log_critical("No disk found\n");
    return intrf_no_disk_ncurses("PhotoRec-NG");
  }

  while(1)
  {
    int top_y, bottom_y, box_h, is_split;
    int left_x, left_w, right_x, right_w, left_h;
    int max_items, i, ch;

    /* Build matching disks */
    match_count = 0;
    for(element_disk = list_disk; element_disk != NULL && match_count < 256; element_disk = element_disk->next)
    {
      if(disk_matches_filter(element_disk->disk, filter_str))
      {
        matched_disks[match_count++] = element_disk;
      }
    }

    if(match_count > 0)
    {
      if(pos_num < 0) pos_num = 0;
      if(pos_num >= match_count) pos_num = match_count - 1;
      current_disk = matched_disks[pos_num];
    }
    else
    {
      pos_num = 0;
      current_disk = NULL;
    }

    /* Layout calculations */
    top_y = 5;
    bottom_y = LINES - 2;
    box_h = bottom_y - top_y + 1;
    if(box_h < 6) box_h = 6;
    is_split = (COLS >= 90 && box_h >= 10);

    if(is_split)
    {
      left_x = 0;
      left_w = COLS * 52 / 100;
      right_x = left_w;
      right_w = COLS - left_w;
      left_h = box_h;
    }
    else
    {
      left_x = 0;
      left_w = COLS;
      right_x = 0;
      right_w = COLS;
      left_h = (box_h > 14) ? (box_h / 2) : box_h;
    }

    /* Header */
    tui_draw_header(stdscr, "PhotoRec-NG", "Media Selection");

    /* Draw Left Pane (Media List) */
    tui_draw_box(stdscr, top_y, left_x, left_h, left_w, "Detected Storage Media", 3);

    /* Filter prompt line if filter active */
    if(filter_mode || filter_str[0] != '\0')
    {
      mvwprintw(stdscr, top_y + 1, left_x + 2, "Search: [");
      if(has_colors())
        wattron(stdscr, COLOR_PAIR(3) | A_BOLD);
      wprintw(stdscr, "%s", filter_str);
      if(filter_mode)
        waddch(stdscr, '_');
      if(has_colors())
        wattroff(stdscr, COLOR_PAIR(3) | A_BOLD);
      wprintw(stdscr, "] (Esc to clear)");
      max_items = left_h - 4;
    }
    else
    {
      mvwprintw(stdscr, top_y + 1, left_x + 2, "Select a drive (Enter: Proceed, /: Search):");
      max_items = left_h - 3;
    }

    if(max_items < 1) max_items = 1;

    /* Adjust scrolling offset */
    if(pos_num < offset)
      offset = pos_num;
    if(pos_num >= offset + max_items)
      offset = pos_num - max_items + 1;

    if(match_count == 0)
    {
      mvwprintw(stdscr, top_y + 3, left_x + 4, "No media matches '%s'", filter_str);
      mvwprintw(stdscr, top_y + 4, left_x + 4, "Press Esc to clear search filter.");
    }
    else
    {
      for(i = 0; i < max_items && (offset + i) < match_count; i++)
      {
        const int item_idx = offset + i;
        const disk_t *d = matched_disks[item_idx]->disk;
        const int is_sel = (item_idx == pos_num);
        const int row_y = top_y + (filter_mode || filter_str[0] != '\0' ? 2 : 2) + i;
        char badge[16];
        char sz_str[32];
        int badge_color = 3;
        int max_desc_len;

        tui_get_disk_badge(d, badge, sizeof(badge), &badge_color);
        tui_format_size(d->disk_size, sz_str, sizeof(sz_str));

        max_desc_len = left_w - 36;
        if(max_desc_len < 10) max_desc_len = 10;

        wmove(stdscr, row_y, left_x + 2);
        wclrtoeol(stdscr);

        if(is_sel)
        {
          wattron(stdscr, A_REVERSE | A_BOLD);
          mvwprintw(stdscr, row_y, left_x + 2, " > %-6s %-12s %8s  %.*s",
                    badge, (d->device ? d->device : ""), sz_str,
                    max_desc_len, (d->model ? d->model : ""));
          wattroff(stdscr, A_REVERSE | A_BOLD);
        }
        else
        {
          mvwprintw(stdscr, row_y, left_x + 2, "   ");
          if(badge_color == 3 && has_colors())
            wattron(stdscr, COLOR_PAIR(3));
          wprintw(stdscr, "%-6s ", badge);
          if(badge_color == 3 && has_colors())
            wattroff(stdscr, COLOR_PAIR(3));
          wprintw(stdscr, "%-12s %8s  %.*s",
                  (d->device ? d->device : ""), sz_str,
                  max_desc_len, (d->model ? d->model : ""));
        }
      }
    }

    /* Draw Right Pane (Live Inspector) */
    if(is_split)
    {
      draw_media_inspector(stdscr, top_y, right_x, box_h, right_w, current_disk ? current_disk->disk : NULL);
    }
    else if(box_h > 14)
    {
      draw_media_inspector(stdscr, top_y + left_h, 0, box_h - left_h, COLS, current_disk ? current_disk->disk : NULL);
    }

    /* Footer */
    if(filter_mode)
      tui_draw_footer(stdscr, "Type to filter   [Enter] Accept search   [Esc] Clear filter");
    else
      tui_draw_footer(stdscr, "[Enter] Proceed   [↑/↓ j/k] Select   [/] Search   [s] Sudo   [q] Quit");

    wrefresh(stdscr);

    ch = wgetch(stdscr);

    if(filter_mode)
    {
      if(ch == 27) /* Esc */
      {
        filter_mode = 0;
        filter_str[0] = '\0';
        pos_num = 0;
        offset = 0;
      }
      else if(ch == '\n' || ch == '\r' || ch == KEY_ENTER)
      {
        filter_mode = 0;
      }
      else if(ch == KEY_BACKSPACE || ch == 127 || ch == '\b')
      {
        size_t flen = strlen(filter_str);
        if(flen > 0)
        {
          filter_str[flen - 1] = '\0';
          pos_num = 0;
          offset = 0;
        }
      }
      else if(ch >= 32 && ch <= 126)
      {
        size_t flen = strlen(filter_str);
        if(flen < sizeof(filter_str) - 2)
        {
          filter_str[flen] = (char)ch;
          filter_str[flen + 1] = '\0';
          pos_num = 0;
          offset = 0;
        }
      }
      continue;
    }

    /* Normal Navigation Mode */
    switch(ch)
    {
      case '/':
        filter_mode = 1;
        break;
      case 'p':
      case 'P':
      case 'k':
      case 'K':
      case KEY_UP:
        if(pos_num > 0)
          pos_num--;
        break;
      case 'n':
      case 'N':
      case 'j':
      case 'J':
      case KEY_DOWN:
        if(pos_num + 1 < match_count)
          pos_num++;
        break;
      case 'g':
      case KEY_HOME:
        pos_num = 0;
        break;
      case 'G':
      case KEY_END:
        pos_num = (match_count > 0 ? match_count - 1 : 0);
        break;
      case KEY_PPAGE:
        pos_num -= (max_items - 1);
        if(pos_num < 0) pos_num = 0;
        break;
      case KEY_NPAGE:
        pos_num += (max_items - 1);
        if(pos_num >= match_count) pos_num = (match_count > 0 ? match_count - 1 : 0);
        break;
      case 27: /* Esc clears filter if set */
        if(filter_str[0] != '\0')
        {
          filter_str[0] = '\0';
          pos_num = 0;
          offset = 0;
        }
        break;
#ifdef KEY_MOUSE
      case KEY_MOUSE:
      {
        MEVENT event;
        if(getmouse(&event) == OK)
        {
#if NCURSES_MOUSE_VERSION > 1
          if(event.bstate & BUTTON4_PRESSED)
          {
            if(pos_num > 0) pos_num--;
          }
          else if(event.bstate & BUTTON5_PRESSED)
          {
            if(pos_num + 1 < match_count) pos_num++;
          }
          else
#endif
          if(event.bstate & (BUTTON1_CLICKED | BUTTON1_PRESSED | BUTTON1_DOUBLE_CLICKED))
          {
            const int click_row = event.y - (top_y + (filter_str[0] != '\0' ? 2 : 2));
            if(click_row >= 0 && click_row < max_items && (offset + click_row) < match_count)
            {
              pos_num = offset + click_row;
              if(event.bstate & BUTTON1_DOUBLE_CLICKED)
                goto do_proceed;
            }
          }
        }
        break;
      }
#endif
      case '\n':
      case '\r':
      case KEY_ENTER:
      case 'o':
      case 'O':
#ifdef KEY_MOUSE
do_proceed:
#endif
        if(current_disk != NULL)
        {
          disk_t *disk = current_disk->disk;
          const int hpa_dco = is_hpa_or_dco(disk);
          autodetect_arch(disk, &arch_none);
          autoset_unit(disk);
          params->disk = disk;
          if((hpa_dco == 0 || interface_check_hidden_ncurses(disk, hpa_dco) == 0) &&
              (options->expert == 0 ||
               change_arch_type_ncurses(disk, options->verbose) == 0))
            menu_photorec(params, options, list_search_space);
        }
        break;
      case 's':
      case 'S':
        return 1;
      case 'q':
      case 'Q':
        return 0;
      case KEY_RESIZE:
        break;
    }
  }
}
#endif

int do_curses_photorec(struct ph_param *params, struct ph_options *options, const list_disk_t *list_disk)
{
  static alloc_data_t list_search_space={
    .list = TD_LIST_HEAD_INIT(list_search_space.list)
  };
  const int resume_session=(params->cmd_device!=NULL && strcmp(params->cmd_device,"resume")==0);
#ifndef DISABLED_FOR_FRAMAC
  if(params->cmd_device==NULL || resume_session!=0)
  {
    char *saved_device=NULL;
    char *saved_cmd=NULL;
    session_load(&saved_device, &saved_cmd,&list_search_space);
    if(saved_device!=NULL && saved_cmd!=NULL && !td_list_empty(&list_search_space.list)
#if defined(HAVE_NCURSES)
	&& ( resume_session!=0 || ask_confirmation("Continue previous session ? (Y/N)")!=0)
#endif
      )
    {
#if defined(HAVE_NCURSES)
      {
	WINDOW *window=newwin(LINES, COLS, 0, 0);	/* full screen */
	aff_copy(window);
	mvwaddstr(window,5,0,"Resuming the recovery. Please wait...");
	wrefresh(window);
	delwin(window);
	(void) clearok(stdscr, TRUE);
#ifdef HAVE_TOUCHWIN
	touchwin(stdscr);
#endif
      }
#endif
      params->cmd_run=saved_cmd;
      params->cmd_device=saved_device;
    }
    else
    {
      free(saved_device);
      free(saved_cmd);
      free_list_search_space(&list_search_space);
      rename("photorec.ses", "photorec.se2");
    }
  }
#endif
  if(params->cmd_device!=NULL && params->cmd_run!=NULL)
  {
    /*@ assert valid_read_string(params->cmd_run); */
    params->disk=photorec_disk_selection_cli(params->cmd_device, list_disk, &list_search_space);
    /*@ assert params->disk == \null || valid_disk(params->disk); */
#if defined(HAVE_NCURSES)
    if(params->disk==NULL)
    {
      log_critical("No disk found\n");
      return intrf_no_disk_ncurses("PhotoRec-NG");
    }
    /*@ assert valid_disk(params->disk); */
    if(change_arch_type_cli(params->disk, options->verbose, &params->cmd_run)==0 ||
	change_arch_type_ncurses(params->disk, options->verbose)==0)
    {
      autoset_unit(params->disk);
      menu_photorec(params, options, &list_search_space);
    }
    return 0;
#else
    if(params->disk==NULL)
    {
      log_critical("No disk found\n");
      /*@ assert params->cmd_run == \null || valid_read_string(params->cmd_run); */
      return 0;
    }
    /*@ assert valid_disk(params->disk); */
    change_arch_type_cli(params->disk, options->verbose, &params->cmd_run);
    autoset_unit(params->disk);
    menu_photorec(params, options, &list_search_space);
    /*@ assert params->cmd_run == \null || valid_read_string(params->cmd_run); */
    return 0;
#endif
  }
  /*@ assert params->cmd_run == \null || valid_read_string(params->cmd_run); */
#if defined(HAVE_NCURSES)
  return photorec_disk_selection_ncurses(params, options, list_disk, &list_search_space);
#else
  return 0;
#endif
}
