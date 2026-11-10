/*

    File: nodisk.c

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

#if defined(__CYGWIN__) || defined(__MINGW32__) || defined(DJGPP) || !defined(HAVE_GETEUID)
#undef SUDO_BIN
#endif

#ifndef SUDO_BIN
#if defined(HAVE_GETEUID) && !defined(__CYGWIN__) && !defined(__MINGW32__) && !defined(DJGPP)
#define SUDO_BIN "/usr/bin/sudo"
#endif
#endif
 
#ifdef HAVE_NCURSES
#include <stdio.h>
#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif
#include "types.h"
#include "common.h"
#include "intrf.h"
#include "intrfn.h"
#include "nodisk.h"

int intrf_no_disk_ncurses(const char *prog_name)
{
  aff_copy(stdscr);
  wmove(stdscr,4,0);
  wprintw(stdscr,"  %s is free software, and",prog_name);
  wmove(stdscr,5,0);
  wprintw(stdscr,"comes with ABSOLUTELY NO WARRANTY.");
  wmove(stdscr,7,0);
  wprintw(stdscr,"No hard disk found\n");
#if defined(__CYGWIN__) || defined(__MINGW32__)
  wmove(stdscr,8,0);
  wprintw(stdscr,"You need to be administrator to use %s.\n", prog_name);
  wmove(stdscr,9,0);
  wprintw(stdscr,"Under Win9x, use the DOS version instead.\n");
  wmove(stdscr,10,0);
  wprintw(stdscr,"Under Vista or later, select %s, right-click and\n", prog_name);
  wmove(stdscr,11,0);
  wprintw(stdscr,"choose \"Run as administrator\".\n");
#elif defined(DJGPP)
#elif defined(HAVE_GETEUID)
  if(geteuid()!=0)
  {
    wmove(stdscr,8,0);
    wprintw(stdscr,"You need to be root to use %s.\n", prog_name);
#ifdef SUDO_BIN
    {
      static const struct MenuItem menuSudo[]=
      {
	{'S',"Sudo","Use the sudo command to restart as root"},
	{'Q',"Quit",""},
	{0,NULL,NULL}
      };
      unsigned int menu=0;
      int command;
      command = wmenuSelect_ext(stdscr,23, 20, 0, menuSudo, 8,
	  "SQ", MENU_VERT | MENU_VERT_WARN | MENU_BUTTON, &menu,NULL);
      if(command=='s' || command=='S')
	return 1;
      return 0;
    }
#endif
  }
#if defined(__APPLE__) || defined(__MACH__)
  else
  {
    prompt_full_disk_access_ncurses(prog_name);
    return 0;
  }
#endif
#endif
  wmove(stdscr,22,0);
  wattrset(stdscr, A_REVERSE);
  waddstr(stdscr,"[ Quit ]");
  wattroff(stdscr, A_REVERSE);
  wrefresh(stdscr);
  while(wgetch(stdscr)==ERR);
  return 0;
}

int prompt_root_ncurses(const char *prog_name)
{
  const char *pname = (prog_name != NULL) ? prog_name : "TestDisk";
  char msg_sudo[128];
  char msg_quit[64];
  snprintf(msg_sudo, sizeof(msg_sudo), "Use sudo to restart %s with root privileges", pname);
  snprintf(msg_quit, sizeof(msg_quit), "Quit %s", pname);
  const struct MenuItem menuRoot[]=
  {
    {'S', "Sudo", msg_sudo},
    {'P', "Proceed", "Continue without root (some or all disks may be missing)"},
    {'Q', "Quit", msg_quit},
    {0, NULL, NULL}
  };
  unsigned int menu=0;
  aff_copy(stdscr);
  wmove(stdscr,4,0);
  wprintw(stdscr,"  %s is free software, and", pname);
  wmove(stdscr,5,0);
  wprintw(stdscr,"comes with ABSOLUTELY NO WARRANTY.");
  wmove(stdscr,7,0);
  if(has_colors())
    wbkgdset(stdscr,' ' | A_BOLD | COLOR_PAIR(1));
  wprintw(stdscr,"Warning: %s is not running as root (superuser).", pname);
  if(has_colors())
    wbkgdset(stdscr,' ' | COLOR_PAIR(0));
  wmove(stdscr,9,0);
  wprintw(stdscr,"%s needs root privileges to detect and access raw disk devices.", pname);
  wmove(stdscr,10,0);
  wprintw(stdscr,"Without root permissions, disks will not appear or may be read-only.");
  wmove(stdscr,12,0);
  wprintw(stdscr,"You can restart using sudo to gain root access, proceed anyway, or quit.");
  wmove(stdscr,15,0);
  wprintw(stdscr,"Use arrow keys / j/k to select, then press Enter key:");
  while(1)
  {
    const int command = wmenuSelect_ext(stdscr, 23, 17, 0, menuRoot, 8,
	"SPQ", MENU_VERT | MENU_VERT_WARN | MENU_BUTTON, &menu, NULL);
    switch(command)
    {
      case 'S':
      case 's':
        return 1;
      case 'P':
      case 'p':
        return 0;
      case 'Q':
      case 'q':
        return 2;
      default:
        break;
    }
  }
}

void prompt_full_disk_access_ncurses(const char *prog_name)
{
  const char *pname = (prog_name != NULL) ? prog_name : "TestDisk";
  aff_copy(stdscr);
  wmove(stdscr, 4, 0);
  if(has_colors())
    wbkgdset(stdscr, ' ' | A_BOLD | COLOR_PAIR(1));
  wprintw(stdscr, "  macOS Full Disk Access (TCC) Required");
  if(has_colors())
    wbkgdset(stdscr, ' ' | COLOR_PAIR(0));
  wmove(stdscr, 6, 0);
  wprintw(stdscr, "Root privileges are active, but macOS Transparency, Consent, and Control\n");
  wprintw(stdscr, "(TCC) is currently blocking direct access to physical raw disk devices.\n\n");
  wprintw(stdscr, "To enable %s to access your drives:\n", pname);
  wprintw(stdscr, "  1. Open macOS System Settings -> Privacy & Security.\n");
  wprintw(stdscr, "  2. Scroll down and click on 'Full Disk Access'.\n");
  wprintw(stdscr, "  3. Click the '+' button or toggle switch to enable your Terminal app\n");
  wprintw(stdscr, "     (Terminal, iTerm2, etc.).\n");
  wprintw(stdscr, "  4. Quit and relaunch %s.\n", pname);
  wmove(stdscr, 17, 0);
  wattrset(stdscr, A_REVERSE);
  waddstr(stdscr, "[ Press any key to continue ]");
  wattroff(stdscr, A_REVERSE);
  wrefresh(stdscr);
  while(wgetch(stdscr) == ERR);
}
#else
int prompt_root_ncurses(const char *prog_name)
{
  return 0;
}
void prompt_full_disk_access_ncurses(const char *prog_name)
{
}
#endif
