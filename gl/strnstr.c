/*
 * Copyright (C) 2004 Free Software Foundation
 * Written by Simon Josefsson
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2, or (at your option)
 * any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA
 * 02111-1307, USA.  */

#if HAVE_CONFIG_H
# include <config.h>
#endif

/* Get MIN. */
#include <minmax.h>

/* Get strlen, strncmp. */
#include <string.h>

/* Locate first occurance of zero terminated string LITLE in the first
   MIN(LEN, strlen(BIG)) characters of the string BIG.  Returns
   pointer to match within BIG, or NULL if no match is found.  If
   LITTLE is the empty string, BIG is returned.  */
char *
strnstr (const char *big, const char *little, size_t len)
{
  size_t searchlen = MIN (len, strlen (big));
  size_t littlelen = strlen (little);
  char *p = (char*) big;
  size_t i;

  if (*little == '\0')
    return p;

  if (searchlen < littlelen)
    return NULL;

  for (i = 0; i <= searchlen - littlelen; i++)
    if (strncmp (&p[i], little, littlelen) == 0)
      return &p[i];

  return NULL;
}
