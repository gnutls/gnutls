/* getdelim.c --- Implementation of replacement getdelim function.
 * Copyright (C) 1994, 1996-1998, 2001, 2003, 2005-2012 Free Software
 * Foundation, Inc.
 *
 * This file is part of GnuTLS.
 *
 * The gnutls library is free software; you can redistribute it
 * and/or modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>
 */

/* Ported from glibc by Simon Josefsson. */

#include <gnutls_int.h>
#include <gnutls_errors.h>
#include <gnutls/xssl.h>
#include <xssl.h>

#ifndef SSIZE_MAX
# define SSIZE_MAX ((ssize_t) (SIZE_MAX / 2))
#endif

/**
 * xssl_get_delim:
 * @sb: is a #xssl_t structure.
 * @lineptr: a pointer.
 * @n: The size of @lineptr.
 * @delimiter: The delimiter to stop reading at.
 *
 * Read up to (and including) a @delimiter from &sb into *LINEPTR (and
 * NUL-terminate it).  @lineptr is a pointer returned from gnutls_malloc() 
 * (or %NULL), pointing to @n characters of space.  It is realloc'ed as
 * necessary.  
 *
 * Only fatal errors are returned by this function.
 *
 * Returns the number of characters read (not including
 * the null terminator), or a negative error code on error. 
 *
 * Since: 3.1.7
 **/
ssize_t
xssl_getdelim (xssl_t sbuf, char **lineptr, size_t *n, int delimiter)
{
  ssize_t result;
  size_t cur_len = 0;

  if (lineptr == NULL || n == NULL || sbuf == NULL)
    {
      return gnutls_assert_val(GNUTLS_E_INVALID_REQUEST);
    }

  if (*lineptr == NULL || *n == 0)
    {
      char *new_lineptr;
      *n = 120;
      new_lineptr = (char *) gnutls_realloc_fast (*lineptr, *n);
      if (new_lineptr == NULL)
        {
          result = gnutls_assert_val(GNUTLS_E_MEMORY_ERROR);
          goto fail;
        }
      *lineptr = new_lineptr;
    }

  for (;;)
    {
      char c;
      
      result = xssl_read(sbuf, &c, 1);
      if (result < 0)
        {
          gnutls_assert();
          break;
        }

      /* Make enough space for len+1 (for final NUL) bytes.  */
      if (cur_len + 1 >= *n)
        {
          size_t needed_max =
            SSIZE_MAX < SIZE_MAX ? (size_t) SSIZE_MAX + 1 : SIZE_MAX;
          size_t needed = 2 * *n + 1;   /* Be generous. */
          char *new_lineptr;

          if (needed_max < needed)
            needed = needed_max;
          if (cur_len + 1 >= needed)
            {
              result = gnutls_assert_val(GNUTLS_E_LARGE_PACKET);
              goto fail;
            }

          new_lineptr = (char *) gnutls_realloc_fast (*lineptr, needed);
          if (new_lineptr == NULL)
            {
              result = gnutls_assert_val(GNUTLS_E_MEMORY_ERROR);
              goto fail;
            }

          *lineptr = new_lineptr;
          *n = needed;
        }

      (*lineptr)[cur_len] = c;
      cur_len++;

      if (c == delimiter)
        break;
    }
  (*lineptr)[cur_len] = '\0';

  if (cur_len != 0)
    result = cur_len;

fail:

  return result;
}
