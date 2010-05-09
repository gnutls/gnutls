/*
 * Copyright (C) 2000, 2001, 2002, 2003, 2004, 2005, 2007, 2008, 2009,
 * 2010 Free Software Foundation, Inc.
 *
 * Author: Nikos Mavrogiannopoulos
 *
 * This file is part of GnuTLS.
 *
 * The GnuTLS is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public License
 * as published by the Free Software Foundation; either version 2.1 of
 * the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301,
 * USA
 *
 */

#ifndef GNUTLS_STR_H
# define GNUTLS_STR_H

#include <gnutls_int.h>

void _gnutls_str_cpy (char *dest, size_t dest_tot_size, const char *src);
void _gnutls_mem_cpy (char *dest, size_t dest_tot_size, const char *src,
		      size_t src_size);
void _gnutls_str_cat (char *dest, size_t dest_tot_size, const char *src);

typedef struct
{
  opaque *allocd;		/* pointer to allocated data */
  opaque *data;			/* API: pointer to data to copy from */
  size_t max_length;
  size_t length;		/* API: current length */
  gnutls_realloc_function realloc_func;
  gnutls_alloc_function alloc_func;
  gnutls_free_function free_func;
} gnutls_string;

void _gnutls_string_init (gnutls_string *, gnutls_alloc_function,
			  gnutls_realloc_function, gnutls_free_function);
void _gnutls_string_clear (gnutls_string *);
int _gnutls_string_resize (gnutls_string *, size_t new_size);

int _gnutls_string_append_str (gnutls_string *, const char *str);
int _gnutls_string_append_data (gnutls_string *, const void *data,
				size_t data_size);

void _gnutls_string_get_data (gnutls_string *, void *, size_t * size);
void _gnutls_string_get_datum (gnutls_string *, gnutls_datum_t *,
			       size_t max_size);

int _gnutls_string_escape(gnutls_string * dest, const char *const invalid_chars);
int _gnutls_string_unescape(gnutls_string * dest);

#ifndef __attribute__
/* This feature is available in gcc versions 2.5 and later.  */
# if __GNUC__ < 2 || (__GNUC__ == 2 && __GNUC_MINOR__ < 5)
#  define __attribute__(Spec)	/* empty */
# endif
#endif

int _gnutls_string_append_printf (gnutls_string * dest, const char *fmt, ...)
  __attribute__ ((format (printf, 2, 3)));

typedef gnutls_string gnutls_buffer;

#define _gnutls_buffer_init(buf) _gnutls_string_init(buf, gnutls_malloc, gnutls_realloc, gnutls_free);
#define _gnutls_buffer_clear _gnutls_string_clear
#define _gnutls_buffer_append _gnutls_string_append_data
#define _gnutls_buffer_get_datum _gnutls_string_get_datum
#define _gnutls_buffer_get_data _gnutls_string_get_data
#define _gnutls_buffer_resize _gnutls_string_resize

char *_gnutls_bin2hex (const void *old, size_t oldlen, char *buffer,
		       size_t buffer_size, const char* separator);
int _gnutls_hex2bin (const opaque * hex_data, int hex_size, opaque * bin_data,
		     size_t * bin_size);

int _gnutls_hostname_compare (const char *certname, size_t certnamesize,
			      const char *hostname);
#define MAX_CN 256

#endif
