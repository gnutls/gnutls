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
} gnutls_buffer_st;

void _gnutls_buffer_init (gnutls_buffer_st *);
void _gnutls_buffer_clear (gnutls_buffer_st *);
int _gnutls_buffer_resize (gnutls_buffer_st *, size_t new_size);

int _gnutls_buffer_append_str (gnutls_buffer_st *, const char *str);
int _gnutls_buffer_append_data (gnutls_buffer_st *, const void *data,
				size_t data_size);

void _gnutls_buffer_get_data (gnutls_buffer_st *, void *, size_t * size);
void _gnutls_buffer_get_datum (gnutls_buffer_st *, gnutls_datum_t *,
			       size_t max_size);

int _gnutls_buffer_escape(gnutls_buffer_st * dest, const char *const invalid_chars);
int _gnutls_buffer_unescape(gnutls_buffer_st * dest);

#ifndef __attribute__
/* This feature is available in gcc versions 2.5 and later.  */
# if __GNUC__ < 2 || (__GNUC__ == 2 && __GNUC_MINOR__ < 5)
#  define __attribute__(Spec)	/* empty */
# endif
#endif

int _gnutls_buffer_append_printf (gnutls_buffer_st * dest, const char *fmt, ...)
  __attribute__ ((format (printf, 2, 3)));

char *_gnutls_bin2hex (const void *old, size_t oldlen, char *buffer,
		       size_t buffer_size, const char* separator);
int _gnutls_hex2bin (const opaque * hex_data, int hex_size, opaque * bin_data,
		     size_t * bin_size);

int _gnutls_hostname_compare (const char *certname, size_t certnamesize,
			      const char *hostname);
#define MAX_CN 256

#endif
