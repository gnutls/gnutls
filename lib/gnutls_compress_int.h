/*
 *      Copyright (C) 2000,2002 Nikos Mavroyanopoulos
 *
 * This file is part of GNUTLS.
 *
 * GNUTLS is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * GNUTLS is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA
 */

#ifndef GNUTLS_COMP_INT
# define GNUTLS_COMP_INT

#ifdef HAVE_LIBZ
# include <zlib.h>
#endif

#define GNUTLS_COMP_FAILED NULL

typedef struct comp_hd_t_STRUCT {
    void *handle;
    gnutls_compression_method algo;
} *comp_hd_t;

comp_hd_t _gnutls_comp_init(gnutls_compression_method, int d);
void _gnutls_comp_deinit(comp_hd_t handle, int d);

int _gnutls_decompress(comp_hd_t handle, opaque * compressed,
		       size_t compressed_size, opaque ** plain,
		       size_t max_record_size);
int _gnutls_compress(comp_hd_t, const opaque * plain, size_t plain_size,
		     opaque ** compressed, size_t max_comp_size);

#endif
