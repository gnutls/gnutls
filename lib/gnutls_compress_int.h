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

typedef struct GNUTLS_COMP_HANDLE_STRUCT {
	void* handle;
	CompressionMethod algo;
} *GNUTLS_COMP_HANDLE;

GNUTLS_COMP_HANDLE _gnutls_comp_init( CompressionMethod, int d);
void _gnutls_comp_deinit(GNUTLS_COMP_HANDLE handle, int d);

int _gnutls_decompress( GNUTLS_COMP_HANDLE handle, char* compressed, int compressed_size, char** plain, int max_record_size);
int _gnutls_compress( GNUTLS_COMP_HANDLE, char* plain, int plain_size, char** compressed, int max_comp_size);

#endif
