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

#include <gnutls_int.h>
#include <gnutls_compress.h>
#include "gnutls_errors.h"

/* The flag d is the direction (compressed, decompress). Non zero is
 * decompress.
 */
GNUTLS_COMP_HANDLE gnutls_comp_init( CompressionMethod method, int d)
{
#ifdef HAVE_LIBZ
GNUTLS_COMP_HANDLE ret;
int err;

	if (method==GNUTLS_COMP_ZLIB) {
		ret = gnutls_malloc( sizeof(z_stream));
		
		if (ret==NULL) {
			gnutls_assert();
			return NULL;
		}
		
		ret->zalloc = (alloc_func)0;
		ret->zfree = (free_func)0;
		ret->opaque = (voidpf)0;

		if (d)
			err = inflateInit(ret);
		else
			err = deflateInit(ret, Z_DEFAULT_COMPRESSION);
		if (err!=Z_OK) {
			gnutls_assert();
			gnutls_free( ret);
			return NULL;
		}
		
		return ret;
	}
#endif
 return NULL;
}

void gnutls_comp_deinit(GNUTLS_COMP_HANDLE handle, int d) {
#ifdef HAVE_LIBZ
int err;

	if (handle!=NULL) {
		if (d)
			err = inflateEnd( handle);
		else
			err = deflateEnd( handle);
		gnutls_free( handle);
		if (err!=Z_OK) {
			gnutls_assert();
			return;
		}
	}
#endif
	return;
}

/* These functions are memory consuming 
 */

int gnutls_compress( GNUTLS_COMP_HANDLE handle, char* plain, int plain_size, char** compressed, int max_comp_size) {
int compressed_size=GNUTLS_E_COMPRESSION_FAILED;
#ifdef HAVE_LIBZ
uLongf size;
#endif
int err;

	if (handle==NULL) {
		*compressed = gnutls_malloc(plain_size);
		if (*compressed==NULL) {
			gnutls_assert();
			return GNUTLS_E_MEMORY_ERROR;
		}
		memcpy(*compressed, plain, plain_size);
		compressed_size = plain_size;
	} 
#ifdef HAVE_LIBZ
	else {
		size = (plain_size*2)+10;
		*compressed=NULL;

		*compressed = gnutls_malloc(size);
		if (*compressed==NULL) {
			gnutls_assert();
			return GNUTLS_E_MEMORY_ERROR;
		}

		handle->next_in = (Bytef*) plain;
		handle->avail_in = plain_size;
		handle->next_out = (Bytef*) *compressed;
		handle->avail_out = size;
		
	 	err = deflate( handle, Z_SYNC_FLUSH);

	 	if (err!=Z_OK || handle->avail_in != 0) {
	 		gnutls_assert();
	 		gnutls_free( *compressed);
	 		return GNUTLS_E_COMPRESSION_FAILED;
	 	}

		compressed_size = size - handle->avail_out;
		
	}
#endif

	if (compressed_size > max_comp_size) {
		gnutls_free(*compressed);
		return GNUTLS_E_COMPRESSION_FAILED;
	}

	return compressed_size;
}

int gnutls_decompress( GNUTLS_COMP_HANDLE handle, char* compressed, int compressed_size, char** plain, int max_record_size) {
int plain_size=GNUTLS_E_DECOMPRESSION_FAILED, err;
#ifdef HAVE_LIBZ
uLongf size;
#endif

	if (compressed_size > max_record_size+1024) {
		gnutls_assert();
		return GNUTLS_E_DECOMPRESSION_FAILED;
	}
	
	if (handle==NULL) {
		*plain = gnutls_malloc(compressed_size);
		if (*plain==NULL) {
			gnutls_assert();
			return GNUTLS_E_MEMORY_ERROR;
		}
		
		memcpy(*plain, compressed, compressed_size);
		plain_size = compressed_size;
	}
#ifdef HAVE_LIBZ
	else {
		*plain = NULL;
		size = compressed_size;
		plain_size = 0;

		handle->next_in = (Bytef*) compressed;
		handle->avail_in = compressed_size;
		
		do {
			size*=2;
			*plain = gnutls_realloc( *plain, size);
			if (*plain==NULL) {
				gnutls_assert();
				return GNUTLS_E_MEMORY_ERROR;
			}

			handle->next_out = (Bytef*) *plain;
			handle->avail_out = size;

		 	err = inflate( handle, Z_SYNC_FLUSH);

		} while( err==Z_BUF_ERROR && handle->avail_out==0 && size < max_record_size);

#if 0
		*plain = gnutls_malloc(2048);
		size =2048;
			handle->next_out = (Bytef*) *plain;
			handle->avail_out = size;

		 	err = inflate( handle, Z_SYNC_FLUSH);

#endif

	 	if (err!=Z_OK || handle->avail_in != 0) {
	 		gnutls_assert();
	 		gnutls_free( *plain);
	 		return GNUTLS_E_DECOMPRESSION_FAILED;
	 	}

		plain_size = size - handle->avail_out;

	}
#endif

	if (plain_size > max_record_size) {
		gnutls_assert();
		gnutls_free( *plain);
		return GNUTLS_E_DECOMPRESSION_FAILED;
	}

	return plain_size;
}
