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
GNUTLS_COMP_HANDLE ret;
int err;

	ret = gnutls_malloc( sizeof( struct GNUTLS_COMP_HANDLE_STRUCT));
	if (ret==NULL) {
		gnutls_assert();
		return NULL;
	}

	ret->algo = method;
	ret->handle = NULL;

#ifdef HAVE_LIBZ
	if (method==GNUTLS_COMP_ZLIB) {
		z_stream* zhandle;

		ret->handle = gnutls_malloc( sizeof( z_stream));
		if (ret->handle==NULL) {
			gnutls_assert();
			return NULL;
		}
		
		zhandle = ret->handle;
		
		zhandle->zalloc = (alloc_func)0;
		zhandle->zfree = (free_func)0;
		zhandle->opaque = (voidpf)0;

		if (d)
			err = inflateInit(zhandle);
		else
			err = deflateInit(zhandle, Z_DEFAULT_COMPRESSION);
		if (err!=Z_OK) {
			gnutls_assert();
			gnutls_free( ret);
			gnutls_free( ret->handle);
			return NULL;
		}
		
	}
#endif
	return ret;
}

void gnutls_comp_deinit(GNUTLS_COMP_HANDLE handle, int d) {
int err;

	if (handle!=NULL) {
		switch( handle->algo) {
#ifdef HAVE_LIBZ
			case GNUTLS_COMP_ZLIB:
				if (d)
					err = inflateEnd( handle->handle);
				else
					err = deflateEnd( handle->handle);
				break;
		}
#endif
		gnutls_free( handle->handle);
		gnutls_free( handle);

	}

	return;
}

/* These functions are memory consuming 
 */

int gnutls_compress( GNUTLS_COMP_HANDLE handle, char* plain, int plain_size, char** compressed, int max_comp_size) {
int compressed_size=GNUTLS_E_COMPRESSION_FAILED;
#ifdef HAVE_LIBZ
uLongf size;
z_stream *zhandle;
#endif
int err;

	/* NULL compression is not handled here
	 */
	
	switch( handle->algo) {
#ifdef HAVE_LIBZ
		case GNUTLS_COMP_ZLIB:
			size = (plain_size*2)+10;
			*compressed=NULL;

			*compressed = gnutls_malloc(size);
			if (*compressed==NULL) {
				gnutls_assert();
				return GNUTLS_E_MEMORY_ERROR;
			}
			
			zhandle = handle->handle;

			zhandle->next_in = (Bytef*) plain;
			zhandle->avail_in = plain_size;
			zhandle->next_out = (Bytef*) *compressed;
			zhandle->avail_out = size;
		
		 	err = deflate( zhandle, Z_SYNC_FLUSH);

		 	if (err!=Z_OK || zhandle->avail_in != 0) {
		 		gnutls_assert();
		 		gnutls_free( *compressed);
		 		return GNUTLS_E_COMPRESSION_FAILED;
		 	}

			compressed_size = size - zhandle->avail_out;
			break;
#endif
		default:
			gnutls_assert();
			return GNUTLS_E_INTERNAL_ERROR;
	} /* switch */

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
z_stream* zhandle;
#endif

	if (compressed_size > max_record_size+1024) {
		gnutls_assert();
		return GNUTLS_E_DECOMPRESSION_FAILED;
	}

	/* NULL compression is not handled here
	 */
	
	switch(handle->algo) {
#ifdef HAVE_LIBZ
		case GNUTLS_COMP_ZLIB:
			*plain = NULL;
			size = compressed_size;
			plain_size = 0;
			
			zhandle = handle->handle;

			zhandle->next_in = (Bytef*) compressed;
			zhandle->avail_in = compressed_size;
		
			do {
				size*=2;
				*plain = gnutls_realloc( *plain, size);
				if (*plain==NULL) {
					gnutls_assert();
					return GNUTLS_E_MEMORY_ERROR;
				}

				zhandle->next_out = (Bytef*) *plain;
				zhandle->avail_out = size;

			 	err = inflate( zhandle, Z_SYNC_FLUSH);

			} while( err==Z_BUF_ERROR && zhandle->avail_out==0 && size < max_record_size);
		
		 	if (err!=Z_OK || zhandle->avail_in != 0) {
		 		gnutls_assert();
		 		gnutls_free( *plain);
		 		return GNUTLS_E_DECOMPRESSION_FAILED;
		 	}

			plain_size = size - zhandle->avail_out;
			break;
#endif
		default:
			gnutls_assert();
			return GNUTLS_E_INTERNAL_ERROR;
	} /* switch */

	if (plain_size > max_record_size) {
		gnutls_assert();
		gnutls_free( *plain);
		return GNUTLS_E_DECOMPRESSION_FAILED;
	}

	return plain_size;
}
