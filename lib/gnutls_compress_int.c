/*
 *      Copyright (C) 2000 Nikos Mavroyanopoulos
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

#include <defines.h>
#include "gnutls_int.h"
#include "gnutls_compress.h"
#include "gnutls_errors.h"
#include "gnutls_compress_int.h"
#include <zlib.h>

int gnutls_compress( CompressionMethod algorithm, char* plain, int plain_size, char** compressed) {
int compressed_size;
uLongf size;
int err;

	switch (algorithm) {
	case GNUTLS_COMPRESSION_NULL:
		*compressed = gnutls_malloc(plain_size);
		memmove(*compressed, plain, plain_size);
		compressed_size = plain_size;
		break;
#ifdef HAVE_LIBZ
	case GNUTLS_ZLIB:
		size = (plain_size*1.2)+12;
		*compressed = gnutls_malloc(size);
		err = compress( *compressed, &size, plain, plain_size);
		if (err!=Z_OK) {
			gnutls_free(*compressed);
			return GNUTLS_E_COMPRESSION_FAILED;
		}
		compressed_size = size;
		break;
#endif
	default:
		*compressed=NULL;
		return GNUTLS_E_UNKNOWN_COMPRESSION_ALGORITHM;
	}
	return compressed_size;
}

int gnutls_decompress( CompressionMethod algorithm, char* compressed, int compressed_size, char** plain) {
int plain_size, err;
uLongf size;

	switch (algorithm) {
	case GNUTLS_COMPRESSION_NULL:
		*plain = gnutls_malloc(compressed_size);
		memmove(*plain, compressed, compressed_size);
		plain_size = compressed_size;
		break;
#ifdef HAVE_LIBZ
	case GNUTLS_ZLIB:
		*plain = NULL;
		size = compressed_size;
		do {
			size += compressed_size;
			*plain = gnutls_realloc(*plain, size);
			err = uncompress( *plain, &size, compressed, compressed_size);
		} while( err==Z_BUF_ERROR && size < 50000); /* quite strange limit */
		if (err!=Z_OK) {
			gnutls_free(*plain);
			return GNUTLS_E_DECOMPRESSION_FAILED;
		}
		plain_size = size;
		break;
#endif
	default:
		*plain=NULL;
		return GNUTLS_E_UNKNOWN_COMPRESSION_ALGORITHM;
	}
	return plain_size;
}
