/*
 * Copyright (C) 2017-2022 Red Hat, Inc.
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
 * You should have received a copy of the GNU Lesser General Public License
 * along with this program.  If not, see <https://www.gnu.org/licenses/>
 *
 */

#include "compress.h"

#ifdef HAVE_LIBZ
#include <zlib.h>
#endif

#ifdef HAVE_LIBBROTLI
#include <brotli/decode.h>
#include <brotli/encode.h>
#endif

#ifdef HAVE_LIBZSTD
#include <zstd.h>
#endif

typedef struct {
	gnutls_compression_method_t id;
	const char *name;
} comp_entry;

static const comp_entry comp_algs[] = {
	{ GNUTLS_COMP_NULL, "NULL" },
#ifdef HAVE_LIBZ
	{ GNUTLS_COMP_ZLIB, "ZLIB" },
#endif
#ifdef HAVE_LIBBROTLI
	{ GNUTLS_COMP_BROTLI, "BROTLI" },
#endif
#ifdef HAVE_LIBZSTD
	{ GNUTLS_COMP_ZSTD, "ZSTD" },
#endif
	{ GNUTLS_COMP_UNKNOWN, NULL }
};

static const gnutls_compression_method_t alg_list[] = {
	GNUTLS_COMP_NULL,
#ifdef HAVE_LIBZ
	GNUTLS_COMP_ZLIB,
#endif
#ifdef HAVE_LIBBROTLI
	GNUTLS_COMP_BROTLI,
#endif
#ifdef HAVE_LIBZSTD
	GNUTLS_COMP_ZSTD,
#endif
	0
};

/**
 * gnutls_compression_get_name:
 * @algorithm: is a Compression algorithm
 *
 * Convert a #gnutls_compression_method_t value to a string.
 *
 * Returns: a pointer to a string that contains the name of the
 *   specified compression algorithm, or %NULL.
 **/
const char *
gnutls_compression_get_name(gnutls_compression_method_t algorithm)
{
	const comp_entry *p;

	for (p = comp_algs; p->name; ++p)
		if (p->id == algorithm)
			return p->name;

	return NULL;
}

/**
 * gnutls_compression_get_id:
 * @name: is a compression method name
 *
 * The names are compared in a case insensitive way.
 *
 * Returns: an id of the specified in a string compression method, or
 *   %GNUTLS_COMP_UNKNOWN on error.
 **/
gnutls_compression_method_t
gnutls_compression_get_id(const char *name)
{
	const comp_entry *p;

	for (p = comp_algs; p->name; ++p)
		if (!strcasecmp(p->name, name))
			return p->id;

	return GNUTLS_COMP_UNKNOWN;
}

/**
 * gnutls_compression_list:
 *
 * Get a list of compression methods.
 *
 * Returns: a zero-terminated list of #gnutls_compression_method_t
 *   integers indicating the available compression methods.
 **/
const gnutls_compression_method_t *
gnutls_compression_list(void)
{
	return alg_list;
}


/*************************/
/* Compression functions */
/*************************/


size_t
_gnutls_compress_bound(gnutls_compression_method_t alg, size_t src_len)
{
	switch (alg) {
#ifdef HAVE_LIBZ
	case GNUTLS_COMP_ZLIB:
		return compressBound(src_len);
#endif
#ifdef HAVE_LIBBROTLI
	case GNUTLS_COMP_BROTLI:
		return BrotliEncoderMaxCompressedSize(src_len);
#endif
#ifdef HAVE_LIBZSTD
	case GNUTLS_COMP_ZSTD:
		return ZSTD_compressBound(src_len);
#endif
	default:
		return 0;
	}
	return 0;
}

int
_gnutls_compress(gnutls_compression_method_t alg, 
		 uint8_t * dst, size_t dst_len,
		 const uint8_t * src, size_t src_len)
{
	int ret = GNUTLS_E_COMPRESSION_FAILED;

	switch (alg) {
#ifdef HAVE_LIBZ
	case GNUTLS_COMP_ZLIB:
		{
			int err;
			uLongf comp_len = dst_len;

			err = compress(dst, &comp_len, src, src_len);
			if (err != Z_OK)
				return gnutls_assert_val(GNUTLS_E_COMPRESSION_FAILED);
			ret = comp_len;
		}
		break;
#endif
#ifdef HAVE_LIBBROTLI
	case GNUTLS_COMP_BROTLI:
		{
			BROTLI_BOOL err;
			size_t comp_len = dst_len; 

			err = BrotliEncoderCompress(BROTLI_DEFAULT_QUALITY,
						    BROTLI_DEFAULT_WINDOW,
						    BROTLI_DEFAULT_MODE,
						    src_len, src, &comp_len, dst);
			if (!err)
				return gnutls_assert_val(GNUTLS_E_COMPRESSION_FAILED);
			ret = comp_len;
		}
		break;
#endif
#ifdef HAVE_LIBZSTD
	case GNUTLS_COMP_ZSTD:
		{
			size_t comp_len;

			comp_len = ZSTD_compress(dst, dst_len, src, src_len, ZSTD_CLEVEL_DEFAULT);
			if (ZSTD_isError(comp_len))
				return gnutls_assert_val(GNUTLS_E_COMPRESSION_FAILED);
			ret = comp_len;
		}
		break;
#endif
	default:
		return gnutls_assert_val(GNUTLS_E_INTERNAL_ERROR);
	}

#ifdef COMPRESSION_DEBUG
	_gnutls_debug_log("Compression ratio: %f\n", (float)((float)ret / (float)src_len));
#endif

	return ret;
}

int
_gnutls_decompress(gnutls_compression_method_t alg,
		   uint8_t * dst, size_t dst_len,
		   const uint8_t * src, size_t src_len)
{
	int ret = GNUTLS_E_DECOMPRESSION_FAILED;

	switch (alg) {
#ifdef HAVE_LIBZ
	case GNUTLS_COMP_ZLIB:
		{
			int err;
			uLongf plain_len = dst_len;

			err = uncompress(dst, &plain_len, src, src_len);
			if (err != Z_OK)
				return gnutls_assert_val(GNUTLS_E_DECOMPRESSION_FAILED);
			ret = plain_len;
		}
		break;
#endif
#ifdef HAVE_LIBBROTLI
	case GNUTLS_COMP_BROTLI:
		{
			BrotliDecoderResult err;
			size_t plain_len = dst_len;

			err = BrotliDecoderDecompress(src_len, src, &plain_len, dst);
			if (err != BROTLI_DECODER_RESULT_SUCCESS)
				return gnutls_assert_val(GNUTLS_E_DECOMPRESSION_FAILED);
			ret = plain_len;
		}
		break;
#endif
#ifdef HAVE_LIBZSTD
	case GNUTLS_COMP_ZSTD:
		{
			size_t plain_len;

			plain_len = ZSTD_decompress(dst, dst_len, src, src_len);
			if (ZSTD_isError(plain_len))
				return gnutls_assert_val(GNUTLS_E_DECOMPRESSION_FAILED);
			ret = plain_len;
		}
		break;
#endif
	default:
		return gnutls_assert_val(GNUTLS_E_INTERNAL_ERROR);
	}

	return ret;
}
