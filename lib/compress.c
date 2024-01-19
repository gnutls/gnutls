/*
 * Copyright (C) 2017-2022 Red Hat, Inc.
 *
 * Authors: Nikos Mavrogiannopoulos,
 *          Zoltan Fridrich
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

#include "config.h"

#include "compress.h"

#ifndef _WIN32
#include <dlfcn.h>
#endif

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

#ifdef HAVE_LIBZ
static void *_zlib_handle;

#if HAVE___TYPEOF__
static __typeof__(compressBound)(*_gnutls_zlib_compressBound);
static __typeof__(compress)(*_gnutls_zlib_compress);
static __typeof__(uncompress)(*_gnutls_zlib_uncompress);
#else
static uLong (*_gnutls_zlib_compressBound)(uLong sourceLen);
static int (*_gnutls_zlib_compress)(Bytef *dest, uLongf *destLen,
				    const Bytef *source, uLong sourceLen);
static int (*_gnutls_zlib_uncompress)(Bytef *dest, uLongf *destLen,
				      const Bytef *source, uLong sourceLen);
#endif /* HAVE___TYPEOF__ */

static void zlib_deinit(void)
{
#ifndef _WIN32
	if (_zlib_handle != NULL) {
		dlclose(_zlib_handle);
		_zlib_handle = NULL;
	}
#endif /* _WIN32 */
}

static int zlib_init(void)
{
#ifndef _WIN32
	if (_zlib_handle != NULL)
		return 0;
	if ((_zlib_handle = dlopen("libz.so.1", RTLD_NOW | RTLD_GLOBAL)) ==
	    NULL)
		goto error;
	if ((_gnutls_zlib_compressBound =
		     dlsym(_zlib_handle, "compressBound")) == NULL)
		goto error;
	if ((_gnutls_zlib_compress = dlsym(_zlib_handle, "compress")) == NULL)
		goto error;
	if ((_gnutls_zlib_uncompress = dlsym(_zlib_handle, "uncompress")) ==
	    NULL)
		goto error;
	return 0;
error:
	zlib_deinit();
	return gnutls_assert_val(GNUTLS_E_INTERNAL_ERROR);
#else
	return gnutls_assert_val(GNUTLS_E_UNIMPLEMENTED_FEATURE);
#endif /* _WIN32 */
}
#endif /* HAVE_LIBZ */

#ifdef HAVE_LIBBROTLI
static void *_brotlienc_handle;
static void *_brotlidec_handle;

#if HAVE___TYPEOF__
static __typeof__(BrotliEncoderMaxCompressedSize)(
	*_gnutls_BrotliEncoderMaxCompressedSize);
static __typeof__(BrotliEncoderCompress)(*_gnutls_BrotliEncoderCompress);
static __typeof__(BrotliDecoderDecompress)(*_gnutls_BrotliDecoderDecompress);
#else
static size_t (*_gnutls_BrotliEncoderMaxCompressedSize)(size_t input_size);
static BROTLI_BOOL (*_gnutls_BrotliEncoderCompress)(
	int quality, int lgwin, BrotliEncoderMode mode, size_t input_size,
	const uint8_t input_buffer[BROTLI_ARRAY_PARAM(input_size)],
	size_t *encoded_size,
	uint8_t encoded_buffer[BROTLI_ARRAY_PARAM(*encoded_size)]);
static BrotliDecoderResult (*_gnutls_BrotliDecoderDecompress)(
	size_t encoded_size,
	const uint8_t encoded_buffer[BROTLI_ARRAY_PARAM(encoded_size)],
	size_t *decoded_size,
	uint8_t decoded_buffer[BROTLI_ARRAY_PARAM(*decoded_size)]);
#endif /* HAVE___TYPEOF__ */

static void brotli_deinit(void)
{
#ifndef _WIN32
	if (_brotlienc_handle != NULL) {
		dlclose(_brotlienc_handle);
		_brotlienc_handle = NULL;
	}
	if (_brotlidec_handle != NULL) {
		dlclose(_brotlidec_handle);
		_brotlidec_handle = NULL;
	}
#endif /* _WIN32 */
}

static int brotli_init(void)
{
#ifndef _WIN32
	if (_brotlienc_handle != NULL || _brotlidec_handle != NULL)
		return 0;
	if ((_brotlienc_handle = dlopen("libbrotlienc.so.1",
					RTLD_NOW | RTLD_GLOBAL)) == NULL)
		goto error;
	if ((_brotlidec_handle = dlopen("libbrotlidec.so.1",
					RTLD_NOW | RTLD_GLOBAL)) == NULL)
		goto error;
	if ((_gnutls_BrotliEncoderMaxCompressedSize =
		     dlsym(_brotlienc_handle,
			   "BrotliEncoderMaxCompressedSize")) == NULL)
		goto error;
	if ((_gnutls_BrotliEncoderCompress =
		     dlsym(_brotlienc_handle, "BrotliEncoderCompress")) == NULL)
		goto error;
	if ((_gnutls_BrotliDecoderDecompress = dlsym(
		     _brotlidec_handle, "BrotliDecoderDecompress")) == NULL)
		goto error;
	return 0;
error:
	brotli_deinit();
	return gnutls_assert_val(GNUTLS_E_INTERNAL_ERROR);
#else
	return gnutls_assert_val(GNUTLS_E_UNIMPLEMENTED_FEATURE);
#endif /* _WIN32 */
}
#endif /* HAVE_LIBBROTLI */

#ifdef HAVE_LIBZSTD
static void *_zstd_handle;

#if HAVE___TYPEOF__
static __typeof__(ZSTD_isError)(*_gnutls_ZSTD_isError);
static __typeof__(ZSTD_compressBound)(*_gnutls_ZSTD_compressBound);
static __typeof__(ZSTD_compress)(*_gnutls_ZSTD_compress);
static __typeof__(ZSTD_decompress)(*_gnutls_ZSTD_decompress);
#else
static unsigned (*_gnutls_ZSTD_isError)(size_t code);
static size_t (*_gnutls_ZSTD_compressBound)(size_t srcSize);
static size_t (*_gnutls_ZSTD_compress)(void *dst, size_t dstCapacity,
				       const void *src, size_t srcSize,
				       int compressionLevel);
static size_t (*_gnutls_ZSTD_decompress)(void *dst, size_t dstCapacity,
					 const void *src,
					 size_t compressedSize);
#endif /* HAVE___TYPEOF__ */

static void zstd_deinit(void)
{
#ifndef _WIN32
	if (_zstd_handle != NULL) {
		dlclose(_zstd_handle);
		_zstd_handle = NULL;
	}
#endif /* _WIN32 */
}

static int zstd_init(void)
{
#ifndef _WIN32
	if (_zstd_handle != NULL)
		return 0;
	if ((_zstd_handle = dlopen("libzstd.so.1", RTLD_NOW | RTLD_GLOBAL)) ==
	    NULL)
		goto error;
	if ((_gnutls_ZSTD_isError = dlsym(_zstd_handle, "ZSTD_isError")) ==
	    NULL)
		goto error;
	if ((_gnutls_ZSTD_compressBound =
		     dlsym(_zstd_handle, "ZSTD_compressBound")) == NULL)
		goto error;
	if ((_gnutls_ZSTD_compress = dlsym(_zstd_handle, "ZSTD_compress")) ==
	    NULL)
		goto error;
	if ((_gnutls_ZSTD_decompress =
		     dlsym(_zstd_handle, "ZSTD_decompress")) == NULL)
		goto error;
	return 0;
error:
	zstd_deinit();
	return gnutls_assert_val(GNUTLS_E_INTERNAL_ERROR);
#else
	return gnutls_assert_val(GNUTLS_E_UNIMPLEMENTED_FEATURE);
#endif /* _WIN32 */
}
#endif /* HAVE_LIBZSTD */

typedef struct {
	gnutls_compression_method_t id;
	const char *name;
	int (*init)(void);
	void (*deinit)(void);
} comp_entry;

static comp_entry comp_algs[] = {
	{ GNUTLS_COMP_NULL, "NULL", NULL, NULL },
#ifdef HAVE_LIBZ
	{ GNUTLS_COMP_ZLIB, "ZLIB", zlib_init, zlib_deinit },
#endif
#ifdef HAVE_LIBBROTLI
	{ GNUTLS_COMP_BROTLI, "BROTLI", brotli_init, brotli_deinit },
#endif
#ifdef HAVE_LIBZSTD
	{ GNUTLS_COMP_ZSTD, "ZSTD", zstd_init, zstd_deinit },
#endif
	{ GNUTLS_COMP_UNKNOWN, NULL, NULL, NULL }
};

static const gnutls_compression_method_t alg_list[] = { GNUTLS_COMP_NULL,
#ifdef HAVE_LIBZ
							GNUTLS_COMP_ZLIB,
#endif
#ifdef HAVE_LIBBROTLI
							GNUTLS_COMP_BROTLI,
#endif
#ifdef HAVE_LIBZSTD
							GNUTLS_COMP_ZSTD,
#endif
							0 };

/* Initialize given compression method
 *
 * Calling any of the compression functions without first initializing
 * the respective compression method results in undefined behavior.
 */
int _gnutls_compression_init_method(gnutls_compression_method_t method)
{
	comp_entry *p;

	for (p = comp_algs; p->name; ++p)
		if (p->id == method)
			return p->init ? p->init() : GNUTLS_E_INVALID_REQUEST;

	return GNUTLS_E_INVALID_REQUEST;
}

/* Deinitialize all compression methods
 * 
 * If no compression methods were initialized,
 * this function does nothing.
 */
void _gnutls_compression_deinit(void)
{
	comp_entry *p;

	for (p = comp_algs; p->name; ++p)
		if (p->deinit)
			p->deinit();
}

/**
 * gnutls_compression_get_name:
 * @algorithm: is a Compression algorithm
 *
 * Convert a #gnutls_compression_method_t value to a string.
 *
 * Returns: a pointer to a string that contains the name of the
 *   specified compression algorithm, or %NULL.
 **/
const char *gnutls_compression_get_name(gnutls_compression_method_t algorithm)
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
gnutls_compression_method_t gnutls_compression_get_id(const char *name)
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
const gnutls_compression_method_t *gnutls_compression_list(void)
{
	return alg_list;
}

/*************************/
/* Compression functions */
/*************************/

size_t _gnutls_compress_bound(gnutls_compression_method_t alg, size_t src_len)
{
	switch (alg) {
#ifdef HAVE_LIBZ
	case GNUTLS_COMP_ZLIB:
		return _gnutls_zlib_compressBound(src_len);
#endif
#ifdef HAVE_LIBBROTLI
	case GNUTLS_COMP_BROTLI:
		return _gnutls_BrotliEncoderMaxCompressedSize(src_len);
#endif
#ifdef HAVE_LIBZSTD
	case GNUTLS_COMP_ZSTD:
		return _gnutls_ZSTD_compressBound(src_len);
#endif
	default:
		return 0;
	}
	return 0;
}

int _gnutls_compress(gnutls_compression_method_t alg, uint8_t *dst,
		     size_t dst_len, const uint8_t *src, size_t src_len)
{
	int ret = GNUTLS_E_COMPRESSION_FAILED;

	switch (alg) {
#ifdef HAVE_LIBZ
	case GNUTLS_COMP_ZLIB: {
		int err;
		uLongf comp_len = dst_len;

		err = _gnutls_zlib_compress(dst, &comp_len, src, src_len);
		if (err != Z_OK)
			return gnutls_assert_val(GNUTLS_E_COMPRESSION_FAILED);
		ret = comp_len;
	} break;
#endif
#ifdef HAVE_LIBBROTLI
	case GNUTLS_COMP_BROTLI: {
		BROTLI_BOOL err;
		size_t comp_len = dst_len;

		err = _gnutls_BrotliEncoderCompress(
			BROTLI_DEFAULT_QUALITY, BROTLI_DEFAULT_WINDOW,
			BROTLI_DEFAULT_MODE, src_len, src, &comp_len, dst);
		if (!err)
			return gnutls_assert_val(GNUTLS_E_COMPRESSION_FAILED);
		ret = comp_len;
	} break;
#endif
#ifdef HAVE_LIBZSTD
	case GNUTLS_COMP_ZSTD: {
		size_t comp_len;

		comp_len = _gnutls_ZSTD_compress(dst, dst_len, src, src_len,
						 ZSTD_CLEVEL_DEFAULT);
		if (_gnutls_ZSTD_isError(comp_len))
			return gnutls_assert_val(GNUTLS_E_COMPRESSION_FAILED);
		ret = comp_len;
	} break;
#endif
	default:
		return gnutls_assert_val(GNUTLS_E_INTERNAL_ERROR);
	}

#ifdef COMPRESSION_DEBUG
	_gnutls_debug_log("Compression ratio: %f\n",
			  (float)((float)ret / (float)src_len));
#endif

	return ret;
}

int _gnutls_decompress(gnutls_compression_method_t alg, uint8_t *dst,
		       size_t dst_len, const uint8_t *src, size_t src_len)
{
	int ret = GNUTLS_E_DECOMPRESSION_FAILED;

	switch (alg) {
#ifdef HAVE_LIBZ
	case GNUTLS_COMP_ZLIB: {
		int err;
		uLongf plain_len = dst_len;

		err = _gnutls_zlib_uncompress(dst, &plain_len, src, src_len);
		if (err != Z_OK)
			return gnutls_assert_val(GNUTLS_E_DECOMPRESSION_FAILED);
		ret = plain_len;
	} break;
#endif
#ifdef HAVE_LIBBROTLI
	case GNUTLS_COMP_BROTLI: {
		BrotliDecoderResult err;
		size_t plain_len = dst_len;

		err = _gnutls_BrotliDecoderDecompress(src_len, src, &plain_len,
						      dst);
		if (err != BROTLI_DECODER_RESULT_SUCCESS)
			return gnutls_assert_val(GNUTLS_E_DECOMPRESSION_FAILED);
		ret = plain_len;
	} break;
#endif
#ifdef HAVE_LIBZSTD
	case GNUTLS_COMP_ZSTD: {
		size_t plain_len;

		plain_len = _gnutls_ZSTD_decompress(dst, dst_len, src, src_len);
		if (_gnutls_ZSTD_isError(plain_len))
			return gnutls_assert_val(GNUTLS_E_DECOMPRESSION_FAILED);
		ret = plain_len;
	} break;
#endif
	default:
		return gnutls_assert_val(GNUTLS_E_INTERNAL_ERROR);
	}

	return ret;
}
