/*
 * Copyright (C) 2010-2016 Free Software Foundation, Inc.
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
 * along with this program.  If not, see <http://www.gnu.org/licenses/>
 *
 */

#include <config.h>
#include <system.h>
#include "gnutls_int.h"
#include "errors.h"

#include <sys/socket.h>
#include <errno.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <c-ctype.h>

static void change_u16_endianness(uint8_t *dst, const uint8_t *src, unsigned size, unsigned be)
{
	unsigned convert = 0;
	unsigned i;
	uint8_t tmp;

#ifdef WORDS_BIGENDIAN
	if (!be)
		convert = 1;
#else
	if (be)
		convert = 1;
#endif

	/* convert to LE */
	if (convert) {
		for (i = 0; i < size; i += 2) {
			tmp = src[i];
			dst[i] = src[1 + i];
			dst[1 + i] = tmp;
		}
	} else {
		if (dst != src)
			memcpy(dst, src, size);
	}
}

#if defined(_WIN32)
#include <windows.h>
#include <winnls.h>

int _gnutls_ucs2_to_utf8(const void *data, size_t size,
			 gnutls_datum_t * output, unsigned be)
{
	int ret;
	unsigned i;
	int len = 0, src_len;
	char *dst = NULL;
	char *src = NULL;
	static unsigned flags = 0;
	static int checked = 0;

	if (checked == 0) {
		/* Not all windows versions support MB_ERR_INVALID_CHARS */
		ret =
		    WideCharToMultiByte(CP_UTF8, MB_ERR_INVALID_CHARS,
				L"hello", -1, NULL, 0, NULL, NULL);
		if (ret > 0)
			flags = MB_ERR_INVALID_CHARS;
		checked = 1;
	}

	if (size > 2 && ((uint8_t *) data)[size-1] == 0 && ((uint8_t *) data)[size-2] == 0) {
		size -= 2;
	}

	src = gnutls_malloc(size+2);
	if (src == NULL)
		return gnutls_assert_val(GNUTLS_E_MEMORY_ERROR);

	/* convert to LE if needed */
	change_u16_endianness(src, data, size, be);

	src[size] = 0;
	src[size+1] = 0;

	src_len = wcslen((void*)src);

	ret =
	    WideCharToMultiByte(CP_UTF8, flags,
				(void *) src, src_len, NULL, 0,
				NULL, NULL);
	if (ret == 0) {
		_gnutls_debug_log("WideCharToMultiByte: %d\n", (int)GetLastError());
		ret = gnutls_assert_val(GNUTLS_E_PARSING_ERROR);
		goto fail;
	}

	len = ret + 1;
	dst = gnutls_malloc(len);
	if (dst == NULL) {
		ret = gnutls_assert_val(GNUTLS_E_MEMORY_ERROR);
		goto fail;
	}
	dst[0] = 0;

	ret =
	    WideCharToMultiByte(CP_UTF8, flags,
				(void *) src, src_len, dst, len-1, NULL,
				NULL);
	if (ret == 0) {
		ret = gnutls_assert_val(GNUTLS_E_PARSING_ERROR);
		goto fail;
	}
	dst[len - 1] = 0;

	output->data = (uint8_t*)dst;
	output->size = ret;

	ret = 0;
	goto cleanup;

      fail:
	gnutls_free(dst);

      cleanup:
	gnutls_free(src);
	return ret;
}

int _gnutls_utf8_to_ucs2(const void *data, size_t size,
			 gnutls_datum_t * output)
{
	int ret;
	unsigned i;
	int len = 0;
	char *dst = NULL;
	static unsigned flags = MB_PRECOMPOSED;
	static int checked = 0;
	uint8_t tmp;

	if (checked == 0) {
		/* Not all windows versions support MB_ERR_INVALID_CHARS */
		ret =
		    MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS,
				"\xff\xff\xff\xff\xff\xff\x00", -1, NULL, 0);
		if (ret > 0)
			flags |= MB_ERR_INVALID_CHARS;
		checked = 1;
	}

	if (((uint8_t *) data)[size-1] == 0) {
		size --;
	}

	ret =
	    MultiByteToWideChar(CP_UTF8, flags,
				data, size, NULL, 0);
	if (ret == 0) {
		_gnutls_debug_log("WideCharToMultiByte: %d\n", (int)GetLastError());
		ret = gnutls_assert_val(GNUTLS_E_PARSING_ERROR);
		goto fail;
	}

	/* we got the number of characters needed, allocate some extra
	 * bytes for more complex encodings */
	len = ret*2;
	dst = gnutls_calloc(1, len+2);
	if (dst == NULL) {
		ret = gnutls_assert_val(GNUTLS_E_MEMORY_ERROR);
		goto fail;
	}
	dst[0] = 0;

	ret =
	    MultiByteToWideChar(CP_UTF8, flags,
				data, size, (void*)dst, len/2);
	if (ret == 0) {
		ret = gnutls_assert_val(GNUTLS_E_PARSING_ERROR);
		goto fail;
	}

	/* convert to BE if needed */
	change_u16_endianness(dst, dst, len, 1);

	dst[len] = 0;
	dst[len+1] = 0;

	output->data = (uint8_t*)dst;
	output->size = len;

	ret = 0;
	goto cleanup;

      fail:
	gnutls_free(dst);

      cleanup:
	return ret;
}

#elif defined(HAVE_LIBUNISTRING)

#include <unistr.h>
#include "num.h"

int _gnutls_ucs2_to_utf8(const void *data, size_t size,
			 gnutls_datum_t * output, unsigned be)
{
	int ret;
	size_t dstlen;
	uint8_t *src;
	uint8_t *tmp_dst = NULL;
	uint8_t *dst = NULL;

	if (size > 2 && ((uint8_t *) data)[size-1] == 0 && ((uint8_t *) data)[size-2] == 0) {
		size -= 2;
	}

	if (size == 0)
		return gnutls_assert_val(GNUTLS_E_INVALID_REQUEST);

	src = gnutls_malloc(size+2);
	if (src == NULL)
		return gnutls_assert_val(GNUTLS_E_MEMORY_ERROR);

	/* convert to LE if needed */
	change_u16_endianness(src, data, size, be);

	dstlen = 0;
	tmp_dst = u16_to_u8((uint16_t*)src, size/2, NULL, &dstlen);
	if (tmp_dst == NULL) {
		ret = gnutls_assert_val(GNUTLS_E_MEMORY_ERROR);
		goto fail;
	}

	dst = gnutls_malloc(dstlen+1);
	if (dst == NULL) {
		gnutls_assert();
		ret = GNUTLS_E_MEMORY_ERROR;
		goto fail;
	}

	memcpy(dst, tmp_dst, dstlen);
	dst[dstlen] = 0;

	output->data = (void *) dst;
	output->size = dstlen;

	ret = 0;
	goto cleanup;

 fail:
	gnutls_free(dst);

 cleanup:
	gnutls_free(src);
	free(tmp_dst);

	return ret;
}

/* This is big-endian output only */
int _gnutls_utf8_to_ucs2(const void *data, size_t size,
			 gnutls_datum_t * output)
{
	int ret;
	size_t dstlen = 0;
	uint16_t *tmp_dst = NULL;
	uint8_t *dst = NULL;

	if (size == 0)
		return gnutls_assert_val(GNUTLS_E_INVALID_REQUEST);

	dstlen = 0;
	tmp_dst = u8_to_u16(data, size, NULL, &dstlen);
	if (tmp_dst == NULL)
		return gnutls_assert_val(GNUTLS_E_MEMORY_ERROR);

	dstlen *= 2; /* convert to bytes */

	dst = gnutls_malloc(dstlen+2);
	if (dst == NULL) {
		gnutls_assert();
		ret = GNUTLS_E_MEMORY_ERROR;
		goto fail;
	}

	/* convert to BE if needed */
	change_u16_endianness(dst, (uint8_t*)tmp_dst, dstlen, 1);
	dst[dstlen] = 0;
	dst[dstlen+1] = 0;

	output->data = (void *) dst;
	output->size = dstlen;

	ret = 0;
	goto cleanup;

 fail:
	gnutls_free(dst);

 cleanup:
	free(tmp_dst);

	return ret;
}

#elif defined(HAVE_ICONV) || defined(HAVE_LIBICONV)

#include <iconv.h>

int _gnutls_ucs2_to_utf8(const void *data, size_t size,
			 gnutls_datum_t * output, unsigned be)
{
	iconv_t conv;
	int ret;
	size_t orig, dstlen = size * 2;
	char *src = (void *) data;
	char *dst = NULL, *pdst;

	if (size == 0)
		return gnutls_assert_val(GNUTLS_E_INVALID_REQUEST);

	if (be) {
		conv = iconv_open("UTF-8", "UTF-16BE");
	} else {
		conv = iconv_open("UTF-8", "UTF-16LE");
	}
	if (conv == (iconv_t) - 1)
		return gnutls_assert_val(GNUTLS_E_MEMORY_ERROR);

	/* Note that dstlen has enough size for every possible input characters.
	 * (remember the in UTF-16 the characters in data are at most size/2, 
	 *  and we allocate 4 bytes per character).
	 */
	pdst = dst = gnutls_malloc(dstlen + 1);
	if (dst == NULL) {
		ret = gnutls_assert_val(GNUTLS_E_MEMORY_ERROR);
		goto fail;
	}

	orig = dstlen;
	ret = iconv(conv, &src, &size, &pdst, &dstlen);
	if (ret == -1) {
		ret = gnutls_assert_val(GNUTLS_E_PARSING_ERROR);
		goto fail;
	}

	output->data = (void *) dst;
	output->size = orig - dstlen;
	output->data[output->size] = 0;

	ret = 0;
	goto cleanup;

      fail:
	gnutls_free(dst);

      cleanup:
	iconv_close(conv);

	return ret;
}

int _gnutls_utf8_to_ucs2(const void *data, size_t size,
			 gnutls_datum_t * output)
{
	iconv_t conv;
	int ret;
	size_t orig, dstlen = size * 4;
	char *src = (void *) data;
	uint8_t *dst = NULL;
	char *pdst;

	if (size == 0)
		return gnutls_assert_val(GNUTLS_E_INVALID_REQUEST);

	conv = iconv_open("UTF-16BE", "UTF-8");
	if (conv == (iconv_t) - 1)
		return gnutls_assert_val(GNUTLS_E_MEMORY_ERROR);

	dst = gnutls_malloc(dstlen+2);
	pdst = (char*)dst;
	if (dst == NULL) {
		ret = gnutls_assert_val(GNUTLS_E_MEMORY_ERROR);
		goto fail;
	}

	orig = dstlen;
	ret = iconv(conv, &src, &size, &pdst, &dstlen);
	if (ret == -1) {
		ret = gnutls_assert_val(GNUTLS_E_PARSING_ERROR);
		goto fail;
	}

	output->data = (void *) dst;
	output->size = orig - dstlen;
	output->data[output->size] = 0;
	output->data[output->size+1] = 0;

	ret = 0;
	goto cleanup;

      fail:
	gnutls_free(dst);

      cleanup:
	iconv_close(conv);

	return ret;
}

#else

/* Can convert only english (ASCII) */
int _gnutls_ucs2_to_utf8(const void *data, size_t size,
			 gnutls_datum_t * output, unsigned be)
{
	unsigned int i, j;
	char *dst;
	const char *src = data;

	if (size == 0 || size % 2 != 0)
		return gnutls_assert_val(GNUTLS_E_INVALID_REQUEST);

	dst = gnutls_malloc(size + 1);
	if (dst == NULL)
		return gnutls_assert_val(GNUTLS_E_MEMORY_ERROR);

	for (i = j = 0; i < size; i += 2, j++) {
		if (src[i] != 0 || !c_isascii(src[i + 1]))
			return gnutls_assert_val(GNUTLS_E_PARSING_ERROR);
		if (be)
			dst[j] = src[i + 1];
		else
			dst[j] = src[i];
	}

	output->data = (void *) dst;
	output->size = j;
	output->data[output->size] = 0;

	return 0;
}

int _gnutls_utf8_to_ucs2(const void *data, size_t size,
			 gnutls_datum_t * output)
{
	unsigned int i, j;
	char *dst;
	const char *src = data;

	dst = gnutls_malloc(2*size + 2);
	if (dst == NULL)
		return gnutls_assert_val(GNUTLS_E_MEMORY_ERROR);

	for (i = j = 0; i < size; i += 2, j++) {
		if (!c_isascii(src[j]))
			return gnutls_assert_val(GNUTLS_E_PARSING_ERROR);

		dst[i] = 0;
		dst[i+1] = src[j];
	}

	output->data = (void *) dst;
	output->size = i;
	output->data[output->size] = 0;
	output->data[output->size+1] = 0;

	return 0;
}
#endif
