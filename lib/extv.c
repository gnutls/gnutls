/*
 * Copyright (C) 2017 Red Hat, Inc.
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

#include "gnutls_int.h"
#include "extensions.h"
#include "errors.h"
#include "extv.h"

/* Iterates through all extensions found, and calls the cb()
 * function with their data */
int _gnutls_extv_parse(void *ctx,
		       int (*cb)(void *ctx, uint16_t tls_id, const uint8_t *data, int data_size),
		       const uint8_t * data, int data_size)
{
	int next, ret;
	int pos = 0;
	uint16_t tls_id;
	const uint8_t *sdata;
	uint16_t size;

	if (data_size == 0)
		return 0;

	DECR_LENGTH_RET(data_size, 2, GNUTLS_E_UNEXPECTED_EXTENSIONS_LENGTH);
	next = _gnutls_read_uint16(data);
	pos += 2;

	DECR_LENGTH_RET(data_size, next, GNUTLS_E_UNEXPECTED_EXTENSIONS_LENGTH);

	if (next == 0 && data_size == 0) /* field is present, but has zero length? Ignore it. */
		return 0;
	else if (data_size > 0) /* forbid unaccounted data */
		return gnutls_assert_val(GNUTLS_E_UNEXPECTED_EXTENSIONS_LENGTH);

	do {
		DECR_LENGTH_RET(next, 2, GNUTLS_E_UNEXPECTED_EXTENSIONS_LENGTH);
		tls_id = _gnutls_read_uint16(&data[pos]);
		pos += 2;

		DECR_LENGTH_RET(next, 2, GNUTLS_E_UNEXPECTED_EXTENSIONS_LENGTH);
		size = _gnutls_read_uint16(&data[pos]);
		pos += 2;

		DECR_LENGTH_RET(next, size, GNUTLS_E_UNEXPECTED_EXTENSIONS_LENGTH);
		sdata = &data[pos];
		pos += size;

		ret = cb(ctx, tls_id, sdata, size);
		if (ret < 0)
			return gnutls_assert_val(ret);
	}
	while (next > 2);

	/* forbid leftovers */
	if (next > 0)
		return gnutls_assert_val(GNUTLS_E_UNEXPECTED_EXTENSIONS_LENGTH);

	return 0;

}

/* Returns:
 *  * On success the number of bytes appended (always positive), or zero if not sent
 *  * On failure, a negative error code.
 */
int _gnutls_extv_append(gnutls_buffer_st *buf,
			uint16_t tls_id,
		        void *ctx,
		        int (*cb)(void *ctx, gnutls_buffer_st *buf))
{
	int size_pos, appended, ret;
	size_t size_prev;

	ret = _gnutls_buffer_append_prefix(buf, 16, tls_id);
	if (ret < 0)
		return gnutls_assert_val(ret);

	size_pos = buf->length;
	ret = _gnutls_buffer_append_prefix(buf, 16, 0);
	if (ret < 0)
		return gnutls_assert_val(ret);

	size_prev = buf->length;
	ret = cb(ctx, buf);
	if (ret < 0 && ret != GNUTLS_E_INT_RET_0) {
		return gnutls_assert_val(ret);
	}

	/* returning GNUTLS_E_INT_RET_0 means to send an empty
	 * extension of this type.
	 */
	appended = buf->length - size_prev;

	if (appended > 0 || ret == GNUTLS_E_INT_RET_0) {
		if (ret == GNUTLS_E_INT_RET_0)
			appended = 0;

		/* write the real size */
		_gnutls_write_uint16(appended,
				     &buf->data[size_pos]);
	} else if (appended == 0) {
		buf->length -= 4;	/* reset type and size */
		return 0;
	}

	return appended + 4;
}

