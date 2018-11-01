/*
 * Copyright (C) 2018 Red Hat, Inc.
 *
 * Author: Daiki Ueno
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

/* This file contains the code for the Record Size Limit TLS extension.
 */

#include "gnutls_int.h"
#include "errors.h"
#include "num.h"
#include <hello_ext.h>
#include <ext/record_size_limit.h>

static int _gnutls_record_size_limit_recv_params(gnutls_session_t session,
						 const uint8_t * data,
						 size_t data_size);
static int _gnutls_record_size_limit_send_params(gnutls_session_t session,
						 gnutls_buffer_st * extdata);

const hello_ext_entry_st ext_mod_record_size_limit = {
	.name = "Record Size Limit",
	.tls_id = 28,
	.gid = GNUTLS_EXTENSION_RECORD_SIZE_LIMIT,
	.parse_type = GNUTLS_EXT_TLS,
	.validity = GNUTLS_EXT_FLAG_TLS | GNUTLS_EXT_FLAG_DTLS | GNUTLS_EXT_FLAG_CLIENT_HELLO |
		    GNUTLS_EXT_FLAG_EE | GNUTLS_EXT_FLAG_TLS12_SERVER_HELLO,
	.recv_func = _gnutls_record_size_limit_recv_params,
	.send_func = _gnutls_record_size_limit_send_params
};

static int
_gnutls_record_size_limit_recv_params(gnutls_session_t session,
				      const uint8_t * data, size_t _data_size)
{
	ssize_t new_size;
	ssize_t data_size = _data_size;

	DECR_LEN(data_size, 2);
	new_size = _gnutls_read_uint16(data);

	/* protocol error */
	if (new_size < 64)
		return gnutls_assert_val(GNUTLS_E_RECEIVED_ILLEGAL_PARAMETER);

	/* we do not want to accept sizes less than our minimum */
	if (new_size < MIN_RECORD_SIZE)
		return 0;

	session->internals.hsk_flags |= HSK_RECORD_SIZE_LIMIT_NEGOTIATED;

	/* if a larger record size limit than the protocol limit is
	 * provided by the peer, ignore it and stick to the default */
	if (unlikely(new_size > DEFAULT_MAX_RECORD_SIZE))
		return gnutls_assert_val(0);

	session->security_parameters.max_record_send_size = new_size;
	session->security_parameters.max_record_recv_size = new_size;

	return 0;
}

/* returns data_size or a negative number on failure
 */
static int
_gnutls_record_size_limit_send_params(gnutls_session_t session,
				      gnutls_buffer_st * extdata)
{
	int ret;

	assert(session->security_parameters.max_record_send_size >= 64 &&
	       session->security_parameters.max_record_send_size <=
	       DEFAULT_MAX_RECORD_SIZE);

	ret = _gnutls_buffer_append_prefix(extdata, 16,
					   session->security_parameters.max_record_send_size);
	if (ret < 0)
		return gnutls_assert_val(ret);

	return 2;
}
