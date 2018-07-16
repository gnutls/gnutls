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

/* This file contains the code for the Early Data TLS 1.3 extension.
 */

#include "gnutls_int.h"
#include "errors.h"
#include "num.h"
#include "hello_ext_lib.h"
#include <ext/early_data.h>

static int early_data_recv_params(gnutls_session_t session,
				  const uint8_t * data,
				  size_t data_size);
static int early_data_send_params(gnutls_session_t session,
				  gnutls_buffer_st * extdata);

const hello_ext_entry_st ext_mod_early_data = {
	.name = "Early Data",
	.tls_id = 42,
	.gid = GNUTLS_EXTENSION_EARLY_DATA,
	.validity = GNUTLS_EXT_FLAG_TLS | GNUTLS_EXT_FLAG_CLIENT_HELLO,
	.parse_type = GNUTLS_EXT_MANDATORY, /* force parsing prior to EXT_TLS extensions */
	.recv_func = early_data_recv_params,
	.send_func = early_data_send_params,
	.pack_func = NULL,
	.unpack_func = NULL,
	.deinit_func = _gnutls_hello_ext_default_deinit,
	.cannot_be_overriden = 0
};

static int
early_data_recv_params(gnutls_session_t session,
		       const uint8_t * data, size_t _data_size)
{
	const version_entry_st *vers = get_version(session);
	if (!vers || !vers->tls13_sem)
		return gnutls_assert_val(0);
	if (session->security_parameters.entity == GNUTLS_SERVER)
		session->internals.hsk_flags |= HSK_EARLY_DATA_IN_FLIGHT;

	return 0;
}

/* returns data_size or a negative number on failure
 */
static int
early_data_send_params(gnutls_session_t session,
		       gnutls_buffer_st * extdata)
{
	return 0;
}

/**
 * gnutls_record_set_max_early_data_size:
 * @session: is a #gnutls_session_t type.
 * @size: is the new size
 *
 * This function sets the maximum early data size in this connection.
 * This property can only be set to servers.  The client may be
 * provided with the maximum allowed size through the "early_data"
 * extension of the NewSessionTicket handshake message.
 *
 * Returns: On success, %GNUTLS_E_SUCCESS (0) is returned,
 *   otherwise a negative error code is returned.
 *
 * Since: 3.6.4
 **/
int
gnutls_record_set_max_early_data_size(gnutls_session_t session,
				      size_t size)
{
	if (session->security_parameters.entity == GNUTLS_CLIENT)
		return GNUTLS_E_INVALID_REQUEST;

	if (size > UINT32_MAX)
		return GNUTLS_E_INVALID_REQUEST;

	session->security_parameters.max_early_data_size = (uint32_t) size;

	return 0;
}
