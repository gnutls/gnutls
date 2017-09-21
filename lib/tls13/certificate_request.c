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
#include "errors.h"
#include "extv.h"
#include "handshake.h"
#include "tls13/certificate_request.h"

static
int parse_cert_extension(void *ctx, uint16_t tls_id, const uint8_t *data, int data_size)
{
	/* ignore all exts */
	return 0;
}

int _gnutls13_recv_certificate_request(gnutls_session_t session)
{
	int ret;
	gnutls_buffer_st buf;

	ret = _gnutls_recv_handshake(session, GNUTLS_HANDSHAKE_CERTIFICATE_REQUEST, 1, &buf);
	if (ret < 0)
		return gnutls_assert_val(ret);

	/* if not received */
	if (buf.length == 0) {
		_gnutls_buffer_clear(&buf);
		return 0;
	}

	_gnutls_handshake_log("HSK[%p]: parsing certificate request\n", session);

	if (buf.data[0] != 0) {
		/* The context field must be empty during handshake */
		gnutls_assert();
		return gnutls_assert_val(GNUTLS_E_RECEIVED_ILLEGAL_PARAMETER);
	}

	/* buf.length is positive */
	buf.data++;
	buf.length--;

	ret = _gnutls_extv_parse(NULL, parse_cert_extension, buf.data, buf.length);
	_gnutls_buffer_clear(&buf);

	if (ret < 0)
		return gnutls_assert_val(ret);

	return 0;
}

int _gnutls13_send_certificate_request(gnutls_session_t session, unsigned again)
{
	return 0;
}
