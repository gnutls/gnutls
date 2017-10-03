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
#include "ext/signature.h"
#include "mbuffers.h"

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

	session->internals.hsk_flags |= HSK_CRT_ASKED;

	return 0;
}


int _gnutls13_send_certificate_request(gnutls_session_t session, unsigned again)
{
	gnutls_certificate_credentials_t cred;
	int ret;
	mbuffer_st *bufel = NULL;
	gnutls_buffer_st buf;
	unsigned init_pos;

	if (again == 0) {
		if (session->internals.send_cert_req == 0)
			return 0;

		cred = (gnutls_certificate_credentials_t)
		    _gnutls_get_cred(session, GNUTLS_CRD_CERTIFICATE);
		if (cred == NULL)
			return gnutls_assert_val(GNUTLS_E_INSUFFICIENT_CREDENTIALS);

		ret = _gnutls_buffer_init_handshake_mbuffer(&buf);
		if (ret < 0)
			return gnutls_assert_val(ret);

		ret = _gnutls_buffer_append_prefix(&buf, 8, 0);
		if (ret < 0) {
			gnutls_assert();
			goto cleanup;
		}

		ret = _gnutls_extv_append_init(&buf);
		if (ret < 0) {
			gnutls_assert();
			goto cleanup;
		}
		init_pos = ret;

		ret = _gnutls_extv_append(&buf, ext_mod_sig.tls_id, session,
					  (extv_append_func)_gnutls_sign_algorithm_write_params);
		if (ret < 0) {
			gnutls_assert();
			goto cleanup;
		}

		ret = _gnutls_extv_append_final(&buf, init_pos);
		if (ret < 0) {
			gnutls_assert();
			goto cleanup;
		}

		bufel = _gnutls_buffer_to_mbuffer(&buf);

		session->internals.hsk_flags |= HSK_CRT_REQ_SENT;
	}

	return _gnutls_send_handshake(session, bufel, GNUTLS_HANDSHAKE_CERTIFICATE_REQUEST);

 cleanup:
	_gnutls_buffer_clear(&buf);
	return ret;

}

