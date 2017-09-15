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
#include "tls13/session_ticket.h"
#include "auth/cert.h"

static int parse_nst_extension(void *ctx, uint16_t tls_id, const uint8_t *data, int data_size);

int _gnutls13_recv_session_ticket(gnutls_session_t session, gnutls_buffer_st *buf)
{
	int ret;
	size_t val;
	gnutls_datum_t nonce;
	gnutls_datum_t ticket;

	_gnutls_handshake_log("HSK[%p]: parsing session ticket message\n", session);

	/* ticket_lifetime */
	ret = _gnutls_buffer_pop_prefix32(buf, &val, 0);
	if (ret < 0) {
		gnutls_assert();
		goto cleanup;
	}

	/* ticket_age_add */
	ret = _gnutls_buffer_pop_prefix32(buf, &val, 0);
	if (ret < 0) {
		gnutls_assert();
		goto cleanup;
	}

	ret = _gnutls_buffer_pop_datum_prefix8(buf, &nonce);
	if (ret < 0) {
		gnutls_assert();
		goto cleanup;
	}

	ret = _gnutls_buffer_pop_datum_prefix16(buf, &ticket);
	if (ret < 0) {
		gnutls_assert();
		goto cleanup;
	}

	ret = _gnutls_extv_parse(NULL, parse_nst_extension, buf->data, buf->length);
	if (ret < 0) {
		gnutls_assert();
		goto cleanup;
	}

	ret = 0;
cleanup:

	return ret;
}

static int parse_nst_extension(void *ctx, uint16_t tls_id, const uint8_t *data, int data_size)
{
	/* ignore all extensions */
	return 0;
}
