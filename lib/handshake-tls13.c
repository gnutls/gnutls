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

/* Functions that relate to the TLS handshake procedure.
 */

#include "gnutls_int.h"
#include "errors.h"
#include "dh.h"
#include "debug.h"
#include "algorithms.h"
#include "cipher.h"
#include "buffers.h"
#include "mbuffers.h"
#include "kx.h"
#include "handshake.h"
#include "num.h"
#include "hash_int.h"
#include "db.h"
#include "hello_ext.h"
#include "supplemental.h"
#include "auth.h"
#include "sslv2_compat.h"
#include <auth/cert.h>
#include "constate.h"
#include <record.h>
#include <state.h>
#include <random.h>
#include <dtls.h>
#include "secrets.h"

/*
 * _gnutls13_handshake_client
 * This function performs the client side of the handshake of the TLS/SSL protocol.
 */
int _gnutls13_handshake_client(gnutls_session_t session)
{
	int ret = 0;

	switch (STATE) {
	case STATE100:
		abort();
		STATE = STATE100;
		IMED_RET("recv encrypted extensions", ret, 0);
		/* fall through */
	case STATE101:
		abort();
		STATE = STATE101;
		IMED_RET("recv certificate request", ret, 0);
		/* fall through */
	case STATE102:
		abort();
		STATE = STATE102;
		IMED_RET("recv certificate", ret, 0);
		/* fall through */
	case STATE103:
		abort();
		STATE = STATE103;
		IMED_RET("recv server certificate verify", ret, 0);
		/* fall through */
	case STATE104:
		ret = _gnutls_run_verify_callback(session, GNUTLS_CLIENT);
		STATE = STATE102;
		if (ret < 0)
			return gnutls_assert_val(ret);
		FALLTHROUGH;
	case STATE105:
		abort();
		STATE = STATE105;
		IMED_RET("recv finished", ret, 0);
		/* fall through */
	case STATE106:
		abort();
		STATE = STATE106;
		IMED_RET("send certificate", ret, 0);
		/* fall through */
	case STATE107:
		abort();
		STATE = STATE107;
		IMED_RET("send certificate verify", ret, 0);
		/* fall through */
	case STATE108:
		abort();
		STATE = STATE108;
		IMED_RET("send finished", ret, 0);

		STATE = STATE0;
		break;
	default:
		return gnutls_assert_val(GNUTLS_E_INTERNAL_ERROR);
	}

	/* explicitly reset any false start flags */
	session->internals.recv_state = RECV_STATE_0;

	return 0;
}

static int generate_hs_traffic_keys(gnutls_session_t session)
{
	int ret;

	if (unlikely(session->key.key.size == 0))
		return gnutls_assert_val(GNUTLS_E_INTERNAL_ERROR);

	ret = _tls13_update_secret(session, session->key.key.data, session->key.key.size);
	if (ret < 0) {
		gnutls_assert();
		return ret;
	}

	ret = _tls13_connection_state_init(session);
	if (ret < 0) {
		gnutls_assert();
		return ret;
	}

	ret = _tls13_derive_secret(session, DERIVED_LABEL, sizeof(DERIVED_LABEL)-1,
				   NULL, 0, session->key.temp_secret);
	if (ret < 0) {
		gnutls_assert();
		return ret;
	}

	return 0;
}

/*
 * _gnutls13_handshake_server
 * This function does the server stuff of the handshake protocol.
 */
int _gnutls13_handshake_server(gnutls_session_t session)
{
	int ret = 0;

	switch (STATE) {
	case STATE100:
		ret =
		    generate_hs_traffic_keys(session);
		STATE = STATE100;
		IMED_RET("generate session keys", ret, 0);
		/* fall through */
	case STATE101:
		abort();
		STATE = STATE101;
		IMED_RET("send encrypted extensions", ret, 0);
		/* fall through */
	case STATE102:
		abort();
		STATE = STATE102;
		IMED_RET("send certificate request", ret, 0);
		/* fall through */
	case STATE103:
		abort();
		STATE = STATE103;
		IMED_RET("send certificate", ret, 0);
		/* fall through */
	case STATE104:
		abort();
		STATE = STATE104;
		IMED_RET("send certificate verify", ret, 0);
		/* fall through */
	case STATE105:
		abort();
		STATE = STATE105;
		IMED_RET("send finished", ret, 0);
		/* fall through */
	case STATE106:
		abort();
		STATE = STATE106;
		IMED_RET("recv certificate", ret, 0);
		/* fall through */
	case STATE107:
		abort();
		STATE = STATE107;
		IMED_RET("recv certificate verify", ret, 0);
		/* fall through */
	case STATE108:
		ret = _gnutls_run_verify_callback(session, GNUTLS_SERVER);
		STATE = STATE108;
		if (ret < 0)
			return gnutls_assert_val(ret);
		/* fall through */
	case STATE109:
		abort();
		STATE = STATE109;
		IMED_RET("recv finished", ret, 0);
		/* fall through */

		STATE = STATE0;
		break;
	default:
		return gnutls_assert_val(GNUTLS_E_INTERNAL_ERROR);
	}

	return 0;
}

