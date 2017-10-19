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
#include "handshake.h"
#include "tls13/key_update.h"
#include "mem.h"
#include "mbuffers.h"
#include "secrets.h"

#define KEY_UPDATES_PER_SEC 1

static int update_keys(gnutls_session_t session, hs_stage_t stage)
{
	int ret;

	ret = _tls13_update_secret(session, session->key.temp_secret,
				   session->key.temp_secret_size);
	if (ret < 0)
		return gnutls_assert_val(ret);

	_gnutls_epoch_bump(session);
	ret = _gnutls_epoch_dup(session);
	if (ret < 0)
		return gnutls_assert_val(ret);

	ret = _tls13_connection_state_init(session, stage);
	if (ret < 0)
		return gnutls_assert_val(ret);

	return 0;
}

int _gnutls13_recv_key_update(gnutls_session_t session, gnutls_buffer_st *buf)
{
	int ret;
	time_t now = gnutls_time(0);

	if (buf->length != 1)
		return gnutls_assert_val(GNUTLS_E_UNEXPECTED_PACKET_LENGTH);

	if (unlikely(now - session->internals.last_key_update < KEY_UPDATES_PER_SEC)) {
		_gnutls_debug_log("reached maximum number of key updates per second (%d)\n",
				  KEY_UPDATES_PER_SEC);
		return gnutls_assert_val(GNUTLS_E_TOO_MANY_HANDSHAKE_PACKETS);
	}

	session->internals.last_key_update = now;

	_gnutls_epoch_gc(session);

	_gnutls_handshake_log("HSK[%p]: requested TLS 1.3 key update (%u)\n",
			      session, (unsigned)buf->data[0]);

	switch(buf->data[0]) {
	case 0:
		/* peer updated its key, not requested our key update */
		ret = update_keys(session, STAGE_UPD_PEERS);
		if (ret < 0)
			return gnutls_assert_val(ret);

		break;
	case 1:
		/* peer updated its key, requested our key update */
		ret = update_keys(session, STAGE_UPD_PEERS);
		if (ret < 0)
			return gnutls_assert_val(ret);

		/* we mark that a key update is schedule, and it
		 * will be performed prior to sending the next application
		 * message.
		 */
		session->internals.key_update_state = KEY_UPDATE_SCHEDULED;

		break;
	default:
		return gnutls_assert_val(GNUTLS_E_RECEIVED_ILLEGAL_PARAMETER);
	}

	return 0;
}

int _gnutls13_send_key_update(gnutls_session_t session, unsigned again)
{
	int ret, ret2;
	mbuffer_st *bufel = NULL;
	const uint8_t val = 0;

	if (again == 0) {
		_gnutls_handshake_log("HSK[%p]: sending key update\n", session);

		bufel = _gnutls_handshake_alloc(session, 1);
		if (bufel == NULL)
			return gnutls_assert_val(GNUTLS_E_MEMORY_ERROR);

		_mbuffer_set_udata_size(bufel, 0);
		ret = _mbuffer_append_data(bufel, (void*)&val, 1);
		if (ret < 0) {
			gnutls_assert();
			goto cleanup;
		}
	}

	ret = _gnutls_send_handshake(session, bufel, GNUTLS_HANDSHAKE_KEY_UPDATE);
	if (ret == 0) {
		/* it was completely sent, update the keys */
		ret2 = update_keys(session, STAGE_UPD_OURS);
		if (ret2 < 0)
			return gnutls_assert_val(ret2);
	}

	return ret;

cleanup:
	_mbuffer_xfree(&bufel);
	return ret;
}
