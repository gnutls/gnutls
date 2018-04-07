/*
 * Copyright (C) 2017 Free Software Foundation, Inc.
 *
 * Author: Ander Juaristi
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
#include "ext/psk_ke_modes.h"
#include "ext/pre_shared_key.h"
#include <assert.h>

#define PSK_KE 0
#define PSK_DHE_KE 1

/*
 * We only support ECDHE-authenticated PSKs.
 * The client just sends a "psk_key_exchange_modes" extension
 * with the value one.
 */
static int
psk_ke_modes_send_params(gnutls_session_t session,
			 gnutls_buffer_t extdata)
{
	int ret;
	gnutls_psk_client_credentials_t cred;
	const version_entry_st *vers;
	uint8_t data[2];
	unsigned pos, i;
	unsigned have_dhpsk = 0;
	unsigned have_psk = 0;

	/* Server doesn't send psk_key_exchange_modes */
	if (session->security_parameters.entity == GNUTLS_SERVER ||
	    !session->internals.priorities->have_psk)
		return 0;

	cred = (gnutls_psk_client_credentials_t)
			_gnutls_get_cred(session, GNUTLS_CRD_PSK);
	if (cred == NULL || _gnutls_have_psk_credentials(cred) == 0)
		return 0;

	vers = _gnutls_version_max(session);
	if (!vers || !vers->tls13_sem)
		return 0;

	pos = 0;
	for (i=0;i<session->internals.priorities->_kx.algorithms;i++) {
		if (session->internals.priorities->_kx.priority[i] == GNUTLS_KX_PSK && !have_psk) {
			assert(pos <= 1);
			data[pos++] = PSK_KE;
			session->internals.hsk_flags |= HSK_PSK_KE_MODE_PSK;
			have_psk = 1;
		} else if ((session->internals.priorities->_kx.priority[i] == GNUTLS_KX_DHE_PSK ||
			    session->internals.priorities->_kx.priority[i] == GNUTLS_KX_ECDHE_PSK) && !have_dhpsk) {
			assert(pos <= 1);
			data[pos++] = PSK_DHE_KE;
			session->internals.hsk_flags |= HSK_PSK_KE_MODE_DHE_PSK;
			have_dhpsk = 1;
		}

		if (have_psk && have_dhpsk)
			break;
	}

	ret = _gnutls_buffer_append_data_prefix(extdata, 8, data, pos);
	if (ret < 0)
		return gnutls_assert_val(ret);

	session->internals.hsk_flags |= HSK_PSK_KE_MODES_SENT;

	return 0;
}

#define MAX_POS INT_MAX

/*
 * Since we only support ECDHE-authenticated PSKs, the server
 * just verifies that a "psk_key_exchange_modes" extension was received,
 * and that it contains the value one.
 */
static int
psk_ke_modes_recv_params(gnutls_session_t session,
			 const unsigned char *data, size_t _len)
{
	uint8_t ke_modes_len;
	ssize_t len = _len;
	const version_entry_st *vers = get_version(session);
	gnutls_psk_server_credentials_t cred;
	int dhpsk_pos = MAX_POS;
	int psk_pos = MAX_POS;
	int cli_psk_pos = MAX_POS;
	int cli_dhpsk_pos = MAX_POS;
	unsigned i;

	/* Server doesn't send psk_key_exchange_modes */
	if (session->security_parameters.entity == GNUTLS_CLIENT)
		return gnutls_assert_val(GNUTLS_E_RECEIVED_ILLEGAL_EXTENSION);

	if (!vers || !vers->tls13_sem)
		return 0;

	cred = (gnutls_psk_server_credentials_t)_gnutls_get_cred(session, GNUTLS_CRD_PSK);
	if (cred == NULL)
		return 0;

	DECR_LEN(len, 1);
	ke_modes_len = *(data++);

	for (i=0;i<session->internals.priorities->_kx.algorithms;i++) {
		if (session->internals.priorities->_kx.priority[i] == GNUTLS_KX_PSK && psk_pos == MAX_POS) {
			psk_pos = i;
		} else if ((session->internals.priorities->_kx.priority[i] == GNUTLS_KX_DHE_PSK ||
			    session->internals.priorities->_kx.priority[i] == GNUTLS_KX_ECDHE_PSK) &&
			    dhpsk_pos == MAX_POS) {
			dhpsk_pos = i;
		}

		if (dhpsk_pos != MAX_POS && psk_pos != MAX_POS)
			break;
	}

	if (session->internals.priorities->groups.size == 0 && psk_pos == MAX_POS)
		return gnutls_assert_val(0);

	for (i=0;i<ke_modes_len;i++) {
		DECR_LEN(len, 1);
		if (data[i] == PSK_DHE_KE)
			cli_dhpsk_pos = i;
		else if (data[i] == PSK_KE)
			cli_psk_pos = i;

		if (cli_psk_pos != MAX_POS && cli_dhpsk_pos != MAX_POS)
			break;
	}

	if (session->internals.priorities->server_precedence) {
		if (dhpsk_pos != MAX_POS && cli_dhpsk_pos != MAX_POS && dhpsk_pos < psk_pos)
			session->internals.hsk_flags |= HSK_PSK_KE_MODE_DHE_PSK;
		else if (psk_pos != MAX_POS && cli_psk_pos != MAX_POS && psk_pos < dhpsk_pos)
			session->internals.hsk_flags |= HSK_PSK_KE_MODE_PSK;
	} else {
		if (dhpsk_pos != MAX_POS && cli_dhpsk_pos != MAX_POS && cli_dhpsk_pos < cli_psk_pos)
			session->internals.hsk_flags |= HSK_PSK_KE_MODE_DHE_PSK;
		else if (psk_pos != MAX_POS && cli_psk_pos != MAX_POS && cli_psk_pos < cli_dhpsk_pos)
			session->internals.hsk_flags |= HSK_PSK_KE_MODE_PSK;
	}

	if ((session->internals.hsk_flags & HSK_PSK_KE_MODE_PSK) ||
	    (session->internals.hsk_flags & HSK_PSK_KE_MODE_DHE_PSK)) {
		return 0;
	} else {
		session->internals.hsk_flags |= HSK_PSK_KE_MODE_INVALID;
		return 0;
	}
}

const hello_ext_entry_st ext_psk_ke_modes = {
	.name = "PSK Key Exchange Modes",
	.tls_id = 45,
	.gid = GNUTLS_EXTENSION_PSK_KE_MODES,
	.parse_type = GNUTLS_EXT_TLS,
	.validity = GNUTLS_EXT_FLAG_CLIENT_HELLO | GNUTLS_EXT_FLAG_TLS13_SERVER_HELLO,
	.send_func = psk_ke_modes_send_params,
	.recv_func = psk_ke_modes_recv_params
};
