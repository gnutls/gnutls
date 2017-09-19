/*
 * Copyright (C) 2011-2012 Free Software Foundation, Inc.
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

/* This file contains the code the Negotiated groups TLS 1.3, or
 * Elliptic curves TLS 1.2 extension.
 */

#include "gnutls_int.h"
#include "errors.h"
#include "num.h"
#include <ext/ecc.h>
#include <state.h>
#include <num.h>
#include <algorithms.h>
#include "auth/psk.h"
#include "auth/cert.h"
#include "auth/anon.h"

static int _gnutls_supported_ecc_recv_params(gnutls_session_t session,
					     const uint8_t * data,
					     size_t data_size);
static int _gnutls_supported_ecc_send_params(gnutls_session_t session,
					     gnutls_buffer_st * extdata);

static int _gnutls_supported_ecc_pf_recv_params(gnutls_session_t session,
						const uint8_t * data,
						size_t data_size);
static int _gnutls_supported_ecc_pf_send_params(gnutls_session_t session,
						gnutls_buffer_st *
						extdata);

const extension_entry_st ext_mod_supported_ecc = {
	.name = "Negotiated Groups",
	.tls_id = 10,
	.gid = GNUTLS_EXTENSION_SUPPORTED_ECC,
	.parse_type = GNUTLS_EXT_TLS,
	.validity = GNUTLS_EXT_FLAG_CLIENT_HELLO|GNUTLS_EXT_FLAG_EE|GNUTLS_EXT_FLAG_TLS12_SERVER_HELLO,

	.recv_func = _gnutls_supported_ecc_recv_params,
	.send_func = _gnutls_supported_ecc_send_params,
	.pack_func = NULL,
	.unpack_func = NULL,
	.deinit_func = NULL,
	.cannot_be_overriden = 1
};

const extension_entry_st ext_mod_supported_ecc_pf = {
	.name = "Supported ECC Point Formats",
	.tls_id = 11,
	.gid = GNUTLS_EXTENSION_SUPPORTED_ECC_PF,
	.parse_type = GNUTLS_EXT_TLS,
	.validity = GNUTLS_EXT_FLAG_CLIENT_HELLO|GNUTLS_EXT_FLAG_TLS12_SERVER_HELLO,

	.recv_func = _gnutls_supported_ecc_pf_recv_params,
	.send_func = _gnutls_supported_ecc_pf_send_params,
	.pack_func = NULL,
	.unpack_func = NULL,
	.deinit_func = NULL
};

static unsigned get_min_dh(gnutls_session_t session)
{
	gnutls_certificate_credentials_t cert_cred;
	gnutls_psk_server_credentials_t psk_cred;
	gnutls_anon_server_credentials_t anon_cred;
	unsigned level = 0;

	cert_cred = (gnutls_certificate_credentials_t)_gnutls_get_cred(session, GNUTLS_CRD_CERTIFICATE);
	psk_cred = (gnutls_psk_server_credentials_t)_gnutls_get_cred(session, GNUTLS_CRD_PSK);
	anon_cred = (gnutls_anon_server_credentials_t)_gnutls_get_cred(session, GNUTLS_CRD_ANON);

	if (cert_cred) {
		level = cert_cred->dh_sec_param;
	} else if (psk_cred) {
		level = psk_cred->dh_sec_param;
	} else if (anon_cred) {
		level = anon_cred->dh_sec_param;
	}

	if (level)
		return gnutls_sec_param_to_pk_bits(GNUTLS_PK_DH, level);

	return 0;
}

/* 
 * In case of a server: if a SUPPORTED_ECC extension type is received then it stores
 * into the session security parameters the new value. The server may use gnutls_session_certificate_type_get(),
 * to access it.
 *
 * In case of a client: If a supported_eccs have been specified then we send the extension.
 *
 */
static int
_gnutls_supported_ecc_recv_params(gnutls_session_t session,
				  const uint8_t * data, size_t _data_size)
{
	int ret, i;
	ssize_t data_size = _data_size;
	uint16_t len;
	const uint8_t *p = data;
	const gnutls_group_entry_st *group = NULL;
	unsigned have_ffdhe = 0;
	unsigned tls_id;
	unsigned min_dh;

	if (session->security_parameters.entity == GNUTLS_CLIENT) {
		/* A client shouldn't receive this extension in TLS1.2. It is
		 * possible to read that message under TLS1.3 as an encrypted
		 * extension. */
		return 0;
	} else {		/* SERVER SIDE - we must check if the sent supported ecc type is the right one 
				 */
		if (data_size < 2)
			return
			    gnutls_assert_val
			    (GNUTLS_E_RECEIVED_ILLEGAL_EXTENSION);

		DECR_LEN(data_size, 2);
		len = _gnutls_read_uint16(p);
		p += 2;

		if (len % 2 != 0)
			return gnutls_assert_val(GNUTLS_E_UNEXPECTED_PACKET_LENGTH);

		DECR_LEN(data_size, len);

		/* we figure what is the minimum DH allowed for this session, if any */
		min_dh = get_min_dh(session);

		/* This is being processed prior to a ciphersuite being selected */
		for (i = 0; i < len; i += 2) {
			if (have_ffdhe == 0 && p[i] == 0x01) {
				have_ffdhe = 1;
			}
			tls_id = _gnutls_read_uint16(&p[i]);
			group = _gnutls_tls_id_to_group(tls_id);

			_gnutls_handshake_log("EXT[%p]: Received group %s (0x%x)\n", session, group?group->name:"unknown", tls_id);
			if (group == NULL)
				continue;

			/* if a DH group and less than expected ignore */
			if (min_dh > 0 && group->prime && group->prime->size*8 < min_dh)
				continue;

			/* Check if we support this group */
			if ((ret =
			     _gnutls_session_supports_group(session,
							    group->id))
			    < 0) {
				group = NULL;
				continue;
			} else {
				if (group->pk == GNUTLS_PK_DH && session->internals.cand_dh_group == NULL)
					session->internals.cand_dh_group = group;
				else if (group->pk != GNUTLS_PK_DH && session->internals.cand_ec_group == NULL)
					session->internals.cand_ec_group = group;
			}
		}

		session->internals.have_ffdhe = have_ffdhe;
	}

	return 0;
}

/* returns data_size or a negative number on failure
 */
static int
_gnutls_supported_ecc_send_params(gnutls_session_t session,
				  gnutls_buffer_st * extdata)
{
	unsigned len, i;
	int ret;
	uint16_t p;

	/* this extension is only being sent on client side */
	if (session->security_parameters.entity == GNUTLS_CLIENT) {

		len = session->internals.priorities->groups.size;
		if (len > 0) {
			ret =
			    _gnutls_buffer_append_prefix(extdata, 16,
							 len * 2);
			if (ret < 0)
				return gnutls_assert_val(ret);

			for (i = 0; i < len; i++) {
				p = session->internals.priorities->groups.entry[i]->tls_id;

				_gnutls_handshake_log("EXT[%p]: sent group %s (0x%x)\n", session,
					session->internals.priorities->groups.entry[i]->name, (unsigned)p);

				ret =
				    _gnutls_buffer_append_prefix(extdata,
								 16, p);
				if (ret < 0)
					return gnutls_assert_val(ret);
			}
			return (len + 1) * 2;
		}

	}

	return 0;
}

/* 
 * In case of a server: if a SUPPORTED_ECC extension type is received then it stores
 * into the session security parameters the new value. The server may use gnutls_session_certificate_type_get(),
 * to access it.
 *
 * In case of a client: If a supported_eccs have been specified then we send the extension.
 *
 */
static int
_gnutls_supported_ecc_pf_recv_params(gnutls_session_t session,
				     const uint8_t * data,
				     size_t _data_size)
{
	int len, i;
	int uncompressed = 0;
	int data_size = _data_size;

	if (session->security_parameters.entity == GNUTLS_CLIENT) {
		if (data_size < 1)
			return
			    gnutls_assert_val
			    (GNUTLS_E_RECEIVED_ILLEGAL_EXTENSION);

		len = data[0];
		if (len < 1)
			return
			    gnutls_assert_val
			    (GNUTLS_E_RECEIVED_ILLEGAL_EXTENSION);

		DECR_LEN(data_size, len + 1);

		for (i = 1; i <= len; i++)
			if (data[i] == 0) {	/* uncompressed */
				uncompressed = 1;
				break;
			}

		if (uncompressed == 0)
			return
			    gnutls_assert_val
			    (GNUTLS_E_UNKNOWN_PK_ALGORITHM);
	} else {
		/* only sanity check here. We only support uncompressed points
		 * and a client must support it thus nothing to check.
		 */
		if (_data_size < 1)
			return
			    gnutls_assert_val
			    (GNUTLS_E_RECEIVED_ILLEGAL_EXTENSION);
	}

	return 0;
}

/* returns data_size or a negative number on failure
 */
static int
_gnutls_supported_ecc_pf_send_params(gnutls_session_t session,
				     gnutls_buffer_st * extdata)
{
	const uint8_t p[2] = { 0x01, 0x00 };	/* only support uncompressed point format */
	int ret;

	if (session->security_parameters.entity == GNUTLS_SERVER
	    && !_gnutls_session_is_ecc(session))
		return 0;

	if (session->internals.priorities->groups.size > 0) {
		ret = _gnutls_buffer_append_data(extdata, p, 2);
		if (ret < 0)
			return gnutls_assert_val(ret);

		return 2;
	}
	return 0;
}


/* Returns 0 if the given ECC curve is allowed in the current
 * session. A negative error value is returned otherwise.
 */
int
_gnutls_session_supports_group(gnutls_session_t session,
				unsigned int group)
{
	unsigned i;

	for (i = 0; i < session->internals.priorities->groups.size; i++) {
		if (session->internals.priorities->groups.entry[i]->id == group)
			return 0;
	}

	return GNUTLS_E_ECC_UNSUPPORTED_CURVE;
}
