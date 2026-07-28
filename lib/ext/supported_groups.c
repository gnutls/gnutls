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
 * along with this program.  If not, see <https://www.gnu.org/licenses/>
 *
 */

/* This file contains the code for the Supported Groups extension (rfc7919).
 * This extension was previously named Supported Elliptic Curves under TLS 1.2.
 */

#include "ext/supported_groups.h"
#include "str.h"
#include "num.h"
#include "auth/psk.h"
#include "auth/cert.h"
#include "auth/anon.h"
#include "algorithms.h"
#include <gnutls/gnutls.h>

static int _gnutls_supported_groups_recv_params(gnutls_session_t session,
						const uint8_t *data,
						size_t data_size);
static int _gnutls_supported_groups_send_params(gnutls_session_t session,
						gnutls_buffer_st *extdata);

const hello_ext_entry_st ext_mod_supported_groups = {
	.name = "Supported Groups",
	.tls_id = 10,
	.gid = GNUTLS_EXTENSION_SUPPORTED_GROUPS,
	.client_parse_point = GNUTLS_EXT_TLS,
	.server_parse_point = GNUTLS_EXT_TLS,
	.validity = GNUTLS_EXT_FLAG_TLS | GNUTLS_EXT_FLAG_DTLS |
		    GNUTLS_EXT_FLAG_CLIENT_HELLO | GNUTLS_EXT_FLAG_EE |
		    GNUTLS_EXT_FLAG_TLS12_SERVER_HELLO,
	.recv_func = _gnutls_supported_groups_recv_params,
	.send_func = _gnutls_supported_groups_send_params,
	.pack_func = NULL,
	.unpack_func = NULL,
	.deinit_func = NULL,
	.cannot_be_overriden = 1
};

#ifdef ENABLE_DHE
static unsigned get_min_dh_bits(gnutls_session_t session)
{
	gnutls_certificate_credentials_t cert_cred;
	gnutls_psk_server_credentials_t psk_cred;
	gnutls_anon_server_credentials_t anon_cred;
	unsigned level = 0;

	cert_cred = (gnutls_certificate_credentials_t)_gnutls_get_cred(
		session, GNUTLS_CRD_CERTIFICATE);
	psk_cred = (gnutls_psk_server_credentials_t)_gnutls_get_cred(
		session, GNUTLS_CRD_PSK);
	anon_cred = (gnutls_anon_server_credentials_t)_gnutls_get_cred(
		session, GNUTLS_CRD_ANON);

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
#endif

enum group_class_t {
	GROUP_CLASS_UNKNOWN,
	GROUP_CLASS_DH,
	GROUP_CLASS_EC,
	GROUP_CLASS_HYBRID,
	GROUP_CLASS_MIN = GROUP_CLASS_DH,
	GROUP_CLASS_MAX = GROUP_CLASS_HYBRID
};

static enum group_class_t classify_group(const gnutls_group_entry_st *group)
{
	if (group->pk == GNUTLS_PK_DH) {
		return GROUP_CLASS_DH;
	} else if (IS_EC(group->pk)) {
		return GROUP_CLASS_EC;
	} else if (IS_GROUP_HYBRID(group)) {
		return GROUP_CLASS_HYBRID;
	}
	return GROUP_CLASS_UNKNOWN;
}

#define NOT_FOUND SIZE_MAX

static size_t find_group(const group_list_st *groups,
			 const gnutls_group_entry_st *group)
{
	for (size_t i = 0; i < groups->size; i++) {
		if (groups->entry[i]->id == group->id)
			return i;
	}
	return NOT_FOUND;
}

static int server_recv_params(gnutls_session_t session, const uint8_t *data,
			      size_t data_size)
{
	if (data_size < 2)
		return gnutls_assert_val(GNUTLS_E_RECEIVED_ILLEGAL_EXTENSION);

	DECR_LEN(data_size, 2);
	uint16_t len = _gnutls_read_uint16(data);
	data += 2;

	if (len != data_size)
		return gnutls_assert_val(GNUTLS_E_UNEXPECTED_PACKET_LENGTH);

#ifdef ENABLE_DHE
	/* Figure the minimum DH allowed for this session, if any */
	unsigned min_dh_bits = get_min_dh_bits(session);
#endif

	size_t cpos_by_class[GROUP_CLASS_MAX + 1];
	size_t spos_by_class[GROUP_CLASS_MAX + 1];

	for (enum group_class_t c = GROUP_CLASS_MIN; c <= GROUP_CLASS_MAX;
	     c++) {
		cpos_by_class[c] = NOT_FOUND;
		spos_by_class[c] = NOT_FOUND;
	}

	size_t cpos, spos;

	/* This extension is being processed prior to a ciphersuite
	 * being selected, so we cannot rely on ciphersuite
	 * information. */
	for (cpos = 0; data_size > 0; cpos++) {
		DECR_LEN(data_size, 2);
		uint16_t tls_id = _gnutls_read_uint16(data);
		data += 2;

		/* Check if tls_id is in the FFDH range, even if it is
		 * unknown to the server. This must be done before
		 * group resolution to fail ciphersuite selection. */
		if (256 <= tls_id && tls_id <= 511)
			session->internals.hsk_flags |= HSK_HAVE_FFDHE;

		const gnutls_group_entry_st *group =
			_gnutls_tls_id_to_group(tls_id);

		if (group == NULL) {
			_gnutls_handshake_log(
				"EXT[%p]: Received unknown group (0x%x)\n",
				session, tls_id);
			continue;
		} else {
			_gnutls_handshake_log(
				"EXT[%p]: Received group %s (0x%x)\n", session,
				group->name, tls_id);
		}

#ifdef ENABLE_DHE
		if (group->pk == GNUTLS_PK_DH) {
			if (min_dh_bits > 0 &&
			    group->prime->size * 8 < min_dh_bits)
				continue;
		}
#endif

		enum group_class_t c = classify_group(group);
		if (c == GROUP_CLASS_UNKNOWN) {
			_gnutls_debug_log(
				"EXT[%p]: Cannot classify group: %s\n", session,
				group->name);
			continue;
		}

		spos = find_group(&session->internals.priorities->groups,
				  group);
		if (spos == NOT_FOUND) {
			_gnutls_debug_log(
				"EXT[%p]: Skipping group %s not found in server priorities\n",
				session, group->name);
			continue;
		}

		/* %SERVER_PRECEDENCE is set and the previous entry
		 * has a lower priority, or it is the first time this
		 * group class appears in the client advertisement. */
		if (session->internals.priorities->server_precedence ?
			    spos < spos_by_class[c] :
			    cpos_by_class[c] == NOT_FOUND) {
			cpos_by_class[c] = cpos;
			spos_by_class[c] = spos;
		}
	}

	/* If there is any FFDH or EC group, record it for later
	 * fallback after ciphersuite selection. */
	if (spos_by_class[GROUP_CLASS_DH] != NOT_FOUND) {
		session->internals.cand_dh_group =
			session->internals.priorities->groups
				.entry[spos_by_class[GROUP_CLASS_DH]];
	}

	if (spos_by_class[GROUP_CLASS_EC] != NOT_FOUND) {
		session->internals.cand_ec_group =
			session->internals.priorities->groups
				.entry[spos_by_class[GROUP_CLASS_EC]];
	}

	/* Now pick the group with the highest priority. */
	cpos = spos = NOT_FOUND;
	if (session->internals.priorities->server_precedence) {
		for (enum group_class_t c = GROUP_CLASS_MIN;
		     c <= GROUP_CLASS_MAX; c++) {
			if (spos_by_class[c] < spos)
				spos = spos_by_class[c];
		}
	} else {
		for (enum group_class_t c = GROUP_CLASS_MIN;
		     c <= GROUP_CLASS_MAX; c++) {
			if (cpos_by_class[c] < cpos) {
				cpos = cpos_by_class[c];
				spos = spos_by_class[c];
			}
		}
	}
	if (spos != NOT_FOUND) {
		session->internals.cand_group =
			session->internals.priorities->groups.entry[spos];
		_gnutls_handshake_log("EXT[%p]: Selected group %s\n", session,
				      session->internals.cand_group->name);
	} else {
		_gnutls_handshake_log("EXT[%p]: No group selected\n", session);
	}

	return 0;
}

static int _gnutls_supported_groups_recv_params(gnutls_session_t session,
						const uint8_t *data,
						size_t data_size)
{
	switch (session->security_parameters.entity) {
	case GNUTLS_CLIENT:
		/* A client shouldn't receive this extension in TLS
		 * 1.2. It is possible to read that message under
		 * TLS 1.3 as an encrypted extension. */
		return 0;
	case GNUTLS_SERVER:
		return server_recv_params(session, data, data_size);
	}
}

/* returns data_size or a negative number on failure
 */
static int _gnutls_supported_groups_send_params(gnutls_session_t session,
						gnutls_buffer_st *extdata)
{
	unsigned len, i;
	int ret;
	uint16_t p;

	/* this extension is only being sent on client side */
	if (session->security_parameters.entity == GNUTLS_CLIENT) {
		len = session->internals.priorities->groups.size;
		if (len > 0) {
			ret = _gnutls_buffer_append_prefix(extdata, 16,
							   len * 2);
			if (ret < 0)
				return gnutls_assert_val(ret);

			for (i = 0; i < len; i++) {
				p = session->internals.priorities->groups
					    .entry[i]
					    ->tls_id;

				_gnutls_handshake_log(
					"EXT[%p]: Sent group %s (0x%x)\n",
					session,
					session->internals.priorities->groups
						.entry[i]
						->name,
					(unsigned)p);

				ret = _gnutls_buffer_append_prefix(extdata, 16,
								   p);
				if (ret < 0)
					return gnutls_assert_val(ret);
			}
			return (len + 1) * 2;
		}
	}

	return 0;
}

/* Returns 0 if the given ECC curve is allowed in the current
 * session. A negative error value is returned otherwise.
 */
bool _gnutls_session_supports_group(gnutls_session_t session,
				    unsigned int group)
{
	unsigned i;

	for (i = 0; i < session->internals.priorities->groups.size; i++) {
		if (session->internals.priorities->groups.entry[i]->id == group)
			return true;
	}

	return false;
}
