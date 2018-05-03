/*
 * Copyright (C) 2017-2018 Free Software Foundation, Inc.
 * Copyright (C) 2018 Red Hat, Inc.
 *
 * Author: Ander Juaristi, Nikos Mavrogiannopoulos
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
#include "auth/psk.h"
#include "secrets.h"
#include "tls13/psk_ext_parser.h"
#include "tls13/finished.h"
#include "auth/psk_passwd.h"
#include <ext/pre_shared_key.h>
#include <assert.h>

static int
compute_binder_key(const mac_entry_st *prf,
		const uint8_t *key, size_t keylen,
		void *out)
{
	int ret;
	char label[] = "ext binder";
	size_t label_len = sizeof(label) - 1;
	uint8_t tmp_key[MAX_HASH_SIZE];

	/* Compute HKDF-Extract(0, psk) */
	ret = _tls13_init_secret2(prf, key, keylen, tmp_key);
	if (ret < 0)
		return ret;

	/* Compute Derive-Secret(secret, label, transcript_hash) */
	ret = _tls13_derive_secret2(prf,
			label, label_len,
			NULL, 0,
			tmp_key,
			out);
	if (ret < 0)
		return ret;

	return 0;
}

static int
compute_psk_binder(gnutls_session_t session,
		const mac_entry_st *prf, unsigned binders_length, unsigned hash_size,
		int exts_length, int ext_offset,
		const gnutls_datum_t *psk, const gnutls_datum_t *client_hello,
		void *out)
{
	int ret;
	unsigned client_hello_pos, extensions_len_pos;
	gnutls_buffer_st handshake_buf;
	uint8_t binder_key[MAX_HASH_SIZE];

	_gnutls_buffer_init(&handshake_buf);

	if (session->security_parameters.entity == GNUTLS_CLIENT) {
		if (session->internals.hsk_flags & HSK_HRR_RECEIVED) {
			ret = gnutls_buffer_append_data(&handshake_buf,
							(const void *) session->internals.handshake_hash_buffer.data,
							session->internals.handshake_hash_buffer.length);
			if (ret < 0) {
				gnutls_assert();
				goto error;
			}
		}

		client_hello_pos = handshake_buf.length;
		ret = gnutls_buffer_append_data(&handshake_buf,
				(const void *)  client_hello->data,
				client_hello->size);
		if (ret < 0) {
			gnutls_assert();
			goto error;
		}

		/* This is a ClientHello message */
		handshake_buf.data[client_hello_pos] = GNUTLS_HANDSHAKE_CLIENT_HELLO;

		/*
		 * At this point we have not yet added the binders to the ClientHello,
		 * but we have to overwrite the size field, pretending as if binders
		 * of the correct length were present.
		 */
		_gnutls_write_uint24(handshake_buf.length - client_hello_pos + binders_length - 2, &handshake_buf.data[client_hello_pos + 1]);
		_gnutls_write_uint16(handshake_buf.length - client_hello_pos + binders_length - ext_offset,
				&handshake_buf.data[client_hello_pos + ext_offset]);

		extensions_len_pos = handshake_buf.length - client_hello_pos - exts_length - 2;
		_gnutls_write_uint16(exts_length + binders_length + 2,
				&handshake_buf.data[client_hello_pos + extensions_len_pos]);
	} else {
		if (session->internals.hsk_flags & HSK_HRR_SENT) {
			if (unlikely(session->internals.handshake_hash_buffer.length <= client_hello->size)) {
				ret = gnutls_assert_val(GNUTLS_E_RECEIVED_ILLEGAL_PARAMETER);
				goto error;
			}

			ret = gnutls_buffer_append_data(&handshake_buf,
							(const void *) session->internals.handshake_hash_buffer.data,
							session->internals.handshake_hash_buffer.length - client_hello->size);
			if (ret < 0) {
				gnutls_assert();
				goto error;
			}
		}

		if (unlikely(client_hello->size <= binders_length)) {
			ret = gnutls_assert_val(GNUTLS_E_RECEIVED_ILLEGAL_PARAMETER);
			goto error;
		}

		ret = gnutls_buffer_append_data(&handshake_buf,
						(const void *) client_hello->data,
						client_hello->size - binders_length);
		if (ret < 0) {
			gnutls_assert();
			goto error;
		}
	}

	ret = compute_binder_key(prf,
				 psk->data, psk->size,
				 binder_key);
	if (ret < 0) {
		gnutls_assert();
		goto error;
	}

	ret = _gnutls13_compute_finished(prf, binder_key,
					 hash_size,
					 &handshake_buf,
					 out);
	if (ret < 0) {
		gnutls_assert();
		goto error;
	}

	ret = 0;
error:
	_gnutls_buffer_clear(&handshake_buf);
	return ret;
}

static int
client_send_params(gnutls_session_t session,
		   gnutls_buffer_t extdata,
		   const gnutls_psk_client_credentials_t cred)
{
	int ret, ext_offset = 0;
	uint8_t binder_value[MAX_HASH_SIZE];
	size_t length, pos;
	gnutls_datum_t username = {NULL, 0}, key = {NULL, 0}, client_hello;
	const mac_entry_st *prf = cred->binder_algo;
	unsigned hash_size = _gnutls_mac_get_algo_len(prf);
	int free_data;

	if (prf == NULL || hash_size == 0 || hash_size > 255)
		return gnutls_assert_val(GNUTLS_E_INSUFFICIENT_CREDENTIALS);

	/* Credentials but no username set - this extension is not applicable */
	if (!_gnutls_have_psk_credentials(cred))
		return 0;

	ret = _gnutls_find_psk_key(session, cred, &username, &key, &free_data);
	if (ret < 0)
		return gnutls_assert_val(ret);

	if (username.size == 0 || username.size > UINT16_MAX) {
		ret = gnutls_assert_val(GNUTLS_E_INVALID_PASSWORD);
		goto cleanup;
	}

	/* placeholder to be filled later */
	pos = extdata->length;
	ret = _gnutls_buffer_append_prefix(extdata, 16, 0);
	if (ret < 0) {
		gnutls_assert_val(ret);
		goto cleanup;
	}

	if ((ret = _gnutls_buffer_append_data_prefix(extdata, 16,
			username.data, username.size)) < 0) {
		gnutls_assert();
		goto cleanup;
	}

	/* Now append the ticket age, which is always zero for out-of-band PSKs */
	if ((ret = _gnutls_buffer_append_prefix(extdata, 32, 0)) < 0) {
		gnutls_assert();
		goto cleanup;
	}
	/* Total length appended is the length of the data, plus six octets */
	length = (username.size + 6);

	_gnutls_write_uint16(length, &extdata->data[pos]);

	ext_offset = _gnutls_ext_get_extensions_offset(session);

	/* Compute the binders. extdata->data points to the start
	 * of this client hello. */
	assert(extdata->length >= sizeof(mbuffer_st));
	assert(ext_offset >= (ssize_t)sizeof(mbuffer_st));
	ext_offset -= sizeof(mbuffer_st);
	client_hello.data = extdata->data+sizeof(mbuffer_st);
	client_hello.size = extdata->length-sizeof(mbuffer_st);

	ret = compute_psk_binder(session, prf,
				 hash_size+1, hash_size, extdata->length-pos,
				 ext_offset, &key, &client_hello,
				 binder_value);
	if (ret < 0) {
		gnutls_assert();
		goto cleanup;
	}

	/* Associate the selected pre-shared key with the session */
	session->key.psk.data = key.data;
	session->key.psk.size = key.size;
	session->key.psk_needs_free = free_data;
	key.data = NULL;
	session->key.proto.tls13.binder_prf = prf;

	/* Now append the binders */
	ret = _gnutls_buffer_append_prefix(extdata, 16, hash_size+1);
	if (ret < 0) {
		gnutls_assert();
		goto cleanup;
	}

	/* Add the size of the binder (we only have one) */
	ret = _gnutls_buffer_append_data_prefix(extdata, 8, binder_value, hash_size);
	if (ret < 0) {
		gnutls_assert();
		goto cleanup;
	}

	ret = 0;

cleanup:
	if (free_data) {
		_gnutls_free_datum(&username);
		_gnutls_free_temp_key_datum(&key);
	}
	return ret;
}

static int
server_send_params(gnutls_session_t session, gnutls_buffer_t extdata)
{
	int ret;

	if (!(session->internals.hsk_flags & HSK_PSK_SELECTED))
		return 0;

	ret = _gnutls_buffer_append_prefix(extdata, 16,
			session->key.proto.tls13.psk_index);
	if (ret < 0)
		return gnutls_assert_val(ret);

	return 2;
}

static int server_recv_params(gnutls_session_t session,
			      const unsigned char *data, size_t len,
			      const gnutls_psk_server_credentials_t pskcred)
{
	int ret;
	const mac_entry_st *prf;
	gnutls_datum_t full_client_hello;
	uint8_t binder_value[MAX_HASH_SIZE];
	int psk_index = -1;
	gnutls_datum_t binder_recvd = { NULL, 0 };
	gnutls_datum_t key = {NULL, 0};
	unsigned hash_size, cand_index;
	psk_ext_parser_st psk_parser;
	struct psk_st psk;
	psk_auth_info_t info;

	ret = _gnutls13_psk_ext_parser_init(&psk_parser, data, len);
	if (ret < 0) {
		if (ret == GNUTLS_E_REQUESTED_DATA_NOT_AVAILABLE) /* No PSKs advertised by client */
			return 0;
		return gnutls_assert_val(ret);
	}

	while ((ret = _gnutls13_psk_ext_parser_next_psk(&psk_parser, &psk)) >= 0) {
		if (psk.ob_ticket_age == 0) {
			cand_index = ret;

			/* _gnutls_psk_pwd_find_entry() expects 0-terminated identities */
			if (psk.identity.size > 0 && psk.identity.size <= MAX_USERNAME_SIZE) {
				char identity_str[psk.identity.size + 1];

				memcpy(identity_str, psk.identity.data, psk.identity.size);
				identity_str[psk.identity.size] = 0;

				ret = _gnutls_psk_pwd_find_entry(session, identity_str, &key);
				if (ret < 0)
					return gnutls_assert_val(ret);

				psk_index = cand_index;
				break;
			}
		}
	}

	if (psk_index < 0)
		return 0;

	ret = _gnutls13_psk_ext_parser_find_binder(&psk_parser, psk_index,
						   &binder_recvd);
	if (ret < 0) {
		gnutls_assert();
		goto fail;
	}

	/* Get full ClientHello */
	if (!_gnutls_ext_get_full_client_hello(session, &full_client_hello)) {
		ret = GNUTLS_E_INTERNAL_ERROR;
		gnutls_assert();
		goto fail;
	}

	/* Compute the binder value for this PSK */
	prf = pskcred->binder_algo;
	hash_size = prf->output_size;
	ret = compute_psk_binder(session, prf, psk_parser.binder_len+2, hash_size, 0, 0,
				 &key, &full_client_hello,
				 binder_value);
	if (ret < 0) {
		gnutls_assert();
		goto fail;
	}

	if (_gnutls_mac_get_algo_len(prf) != binder_recvd.size ||
	    safe_memcmp(binder_value, binder_recvd.data, binder_recvd.size)) {
		gnutls_assert();
		ret = GNUTLS_E_RECEIVED_ILLEGAL_PARAMETER;
		goto fail;
	}

	if (session->internals.hsk_flags & HSK_PSK_KE_MODE_DHE_PSK)
		_gnutls_handshake_log("EXT[%p]: Selected DHE-PSK mode\n", session);
	else {
		reset_cand_groups(session);
		_gnutls_handshake_log("EXT[%p]: Selected PSK mode\n", session);
	}

	/* save the username in psk_auth_info to make it available
	 * using gnutls_psk_server_get_username() */
	if (psk.ob_ticket_age == 0) {
		if (psk.identity.size >= sizeof(info->username)) {
			gnutls_assert();
			ret = GNUTLS_E_RECEIVED_ILLEGAL_PARAMETER;
			goto fail;
		}

		ret = _gnutls_auth_info_set(session, GNUTLS_CRD_PSK, sizeof(psk_auth_info_st), 1);
		if (ret < 0) {
			gnutls_assert();
			goto fail;
		}

		info = _gnutls_get_auth_info(session, GNUTLS_CRD_PSK);
		assert(info != NULL);

		memcpy(info->username, psk.identity.data, psk.identity.size);
		info->username[psk.identity.size] = 0;
		_gnutls_handshake_log("EXT[%p]: Selected PSK identity: %s\n", session, info->username);
	}

	session->internals.hsk_flags |= HSK_PSK_SELECTED;

	/* Reference the selected pre-shared key */
	session->key.psk.data = key.data;
	session->key.psk.size = key.size;
	session->key.psk_needs_free = 1;

	session->key.proto.tls13.psk_index = psk_index;
	session->key.proto.tls13.binder_prf = prf;

	return 0;

 fail:
	gnutls_free(key.data);
	return ret;
}

/*
 * Return values for this function:
 *  -  0 : Not applicable.
 *  - >0 : Ok. Return size of extension data.
 *  - GNUTLS_E_INT_RET_0 : Size of extension data is zero.
 *  - <0 : There's been an error.
 *
 * In the client, generates the PskIdentity and PskBinderEntry messages.
 *
 *      PskIdentity identities<7..2^16-1>;
 *      PskBinderEntry binders<33..2^16-1>;
 *
 *      struct {
 *          opaque identity<1..2^16-1>;
 *          uint32 obfuscated_ticket_age;
 *      } PskIdentity;
 *
 *      opaque PskBinderEntry<32..255>;
 *
 * The server sends the selected identity, which is a zero-based index
 * of the PSKs offered by the client:
 *
 *      struct {
 *          uint16 selected_identity;
 *      } PreSharedKeyExtension;
 */
static int _gnutls_psk_send_params(gnutls_session_t session,
				   gnutls_buffer_t extdata)
{
	gnutls_psk_client_credentials_t cred = NULL;
	const version_entry_st *vers;

	if (session->security_parameters.entity == GNUTLS_CLIENT) {
		vers = _gnutls_version_max(session);

		if (!vers || !vers->tls13_sem)
			return 0;

		if (session->internals.hsk_flags & HSK_PSK_KE_MODES_SENT) {
			cred = (gnutls_psk_client_credentials_t)
					_gnutls_get_cred(session, GNUTLS_CRD_PSK);
			/* If there are no PSK credentials, this extension is not applicable,
			 * so we return zero. */
			if (cred == NULL || !session->internals.priorities->have_psk)
				return 0;

			return client_send_params(session, extdata, cred);
		} else {
			return 0;
		}
	} else {
		vers = get_version(session);

		if (!vers || !vers->tls13_sem)
			return 0;

		cred = (gnutls_psk_client_credentials_t)
				_gnutls_get_cred(session, GNUTLS_CRD_PSK);
		if (cred == NULL || !session->internals.priorities->have_psk)
			return 0;

		if (session->internals.hsk_flags & HSK_PSK_KE_MODES_RECEIVED)
			return server_send_params(session, extdata);
		else
			return 0;
	}
}

/*
 * Return values for this function:
 *  -  0 : Not applicable.
 *  - >0 : Ok. Return size of extension data.
 *  - <0 : There's been an error.
 */
static int _gnutls_psk_recv_params(gnutls_session_t session,
				   const unsigned char *data, size_t len)
{
	gnutls_psk_server_credentials_t pskcred;
	const version_entry_st *vers = get_version(session);

	if (!vers || !vers->tls13_sem)
		return 0;

	if (session->security_parameters.entity == GNUTLS_CLIENT) {
		if (session->internals.hsk_flags & HSK_PSK_KE_MODES_SENT) {
			uint16_t selected_identity = _gnutls_read_uint16(data);

			if (selected_identity == 0) {
				_gnutls_handshake_log("EXT[%p]: Selected PSK mode\n", session);
				session->internals.hsk_flags |= HSK_PSK_SELECTED;
			}
			return 0;
		} else {
			return gnutls_assert_val(GNUTLS_E_RECEIVED_ILLEGAL_EXTENSION);
		}
	} else {
		if (session->internals.hsk_flags & HSK_PSK_KE_MODES_RECEIVED) {
			if (session->internals.hsk_flags & HSK_PSK_KE_MODE_INVALID) {
				/* We received a "psk_ke_modes" extension, but with a value we don't support */
				return 0;
			}

			pskcred = (gnutls_psk_server_credentials_t)
					_gnutls_get_cred(session, GNUTLS_CRD_PSK);

			/* If there are no PSK credentials, this extension is not applicable,
			 * so we return zero. */
			if (pskcred == NULL)
				return 0;

			return server_recv_params(session, data, len, pskcred);
		} else {
			return gnutls_assert_val(GNUTLS_E_RECEIVED_ILLEGAL_EXTENSION);
		}
	}
}

const hello_ext_entry_st ext_pre_shared_key = {
	.name = "Pre Shared Key",
	.tls_id = 41,
	.gid = GNUTLS_EXTENSION_PRE_SHARED_KEY,
	.parse_type = GNUTLS_EXT_TLS,
	.validity = GNUTLS_EXT_FLAG_TLS | GNUTLS_EXT_FLAG_CLIENT_HELLO | GNUTLS_EXT_FLAG_TLS13_SERVER_HELLO,
	.send_func = _gnutls_psk_send_params,
	.recv_func = _gnutls_psk_recv_params
};
