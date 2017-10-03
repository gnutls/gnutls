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
#include "algorithms.h"
#include "auth/cert.h"

typedef struct crt_req_ctx_st {
	gnutls_session_t session;
	gnutls_pk_algorithm_t pk_algos[MAX_ALGOS];
	unsigned pk_algos_length;
	uint8_t *rdn;
	unsigned rdn_size;
} crt_req_ctx_st;

static unsigned is_algo_in_list(gnutls_pk_algorithm_t algo, gnutls_pk_algorithm_t *list, unsigned list_size)
{
	unsigned j;

	for (j=0;j<list_size;j++) {
		if (list[j] == algo)
			return 1;
	}
	return 0;
}

static
int parse_cert_extension(void *_ctx, uint16_t tls_id, const uint8_t *data, int data_size)
{
	crt_req_ctx_st *ctx = _ctx;
	gnutls_session_t session = ctx->session;
	int ret;

	/* Decide which certificate to use if the signature algorithms extension
	 * is present.
	 */
	if (tls_id == ext_mod_sig.tls_id) {
		const version_entry_st *ver = get_version(session);
		const gnutls_sign_entry_st *se;
		/* signature algorithms; let's use it to decide the certificate to use */
		unsigned i;

		if (session->internals.hsk_flags & HSK_CRT_REQ_GOT_SIG_ALGO)
			return gnutls_assert_val(GNUTLS_E_RECEIVED_ILLEGAL_EXTENSION);

		session->internals.hsk_flags |= HSK_CRT_REQ_GOT_SIG_ALGO;

		ret = _gnutls_sign_algorithm_parse_data(session, data, data_size);
		if (ret < 0)
			return gnutls_assert_val(ret);

		/* The APIs to retrieve a client certificate accept the public
		 * key algorithms instead of signatures. Get the public key algorithms
		 * from the signatures.
		 */
		for (i=0;i<(unsigned)data_size;i+=2) {
			se = _gnutls_tls_aid_to_sign_entry(data[i], data[i+1], ver);
			if (se == NULL)
				continue;

			if (ctx->pk_algos_length >= sizeof(ctx->pk_algos)/sizeof(ctx->pk_algos[0]))
				break;

			if (is_algo_in_list(se->pk, ctx->pk_algos, ctx->pk_algos_length))
				continue;

			ctx->pk_algos[ctx->pk_algos_length++] = se->pk;
		}
	}

	return 0;
}

int _gnutls13_recv_certificate_request(gnutls_session_t session)
{
	int ret;
	gnutls_buffer_st buf;
	crt_req_ctx_st ctx;

	if (unlikely(session->security_parameters.entity != GNUTLS_CLIENT))
		return gnutls_assert_val(GNUTLS_E_INTERNAL_ERROR);

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
		ret = GNUTLS_E_RECEIVED_ILLEGAL_PARAMETER;
		gnutls_assert();
		goto cleanup;
	}

	/* buf.length is positive */
	buf.data++;
	buf.length--;

	memset(&ctx, 0, sizeof(ctx));
	ctx.session = session;

	ret = _gnutls_extv_parse(&ctx, parse_cert_extension, buf.data, buf.length);
	if (ret < 0) {
		gnutls_assert();
		goto cleanup;
	}

	session->internals.crt_requested = 1;

	ret = _gnutls_select_client_cert(session, ctx.rdn, ctx.rdn_size,
					 ctx.pk_algos, ctx.pk_algos_length);
	if (ret < 0) {
		gnutls_assert();
		goto cleanup;
	}

	session->internals.hsk_flags |= HSK_CRT_ASKED;

	ret = 0;

 cleanup:
	_gnutls_buffer_clear(&buf);
	gnutls_free(ctx.rdn);
	return ret;
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

