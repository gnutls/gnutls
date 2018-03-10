/*
 * Copyright (C) 2017-2018 Red Hat, Inc.
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
#include <auth/cert.h>
#include <algorithms.h>
#include <ext/signature.h>
#include <abstract_int.h>
#include "tls13-sig.h"
#include "hash_int.h"

#undef PREFIX_SIZE
#define PREFIX_SIZE 64
#if PREFIX_SIZE < MAX_HASH_SIZE
/* we assume later that prefix is sufficient to store hash output */
# error Need to modify code
#endif

int
_gnutls13_handshake_verify_data(gnutls_session_t session,
			      unsigned verify_flags,
			      gnutls_pcert_st *cert,
			      const gnutls_datum_t *context,
			      const gnutls_datum_t *signature,
			      const gnutls_sign_entry_st *se)
{
	int ret;
	const version_entry_st *ver = get_version(session);
	gnutls_buffer_st buf;
	uint8_t prefix[PREFIX_SIZE];
	gnutls_datum_t p;

	_gnutls_handshake_log
	    ("HSK[%p]: verifying TLS 1.3 handshake data using %s\n", session,
	     se->name);

	ret =
	    _gnutls_pubkey_compatible_with_sig(session,
					       cert->pubkey, ver,
					       se->id);
	if (ret < 0)
		return gnutls_assert_val(ret);

	if (unlikely(sign_supports_cert_pk_algorithm(se, cert->pubkey->params.algo) == 0)) {
		_gnutls_handshake_log("HSK[%p]: certificate of %s cannot be combined with %s sig\n",
				      session, gnutls_pk_get_name(cert->pubkey->params.algo), se->name);
		return gnutls_assert_val(GNUTLS_E_RECEIVED_ILLEGAL_PARAMETER);
	}

	ret =
	    _gnutls_session_sign_algo_enabled(session, se->id);
	if (ret < 0)
		return gnutls_assert_val(ret);

	if (se->tls13_ok == 0) /* explicitly prohibited */
		return gnutls_assert_val(GNUTLS_E_RECEIVED_ILLEGAL_PARAMETER);

	_gnutls_buffer_init(&buf);

	memset(prefix, 0x20, sizeof(prefix));
	ret = _gnutls_buffer_append_data(&buf, prefix, sizeof(prefix));
	if (ret < 0) {
		gnutls_assert();
		goto cleanup;
	}

	ret = _gnutls_buffer_append_data(&buf, context->data, context->size);
	if (ret < 0) {
		gnutls_assert();
		goto cleanup;
	}

	ret = _gnutls_buffer_append_data(&buf, "\x00", 1);
	if (ret < 0) {
		gnutls_assert();
		goto cleanup;
	}

	ret = gnutls_hash_fast(session->security_parameters.prf->id,
			       session->internals.handshake_hash_buffer.data,
			       session->internals.handshake_hash_buffer_prev_len,
			       prefix);
	if (ret < 0) {
		gnutls_assert();
		goto cleanup;
	}

	ret = _gnutls_buffer_append_data(&buf, prefix, session->security_parameters.prf->output_size);
	if (ret < 0) {
		gnutls_assert();
		goto cleanup;
	}

	p.data = buf.data;
	p.size = buf.length;

	/* Here we intentionally enable flag GNUTLS_VERIFY_ALLOW_BROKEN
	 * because we have checked whether the currently used signature
	 * algorithm is allowed in the session. */
	ret = gnutls_pubkey_verify_data2(cert->pubkey, se->id,
					 verify_flags|GNUTLS_VERIFY_ALLOW_BROKEN,
					 &p, signature);
	if (ret < 0) {
		gnutls_assert();
		goto cleanup;
	}

	ret = 0;
 cleanup:
	_gnutls_buffer_clear(&buf);

	return ret;
}

int
_gnutls13_handshake_sign_data(gnutls_session_t session,
			      gnutls_pcert_st * cert, gnutls_privkey_t pkey,
			      const gnutls_datum_t *context,
			      gnutls_datum_t * signature,
			      const gnutls_sign_entry_st *se)
{
	gnutls_datum_t p;
	int ret;
	gnutls_buffer_st buf;
	uint8_t prefix[PREFIX_SIZE];

	if (unlikely(se == NULL || se->tls13_ok == 0))
		return gnutls_assert_val(GNUTLS_E_RECEIVED_ILLEGAL_PARAMETER);

	if (unlikely(sign_supports_priv_pk_algorithm(se, pkey->pk_algorithm) == 0))
		return gnutls_assert_val(GNUTLS_E_RECEIVED_ILLEGAL_PARAMETER);

	_gnutls_handshake_log
	    ("HSK[%p]: signing TLS 1.3 handshake data: using %s\n", session, se->name);

	_gnutls_buffer_init(&buf);

	memset(prefix, 0x20, sizeof(prefix));
	ret = _gnutls_buffer_append_data(&buf, prefix, sizeof(prefix));
	if (ret < 0) {
		gnutls_assert();
		goto cleanup;
	}

	ret = _gnutls_buffer_append_data(&buf, context->data, context->size);
	if (ret < 0) {
		gnutls_assert();
		goto cleanup;
	}

	ret = _gnutls_buffer_append_data(&buf, "\x00", 1);
	if (ret < 0) {
		gnutls_assert();
		goto cleanup;
	}

	ret = gnutls_hash_fast(session->security_parameters.prf->id,
			       session->internals.handshake_hash_buffer.data,
			       session->internals.handshake_hash_buffer.length,
			       prefix);
	if (ret < 0) {
		gnutls_assert();
		goto cleanup;
	}

	ret = _gnutls_buffer_append_data(&buf, prefix, session->security_parameters.prf->output_size);
	if (ret < 0) {
		gnutls_assert();
		goto cleanup;
	}

	p.data = buf.data;
	p.size = buf.length;

	ret = gnutls_privkey_sign_data2(pkey, se->id, 0, &p, signature);
	if (ret < 0) {
		gnutls_assert();
	}

	ret = 0;
 cleanup:
	_gnutls_buffer_clear(&buf);

	return ret;

}
