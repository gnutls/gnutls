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
#include "auth/cert.h"
#include "ext/signature.h"
#include "algorithms.h"
#include "tls13-sig.h"
#include "tls13/certificate_verify.h"

#define SRV_CTX "TLS 1.3, server CertificateVerify"
static const gnutls_datum_t srv_ctx = {
	(void*)SRV_CTX, sizeof(SRV_CTX)-1
};

int _gnutls13_recv_certificate_verify(gnutls_session_t session)
{
	int ret;
	gnutls_buffer_st buf;
	const gnutls_sign_entry_st *se;
	gnutls_datum_t sig_data;
	gnutls_certificate_credentials_t cred;
	unsigned vflags;
	gnutls_pcert_st peer_cert;
	cert_auth_info_t info = _gnutls_get_auth_info(session, GNUTLS_CRD_CERTIFICATE);

	memset(&peer_cert, 0, sizeof(peer_cert));

	cred = (gnutls_certificate_credentials_t)
		_gnutls_get_cred(session, GNUTLS_CRD_CERTIFICATE);
	if (unlikely(cred == NULL))
		return gnutls_assert_val(GNUTLS_E_INSUFFICIENT_CREDENTIALS);
	if (unlikely(info == NULL))
		return gnutls_assert_val(GNUTLS_E_INTERNAL_ERROR);

	ret = _gnutls_recv_handshake(session, GNUTLS_HANDSHAKE_CERTIFICATE_VERIFY, 0, &buf);
	if (ret < 0)
		return gnutls_assert_val(ret);

	_gnutls_handshake_log("HSK[%p]: parsing certificate verify\n", session);

	if (buf.length < 2) {
		gnutls_assert();
		ret = GNUTLS_E_UNEXPECTED_PACKET_LENGTH;
		goto cleanup;
	}

	se = _gnutls_tls_aid_to_sign_entry(buf.data[0], buf.data[1], get_version(session));
	if (se == NULL) {
		_gnutls_handshake_log("found unsupported signature (%d.%d)\n", (int)buf.data[0], (int)buf.data[1]);
		ret = gnutls_assert_val(GNUTLS_E_UNSUPPORTED_SIGNATURE_ALGORITHM);
		goto cleanup;
	}

	gnutls_sign_algorithm_set_server(session, se->id);

	buf.data+=2;
	buf.length-=2;

	/* we check during verification whether the algorithm is enabled */

	ret = _gnutls_buffer_pop_datum_prefix16(&buf, &sig_data);
	if (ret < 0) {
		gnutls_assert();
		goto cleanup;
	}

	if (sig_data.size == 0) {
		gnutls_assert();
		ret = GNUTLS_E_RECEIVED_ILLEGAL_PARAMETER;
		goto cleanup;
	}

	/* Verify the signature */
	ret = _gnutls_get_auth_info_pcert(&peer_cert, session->security_parameters.cert_type, info);
	if (ret < 0) {
		gnutls_assert();
		goto cleanup;
	}

	vflags = cred->verify_flags | session->internals.additional_verify_flags;

	ret = _gnutls13_handshake_verify_data(session, vflags, &peer_cert, &srv_ctx, &sig_data, se);
	if (ret < 0) {
		gnutls_assert();
		goto cleanup;
	}

	if (buf.length > 0) {
		gnutls_assert();
		ret = GNUTLS_E_UNEXPECTED_PACKET_LENGTH;
		goto cleanup;
	}

	ret = 0;
 cleanup:
	gnutls_pcert_deinit(&peer_cert);
	_gnutls_buffer_clear(&buf);
	return ret;
}

int _gnutls13_send_certificate_verify(gnutls_session_t session)
{
	return 0;
}
