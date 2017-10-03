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
#include "tls13/certificate.h"
#include "auth/cert.h"
#include "mbuffers.h"

static int parse_cert_extension(void *ctx, uint16_t tls_id, const uint8_t *data, int data_size);
static int parse_cert_list(gnutls_session_t session, uint8_t * data, size_t data_size);

int _gnutls13_recv_certificate(gnutls_session_t session)
{
	int ret;
	gnutls_buffer_st buf;
	unsigned optional = 0;

	if (session->security_parameters.entity == GNUTLS_SERVER) {
		/* if we didn't request a certificate, there will not be any */
		if (session->internals.send_cert_req == 0)
			return 0;

		if (session->internals.send_cert_req != GNUTLS_CERT_REQUIRE)
			optional = 1;
	}

	ret = _gnutls_recv_handshake(session, GNUTLS_HANDSHAKE_CERTIFICATE_PKT, optional, &buf);
	if (ret < 0) {
		if (ret == GNUTLS_E_UNEXPECTED_HANDSHAKE_PACKET && session->internals.send_cert_req)
			return gnutls_assert_val(GNUTLS_E_NO_CERTIFICATE_FOUND);

		return gnutls_assert_val(ret);
	}

	if (buf.length == 0 && optional) {
		return 0;
	}

	if (buf.data[0] != 0) {
		/* The context field must be empty during handshake */
		gnutls_assert();
		ret = GNUTLS_E_RECEIVED_ILLEGAL_PARAMETER;
		goto cleanup;
	}

	/* buf.length is positive */
	buf.data++;
	buf.length--;

	_gnutls_handshake_log("HSK[%p]: parsing certificate message\n", session);

	ret = parse_cert_list(session, buf.data, buf.length);
	if (ret < 0) {
		gnutls_assert();
		goto cleanup;
	}

	session->internals.hsk_flags |= HSK_CRT_VRFY_EXPECTED;

	ret = 0;
cleanup:

	_gnutls_buffer_clear(&buf);
	return ret;
}

int _gnutls13_send_certificate(gnutls_session_t session, unsigned again)
{
	int ret;
	gnutls_pcert_st *apr_cert_list;
	gnutls_privkey_t apr_pkey;
	int apr_cert_list_length;
	mbuffer_st *bufel = NULL;
	gnutls_buffer_st buf;
	unsigned pos_mark;
	unsigned i;

	if (again == 0) {
		ret = _gnutls_get_selected_cert(session, &apr_cert_list,
						&apr_cert_list_length, &apr_pkey);
		if (ret < 0)
			return gnutls_assert_val(ret);

		if (session->security_parameters.entity == GNUTLS_CLIENT) {
			/* if we didn't get a cert request there will not be any */
			if (apr_cert_list_length == 0 ||
			    !(session->internals.hsk_flags & HSK_CRT_ASKED)) {
				return 0;
			}
		}

		ret = _gnutls_buffer_init_handshake_mbuffer(&buf);
		if (ret < 0)
			return gnutls_assert_val(ret);

		ret = _gnutls_buffer_append_prefix(&buf, 8, 0);
		if (ret < 0) {
			gnutls_assert();
			goto cleanup;
		}

		/* mark total size */
		pos_mark = buf.length;
		ret = _gnutls_buffer_append_prefix(&buf, 24, 0);
		if (ret < 0) {
			gnutls_assert();
			goto cleanup;
		}

		for (i=0;i<(unsigned)apr_cert_list_length;i++) {
			ret = _gnutls_buffer_append_data_prefix(&buf, 24,
								apr_cert_list[i].cert.data,
								apr_cert_list[i].cert.size);
			if (ret < 0) {
				gnutls_assert();
				goto cleanup;
			}

			/* no extensions for now */
			ret = _gnutls_buffer_append_prefix(&buf, 16, 0);
			if (ret < 0) {
				gnutls_assert();
				goto cleanup;
			}
		}

		_gnutls_write_uint24(buf.length-pos_mark-3, &buf.data[pos_mark]);

		bufel = _gnutls_buffer_to_mbuffer(&buf);
	}

	return _gnutls_send_handshake(session, bufel, GNUTLS_HANDSHAKE_CERTIFICATE_PKT);

 cleanup:
	_gnutls_buffer_clear(&buf);
	return ret;
}

static int parse_cert_extension(void *ctx, uint16_t tls_id, const uint8_t *data, int data_size)
{
	/* ignore all extensions */
	return 0;
}

static int
parse_cert_list(gnutls_session_t session, uint8_t * data, size_t data_size)
{
	int len, ret;
	uint8_t *p = data;
	cert_auth_info_t info;
	gnutls_certificate_credentials_t cred;
	ssize_t dsize = data_size, size;
	int i;
	gnutls_pcert_st *peer_certificate_list;
	size_t peer_certificate_list_size = 0, j, x;
	gnutls_datum_t tmp;

	cred = (gnutls_certificate_credentials_t)
	    _gnutls_get_cred(session, GNUTLS_CRD_CERTIFICATE);
	if (cred == NULL) {
		gnutls_assert();
		return GNUTLS_E_INSUFFICIENT_CREDENTIALS;
	}

	if ((ret =
	     _gnutls_auth_info_set(session, GNUTLS_CRD_CERTIFICATE,
				   sizeof(cert_auth_info_st), 1)) < 0) {
		gnutls_assert();
		return ret;
	}

	info = _gnutls_get_auth_info(session, GNUTLS_CRD_CERTIFICATE);

	if (data == NULL || data_size == 0) {
		gnutls_assert();
		/* no certificate was sent */
		return GNUTLS_E_NO_CERTIFICATE_FOUND;
	}

	DECR_LEN(dsize, 3);
	size = _gnutls_read_uint24(p);
	p += 3;

	if (size != dsize)
		return gnutls_assert_val(GNUTLS_E_UNEXPECTED_PACKET_LENGTH);

	if (size == 0) {
		gnutls_assert();
		/* no certificate was sent */
		return GNUTLS_E_NO_CERTIFICATE_FOUND;
	}

	i = dsize;
	while (i > 0) {
		DECR_LEN(dsize, 3);
		len = _gnutls_read_uint24(p);
		p += 3;
		DECR_LEN(dsize, len);
		p += len;
		i -= len + 3;

		DECR_LEN(dsize, 2);
		len = _gnutls_read_uint16(p);
		DECR_LEN(dsize, len);

		i -= len + 2;

		peer_certificate_list_size++;
	}

	if (dsize != 0)
		return gnutls_assert_val(GNUTLS_E_UNEXPECTED_PACKET_LENGTH);

	if (peer_certificate_list_size == 0) {
		gnutls_assert();
		return GNUTLS_E_NO_CERTIFICATE_FOUND;
	}

	/* Ok we now allocate the memory to hold the
	 * certificate list
	 */

	peer_certificate_list =
	    gnutls_calloc(1,
			  sizeof(gnutls_pcert_st) *
			  (peer_certificate_list_size));
	if (peer_certificate_list == NULL) {
		gnutls_assert();
		return GNUTLS_E_MEMORY_ERROR;
	}

	p = data+3;

	/* Now we start parsing the list (again).
	 * We don't use DECR_LEN since the list has
	 * been parsed before.
	 */

	for (j = 0; j < peer_certificate_list_size; j++) {
		len = _gnutls_read_uint24(p);
		p += 3;

		tmp.size = len;
		tmp.data = p;

		ret =
		    gnutls_pcert_import_x509_raw(&peer_certificate_list
						 [j], &tmp,
						 GNUTLS_X509_FMT_DER, 0);
		if (ret < 0) {
			gnutls_assert();
			_gnutls_debug_log("error importing certificate[%d]: %s\n", (int)j, gnutls_strerror(ret));
			peer_certificate_list_size = j;
			ret = GNUTLS_E_CERTIFICATE_ERROR;
			goto cleanup;
		}

		p += len;

		len = _gnutls_read_uint16(p);
		p += 2;

		/* FIXME: properly parse extensions */
		ret = _gnutls_extv_parse(NULL, parse_cert_extension, p, len);
		if (ret < 0) {
			gnutls_assert();
			peer_certificate_list_size = j+1;
			goto cleanup;
		}
	}

	ret =
	     _gnutls_copy_certificate_auth_info(info,
					peer_certificate_list,
					peer_certificate_list_size);
	if (ret < 0) {
		gnutls_assert();
		goto cleanup;
	}

	ret = 0;

 cleanup:
	for(x=0;x<peer_certificate_list_size;x++)
		gnutls_pcert_deinit(&peer_certificate_list[x]);
	gnutls_free(peer_certificate_list);
	return ret;

}

