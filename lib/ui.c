/*
 * Copyright (C) 2001-2012 Free Software Foundation, Inc.
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

/* This file contains certificate authentication functions to be exported in the
 * API which did not fit elsewhere.
 */

#include "gnutls_int.h"
#include <auth/srp_kx.h>
#include <auth/anon.h>
#include <auth/cert.h>
#include <auth/psk.h>
#include "errors.h"
#include <auth.h>
#include <state.h>
#include <datum.h>
#include <algorithms.h>

/**
 * gnutls_fingerprint:
 * @algo: is a digest algorithm
 * @data: is the data
 * @result: is the place where the result will be copied (may be null).
 * @result_size: should hold the size of the result. The actual size
 * of the returned result will also be copied there.
 *
 * This function will calculate a fingerprint (actually a hash), of
 * the given data.  The result is not printable data.  You should
 * convert it to hex, or to something else printable.
 *
 * This is the usual way to calculate a fingerprint of an X.509 DER
 * encoded certificate.  Note however that the fingerprint of an
 * OpenPGP certificate is not just a hash and cannot be calculated with this
 * function.
 *
 * Returns: On success, %GNUTLS_E_SUCCESS (0) is returned, otherwise
 *   an error code is returned.
 **/
int
gnutls_fingerprint(gnutls_digest_algorithm_t algo,
		   const gnutls_datum_t * data, void *result,
		   size_t * result_size)
{
	int ret;
	int hash_len = _gnutls_hash_get_algo_len(hash_to_entry(algo));

	if (hash_len < 0 || (unsigned) hash_len > *result_size
	    || result == NULL) {
		*result_size = hash_len;
		return GNUTLS_E_SHORT_MEMORY_BUFFER;
	}
	*result_size = hash_len;

	if (result) {
		ret =
		    _gnutls_hash_fast(algo, data->data, data->size,
				      result);
		if (ret < 0)
			return gnutls_assert_val(ret);
	}

	return 0;
}

#ifdef ENABLE_PSK
/**
 * gnutls_psk_set_params_function:
 * @res: is a gnutls_psk_server_credentials_t type
 * @func: is the function to be called
 *
 * This function will set a callback in order for the server to get
 * the Diffie-Hellman or RSA parameters for PSK authentication.  The
 * callback should return %GNUTLS_E_SUCCESS (0) on success.
 **/
void
gnutls_psk_set_params_function(gnutls_psk_server_credentials_t res,
			       gnutls_params_function * func)
{
	res->params_func = func;
}
#endif

#ifdef ENABLE_ANON
/**
 * gnutls_anon_set_params_function:
 * @res: is a gnutls_anon_server_credentials_t type
 * @func: is the function to be called
 *
 * This function will set a callback in order for the server to get
 * the Diffie-Hellman or RSA parameters for anonymous authentication.
 * The callback should return %GNUTLS_E_SUCCESS (0) on success.
 **/
void
gnutls_anon_set_params_function(gnutls_anon_server_credentials_t res,
				gnutls_params_function * func)
{
	res->params_func = func;
}
#endif

#ifdef ENABLE_OCSP
/**
 * gnutls_ocsp_status_request_is_checked:
 * @session: is a gnutls session
 * @flags: should be zero or %GNUTLS_OCSP_SR_IS_AVAIL
 *
 * Check whether an OCSP status response was included in the handshake
 * and whether it was checked and valid (not too old or superseded). 
 * This is a helper function when needing to decide whether to perform an
 * OCSP validity check on the peer's certificate. Should be called after
 * any of gnutls_certificate_verify_peers*() are called.
 *
 * If the flag %GNUTLS_OCSP_SR_IS_AVAIL is specified, the return
 * value of the function indicates whether an OCSP status response have
 * been received (even if invalid).
 *
 * Returns: non zero if the response was valid, or a zero if it wasn't sent,
 * or sent and was invalid.
 **/
int
gnutls_ocsp_status_request_is_checked(gnutls_session_t session,
				      unsigned int flags)
{
	int ret;
	gnutls_datum_t data;

	if (flags & GNUTLS_OCSP_SR_IS_AVAIL) {
		ret = gnutls_ocsp_status_request_get(session, &data);
		if (ret < 0)
			return gnutls_assert_val(0);

		if (data.data == NULL)
			return gnutls_assert_val(0);
		return 1;
	}
	return session->internals.ocsp_check_ok;
}
#endif

#define DESC_SIZE 64

/**
 * gnutls_session_get_desc:
 * @session: is a gnutls session
 *
 * This function returns a string describing the current session.
 * The string is null terminated and allocated using gnutls_malloc().
 *
 * If initial negotiation is not complete when this function is called,
 * %NULL will be returned.
 *
 * Returns: a description of the protocols and algorithms in the current session.
 *
 * Since: 3.1.10
 **/
char *gnutls_session_get_desc(gnutls_session_t session)
{
	gnutls_kx_algorithm_t kx;
	const char *kx_str;
	unsigned type;
	char kx_name[32];
	char proto_name[32];
	const char *curve_name = NULL;
	unsigned dh_bits = 0;
	unsigned mac_id;
	char *desc;

	if (session->internals.initial_negotiation_completed == 0)
		return NULL;

	kx = session->security_parameters.kx_algorithm;

	if (kx == GNUTLS_KX_ANON_ECDH || kx == GNUTLS_KX_ECDHE_PSK ||
	    kx == GNUTLS_KX_ECDHE_RSA || kx == GNUTLS_KX_ECDHE_ECDSA) {
		curve_name =
		    gnutls_ecc_curve_get_name(gnutls_ecc_curve_get
					      (session));
#if defined(ENABLE_DHE) || defined(ENABLE_ANON)
	} else if (kx == GNUTLS_KX_ANON_DH || kx == GNUTLS_KX_DHE_PSK
		   || kx == GNUTLS_KX_DHE_RSA || kx == GNUTLS_KX_DHE_DSS) {
		dh_bits = gnutls_dh_get_prime_bits(session);
#endif
	}

	kx_str = gnutls_kx_get_name(kx);
	if (kx_str) {
		if (curve_name != NULL)
			snprintf(kx_name, sizeof(kx_name), "%s-%s",
				 kx_str, curve_name);
		else if (dh_bits != 0)
			snprintf(kx_name, sizeof(kx_name), "%s-%u",
				 kx_str, dh_bits);
		else
			snprintf(kx_name, sizeof(kx_name), "%s",
				 kx_str);
	} else {
		strcpy(kx_name, "NULL");
	}

	type = gnutls_certificate_type_get(session);
	if (type == GNUTLS_CRT_X509)
		snprintf(proto_name, sizeof(proto_name), "%s",
			 gnutls_protocol_get_name(get_num_version
						  (session)));
	else
		snprintf(proto_name, sizeof(proto_name), "%s-%s",
			 gnutls_protocol_get_name(get_num_version
						  (session)),
			 gnutls_certificate_type_get_name(type));

	gnutls_protocol_get_name(get_num_version(session)),
	    desc = gnutls_malloc(DESC_SIZE);
	if (desc == NULL)
		return NULL;

	mac_id = gnutls_mac_get(session);
	if (mac_id == GNUTLS_MAC_AEAD) { /* no need to print */
		snprintf(desc, DESC_SIZE,
			 "(%s)-(%s)-(%s)",
			 proto_name,
			 kx_name,
			 gnutls_cipher_get_name(gnutls_cipher_get(session)));
	} else {
		snprintf(desc, DESC_SIZE,
			 "(%s)-(%s)-(%s)-(%s)",
			 proto_name,
			 kx_name,
			 gnutls_cipher_get_name(gnutls_cipher_get(session)),
			 gnutls_mac_get_name(mac_id));
	}

	return desc;
}

/**
 * gnutls_session_set_id:
 * @session: is a #gnutls_session_t type.
 * @sid: the session identifier
 *
 * This function sets the session ID to be used in a client hello.
 * This is a function intended for exceptional uses. Do not use this
 * function unless you are implementing a custom protocol.
 *
 * To set session resumption parameters use gnutls_session_set_data() instead.
 *
 * Returns: On success, %GNUTLS_E_SUCCESS (0) is returned, otherwise
 *   an error code is returned.
 **/
int
gnutls_session_set_id(gnutls_session_t session, const gnutls_datum_t * sid)
{
	if (session->security_parameters.entity == GNUTLS_SERVER ||
	    sid->size > GNUTLS_MAX_SESSION_ID_SIZE)
		return gnutls_assert_val(GNUTLS_E_INVALID_REQUEST);

	memset(&session->internals.resumed_security_parameters, 0,
	       sizeof(session->internals.resumed_security_parameters));

	session->internals.resumed_security_parameters.session_id_size =
	    sid->size;
	memcpy(session->internals.resumed_security_parameters.session_id,
	       sid->data, sid->size);

	return 0;
}
