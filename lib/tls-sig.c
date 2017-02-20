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

#include "gnutls_int.h"
#include "errors.h"
#include <x509_b64.h>
#include <auth/cert.h>
#include <algorithms.h>
#include <datum.h>
#include <mpi.h>
#include <global.h>
#include <pk.h>
#include <debug.h>
#include <buffers.h>
#include <tls-sig.h>
#include <kx.h>
#include <libtasn1.h>
#include <ext/signature.h>
#include <state.h>
#include <x509/common.h>
#include <abstract_int.h>

static int
sign_tls_hash(gnutls_session_t session, const mac_entry_st * hash_algo,
	      gnutls_pcert_st * cert, gnutls_privkey_t pkey,
	      const gnutls_datum_t * hash_concat,
	      gnutls_datum_t * signature);


/* Generates a signature of all the random data and the parameters.
 * Used in DHE_* ciphersuites.
 */
int
_gnutls_handshake_sign_data(gnutls_session_t session,
			    gnutls_pcert_st * cert, gnutls_privkey_t pkey,
			    gnutls_datum_t * params,
			    gnutls_datum_t * signature,
			    gnutls_sign_algorithm_t * sign_algo)
{
	gnutls_datum_t dconcat;
	int ret;
	digest_hd_st td_sha;
	uint8_t concat[MAX_SIG_SIZE];
	const version_entry_st *ver = get_version(session);
	const mac_entry_st *hash_algo;

	*sign_algo = _gnutls_session_get_sign_algo(session, cert, 0);
	if (*sign_algo == GNUTLS_SIGN_UNKNOWN) {
		gnutls_assert();
		return GNUTLS_E_UNKNOWN_PK_ALGORITHM;
	}

	gnutls_sign_algorithm_set_server(session, *sign_algo);

	if (!_gnutls_version_has_selectable_sighash(ver) &&
	    gnutls_privkey_get_pk_algorithm(pkey, NULL) == GNUTLS_PK_RSA)
		hash_algo = hash_to_entry(GNUTLS_DIG_MD5_SHA1);
	else
		hash_algo = hash_to_entry(
				gnutls_sign_get_hash_algorithm(*sign_algo));
	if (hash_algo == NULL)
		return gnutls_assert_val(GNUTLS_E_UNKNOWN_HASH_ALGORITHM);

	_gnutls_handshake_log
	    ("HSK[%p]: signing handshake data: using %s\n", session,
	     gnutls_sign_algorithm_get_name(*sign_algo));

	ret = _gnutls_hash_init(&td_sha, hash_algo);
	if (ret < 0) {
		gnutls_assert();
		return ret;
	}

	_gnutls_hash(&td_sha, session->security_parameters.client_random,
		     GNUTLS_RANDOM_SIZE);
	_gnutls_hash(&td_sha, session->security_parameters.server_random,
		     GNUTLS_RANDOM_SIZE);
	_gnutls_hash(&td_sha, params->data, params->size);

	_gnutls_hash_deinit(&td_sha, concat);

	dconcat.data = concat;
	dconcat.size = _gnutls_hash_get_algo_len(hash_algo);

	ret =
	    sign_tls_hash(session, hash_algo, cert, pkey, &dconcat,
			  signature);
	if (ret < 0) {
		gnutls_assert();
	}

	return ret;

}

static
int check_key_usage_for_sig(gnutls_session_t session, unsigned key_usage, unsigned our_cert)
{
	const char *lstr;
	unsigned allow_key_usage_violation;

	if (our_cert) {
		lstr = "Local";
		allow_key_usage_violation = session->internals.priorities.allow_server_key_usage_violation;
	} else {
		lstr = "Peer's";
		allow_key_usage_violation = session->internals.priorities.allow_key_usage_violation;
	}

	if (key_usage != 0) {
		if (!(key_usage & GNUTLS_KEY_DIGITAL_SIGNATURE)) {
			gnutls_assert();
			if (likely(allow_key_usage_violation == 0)) {
				_gnutls_audit_log(session,
					  "%s certificate does not allow digital signatures. Key usage violation detected.\n", lstr);
				return GNUTLS_E_KEY_USAGE_VIOLATION;
			} else {
				_gnutls_audit_log(session,
					  "%s certificate does not allow digital signatures. Key usage violation detected (ignored).\n", lstr);
			}
		}
	}
	return 0;
}

/* This will create a PKCS1 or DSA signature, as defined in the TLS protocol.
 * Cert is the certificate of the corresponding private key. It is only checked if
 * it supports signing.
 */
static int
sign_tls_hash(gnutls_session_t session, const mac_entry_st * hash_algo,
	      gnutls_pcert_st * cert, gnutls_privkey_t pkey,
	      const gnutls_datum_t * hash_concat,
	      gnutls_datum_t * signature)
{
	const version_entry_st *ver = get_version(session);
	unsigned int key_usage = 0;
	int ret;

	/* If our certificate supports signing
	 */
	if (cert != NULL) {
		gnutls_pubkey_get_key_usage(cert->pubkey, &key_usage);

		ret = check_key_usage_for_sig(session, key_usage, 1);
		if (ret < 0)
			return gnutls_assert_val(ret);
	}

	if (!_gnutls_version_has_selectable_sighash(ver)) {
		return gnutls_privkey_sign_raw_data(pkey, 0, hash_concat,
						    signature);
	} else {
		assert(hash_algo != NULL);
		return gnutls_privkey_sign_hash(pkey, 
						(gnutls_digest_algorithm_t)hash_algo->id,
						0, hash_concat, signature);
	}
}

static int
verify_tls_hash(gnutls_session_t session,
		gnutls_pcert_st * cert,
		const gnutls_datum_t * hash_concat,
		gnutls_datum_t * signature,
		gnutls_sign_algorithm_t sign_algo,
		unsigned flags)
{
	int ret;
	unsigned int key_usage = 0;

	if (cert == NULL) {
		gnutls_assert();
		return GNUTLS_E_CERTIFICATE_ERROR;
	}

	gnutls_pubkey_get_key_usage(cert->pubkey, &key_usage);

	ret = check_key_usage_for_sig(session, key_usage, 0);
	if (ret < 0)
		return gnutls_assert_val(ret);

	/* verify signature */

	if (session->security_parameters.entity == GNUTLS_CLIENT)
		gnutls_sign_algorithm_set_server(session, sign_algo);

	ret = gnutls_pubkey_verify_hash2(cert->pubkey, sign_algo, flags,
					 hash_concat, signature);

	if (ret < 0)
		return gnutls_assert_val(ret);


	return 0;
}


/* Generates a signature of all the random data and the parameters.
 * Used in DHE_* ciphersuites.
 */
int
_gnutls_handshake_verify_data(gnutls_session_t session,
			      gnutls_pcert_st * cert,
			      const gnutls_datum_t * params,
			      gnutls_datum_t * signature,
			      gnutls_sign_algorithm_t sign_algo)
{
	gnutls_datum_t dconcat;
	int ret;
	digest_hd_st td_sha;
	uint8_t concat[MAX_SIG_SIZE];
	const version_entry_st *ver = get_version(session);
	gnutls_digest_algorithm_t hash_algo;
	const mac_entry_st *me;
	gnutls_pk_algorithm_t pk_algo;
	unsigned flags = 0;

	if (_gnutls_version_has_selectable_sighash(ver)) {
		_gnutls_handshake_log
		    ("HSK[%p]: verify handshake data: using %s\n", session,
		     gnutls_sign_algorithm_get_name(sign_algo));

		ret =
		    _gnutls_pubkey_compatible_with_sig(session,
						       cert->pubkey, ver,
						       sign_algo);
		if (ret < 0)
			return gnutls_assert_val(ret);

		ret =
		    _gnutls_session_sign_algo_enabled(session, sign_algo);
		if (ret < 0)
			return gnutls_assert_val(ret);

		pk_algo = gnutls_sign_get_pk_algorithm(sign_algo);
		hash_algo = gnutls_sign_get_hash_algorithm(sign_algo);
	} else {
		pk_algo = gnutls_pubkey_get_pk_algorithm(cert->pubkey, NULL);
		if (pk_algo == GNUTLS_PK_RSA) {
			hash_algo = GNUTLS_DIG_MD5_SHA1;
			flags = GNUTLS_PUBKEY_VERIFY_FLAG_TLS1_RSA;
		} else
			hash_algo = GNUTLS_DIG_SHA1;
	}
	me = hash_to_entry(hash_algo);

	ret = _gnutls_hash_init(&td_sha, me);
	if (ret < 0) {
		gnutls_assert();
		return ret;
	}

	_gnutls_hash(&td_sha, session->security_parameters.client_random,
		     GNUTLS_RANDOM_SIZE);
	_gnutls_hash(&td_sha, session->security_parameters.server_random,
		     GNUTLS_RANDOM_SIZE);
	_gnutls_hash(&td_sha, params->data, params->size);

	_gnutls_hash_deinit(&td_sha, concat);

	dconcat.data = concat;
	dconcat.size = _gnutls_hash_get_algo_len(me);

	ret = verify_tls_hash(session, cert, &dconcat, signature,
			      sign_algo, flags);
	if (ret < 0) {
		gnutls_assert();
		return ret;
	}

	return ret;

}

/* Client certificate verify calculations
 */

/* this is _gnutls_handshake_verify_crt_vrfy for TLS 1.2
 */
static int
_gnutls_handshake_verify_crt_vrfy12(gnutls_session_t session,
				    gnutls_pcert_st * cert,
				    gnutls_datum_t * signature,
				    gnutls_sign_algorithm_t sign_algo)
{
	int ret;
	uint8_t concat[MAX_HASH_SIZE];
	gnutls_datum_t dconcat;
	const mac_entry_st *me;

	ret = _gnutls_session_sign_algo_enabled(session, sign_algo);
	if (ret < 0)
		return gnutls_assert_val(ret);

	gnutls_sign_algorithm_set_client(session, sign_algo);

	me = hash_to_entry(gnutls_sign_get_hash_algorithm(sign_algo));

	ret =
	    _gnutls_hash_fast((gnutls_digest_algorithm_t)me->id,
			      session->internals.handshake_hash_buffer.
			      data,
			      session->internals.
			      handshake_hash_buffer_prev_len, concat);
	if (ret < 0)
		return gnutls_assert_val(ret);

	dconcat.data = concat;
	dconcat.size = _gnutls_hash_get_algo_len(me);

	ret =
	    verify_tls_hash(session, cert, &dconcat, signature,
			    sign_algo, 0);
	if (ret < 0) {
		gnutls_assert();
		return ret;
	}

	return ret;

}

/* Verifies a SSL 3.0 signature (like the one in the client certificate
 * verify message).
 */
#ifdef ENABLE_SSL3
static int
_gnutls_handshake_verify_crt_vrfy3(gnutls_session_t session,
				   gnutls_pcert_st * cert,
				   gnutls_datum_t * signature,
				   gnutls_sign_algorithm_t sign_algo)
{
	int ret;
	uint8_t concat[MAX_SIG_SIZE];
	digest_hd_st td_sha;
	gnutls_datum_t dconcat;
	gnutls_pk_algorithm_t pk =
	    gnutls_pubkey_get_pk_algorithm(cert->pubkey, NULL);

	ret = _gnutls_generate_master(session, 1);
	if (ret < 0) {
		return gnutls_assert_val(ret);
	}

	dconcat.data = concat;
	dconcat.size = 0;

	if (pk == GNUTLS_PK_RSA) {
		digest_hd_st td_md5;

		ret = _gnutls_hash_init(&td_md5,
					hash_to_entry(GNUTLS_DIG_MD5));
		if (ret < 0)
			return gnutls_assert_val(ret);

		_gnutls_hash(&td_md5,
				session->internals.handshake_hash_buffer.data,
				session->internals.handshake_hash_buffer_prev_len);

		ret = _gnutls_mac_deinit_ssl3_handshake(&td_md5, concat,
						session->security_parameters.
						master_secret,
						GNUTLS_MASTER_SIZE);
		if (ret < 0)
			return gnutls_assert_val(ret);

		dconcat.size = 16;
	}

	ret = _gnutls_hash_init(&td_sha, hash_to_entry(GNUTLS_DIG_SHA1));
	if (ret < 0) {
		gnutls_assert();
		return GNUTLS_E_HASH_FAILED;
	}

	_gnutls_hash(&td_sha,
		     session->internals.handshake_hash_buffer.data,
		     session->internals.handshake_hash_buffer_prev_len);

	ret =
	    _gnutls_mac_deinit_ssl3_handshake(&td_sha,
					      dconcat.data + dconcat.size,
					      session->security_parameters.
					      master_secret,
					      GNUTLS_MASTER_SIZE);
	if (ret < 0) {
		return gnutls_assert_val(ret);
	}

	dconcat.size += 20;

	ret =
	    verify_tls_hash(session, cert, &dconcat, signature,
			    GNUTLS_SIGN_UNKNOWN,
			    GNUTLS_PUBKEY_VERIFY_FLAG_TLS1_RSA);
	if (ret < 0) {
		gnutls_assert();
		return ret;
	}

	return ret;
}
#endif

/* Verifies a TLS signature (like the one in the client certificate
 * verify message). 
 */
int
_gnutls_handshake_verify_crt_vrfy(gnutls_session_t session,
				  gnutls_pcert_st * cert,
				  gnutls_datum_t * signature,
				  gnutls_sign_algorithm_t sign_algo)
{
	int ret;
	uint8_t concat[MAX_SIG_SIZE];
	digest_hd_st td_sha;
	gnutls_datum_t dconcat;
	const version_entry_st *ver = get_version(session);
	gnutls_pk_algorithm_t pk_algo;
	const mac_entry_st *me;
	unsigned flags = 0;

	_gnutls_handshake_log("HSK[%p]: verify cert vrfy: using %s\n",
			      session,
			      gnutls_sign_algorithm_get_name(sign_algo));

	if (unlikely(ver == NULL))
		return gnutls_assert_val(GNUTLS_E_INTERNAL_ERROR);

	if (_gnutls_version_has_selectable_sighash(ver))
		return _gnutls_handshake_verify_crt_vrfy12(session, cert,
							   signature,
							   sign_algo);
#ifdef ENABLE_SSL3
	if (ver->id == GNUTLS_SSL3)
		return _gnutls_handshake_verify_crt_vrfy3(session, cert,
							  signature,
							  sign_algo);
#endif

	pk_algo = gnutls_pubkey_get_pk_algorithm(cert->pubkey, NULL);
	if (pk_algo == GNUTLS_PK_RSA) {
		me = hash_to_entry(GNUTLS_DIG_MD5_SHA1);
		flags = GNUTLS_PUBKEY_VERIFY_FLAG_TLS1_RSA;
	} else
		me = hash_to_entry(GNUTLS_DIG_SHA1);
	ret = _gnutls_hash_init(&td_sha, me);
	if (ret < 0) {
		gnutls_assert();
		return ret;
	}

	_gnutls_hash(&td_sha,
		     session->internals.handshake_hash_buffer.data,
		     session->internals.handshake_hash_buffer_prev_len);

	_gnutls_hash_deinit(&td_sha, concat);

	dconcat.data = concat;
	dconcat.size = _gnutls_hash_get_algo_len(me);

	ret =
	    verify_tls_hash(session, cert, &dconcat, signature,
			    GNUTLS_SIGN_UNKNOWN, flags);
	if (ret < 0) {
		gnutls_assert();
		return ret;
	}

	return ret;
}

/* the same as _gnutls_handshake_sign_crt_vrfy except that it is made for TLS 1.2
 */
static int
_gnutls_handshake_sign_crt_vrfy12(gnutls_session_t session,
				  gnutls_pcert_st * cert,
				  gnutls_privkey_t pkey,
				  gnutls_datum_t * signature)
{
	gnutls_datum_t dconcat;
	int ret;
	uint8_t concat[MAX_SIG_SIZE];
	gnutls_sign_algorithm_t sign_algo;
	const mac_entry_st *me;

	sign_algo = _gnutls_privkey_get_preferred_sign_algo(pkey);
	if (sign_algo == GNUTLS_SIGN_UNKNOWN || 
	    _gnutls_session_sign_algo_enabled(session, sign_algo) < 0) {

		sign_algo = _gnutls_session_get_sign_algo(session, cert, 1);
		if (sign_algo == GNUTLS_SIGN_UNKNOWN) {
			gnutls_assert();
			return GNUTLS_E_UNKNOWN_PK_ALGORITHM;
		}
	}

	gnutls_sign_algorithm_set_client(session, sign_algo);

	me = hash_to_entry(gnutls_sign_get_hash_algorithm(sign_algo));

	_gnutls_debug_log("sign handshake cert vrfy: picked %s with %s\n",
			  gnutls_sign_algorithm_get_name(sign_algo),
			  _gnutls_mac_get_name(me));

	ret =
	    _gnutls_hash_fast((gnutls_digest_algorithm_t)me->id,
			      session->internals.handshake_hash_buffer.
			      data,
			      session->internals.handshake_hash_buffer.
			      length, concat);
	if (ret < 0)
		return gnutls_assert_val(ret);

	dconcat.data = concat;
	dconcat.size = _gnutls_hash_get_algo_len(me);

	ret = sign_tls_hash(session, me, cert, pkey, &dconcat, signature);
	if (ret < 0) {
		gnutls_assert();
		return ret;
	}

	return sign_algo;
}

#ifdef ENABLE_SSL3
static int
_gnutls_handshake_sign_crt_vrfy3(gnutls_session_t session,
				 gnutls_pcert_st * cert,
				 gnutls_privkey_t pkey,
				 gnutls_datum_t * signature)
{
	gnutls_datum_t dconcat;
	int ret;
	uint8_t concat[MAX_SIG_SIZE];
	digest_hd_st td_sha;
	const version_entry_st *ver = get_version(session);
	gnutls_pk_algorithm_t pk =
	    gnutls_privkey_get_pk_algorithm(pkey, NULL);

	ret = _gnutls_generate_master(session, 1);
	if (ret < 0) {
		gnutls_assert();
		return ret;
	}

	/* ensure 1024 bit DSA keys are used */
	ret =
	    _gnutls_pubkey_compatible_with_sig(session, cert->pubkey, ver,
					       GNUTLS_SIGN_UNKNOWN);
	if (ret < 0)
		return gnutls_assert_val(ret);

	dconcat.data = concat;
	dconcat.size = 0;

	if (pk == GNUTLS_PK_RSA) {
		digest_hd_st td_md5;
		ret =
		    _gnutls_hash_init(&td_md5,
				      hash_to_entry(GNUTLS_DIG_MD5));
		if (ret < 0)
			return gnutls_assert_val(ret);

		_gnutls_hash(&td_md5,
			     session->internals.handshake_hash_buffer.data,
			     session->internals.handshake_hash_buffer.
			     length);

		ret = _gnutls_mac_deinit_ssl3_handshake(&td_md5,
							dconcat.data,
							session->security_parameters.
							master_secret,
							GNUTLS_MASTER_SIZE);
		if (ret < 0)
			return gnutls_assert_val(ret);

		dconcat.size = 16;
	}

	ret = _gnutls_hash_init(&td_sha, hash_to_entry(GNUTLS_DIG_SHA1));
	if (ret < 0) {
		gnutls_assert();
		return ret;
	}

	_gnutls_hash(&td_sha,
		     session->internals.handshake_hash_buffer.data,
		     session->internals.handshake_hash_buffer.length);
	ret =
		_gnutls_mac_deinit_ssl3_handshake(&td_sha,
				dconcat.data + dconcat.size,
				session->security_parameters.
				master_secret,
				GNUTLS_MASTER_SIZE);
	if (ret < 0)
		return gnutls_assert_val(ret);

	dconcat.size += 20;

	ret = sign_tls_hash(session, NULL, cert, pkey, &dconcat, signature);
	if (ret < 0) {
		gnutls_assert();
	}

	return ret;
}
#endif

/* Generates a signature of all the previous sent packets in the
 * handshake procedure.
 * 20040227: now it works for SSL 3.0 as well
 * 20091031: works for TLS 1.2 too!
 *
 * For TLS1.x, x<2 returns negative for failure and zero or unspecified for success.
 * For TLS1.2 returns the signature algorithm used on success, or a negative error code;
 */
int
_gnutls_handshake_sign_crt_vrfy(gnutls_session_t session,
				gnutls_pcert_st * cert,
				gnutls_privkey_t pkey,
				gnutls_datum_t * signature)
{
	gnutls_datum_t dconcat;
	int ret;
	uint8_t concat[MAX_SIG_SIZE];
	digest_hd_st td_sha;
	const version_entry_st *ver = get_version(session);
	gnutls_pk_algorithm_t pk =
	    gnutls_privkey_get_pk_algorithm(pkey, NULL);
	const mac_entry_st *me;

	if (unlikely(ver == NULL))
		return gnutls_assert_val(GNUTLS_E_INTERNAL_ERROR);

	if (_gnutls_version_has_selectable_sighash(ver))
		return _gnutls_handshake_sign_crt_vrfy12(session, cert,
							 pkey, signature);

#ifdef ENABLE_SSL3
	if (ver->id == GNUTLS_SSL3)
		return _gnutls_handshake_sign_crt_vrfy3(session, cert,
							pkey, signature);
#endif

	if (pk == GNUTLS_PK_RSA)
		me = hash_to_entry(GNUTLS_DIG_MD5_SHA1);
	else
		me = hash_to_entry(GNUTLS_DIG_SHA1);

	ret = _gnutls_hash_init(&td_sha, me);
	if (ret < 0) {
		gnutls_assert();
		return ret;
	}

	_gnutls_hash(&td_sha,
		     session->internals.handshake_hash_buffer.data,
		     session->internals.handshake_hash_buffer.length);

	_gnutls_hash_deinit(&td_sha, concat);

	dconcat.data = concat;
	dconcat.size = _gnutls_hash_get_algo_len(me);


	/* ensure 1024 bit DSA keys are used */
	ret =
	    _gnutls_pubkey_compatible_with_sig(session, cert->pubkey, ver,
					       GNUTLS_SIGN_UNKNOWN);
	if (ret < 0)
		return gnutls_assert_val(ret);

	ret =
	    sign_tls_hash(session, NULL, cert, pkey, &dconcat, signature);
	if (ret < 0) {
		gnutls_assert();
	}

	return ret;
}

