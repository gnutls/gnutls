/*
 *      Copyright (C) 2001 Nikos Mavroyanopoulos
 *
 * This file is part of GNUTLS.
 *
 *  The GNUTLS library is free software; you can redistribute it and/or
 *  modify it under the terms of the GNU Lesser General Public   
 *  License as published by the Free Software Foundation; either 
 *  version 2.1 of the License, or (at your option) any later version.
 *
 *  This library is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of 
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 *  Lesser General Public License for more details.
 *
 *  You should have received a copy of the GNU Lesser General Public
 *  License along with this library; if not, write to the Free Software
 *  Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA 02111-1307  USA
 *
 */

#include <gnutls_int.h>
#include <gnutls_errors.h>
#include <x509_b64.h>
#include <auth_cert.h>
#include <gnutls_cert.h>
#include <libasn1.h>
#include <gnutls_datum.h>
#include <gnutls_mpi.h>
#include <gnutls_privkey.h>
#include <gnutls_global.h>
#include <gnutls_pk.h>
#include <debug.h>
#include <gnutls_buffers.h>
#include <gnutls_sig.h>


int _gnutls_generate_sig( gnutls_cert* cert, gnutls_private_key *pkey, const gnutls_datum* hash_concat, gnutls_datum *signature);


/* Generates a signature of all the previous sent packets in the 
 * handshake procedure.
 */
int _gnutls_generate_sig_from_hdata( GNUTLS_STATE state, gnutls_cert* cert, gnutls_private_key *pkey, gnutls_datum *signature) {
gnutls_datum dconcat;
int ret;
opaque concat[36];
GNUTLS_MAC_HANDLE td_md5;
GNUTLS_MAC_HANDLE td_sha;


	td_sha = _gnutls_hash_copy( state->gnutls_internals.handshake_mac_handle_sha);
	if (td_sha == NULL) {
		gnutls_assert();
		return GNUTLS_E_HASH_FAILED;
	}

	_gnutls_hash_deinit(td_sha, &concat[16]);

	switch (cert->subject_pk_algorithm) {
		case GNUTLS_PK_RSA:
			td_md5 = _gnutls_hash_copy( state->gnutls_internals.handshake_mac_handle_md5);
			if (td_md5 == NULL) {
				gnutls_assert();
				return GNUTLS_E_HASH_FAILED;
			}
			_gnutls_hash_deinit(td_md5, concat);

			dconcat.data = concat;
			dconcat.size = 36;
			break;
		case GNUTLS_PK_DSA:
			dconcat.data = &concat[16];
			dconcat.size = 20;
			break;
		
		default:
			gnutls_assert();
			return GNUTLS_E_INTERNAL_ERROR;
	}
	ret = _gnutls_generate_sig( cert, pkey, &dconcat, signature);
	if (ret < 0)
		gnutls_assert();
	
	return ret;

}

/* Generates a signature of all the random data and the parameters.
 * Used in DHE_* ciphersuites.
 */
int _gnutls_generate_sig_params( GNUTLS_STATE state, gnutls_cert* cert, gnutls_private_key *pkey, gnutls_datum* params, gnutls_datum *signature) 
{
gnutls_datum dconcat;
int ret;
GNUTLS_MAC_HANDLE td_md5;
GNUTLS_MAC_HANDLE td_sha;
opaque concat[36];


	td_sha = _gnutls_hash_init( GNUTLS_MAC_SHA);
	if (td_sha == NULL) {
		gnutls_assert();
		return GNUTLS_E_HASH_FAILED;
	}

	_gnutls_hash( td_sha, state->security_parameters.client_random, TLS_RANDOM_SIZE);
	_gnutls_hash( td_sha, state->security_parameters.server_random, TLS_RANDOM_SIZE);
	_gnutls_hash( td_sha, params->data, params->size);

	_gnutls_hash_deinit(td_sha, &concat[16]);

	switch (cert->subject_pk_algorithm) {
		case GNUTLS_PK_RSA:
			td_md5 = _gnutls_hash_init( GNUTLS_MAC_MD5);
			if (td_md5 == NULL) {
				gnutls_assert();
				return GNUTLS_E_HASH_FAILED;
			}

			_gnutls_hash( td_md5, state->security_parameters.client_random, TLS_RANDOM_SIZE);
			_gnutls_hash( td_md5, state->security_parameters.server_random, TLS_RANDOM_SIZE);
			_gnutls_hash( td_md5, params->data, params->size);

			_gnutls_hash_deinit(td_md5, concat);

			dconcat.data = concat;
			dconcat.size = 36;
			break;
		case GNUTLS_PK_DSA:
			dconcat.data = &concat[16];
			dconcat.size = 20;
			break;
		
		default:
			gnutls_assert();
			return GNUTLS_E_INTERNAL_ERROR;
	}
	ret = _gnutls_generate_sig( cert, pkey, &dconcat, signature);
	if (ret < 0)
		gnutls_assert();
	
	return ret;

}


/* This will create a PKCS1 or DSA signature, as defined in the TLS protocol.
 * Cert is the certificate of the corresponding private key. It is only checked if
 * it supports signing.
 */
int _gnutls_generate_sig( gnutls_cert* cert, gnutls_private_key *pkey, const gnutls_datum* hash_concat, gnutls_datum *signature)
{
int ret;
gnutls_datum tmpdata;

	/* If our certificate supports signing
	 */

	if ( cert != NULL)
	   if ( cert->keyUsage != 0)
		if ( !(cert->keyUsage & GNUTLS_X509KEY_DIGITAL_SIGNATURE)) {
			gnutls_assert();
			return GNUTLS_E_X509_KEY_USAGE_VIOLATION;
		}

	tmpdata.data = hash_concat->data;
	tmpdata.size = hash_concat->size;

	switch(pkey->pk_algorithm) {
		case GNUTLS_PK_RSA:
			/* encrypt */
			if ((ret=_gnutls_pkcs1_rsa_encrypt( signature, tmpdata, pkey->params, 
				pkey->params_size, 1)) < 0) {
			     gnutls_assert();
			     return ret;
			}

			break;
		case GNUTLS_PK_DSA:
			/* sign */
			if ((ret=_gnutls_dsa_sign( signature, &tmpdata, pkey->params, 
				pkey->params_size)) < 0) {
			     gnutls_assert();
			     return ret;
			}
			break;
		default:
			gnutls_assert();
			return GNUTLS_E_UNIMPLEMENTED_FEATURE;
			break;
	}



	return 0;
}



int _gnutls_pkcs1_rsa_verify_sig( gnutls_cert *cert, const gnutls_datum *hash_concat, gnutls_datum *signature) {
	int ret;
	gnutls_datum vdata;

	if (cert->version == 0 || cert==NULL) {                /* this is the only way to check
							       * if it is initialized
							       */
		gnutls_assert();
		return GNUTLS_E_X509_CERTIFICATE_ERROR;
	}

	/* If the certificate supports signing continue.
	 */
	if ( cert != NULL)
	   if ( cert->keyUsage != 0)
		if ( !(cert->keyUsage & GNUTLS_X509KEY_DIGITAL_SIGNATURE)) {
			gnutls_assert();
			return GNUTLS_E_X509_KEY_USAGE_VIOLATION;
		}

	switch(cert->subject_pk_algorithm) {
		case GNUTLS_PK_RSA:
			
			vdata.data = hash_concat->data;
			vdata.size = hash_concat->size;

			/* verify signature */
			if ( (ret=_gnutls_rsa_verify( &vdata, signature, cert->params, 
				cert->params_size, 1)) < 0) {
			     gnutls_assert();
			     return ret;
			}

			break;
		case GNUTLS_PK_DSA:
			
			vdata.data = &hash_concat->data[16];
			vdata.size = 20; /* sha1 */

			/* decrypt signature */
			if ( (ret=_gnutls_dsa_verify( &vdata, signature, cert->params,
				cert->params_size)) < 0) { 
			     gnutls_assert();
			     return ret;
			}

			break;

		default:
			gnutls_assert();
			return GNUTLS_E_UNIMPLEMENTED_FEATURE;
	}
	


	return 0;
}


/* Verifies a TLS signature (like the one in the client certificate
 * verify message). ubuffer_size is a buffer to remove from the hash buffer
 * in order to avoid hashing the last message.
 */
int _gnutls_verify_sig_hdata( GNUTLS_STATE state, gnutls_cert *cert, gnutls_datum* signature, int ubuffer_size) {
int ret;
opaque concat[36];
GNUTLS_MAC_HANDLE td_md5;
GNUTLS_MAC_HANDLE td_sha;
gnutls_datum dconcat;

	td_md5 = _gnutls_hash_copy( state->gnutls_internals.handshake_mac_handle_md5);
	if (td_md5 == NULL) {
		gnutls_assert();
		return GNUTLS_E_HASH_FAILED;
	}

	td_sha = _gnutls_hash_copy( state->gnutls_internals.handshake_mac_handle_sha);
	if (td_sha == NULL) {
		gnutls_assert();
		_gnutls_hash_deinit( td_md5, NULL);
		return GNUTLS_E_HASH_FAILED;
	}

	_gnutls_hash_deinit(td_md5, concat);
	_gnutls_hash_deinit(td_sha, &concat[16]);
	
	dconcat.data = concat;
	dconcat.size = 20+16; /* md5+ sha */

	ret = _gnutls_pkcs1_rsa_verify_sig( cert, &dconcat, signature);
	if (ret < 0) {
		gnutls_assert();
		return ret;
	}

	return ret;

}

/* Generates a signature of all the random data and the parameters.
 * Used in DHE_* ciphersuites.
 */
int _gnutls_verify_sig_params( GNUTLS_STATE state, gnutls_cert *cert, const gnutls_datum* params, gnutls_datum *signature) 
{
gnutls_datum dconcat;
int ret;
GNUTLS_MAC_HANDLE td_md5;
GNUTLS_MAC_HANDLE td_sha;
opaque concat[36];

	td_md5 = _gnutls_hash_init( GNUTLS_MAC_MD5);
	if (td_md5 == NULL) {
		gnutls_assert();
		return GNUTLS_E_HASH_FAILED;
	}

	td_sha = _gnutls_hash_init( GNUTLS_MAC_SHA);
	if (td_sha == NULL) {
		gnutls_assert();
		_gnutls_hash_deinit( td_md5, NULL);
		return GNUTLS_E_HASH_FAILED;
	}

	_gnutls_hash( td_md5, state->security_parameters.client_random, TLS_RANDOM_SIZE);
	_gnutls_hash( td_md5, state->security_parameters.server_random, TLS_RANDOM_SIZE);
	_gnutls_hash( td_md5, params->data, params->size);

	_gnutls_hash( td_sha, state->security_parameters.client_random, TLS_RANDOM_SIZE);
	_gnutls_hash( td_sha, state->security_parameters.server_random, TLS_RANDOM_SIZE);
	_gnutls_hash( td_sha, params->data, params->size);

	_gnutls_hash_deinit(td_md5, concat);
	_gnutls_hash_deinit(td_sha, &concat[16]);

	dconcat.data = concat;
	dconcat.size = 36;

	ret = _gnutls_pkcs1_rsa_verify_sig( cert, &dconcat, signature);
	if (ret < 0) {
		gnutls_assert();
		return ret;
	}

	return ret;

}

