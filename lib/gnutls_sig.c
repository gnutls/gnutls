/*
 *      Copyright (C) 2001 Nikos Mavroyanopoulos
 *
 * This file is part of GNUTLS.
 *
 * GNUTLS is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * GNUTLS is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA
 */

#include <gnutls_int.h>
#include <gnutls_errors.h>
#include <x509_b64.h>
#include <auth_x509.h>
#include <gnutls_cert.h>
#include <x509_asn1.h>
#include <x509_der.h>
#include <gnutls_datum.h>
#include <gnutls_gcry.h>
#include <gnutls_privkey.h>
#include <gnutls_global.h>
#include <gnutls_pk.h>
#include <debug.h>
#include <gnutls_buffers.h>
#include <gnutls_sig.h>



/* Generates a signature of all the previous sent packets in the 
 * handshake procedure.
 */
int _gnutls_generate_sig_from_hdata( GNUTLS_STATE state, gnutls_cert* cert, gnutls_private_key *pkey, gnutls_datum *signature) {
gnutls_datum data;
int size = gnutls_get_handshake_buffer_size( state);
int ret;

	data.data = gnutls_malloc(size);
	data.size = size;
	if (data.data==NULL) {
		gnutls_assert();
		return GNUTLS_E_MEMORY_ERROR;
	}
			
	gnutls_read_handshake_buffer( state, data.data, data.size);

	ret = _gnutls_pkcs1_rsa_generate_sig( cert, pkey, &data, signature);
	gnutls_free_datum( &data);
	if (ret < 0) {
		gnutls_assert();
		return ret;
	}

	return ret;

}

/* Generates a signature of all the random data and the parameters.
 * Used in DHE_* ciphersuites.
 */
int _gnutls_generate_sig_params( GNUTLS_STATE state, gnutls_cert* cert, gnutls_private_key *pkey, gnutls_datum* params, gnutls_datum *signature) 
{
	gnutls_datum sdata;
	int size = 2*TLS_RANDOM_SIZE; 
	int ret;

	sdata.data = gnutls_malloc( size+params->size);
	sdata.size = size + params->size;
	if (sdata.data==NULL) {
		gnutls_assert();
		return GNUTLS_E_MEMORY_ERROR;
	}
	
	memcpy( sdata.data, state->security_parameters.client_random, TLS_RANDOM_SIZE);
	memcpy( &sdata.data[TLS_RANDOM_SIZE], state->security_parameters.server_random, TLS_RANDOM_SIZE);
	memcpy( &sdata.data[2*TLS_RANDOM_SIZE], params->data, params->size);

	ret = _gnutls_pkcs1_rsa_generate_sig( cert, pkey, &sdata, signature);

	gnutls_free_datum( &sdata);
	if (ret < 0) {
		gnutls_assert();
		return ret;
	}

	return ret;

}


/* This will create a PKCS1 signature, as defined in the TLS protocol.
 * Cert is the certificate of the corresponding private key. It is only checked if
 * it supports signing.
 */
int _gnutls_pkcs1_rsa_generate_sig( gnutls_cert* cert, gnutls_private_key *pkey, const gnutls_datum *data, gnutls_datum *signature) 
{
int ret;
opaque digest[20+16];
gnutls_datum tmpdata;
GNUTLS_HASH_HANDLE td;

	/* If our certificate supports signing
	 */

	if ( cert != NULL)
	   if ( cert->keyUsage != 0)
		if ( !(cert->keyUsage & X509KEY_DIGITAL_SIGNATURE)) {
			gnutls_assert();
			return GNUTLS_E_X509_KEY_USAGE_VIOLATION;
		}

	switch(pkey->pk_algorithm) {
		case GNUTLS_PK_RSA:
			
			td = gnutls_hash_init( GNUTLS_MAC_MD5);
			if (td==NULL) {
				gnutls_assert();
				return GNUTLS_E_MEMORY_ERROR;
			}
			gnutls_hash( td, data->data, data->size);
			gnutls_hash_deinit( td, digest);

			td = gnutls_hash_init( GNUTLS_MAC_SHA);
			if (td==NULL) {
				gnutls_assert();
				return GNUTLS_E_MEMORY_ERROR;
			}
			gnutls_hash( td, data->data, data->size);
			gnutls_hash_deinit( td, &digest[16]);
			

			tmpdata.data = digest;
			tmpdata.size = 20+16; /* md5 + sha */	

			break;
		default:
			gnutls_assert();
			return GNUTLS_E_UNIMPLEMENTED_FEATURE;
			break;
	}


	/* encrypt der */
	if ( (ret=_gnutls_pkcs1_rsa_encrypt( signature, tmpdata, pkey->params[0], pkey->params[1], 1)) < 0) {
	     gnutls_assert();
	     return ret;
	}

	return 0;
}

int _gnutls_pkcs1_rsa_verify_sig( gnutls_cert *cert, const gnutls_datum *data, gnutls_datum *signature) {
	int ret;
	gnutls_datum plain, vdata;
	opaque digest[20+16];
	GNUTLS_HASH_HANDLE td;

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
		if ( !(cert->keyUsage & X509KEY_DIGITAL_SIGNATURE)) {
			gnutls_assert();
			return GNUTLS_E_X509_KEY_USAGE_VIOLATION;
		}

	switch(cert->subject_pk_algorithm) {
		case GNUTLS_PK_RSA:
			
			td = gnutls_hash_init( GNUTLS_MAC_MD5);
			if (td==NULL) {
				gnutls_assert();
				return GNUTLS_E_MEMORY_ERROR;
			}
			gnutls_hash( td, data->data, data->size);
			gnutls_hash_deinit( td, digest);

			td = gnutls_hash_init( GNUTLS_MAC_SHA);
			if (td==NULL) {
				gnutls_assert();
				return GNUTLS_E_MEMORY_ERROR;
			}
			gnutls_hash( td, data->data, data->size);
			gnutls_hash_deinit( td, &digest[16]);
			
			vdata.data = digest;
			vdata.size = 20+16; /* md5 + sha */	

			break;
		default:
			gnutls_assert();
			return GNUTLS_E_UNIMPLEMENTED_FEATURE;
	}
	
	/* decrypt signature */
	if ( (ret=_gnutls_pkcs1_rsa_decrypt( &plain, *signature, cert->params[1], cert->params[0], 1)) < 0) {
	     gnutls_assert();
	     return ret;
	}

	if (plain.size != vdata.size) {
		gnutls_assert();
		gnutls_sfree_datum( &plain);
		return GNUTLS_E_PK_SIGNATURE_FAILED;
	}

	if ( memcmp(plain.data, vdata.data, plain.size)!=0) {
		gnutls_assert();
		gnutls_sfree_datum( &plain);
		return GNUTLS_E_PK_SIGNATURE_FAILED;
	}
	gnutls_sfree_datum( &plain);

	return 0;
}


/* Verifies a TLS signature (like the one in the client certificate
 * verify message). ubuffer_size is a buffer to remove from the hash buffer
 * in order to avoid hashing the last message.
 */
int _gnutls_verify_sig_hdata( GNUTLS_STATE state, gnutls_cert *cert, gnutls_datum* signature, int ubuffer_size) {
gnutls_datum data;
int size = gnutls_get_handshake_buffer_size( state) - ubuffer_size; /* do not get the last message */
int ret;

	data.data = gnutls_malloc(size);
	data.size = size;
	if (data.data==NULL) {
		gnutls_assert();
		return GNUTLS_E_MEMORY_ERROR;
	}
			
	gnutls_read_handshake_buffer( state, data.data, data.size);

	ret = _gnutls_pkcs1_rsa_verify_sig( cert, &data, signature);
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
	gnutls_datum sdata;
	int size = 2*TLS_RANDOM_SIZE; 
	int ret;

	sdata.data = gnutls_malloc( size+params->size);
	sdata.size = size + params->size;
	if (sdata.data==NULL) {
		gnutls_assert();
		return GNUTLS_E_MEMORY_ERROR;
	}

	memcpy( sdata.data, state->security_parameters.client_random, TLS_RANDOM_SIZE);
	memcpy( &sdata.data[TLS_RANDOM_SIZE], state->security_parameters.server_random, TLS_RANDOM_SIZE);
	memcpy( &sdata.data[2*TLS_RANDOM_SIZE], params->data, params->size);

	ret = _gnutls_pkcs1_rsa_verify_sig( cert, &sdata, signature);
	gnutls_free_datum( &sdata);
	if (ret < 0) {
		gnutls_assert();
		return ret;
	}

	return ret;

}

