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

int _gnutls_generate_sig( GNUTLS_STATE state, gnutls_private_key *pkey, gnutls_datum *signature) {
opaque digest[20+16];
gnutls_datum data;
GNUTLS_HASH_HANDLE td;
int size = gnutls_getHashDataBufferSize( state);
int ret;

	data.data = gnutls_malloc(size);
	data.size = size;
	if (data.data==NULL) {
		gnutls_assert();
		return GNUTLS_E_MEMORY_ERROR;
	}
			
	gnutls_readHashDataFromBuffer( state, data.data, data.size);

	switch(pkey->pk_algorithm) {
		case GNUTLS_PK_RSA:
			
			td = gnutls_hash_init( GNUTLS_MAC_MD5);
			if (td==NULL) {
				gnutls_assert();
				gnutls_free_datum( &data);
				return GNUTLS_E_MEMORY_ERROR;
			}
			gnutls_hash( td, data.data, data.size);
			gnutls_hash_deinit( td, digest);

			td = gnutls_hash_init( GNUTLS_MAC_SHA);
			if (td==NULL) {
				gnutls_assert();
				gnutls_free_datum( &data);
				return GNUTLS_E_MEMORY_ERROR;
			}
			gnutls_hash( td, data.data, data.size);
			gnutls_hash_deinit( td, &digest[16]);
			gnutls_free_datum( &data);
			

			data.data = digest;
			data.size = 20+16; /* md5 + sha */	
			ret = _gnutls_pkcs1_rsa_generate_sig( pkey, &data, signature);

			break;
		default:
			gnutls_free_datum( &data);
			ret = GNUTLS_E_UNIMPLEMENTED_FEATURE;
			break;
	}

	return ret;

}

int _gnutls_pkcs1_rsa_generate_sig( gnutls_private_key *pkey, const gnutls_datum *data, gnutls_datum *signature) {
	int ret;

	/* encrypt der */
	if ( (ret=_gnutls_pkcs1_rsa_encrypt( signature, *data, pkey->params[0], pkey->params[1], 1)) < 0) {
	     gnutls_assert();
	     return ret;
	}

	return 0;
}

int _gnutls_pkcs1_rsa_verify_sig( gnutls_cert *cert, const gnutls_datum *data, gnutls_datum *signature) {
	int ret;
	gnutls_datum plain;
	
	/* decrypt signature */
	if ( (ret=_gnutls_pkcs1_rsa_decrypt( &plain, *signature, cert->params[0], cert->params[1], 1)) < 0) {
	     gnutls_assert();
	     return ret;
	}

	if (plain.size != data->size) {
		gnutls_assert();
		return GNUTLS_E_PK_SIGNATURE_FAILED;
	}

	if ( memcmp(plain.data, data->data, plain.size)!=0) {
		gnutls_assert();
		return GNUTLS_E_PK_SIGNATURE_FAILED;
	}

	return 0;
}


/* Verifies a TLS signature (like the one in the client certificate
 * verify message).
 */
int _gnutls_verify_sig( GNUTLS_STATE state, gnutls_cert *cert, gnutls_datum* signature, int ubuffer_size) {
opaque digest[20+16];
gnutls_datum data;
GNUTLS_HASH_HANDLE td;
int size = gnutls_getHashDataBufferSize( state) - ubuffer_size; /* do not get the last message */
int ret;

	data.data = gnutls_malloc(size);
	data.size = size;
	if (data.data==NULL) {
		gnutls_assert();
		return GNUTLS_E_MEMORY_ERROR;
	}
			
	gnutls_readHashDataFromBuffer( state, data.data, data.size);

	switch(cert->subject_pk_algorithm) {
		case GNUTLS_PK_RSA:
			
			td = gnutls_hash_init( GNUTLS_MAC_MD5);
			if (td==NULL) {
				gnutls_assert();
				gnutls_free_datum( &data);
				return GNUTLS_E_MEMORY_ERROR;
			}
			gnutls_hash( td, data.data, data.size);
			gnutls_hash_deinit( td, digest);

			td = gnutls_hash_init( GNUTLS_MAC_SHA);
			if (td==NULL) {
				gnutls_assert();
				gnutls_free_datum( &data);
				return GNUTLS_E_MEMORY_ERROR;
			}
			gnutls_hash( td, data.data, data.size);
			gnutls_hash_deinit( td, &digest[16]);
			gnutls_free_datum( &data);
			

			data.data = digest;
			data.size = 20+16; /* md5 + sha */	
			ret = _gnutls_pkcs1_rsa_verify_sig( cert, &data, signature);

			break;
		default:
			gnutls_assert();
			gnutls_free_datum( &data);
			ret = GNUTLS_E_UNIMPLEMENTED_FEATURE;
			break;
	}

	return ret;

}





