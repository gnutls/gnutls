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
			ret = _gnutls_pkcs1_rsa_generate_sig( GNUTLS_MAC_MD5, pkey, &data, signature);

			break;
		default:
			gnutls_free_datum( &data);
			ret = GNUTLS_E_UNIMPLEMENTED_FEATURE;
			break;
	}

	return ret;

}

#ifdef NO_SSL_SIGS
/* This is not used in SSL signatures
 */
static int _gnutls_digestinfo_encode( opaque* data, int data_size, char* OID, gnutls_datum* der) {
node_asn *di;
int result;

	if (asn1_create_structure( _gnutls_get_pkcs(),
                    "PKCS-1.DigestInfo", &di, "di") != ASN_OK) {
        	gnutls_assert();
		return GNUTLS_E_ASN1_ERROR;
	}
	
	result = asn1_write_value( di, "di.digestAlgorithm.algorithm", OID, 1);
	if (result!=ASN_OK) {
        	gnutls_assert();
		asn1_delete_structure( di);
		return GNUTLS_E_ASN1_ERROR;
	}

	result = asn1_write_value( di, "di.digestAlgorithm.parameters", NULL, 0);
	if (result!=ASN_OK) {
        	gnutls_assert();
		asn1_delete_structure( di);
		return GNUTLS_E_ASN1_ERROR;
	}

	result = asn1_write_value( di, "di.digest", data, data_size);
	if (result!=ASN_OK) {
        	gnutls_assert();
		asn1_delete_structure( di);
		return GNUTLS_E_ASN1_ERROR;
	}

	der->size = data_size + 200;
	der->data = gnutls_malloc( der->size);
	if (der->data==NULL) {
		gnutls_assert();
		asn1_delete_structure( di);
		return GNUTLS_E_MEMORY_ERROR;
	}
	
	result = asn1_create_der( di, "di", der->data, &der->size);
	if (result!=ASN_OK) {
        	gnutls_assert();
		asn1_delete_structure( di);
        	gnutls_free_datum( der);
		return GNUTLS_E_ASN1_ERROR;
	}
	asn1_delete_structure( di);

	return 0;
}
#endif

int _gnutls_pkcs1_rsa_generate_sig( MACAlgorithm hash_algo, gnutls_private_key *pkey, const gnutls_datum *data, gnutls_datum *signature) {
	int ret;
#ifdef NO_SSL_SIGS	
	GNUTLS_HASH_HANDLE hd;
	opaque digest[MAX_HASH_SIZE];
	char OID[40];
	int digest_size =  gnutls_hash_get_algo_len( hash_algo);
	gnutls_datum der;
	
	if (hash_algo==GNUTLS_MAC_MD5)
		strcpy(OID, "1 2 840 113549 2 5");
	else if (hash_algo==GNUTLS_MAC_SHA)
		strcpy(OID, "1 3 14 3 2 26");
	else {
		gnutls_assert();
		return GNUTLS_E_UNKNOWN_MAC_ALGORITHM;
	}
	
	/* hash data */
	hd = gnutls_hash_init( hash_algo);
	if (hd==NULL) {
		gnutls_assert();
		return GNUTLS_E_MEMORY_ERROR;
	}
	gnutls_hash( hd, data->data, data->size);
	gnutls_hash_deinit( hd, digest);

	/* encode digest to DigestInfo (der) */
	if ( (ret=_gnutls_digestinfo_encode( digest, digest_size, OID, &der)) < 0) {
		gnutls_assert();
		return ret;
	}	
#endif

	/* encrypt der */
	if ( (ret=_gnutls_pkcs1_rsa_encrypt( signature, *data, pkey->params[0], pkey->params[1], 1)) < 0) {
	     gnutls_assert();
	     return ret;
	}

#ifdef NO_SSL_SIGS
	gnutls_free_datum( &der);
#endif
	return 0;
}
