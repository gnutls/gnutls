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
#include <gnutls_str.h>

static gnutls_datum _gnutls_get_tbs( gnutls_cert* cert) {
node_asn *c2;
gnutls_datum ret = {NULL, 0};
opaque *str;
int result, len;
int start, end;

	if (asn1_create_structure( _gnutls_get_pkix(), "PKIX1Implicit88.Certificate", &c2, "certificate")!=ASN_OK) {
		gnutls_assert();
		return ret;
	}
	
	result = asn1_get_der( c2, cert->raw.data, cert->raw.size);
	if (result != ASN_OK) {
		gnutls_assert();
		asn1_delete_structure(c2);
		return ret;
	}
	
	result = asn1_get_start_end_der( c2, cert->raw.data, cert->raw.size, 
		"certificate.tbsCertificate", &start, &end);
	asn1_delete_structure(c2);
		
	if (result != ASN_OK) {
		gnutls_assert();
		return ret;
	}

	len = end - start + 1;
	str = &cert->raw.data[start];

	if (gnutls_set_datum( &ret, str, len) < 0) {
		gnutls_assert();
		return ret;
	}
	
	return ret;
}


/* we use DER here -- FIXME: use BER
 */
static int _gnutls_get_ber_digest_info( const gnutls_datum *info, MACAlgorithm *hash, opaque* digest, int *digest_size) {
node_asn* dinfo;
int result;
opaque str[1024];
int len;

	if (asn1_create_structure( _gnutls_get_gnutls_asn(), "GNUTLS.DigestInfo", &dinfo, "digest_info")!=ASN_OK) {
		gnutls_assert();
		return GNUTLS_E_ASN1_ERROR;
	}

	result = asn1_get_der( dinfo, info->data, info->size);
	if (result != ASN_OK) {
		gnutls_assert();
		asn1_delete_structure(dinfo);
		return GNUTLS_E_ASN1_PARSING_ERROR;
	}
	
	len = sizeof(str)-1;
	result =
	    asn1_read_value( dinfo, "digest_info.digestAlgorithm.algorithm", str, &len);
	if (result != ASN_OK) {
		gnutls_assert();
		asn1_delete_structure(dinfo);
		return GNUTLS_E_ASN1_PARSING_ERROR;
	}

	*hash = -1;
	
	if ( strcmp(str, "1 2 840 113549 2 5")==0) { /* MD5 */
		*hash = GNUTLS_MAC_MD5;
	} else 
	if ( strcmp(str, "1 3 14 3 2 26")==0) { /* SHA1 ID */
		*hash = GNUTLS_MAC_SHA;
	}

	if (*hash==-1) {

		_gnutls_log( "X509_sig: HASH OID: %s\n", str);

		gnutls_assert();
		return GNUTLS_E_UNIMPLEMENTED_FEATURE;
	}
	
	result =
	    asn1_read_value( dinfo, "digest_info.digest", digest, digest_size);
	if (result != ASN_OK) {
		gnutls_assert();
		asn1_delete_structure(dinfo);
		return GNUTLS_E_ASN1_PARSING_ERROR;
	}

	asn1_delete_structure(dinfo);
		
	return 0;
}

/* if hash==MD5 then we do RSA-MD5
 * if hash==SHA then we do RSA-SHA
 * m is modulus
 * e is public key
 */
int
_pkcs1_rsa_verify_sig( gnutls_datum* signature, gnutls_datum* text, MPI e, MPI m)
{
	MACAlgorithm hash;
	int ret;
	opaque digest[MAX_HASH_SIZE], md[MAX_HASH_SIZE];
	int digest_size; 
	GNUTLS_HASH_HANDLE hd;
	gnutls_datum decrypted;
	

	if ( (ret=_gnutls_pkcs1_rsa_decrypt( &decrypted, *signature, e, m, 1)) < 0) {
		gnutls_assert();
		return ret;
	}
	
	/* decrypted is a BER encoded data of type DigestInfo
	 */

	digest_size = sizeof(digest);	
	if ( (ret = _gnutls_get_ber_digest_info( &decrypted, &hash, digest, &digest_size )) != 0) {
		gnutls_assert();
		gnutls_sfree_datum( &decrypted);
		return ret;
	}

	gnutls_sfree_datum( &decrypted);

	if (digest_size != gnutls_hash_get_algo_len(hash)) {
		gnutls_assert();
		return GNUTLS_E_ASN1_PARSING_ERROR;
	}

	hd = gnutls_hash_init( hash);
	gnutls_hash( hd, text->data, text->size);
	gnutls_hash_deinit( hd, md);

	if (memcmp( md, digest, digest_size)!=0) {
		gnutls_assert();
		return GNUTLS_E_PK_SIGNATURE_FAILED;
	}

	return 0;		
}

#ifdef DEBUG
/* This is for CA DSS params - can wait */
# warning CHECK HERE FOR DSS
#endif

/* verifies if the certificate is properly signed.
 */
CertificateStatus gnutls_x509_verify_signature(gnutls_cert* cert, gnutls_cert* issuer) {
gnutls_datum signature;
gnutls_datum tbs;

	if ( issuer->subject_pk_algorithm == GNUTLS_PK_RSA) {
		signature.data = cert->signature;
		signature.size = cert->signature_size;
		
		tbs = _gnutls_get_tbs( cert);
		if (tbs.data==NULL) {
			gnutls_assert();
			return GNUTLS_CERT_INVALID;
		}
		
		if (_pkcs1_rsa_verify_sig( &signature, &tbs, issuer->params[1], issuer->params[0])!=0) {
			gnutls_assert();
			gnutls_free_datum( &tbs);
			return GNUTLS_CERT_NOT_TRUSTED;
		}
		gnutls_free_datum(&tbs);
		return GNUTLS_CERT_TRUSTED;
	}

	_gnutls_log( "X509_sig: PK: %d\n", issuer->subject_pk_algorithm);	

	gnutls_assert();
	return GNUTLS_CERT_INVALID;
}


#if 0
/* Signature generation - not tested */
static int _gnutls_digestinfo_encode( opaque* data, int data_size, char* OID, gnutls_datum* der) {
node_asn *di;
int result;

	if (asn1_create_structure( _gnutls_get_gnutls_asn(),
                    "GNUTLS.DigestInfo", &di, "di") != ASN_OK) {
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

int _pkcs1_rsa_generate_sig( MACAlgorithm hash_algo, gnutls_private_key *pkey, const gnutls_datum *data, gnutls_datum *signature) {
	int ret;
	GNUTLS_HASH_HANDLE hd;
	opaque digest[MAX_HASH_SIZE];
	char OID[64];
	int digest_size =  gnutls_hash_get_algo_len( hash_algo);
	gnutls_datum der;
	
	if (hash_algo==GNUTLS_MAC_MD5)
		_gnutls_str_cpy(OID, sizeof(OID), "1 2 840 113549 2 5"); 
	else if (hash_algo==GNUTLS_MAC_SHA)
		_gnutls_str_cpy(OID, sizeof(OID), "1 3 14 3 2 26"); 
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

	der.data = digest;
	der.size = digest_size;
	/* encrypt der */
	if ( (ret=_gnutls_pkcs1_rsa_encrypt( signature, der, pkey->params[0], pkey->params[1], 1)) < 0) {
	     gnutls_assert();
	     return ret;
	}

	return 0;
}
#endif
