/*
 *      Copyright (C) 2001,2002 Nikos Mavroyanopoulos
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

/* Functions that relate to X.509 certificate signature checking.
 */

#include <gnutls_int.h>
#include <gnutls_errors.h>
#include <x509_b64.h>
#include <auth_cert.h>
#include <gnutls_cert.h>
#include <libtasn1.h>
#include <gnutls_datum.h>
#include <gnutls_mpi.h>
#include <gnutls_privkey.h>
#include <gnutls_global.h>
#include <gnutls_pk.h>
#include <debug.h>
#include <gnutls_str.h>

/* returns DER tbsCertificate
 */
static gnutls_datum _gnutls_get_tbs( gnutls_cert* cert) {
ASN1_TYPE c2;
gnutls_datum ret = {NULL, 0};
opaque *str;
int result, len;
int start, end;

	if (_gnutls_asn1_create_element( _gnutls_get_pkix(), "PKIX1.Certificate", &c2, "certificate")!=ASN1_SUCCESS) {
		gnutls_assert();
		return ret;
	}
	
	result = asn1_der_decoding( &c2, cert->raw.data, cert->raw.size, NULL);
	if (result != ASN1_SUCCESS) {
		gnutls_assert();
		asn1_delete_structure(&c2);
		return ret;
	}
	
	result = asn1_der_decoding_startEnd( c2, cert->raw.data, cert->raw.size, 
		"certificate.tbsCertificate", &start, &end);
	asn1_delete_structure(&c2);
		
	if (result != ASN1_SUCCESS) {
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
static int _gnutls_get_ber_digest_info( const gnutls_datum *info, gnutls_mac_algorithm *hash, opaque* digest, int *digest_size) {
ASN1_TYPE dinfo;
int result;
opaque str[1024];
int len;

	if ((result=_gnutls_asn1_create_element( _gnutls_get_gnutls_asn(), "GNUTLS.DigestInfo", &dinfo, "digest_info"))!=ASN1_SUCCESS) {
		gnutls_assert();
		return _gnutls_asn2err(result);
	}

	result = asn1_der_decoding( &dinfo, info->data, info->size, NULL);
	if (result != ASN1_SUCCESS) {
		gnutls_assert();
		asn1_delete_structure(&dinfo);
		return _gnutls_asn2err(result);
	}
	
	len = sizeof(str)-1;
	result =
	    asn1_read_value( dinfo, "digest_info.digestAlgorithm.algorithm", str, &len);
	if (result != ASN1_SUCCESS) {
		gnutls_assert();
		asn1_delete_structure(&dinfo);
		return _gnutls_asn2err(result);
	}

	*hash = -1;
	
	if ( strcmp(str, "1 2 840 113549 2 5")==0) { /* MD5 */
		*hash = GNUTLS_MAC_MD5;
	} else 
	if ( strcmp(str, "1 3 14 3 2 26")==0) { /* SHA1 ID */
		*hash = GNUTLS_MAC_SHA;
	}

	if (*hash==-1) {

		_gnutls_x509_log( "X509_SIG: HASH OID: %s\n", str);

		gnutls_assert();
		return GNUTLS_E_UNIMPLEMENTED_FEATURE;
	}
	
	result =
	    asn1_read_value( dinfo, "digest_info.digest", digest, digest_size);
	if (result != ASN1_SUCCESS) {
		gnutls_assert();
		asn1_delete_structure(&dinfo);
		return _gnutls_asn2err(result);
	}

	asn1_delete_structure(&dinfo);
		
	return 0;
}

/* if hash==MD5 then we do RSA-MD5
 * if hash==SHA then we do RSA-SHA
 * params[0] is modulus
 * params[1] is public key
 */
static int
_pkcs1_rsa_verify_sig( const gnutls_datum* signature, gnutls_datum* text, GNUTLS_MPI *params, int params_len)
{
	gnutls_mac_algorithm hash;
	int ret;
	opaque digest[MAX_HASH_SIZE], md[MAX_HASH_SIZE];
	int digest_size; 
	GNUTLS_HASH_HANDLE hd;
	gnutls_datum decrypted;
	
	if ( (ret=_gnutls_pkcs1_rsa_decrypt( &decrypted, *signature, params, params_len, 1)) < 0) {
		gnutls_assert();
		return ret;
	}
	
	/* decrypted is a BER encoded data of type DigestInfo
	 */

	digest_size = sizeof(digest);	
	if ( (ret = _gnutls_get_ber_digest_info( &decrypted, &hash, digest, &digest_size)) != 0) {
		gnutls_assert();
		gnutls_sfree_datum( &decrypted);
		return ret;
	}

	gnutls_sfree_datum( &decrypted);

	if (digest_size != _gnutls_hash_get_algo_len(hash)) {
		gnutls_assert();
		return GNUTLS_E_ASN1_GENERIC_ERROR;
	}

	hd = _gnutls_hash_init( hash);
	_gnutls_hash( hd, text->data, text->size);
	_gnutls_hash_deinit( hd, md);

	if (memcmp( md, digest, digest_size)!=0) {
		gnutls_assert();
		return GNUTLS_E_PK_SIGNATURE_FAILED;
	}

	return 0;		
}

/* verifies if the certificate is properly signed.
 * returns 0 on success.
 */
gnutls_certificate_status gnutls_x509_verify_signature(gnutls_cert* cert, gnutls_cert* issuer) {
gnutls_datum signature;
gnutls_datum tbs;

	signature.data = cert->signature.data;
	signature.size = cert->signature.size;
		
	tbs = _gnutls_get_tbs( cert);
	if (tbs.data==NULL) {
		gnutls_assert();
		return GNUTLS_CERT_INVALID;
	}

	_gnutls_x509_log("X509_VERIFY: CERT[%s]\n", GET_CN(cert->raw));
	_gnutls_x509_log("X509_VERIFY: ISSUER[%s]\n", GET_CN(issuer->raw));

	switch( issuer->subject_pk_algorithm) {
		case GNUTLS_PK_RSA:
		
			if (_pkcs1_rsa_verify_sig( &signature, &tbs, issuer->params, issuer->params_size)!=0) {
				gnutls_assert();
				gnutls_free_datum( &tbs);
				return GNUTLS_CERT_INVALID;
			}

			gnutls_free_datum(&tbs);
			return 0;
			break;

		case GNUTLS_PK_DSA:
			if (_gnutls_dsa_verify( &tbs, &signature, issuer->params, issuer->params_size)!=0) {
				gnutls_assert();
				gnutls_free_datum( &tbs);
				return GNUTLS_CERT_INVALID;
			}

			gnutls_free_datum(&tbs);
			return 0;
			break;
		default:
			gnutls_assert();
			gnutls_free_datum(&tbs);
			return GNUTLS_E_INTERNAL_ERROR;

	}

	gnutls_free_datum(&tbs);

	_gnutls_x509_log( "X509_SIG: PK: %d\n", issuer->subject_pk_algorithm);	

	gnutls_assert();
	return GNUTLS_CERT_INVALID;
}


