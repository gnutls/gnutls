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
#include <cert_b64.h>
#include <auth_x509.h>
#include <gnutls_cert.h>
#include <cert_asn1.h>
#include <cert_der.h>
#include <gnutls_datum.h>
#include <gnutls_gcry.h>
#include <gnutls_privkey.h>
#include <gnutls_global.h>
#include <gnutls_pk.h>

static gnutls_datum* _gnutls_get_tbs( gnutls_cert* cert) {
node_asn *c2;
gnutls_datum * ret;
opaque str[10*1024];
int result, len;

	if (asn1_create_structure( _gnutls_get_pkix(), "Certificate", &c2, "certificate")!=ASN_OK) {
		gnutls_assert();
		return NULL;
	}
	
	result = asn1_get_der( c2, cert->raw.data, cert->raw.size);
	if (result != ASN_OK) {
		gnutls_assert();
		asn1_delete_structure(c2);
		return NULL;
	}
	
	len = sizeof(str)-1;
	result =
	    asn1_read_value( c2, "certificate.tbsCertificate", str, &len);
	if (result != ASN_OK) {
		gnutls_assert();
		asn1_delete_structure(c2);
		return NULL;
	}

	asn1_delete_structure(c2);

	ret = gnutls_malloc(sizeof(gnutls_cert));
	if (ret==NULL) {
		gnutls_assert();
		return NULL;
	}
	
	ret->data = gnutls_malloc( len);
	if (ret->data==NULL) {
		gnutls_assert();
		gnutls_free(ret);
		return NULL;
	}
	
	memcpy( ret->data, str, len);
	ret->size = len;

	return ret;
}


/* we use DER here -- FIXME: use BER
 */
static int _gnutls_get_ber_digest_info( const gnutls_datum *info, MACAlgorithm *hash, opaque* digest, int digest_size) {
node_asn* dinfo;
int result;
opaque str[1024];
int len;

	if (asn1_create_structure( _gnutls_get_pkcs(), "PKCS-1.DigestInfo", &dinfo, "digest_info")!=ASN_OK) {
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
	if ( strcmp(str, "xxxxxx")==0) { /* SHA1 ID */
		*hash = GNUTLS_MAC_SHA;
	}

	if (*hash==-1) {
fprintf(stderr, "OID: %s\n", str);
		gnutls_assert();
		return GNUTLS_E_UNIMPLEMENTED_FEATURE;
	}
	
	len = digest_size;
	result =
	    asn1_read_value( dinfo, "digest_info.digest", digest, &len);
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
_gnutls_pkcs1_rsa_verify_sig( gnutls_datum* signature, gnutls_datum* text, MPI m, MPI e)
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
	
	if ( (ret = _gnutls_get_ber_digest_info( &decrypted, &hash, digest, sizeof(digest))) != 0) {
		gnutls_assert();
		return ret;
	}

	gnutls_free_datum( &decrypted);

	digest_size = gnutls_hash_get_algo_len(hash);

	hd = gnutls_hash_init(hash);
	gnutls_hash(hd, text->data, text->size);
	gnutls_hash_deinit(hd, md);

	if (memcmp( md, digest, digest_size)!=0) 
		return GNUTLS_E_PK_SIGNATURE_FAILED;

	return 0;		
}

CertificateStatus gnutls_verify_signature(gnutls_cert* cert, gnutls_cert* issuer) {
gnutls_datum signature;
gnutls_datum* tbs;

	if ( issuer->subject_pk_algorithm == GNUTLS_PK_RSA) {
		signature.data = cert->signature;
		signature.size = cert->signature_size;
		
		tbs = _gnutls_get_tbs( cert);
		if (tbs==NULL) {
			gnutls_assert();
			return GNUTLS_CERT_INVALID;
		}
		
		if (_gnutls_pkcs1_rsa_verify_sig( &signature, tbs, issuer->params[1], issuer->params[0])!=0) {
			gnutls_assert();
			gnutls_free_datum( tbs);
			return GNUTLS_CERT_NOT_TRUSTED;
		}
		gnutls_free_datum(tbs);
		return GNUTLS_CERT_TRUSTED;
	}
fprintf(stderr, "PK: %d\n", issuer->subject_pk_algorithm);	
	gnutls_assert();
	return GNUTLS_CERT_INVALID;
}
