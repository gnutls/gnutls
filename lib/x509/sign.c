/*
 *  Copyright (C) 2003 Nikos Mavroyanopoulos <nmav@hellug.gr>
 *
 *  This file is part of GNUTLS.
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

/* All functions which relate to X.509 certificate signing stuff are
 * included here
 */

#include <gnutls_int.h>

#ifdef ENABLE_PKI

#include <gnutls_errors.h>
#include <gnutls_cert.h>
#include <libtasn1.h>
#include <gnutls_global.h>
#include <gnutls_num.h>		/* GMAX */
#include <gnutls_sig.h>
#include <gnutls_str.h>
#include <gnutls_datum.h>
#include <dn.h>
#include <x509.h>
#include <mpi.h>
#include <sign.h>
#include <common.h>
#include <verify.h>

/* Writes the digest information and the digest in a DER encoded
 * structure. The digest info is allocated and stored into the info structure.
 */
static int encode_ber_digest_info( gnutls_mac_algorithm hash, 
	const gnutls_datum* digest, gnutls_datum *info) 
{
ASN1_TYPE dinfo = ASN1_TYPE_EMPTY;
int result;
const char* algo;

	algo = _gnutls_x509_mac2oid( hash);
	if (algo == NULL) {
		gnutls_assert();
		return GNUTLS_E_UNKNOWN_PK_ALGORITHM;
	}

	if ((result=asn1_create_element( _gnutls_get_gnutls_asn(), 
		"GNUTLS.DigestInfo", &dinfo))!=ASN1_SUCCESS) {
		gnutls_assert();
		return _gnutls_asn2err(result);
	}
		
	result =
	    asn1_write_value( dinfo, "digestAlgorithm.algorithm", algo, 1);
	if (result != ASN1_SUCCESS) {
		gnutls_assert();
		asn1_delete_structure(&dinfo);
		return _gnutls_asn2err(result);
	}

	result =
	    asn1_write_value( dinfo, "digestAlgorithm.parameters", NULL, 0);
	if (result != ASN1_SUCCESS) {
		gnutls_assert();
		asn1_delete_structure(&dinfo);
		return _gnutls_asn2err(result);
	}

	result =
	    asn1_write_value( dinfo, "digest", digest->data, digest->size);
	if (result != ASN1_SUCCESS) {
		gnutls_assert();
		asn1_delete_structure(&dinfo);
		return _gnutls_asn2err(result);
	}

	info->size = 0;
	asn1_der_coding( dinfo, "", NULL, &info->size, NULL);

	info->data = gnutls_malloc( info->size);
	if (info->data == NULL) {
		gnutls_assert();
		asn1_delete_structure(&dinfo);
		return GNUTLS_E_MEMORY_ERROR;
	}

	result = asn1_der_coding( dinfo, "", info->data, &info->size, NULL);
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
_pkcs1_rsa_sign( gnutls_mac_algorithm hash, const gnutls_datum* text,  
	GNUTLS_MPI *params, int params_len, gnutls_datum* signature)
{
	int ret;
	opaque _digest[MAX_HASH_SIZE];
	GNUTLS_HASH_HANDLE hd;
	gnutls_datum digest, info;

	hd = _gnutls_hash_init( hash);
	if (hd == NULL) {
		gnutls_assert();
		return GNUTLS_E_HASH_FAILED;
	}
	
	_gnutls_hash( hd, text->data, text->size);
	_gnutls_hash_deinit( hd, _digest);

	digest.data = _digest;
	digest.size = _gnutls_hash_get_algo_len(hash);

	/* Encode the digest as a DigestInfo
	 */
	if ( (ret = encode_ber_digest_info( hash, &digest, &info)) != 0) {
		gnutls_assert();
		return ret;
	}

	if ( (ret=_gnutls_sign( GNUTLS_PK_RSA, params, params_len, &info, signature)) < 0) {
		gnutls_assert();
		_gnutls_free_datum( &info);
		return ret;
	}

	_gnutls_free_datum( &info);

	return 0;		
}

/* Signs the given data using the parameters from the signer's
 * private key.
 *
 * returns 0 on success.
 * 
 * 'tbs' is the data to be signed
 * 'signature' will hold the signature!
 * 'hash' is only used in PKCS1 RSA signing.
 */
int _gnutls_x509_sign( const gnutls_datum* tbs, gnutls_mac_algorithm hash,
	gnutls_x509_privkey signer, gnutls_datum* signature) 
{
int ret;

	switch( signer->pk_algorithm)
	{
		case GNUTLS_PK_RSA:

			ret = _pkcs1_rsa_sign( hash, tbs, signer->params, signer->params_size,
				signature);
			if (ret < 0) {
				gnutls_assert();
				return ret;
			}
			return 0;
			break;

		case GNUTLS_PK_DSA:
			ret = _gnutls_dsa_sign( signature, tbs, signer->params, signer->params_size);
			if (ret < 0) {
				gnutls_assert();
				return ret;
			}

			return 0;
			break;
		default:
			gnutls_assert();
			return GNUTLS_E_INTERNAL_ERROR;
	}

}

/* This is the same as the _gnutls_x509_sign, but this one will decode
 * the ASN1_TYPE given, and sign the DER data. Actually used to get the DER
 * of the TBS and sign it on the fly.
 */
int _gnutls_x509_sign_tbs( ASN1_TYPE cert, const char* tbs_name,
	gnutls_mac_algorithm hash, gnutls_x509_privkey signer, gnutls_datum* signature) 
{
int result;
opaque *buf;
int buf_size;
gnutls_datum tbs;

	buf_size = 0;
	asn1_der_coding( cert, tbs_name, NULL, &buf_size, NULL);

	buf = gnutls_alloca( buf_size);
	if (buf == NULL) {
		gnutls_assert();
		return GNUTLS_E_MEMORY_ERROR;
	}

	result = asn1_der_coding( cert, tbs_name, buf, &buf_size, NULL);
	
	if (result != ASN1_SUCCESS) {
		gnutls_assert();
		gnutls_afree(buf);
		return _gnutls_asn2err(result);
	}

	tbs.data = buf;
	tbs.size = buf_size;
	
	result = _gnutls_x509_sign( &tbs, hash, signer, signature);
	gnutls_afree(buf);
	
	return result;
}

#endif
