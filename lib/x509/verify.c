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

/* All functions which relate to X.509 certificate verification stuff are
 * included here
 */

#include <gnutls_int.h>
#include <gnutls_errors.h>
#include <gnutls_cert.h>
#include <libtasn1.h>
#include <gnutls_global.h>
#include <gnutls_num.h>		/* GMAX */
#include <gnutls_sig.h>
#include <gnutls_str.h>
#include <gnutls_datum.h>
#include <x509.h>
#include <crl.h>
#include <mpi.h>
#include <verify.h>

static int _gnutls_verify_certificate2(gnutls_x509_certificate cert,
			       gnutls_x509_certificate *trusted_cas, int tcas_size);
static
int _gnutls_x509_verify_signature(gnutls_x509_certificate cert, gnutls_x509_certificate issuer);


/* Checks if the issuer of a certificate is a
 * Certificate Authority, or if the certificate is the same
 * as the issuer (and therefore it doesn't need to be a CA).
 *
 * Returns true or false, if the issuer is a CA,
 * or not.
 */
static int check_if_ca(gnutls_x509_certificate cert,
	gnutls_x509_certificate issuer)
{
	/* Check if the issuer is the same with the
	 * certificate. This is added in order for trusted
	 * certificates to be able to verify themselves.
	 */
	if (cert->signed_data.size == issuer->signed_data.size) {
		if (
		    (memcmp(cert->signed_data.data, issuer->signed_data.data,
		    	cert->signed_data.size) == 0) &&
		    (cert->signature.size == issuer->signature.size) &&
		    (memcmp(cert->signature.data, issuer->signature.data,
		    	cert->signature.size) == 0))

			return 1;
	}

	if (gnutls_x509_certificate_get_ca_status(issuer, NULL) == 1) {
		return 1;
	} else
		gnutls_assert();

	return 0;
}


/* This function checks if 'certs' issuer is 'issuer_cert'.
 * This does a straight (DER) compare of the issuer/subject fields in
 * the given certificates.
 *
 * FIXME: use a real DN comparison algorithm.
 *
 * Returns 1 if the match and zero if they don't match. Otherwise
 * a negative value is returned to indicate error.
 */
static
int compare_dn(gnutls_x509_certificate cert, gnutls_x509_certificate issuer_cert)
{
	ASN1_TYPE c2, c3;
	int result, len1;
	int len2;
	int start1, start2, end1, end2;

	/* get the issuer of 'cert'
	 */
	if ((result =
	     _gnutls_asn1_create_element(_gnutls_get_pkix(), "PKIX1.TBSCertificate",
				   &c2, "c2")) != ASN1_SUCCESS) {
		gnutls_assert();
		return _gnutls_asn2err(result);
	}

	result = asn1_der_decoding(&c2, cert->signed_data.data, cert->signed_data.size, NULL);
	if (result != ASN1_SUCCESS) {
		/* couldn't decode DER */
		gnutls_assert();
		asn1_delete_structure(&c2);
		return _gnutls_asn2err(result);
	}


	/* get the 'subject' info of 'issuer_cert'
	 */
	if ((result =
	     _gnutls_asn1_create_element(_gnutls_get_pkix(), "PKIX1.TBSCertificate",
				   &c3, "c3")) != ASN1_SUCCESS) {
		gnutls_assert();
		asn1_delete_structure(&c2);
		return _gnutls_asn2err(result);
	}

	result =
	    asn1_der_decoding(&c3, issuer_cert->signed_data.data, issuer_cert->signed_data.size, NULL);
	if (result != ASN1_SUCCESS) {
		/* couldn't decode DER */
		gnutls_assert();
		asn1_delete_structure(&c2);
		asn1_delete_structure(&c3);
		return _gnutls_asn2err(result);
	}


	result =
	    asn1_der_decoding_startEnd(c2, cert->signed_data.data, cert->signed_data.size,
		   "c2.issuer", &start1, &end1);
	asn1_delete_structure(&c2);

	if (result != ASN1_SUCCESS) {
		gnutls_assert();
		asn1_delete_structure(&c3);
		return _gnutls_asn2err(result);
	}

	len1 = end1 - start1 + 1;

	result =
	    asn1_der_decoding_startEnd(c3, issuer_cert->signed_data.data,
				   issuer_cert->signed_data.size, 
				   "c3.subject",
				    &start2, &end2);
	asn1_delete_structure(&c3);

	if (result != ASN1_SUCCESS) {
		gnutls_assert();
		return _gnutls_asn2err(result);
	}

	len2 = end2 - start2 + 1;

	/* The error code returned does not really matter
	 * here.
	 */
	if (len1 != len2) {
		gnutls_assert();
		return 0;
	}
	if (memcmp(&issuer_cert->signed_data.data[start2],
		   &cert->signed_data.data[start1], len1) != 0) {
		gnutls_assert();
		return 0;
	}

	/* they match */
	return 1;

}

static gnutls_x509_certificate find_issuer(gnutls_x509_certificate cert,
				gnutls_x509_certificate * trusted_cas, int tcas_size)
{
	int i;

	/* this is serial search. 
	 */

	for (i = 0; i < tcas_size; i++) {
		if (compare_dn(cert, trusted_cas[i]) == 1)
			return trusted_cas[i];
	}

	gnutls_assert();
	return NULL;
}

/* 
 * Returns only 0 or 1. If 1 it means that the certificate 
 * was successfuly verified.
 */
static int _gnutls_verify_certificate2(gnutls_x509_certificate cert,
			       gnutls_x509_certificate *trusted_cas, int tcas_size)
{
/* CRL is ignored for now */

	gnutls_x509_certificate issuer;
	int ret;

	if (tcas_size >= 1)
		issuer = find_issuer(cert, trusted_cas, tcas_size);
	else {
		gnutls_assert();
		return 0;
	}

	/* issuer is not in trusted certificate
	 * authorities.
	 */
	if (issuer == NULL) {
		gnutls_assert();
		return 0;
	}

	if (check_if_ca(cert, issuer)==0) {
		gnutls_assert();
		return 0;
	}

	ret = _gnutls_x509_verify_signature(cert, issuer);
	if (ret < 0) {
		gnutls_assert();
		/* error. ignore it */
		ret = 0;
	}

	return ret;
}

/* The algorithm used is:
 * 1. Check the certificate chain given by the peer, if it is ok.
 * 2. If any certificate in the chain are revoked, not
 *    valid, or they are not CAs then the certificate is invalid.
 * 3. If 1 is ok, then find a certificate in the trusted CAs file
 *    that has the DN of the issuer field in the last certificate
 *    in the peer's certificate chain.
 * 4. If it does exist then verify it. If verification is ok then
 *    it is trusted. Otherwise it is just valid (but not trusted).
 */
/* This function verifies a X.509 certificate list. The certificate list should
 * lead to a trusted CA in order to be trusted.
 */
static
unsigned int _gnutls_x509_verify_certificate(gnutls_x509_certificate * certificate_list,
				    int clist_size,
				    gnutls_x509_certificate * trusted_cas,
				    int tcas_size, gnutls_x509_crl *CRLs,
				    int crls_size)
{
	int i = 0, ret;
	unsigned int status = 0;

	/* Verify the certificate path */
	for (i = 0; i < clist_size; i++) {
		if (i + 1 >= clist_size)
			break;

		if ((ret =
		     _gnutls_verify_certificate2(certificate_list[i],
						 &certificate_list[i + 1], 1)) != 1) 
		{
			status |= GNUTLS_CERT_INVALID;
		}
	}

	if (status != 0) { /* If there is any problem in the
			   * certificate chain then mark as not trusted
			   * and return immediately.
			   */
		return (status | GNUTLS_CERT_NOT_TRUSTED);
	}
	
	/* Now verify the last certificate in the certificate path
	 * against the trusted CA certificate list.
	 *
	 * If no CAs are present returns NOT_TRUSTED. Thus works
	 * in self signed etc certificates.
	 */
	ret =
	    _gnutls_verify_certificate2(certificate_list[i], trusted_cas,
				       tcas_size);

	if (ret == 0) {
		/* if the last certificate in the certificate
		 * list is invalid, then the certificate is not
		 * trusted.
		 */
		gnutls_assert();
		status |= GNUTLS_CERT_NOT_TRUSTED;
	}

	/* FIXME: Check CRL --not done yet.
	 */

	return status;
}




/* Reads the digest information.
 * we use DER here, although we should use BER. It works fine
 * anyway.
 */
static int _gnutls_get_ber_digest_info( const gnutls_datum *info, gnutls_mac_algorithm *hash, 
	opaque* digest, int *digest_size) 
{
ASN1_TYPE dinfo = ASN1_TYPE_EMPTY;
int result;
opaque str[1024];
int len;

	if ((result=asn1_create_element( _gnutls_get_gnutls_asn(), 
		"GNUTLS.DigestInfo", &dinfo, "digest_info"))!=ASN1_SUCCESS) {
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

	*hash = (gnutls_mac_algorithm)-1;
	
	if ( strcmp(str, "1 2 840 113549 2 5")==0) { /* MD5 */
		*hash = GNUTLS_MAC_MD5;
	} else 
	if ( strcmp(str, "1 3 14 3 2 26")==0) { /* SHA1 ID */
		*hash = GNUTLS_MAC_SHA;
	}

	if (*hash==(gnutls_mac_algorithm)-1) {

		_gnutls_x509_log( "X509_SIG: HASH OID: %s\n", str);

		gnutls_assert();
		asn1_delete_structure(&dinfo);
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
		_gnutls_free_datum( &decrypted);
		return ret;
	}

	_gnutls_free_datum( &decrypted);

	if (digest_size != _gnutls_hash_get_algo_len(hash)) {
		gnutls_assert();
		return GNUTLS_E_ASN1_GENERIC_ERROR;
	}

	hd = _gnutls_hash_init( hash);
	_gnutls_hash( hd, text->data, text->size);
	_gnutls_hash_deinit( hd, md);

	if (memcmp( md, digest, digest_size)!=0) {
		gnutls_assert();
		return GNUTLS_E_PK_SIG_VERIFY_FAILED;
	}

	return 0;		
}

/* verifies if the certificate is properly signed.
 * returns 0 on failure and 1 on success.
 */
static
int _gnutls_x509_verify_signature(gnutls_x509_certificate cert, gnutls_x509_certificate issuer) 
{
gnutls_datum signature;
gnutls_datum tbs;
GNUTLS_MPI issuer_params[MAX_PARAMS_SIZE];
int ret, issuer_params_size, i;

	signature = cert->signature;
	tbs = cert->signed_data;

	/* Read the MPI parameters from the issuer's certificate.
	 */
	issuer_params_size = MAX_PARAMS_SIZE;
	ret = _gnutls_x509_certificate_get_mpis(issuer, issuer_params, &issuer_params_size);

	if ( ret < 0) {
		gnutls_assert();
		return ret;
	}

	switch( gnutls_x509_certificate_get_pk_algorithm(issuer, NULL)) 
	{
		case GNUTLS_PK_RSA:

			if (_pkcs1_rsa_verify_sig( &signature, &tbs, issuer_params, issuer_params_size)!=0) {
				gnutls_assert();
				ret = 0;
				goto finish;
			}

			ret = 1;
			goto finish;
			break;

		case GNUTLS_PK_DSA:
			if (_gnutls_dsa_verify( &tbs, &signature, issuer_params, issuer_params_size)!=0) {
				gnutls_assert();
				ret = 0;
				goto finish;
			}

			ret = 1;
			goto finish;
			break;
		default:
			gnutls_assert();
			ret = GNUTLS_E_INTERNAL_ERROR;
			goto finish;

	}

	finish:

	/* release all allocated MPIs
	 */
	for (i = 0; i < issuer_params_size; i++) {
		_gnutls_mpi_release( &issuer_params[i]);
	}
	return ret;
}

/**
  * gnutls_x509_certificate_list_verify - This function verifies the given certificate list
  * @cert_list: is the certificate list to be verified
  * @cert_list_length: holds the number of certificate in cert_list
  * @CA_list: is the CA list which will be used in verification
  * @CA_list_length: holds the number of CA certificate in CA_list
  * @CRL_list: holds a list of CRLs.
  * @CRL_list_length: the length of CRL list.
  * @verify: will hold the certificate verification output.
  *
  * This function will try to verify the given certificate list and return it's status (TRUSTED, EXPIRED etc.). 
  * The return value (status) should be one or more of the gnutls_certificate_status 
  * enumerated elements bitwise or'd. Note that expiration and activation dates are not checked 
  * by this function, you should check them using the appropriate functions.
  *
  * This function uses the basicConstraints (2 5 29 19) PKIX extension.
  * This means that only a certificate authority can sign a certificate.
  *
  * However you must also check the peer's name in order to check if the verified 
  * certificate belongs to the actual peer. 
  *
  *
  * The certificate verification output will be put in 'verify' and will be
  * one or more of the gnutls_certificate_status enumerated elements bitwise or'd.
  *
  * GNUTLS_CERT_NOT_TRUSTED\: the peer's certificate is not trusted.
  *
  * GNUTLS_CERT_INVALID\: the certificate chain is broken.
  *
  * GNUTLS_CERT_REVOKED\: the certificate has been revoked.
  *
  * GNUTLS_CERT_CORRUPTED\: the certificate is corrupted.
  *
  *
  * Returns 0 on success and a negative value in case of an error.
  *
  **/
int gnutls_x509_certificate_list_verify( gnutls_x509_certificate* cert_list, int cert_list_length, 
	gnutls_x509_certificate * CA_list, int CA_list_length, 
	gnutls_x509_crl* CRL_list, int CRL_list_length, unsigned int *verify)
{
	if (cert_list == NULL || cert_list_length == 0)
		return GNUTLS_E_NO_CERTIFICATE_FOUND;

	/* Verify certificate 
	 */
	*verify =
	    _gnutls_x509_verify_certificate( cert_list, cert_list_length,
		CA_list, CA_list_length, CRL_list, CRL_list_length);

	return 0;
}
