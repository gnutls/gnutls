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
#include <dn.h>
#include <x509.h>
#include <mpi.h>
#include <verify.h>

static int _gnutls_verify_certificate2(gnutls_x509_crt cert,
			       gnutls_x509_crt *trusted_cas, int tcas_size, 
			       unsigned int flags);
static
int _gnutls_x509_verify_signature(const gnutls_datum* signed_data,
	const gnutls_datum* signature, gnutls_x509_crt issuer);


/* Checks if the issuer of a certificate is a
 * Certificate Authority, or if the certificate is the same
 * as the issuer (and therefore it doesn't need to be a CA).
 *
 * Returns true or false, if the issuer is a CA,
 * or not.
 */
static int check_if_ca(gnutls_x509_crt cert,
	gnutls_x509_crt issuer)
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

	if (gnutls_x509_crt_get_ca_status(issuer, NULL) == 1) {
		return 1;
	} else
		gnutls_assert();

	return 0;
}


/* This function checks if 'certs' issuer is 'issuer_cert'.
 * This does a straight (DER) compare of the issuer/subject fields in
 * the given certificates.
 *
 * Returns 1 if the match and zero if they don't match. Otherwise
 * a negative value is returned to indicate error.
 */
static
int is_issuer(gnutls_x509_crt cert, gnutls_x509_crt issuer_cert)
{
	gnutls_const_datum dn1, dn2;
	int ret;

	ret = _gnutls_x509_crt_get_raw_issuer_dn( cert, &dn1);
	if (ret < 0) {
		gnutls_assert();
		return ret;
	}

	ret = _gnutls_x509_crt_get_raw_dn( issuer_cert, &dn2);
	if (ret < 0) {
		gnutls_assert();
		return ret;
	}

	return _gnutls_x509_compare_raw_dn( &dn1, &dn2);

}

/* The same as above, but here we've got a CRL.
 */
static
int is_crl_issuer(gnutls_x509_crl crl, gnutls_x509_crt issuer_cert)
{
	gnutls_const_datum dn1, dn2;
	int ret;

	ret = _gnutls_x509_crl_get_raw_issuer_dn( crl, &dn1);
	if (ret < 0) {
		gnutls_assert();
		return ret;
	}

	ret = _gnutls_x509_crt_get_raw_dn( issuer_cert, &dn2);
	if (ret < 0) {
		gnutls_assert();
		return ret;
	}

	return _gnutls_x509_compare_raw_dn( &dn1, &dn2);

}

static inline
gnutls_x509_crt find_crl_issuer(gnutls_x509_crl crl,
				gnutls_x509_crt * trusted_cas, int tcas_size)
{
	int i;

	/* this is serial search. 
	 */

	for (i = 0; i < tcas_size; i++) {
		if (is_crl_issuer(crl, trusted_cas[i]) == 1)
			return trusted_cas[i];
	}

	gnutls_assert();
	return NULL;
}



static inline
gnutls_x509_crt find_issuer(gnutls_x509_crt cert,
				gnutls_x509_crt * trusted_cas, int tcas_size)
{
	int i;

	/* this is serial search. 
	 */

	for (i = 0; i < tcas_size; i++) {
		if (is_issuer(cert, trusted_cas[i]) == 1)
			return trusted_cas[i];
	}

	gnutls_assert();
	return NULL;
}



/* 
 * Returns only 0 or 1. If 1 it means that the certificate 
 * was successfuly verified.
 *
 * 'flags': an OR of the gnutls_certificate_verify_flags enumeration.
 */
static int _gnutls_verify_certificate2(gnutls_x509_crt cert,
			       gnutls_x509_crt *trusted_cas, int tcas_size, 
			       unsigned int flags)
{
/* CRL is ignored for now */

	gnutls_x509_crt issuer;
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

	if (!(flags & GNUTLS_VERIFY_DISABLE_CA_SIGN)) {
		if (check_if_ca(cert, issuer)==0) {
			gnutls_assert();
			return 0;
		}
	}

	ret = _gnutls_x509_verify_signature(&cert->signed_data, &cert->signature, issuer);
	if (ret < 0) {
		gnutls_assert();
		/* error. ignore it */
		ret = 0;
	}

	return ret;
}

/* 
 * Returns only 0 or 1. If 1 it means that the CRL
 * was successfuly verified.
 *
 * 'flags': an OR of the gnutls_certificate_verify_flags enumeration.
 */
static int _gnutls_verify_crl2(gnutls_x509_crl crl,
			       gnutls_x509_crt *trusted_cas, int tcas_size, 
			       unsigned int flags)
{
/* CRL is ignored for now */

	gnutls_x509_crt issuer;
	int ret;

	if (tcas_size >= 1)
		issuer = find_crl_issuer(crl, trusted_cas, tcas_size);
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

	if (!(flags & GNUTLS_VERIFY_DISABLE_CA_SIGN)) {
		if (gnutls_x509_crt_get_ca_status(issuer, NULL) != 1) 
		{
			gnutls_assert();
			return 0;
		}
	}

	ret = _gnutls_x509_verify_signature(&crl->signed_data, &crl->signature, issuer);
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
unsigned int _gnutls_x509_verify_certificate(gnutls_x509_crt * certificate_list,
				    int clist_size,
				    gnutls_x509_crt * trusted_cas,
				    int tcas_size, gnutls_x509_crl *CRLs,
				    int crls_size, unsigned int flags)
{
	int i = 0, ret;
	unsigned int status = 0;

	/* Check for revoked certificates in the chain
	 */
	for (i = 0; i < clist_size; i++) {
		ret = gnutls_x509_crt_check_revocation( certificate_list[i],
			CRLs, crls_size);
		if (ret == 1) { /* revoked */
			status |= GNUTLS_CERT_REVOKED;
		}
	}

	/* Verify the certificate path 
	 */
	for (i = 0; i < clist_size; i++) {
		if (i + 1 >= clist_size)
			break;

		if ((ret =
		     _gnutls_verify_certificate2(certificate_list[i],
						 &certificate_list[i + 1], 1, flags)) != 1) 
		{
			status |= GNUTLS_CERT_INVALID;
		}
	}

	if (status != 0) {
		  /* If there is any problem in the
		   * certificate chain then mark as not trusted
		   * and return immediately.
		   */
		gnutls_assert();
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
				       tcas_size, flags);

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


#define OID_SHA1 "1.3.14.3.2.26"
#define OID_MD5 "1.2.840.113549.2.5"

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
		"GNUTLS.DigestInfo", &dinfo))!=ASN1_SUCCESS) {
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
	    asn1_read_value( dinfo, "digestAlgorithm.algorithm", str, &len);
	if (result != ASN1_SUCCESS) {
		gnutls_assert();
		asn1_delete_structure(&dinfo);
		return _gnutls_asn2err(result);
	}

	*hash = (gnutls_mac_algorithm)-1;
	
	if ( strcmp(str, OID_MD5)==0) { /* MD5 */
		*hash = GNUTLS_MAC_MD5;
	} else 
	if ( strcmp(str, OID_SHA1)==0) { /* SHA1 ID */
		*hash = GNUTLS_MAC_SHA;
	}

	if (*hash==(gnutls_mac_algorithm)-1) {

		_gnutls_x509_log( "X509_SIG: HASH OID: %s\n", str);

		gnutls_assert();
		asn1_delete_structure(&dinfo);
		return GNUTLS_E_UNIMPLEMENTED_FEATURE;
	}
	
	result =
	    asn1_read_value( dinfo, "digest", digest, digest_size);
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
_pkcs1_rsa_verify_sig( const gnutls_datum* text, const gnutls_datum* signature, 
	GNUTLS_MPI *params, int params_len)
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
 * 
 * 'tbs' is the signed data
 * 'signature' is the signature!
 */
static
int _gnutls_x509_verify_signature( const gnutls_datum* tbs,
	const gnutls_datum* signature, gnutls_x509_crt issuer) 
{
GNUTLS_MPI issuer_params[MAX_PARAMS_SIZE];
int ret, issuer_params_size, i;

	/* Read the MPI parameters from the issuer's certificate.
	 */
	issuer_params_size = MAX_PARAMS_SIZE;
	ret = _gnutls_x509_crt_get_mpis(issuer, issuer_params, &issuer_params_size);

	if ( ret < 0) {
		gnutls_assert();
		return ret;
	}

	switch( gnutls_x509_crt_get_pk_algorithm(issuer, NULL)) 
	{
		case GNUTLS_PK_RSA:

			if (_pkcs1_rsa_verify_sig( tbs, signature, issuer_params, issuer_params_size)!=0) {
				gnutls_assert();
				ret = 0;
				goto finish;
			}

			ret = 1;
			goto finish;
			break;

		case GNUTLS_PK_DSA:
			if (_gnutls_dsa_verify( tbs, signature, issuer_params, issuer_params_size)!=0) {
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
  * gnutls_x509_crt_list_verify - This function verifies the given certificate list
  * @cert_list: is the certificate list to be verified
  * @cert_list_length: holds the number of certificate in cert_list
  * @CA_list: is the CA list which will be used in verification
  * @CA_list_length: holds the number of CA certificate in CA_list
  * @CRL_list: holds a list of CRLs.
  * @CRL_list_length: the length of CRL list.
  * @flags: Flags that may be used to change the verification algorithm. Use OR of the gnutls_certificate_verify_flags enumerations.
  * @verify: will hold the certificate verification output.
  *
  * This function will try to verify the given certificate list and return it's status (TRUSTED, REVOKED etc.). 
  * The return value (status) should be one or more of the gnutls_certificate_status 
  * enumerated elements bitwise or'd. Note that expiration and activation dates are not checked 
  * by this function, you should check them using the appropriate functions.
  *
  * If no flags are specified (0), this function will use the 
  * basicConstraints (2.5.29.19) PKIX extension. This means that only a certificate 
  * authority is allowed to sign a certificate.
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
int gnutls_x509_crt_list_verify( gnutls_x509_crt* cert_list, int cert_list_length, 
	gnutls_x509_crt * CA_list, int CA_list_length, 
	gnutls_x509_crl* CRL_list, int CRL_list_length, 
	unsigned int flags, unsigned int *verify)
{
	if (cert_list == NULL || cert_list_length == 0)
		return GNUTLS_E_NO_CERTIFICATE_FOUND;

	/* Verify certificate 
	 */
	*verify =
	    _gnutls_x509_verify_certificate( cert_list, cert_list_length,
		CA_list, CA_list_length, CRL_list, CRL_list_length, flags);

	return 0;
}

/**
  * gnutls_x509_crt_verify - This function verifies the given certificate against a given trusted one
  * @cert: is the certificate to be verified
  * @CA_list: is one certificate that is considered to be trusted one
  * @CA_list_length: holds the number of CA certificate in CA_list
  * @flags: Flags that may be used to change the verification algorithm. Use OR of the gnutls_certificate_verify_flags enumerations.
  * @verify: will hold the certificate verification output.
  *
  * This function will try to verify the given certificate and return it's status. 
  * See gnutls_x509_crt_list_verify() for a detailed description of
  * return values.
  *
  * Returns 0 on success and a negative value in case of an error.
  *
  **/
int gnutls_x509_crt_verify( gnutls_x509_crt cert,
	gnutls_x509_crt *CA_list, int CA_list_length,
	unsigned int flags, unsigned int *verify)
{
	/* Verify certificate 
	 */
	*verify =
	    _gnutls_verify_certificate2( cert, CA_list, CA_list_length, flags);

	return 0;
}

/**
  * gnutls_x509_crt_check_issuer - This function checks if the certificate given has the given issuer
  * @cert: is the certificate to be checked
  * @issuer: is the certificate of a possible issuer
  *
  * This function will check if the given certificate was issued by the
  * given issuer. It will return true (1) if the given certificate is issued
  * by the given issuer, and false (0) if not.
  *
  * A negative value is returned in case of an error.
  *
  **/
int gnutls_x509_crt_check_issuer( gnutls_x509_crt cert,
	gnutls_x509_crt issuer)
{
	return is_issuer(cert, issuer);
}

/**
  * gnutls_x509_crl_check_issuer - This function checks if the CRL given has the given issuer
  * @crl: is the CRL to be checked
  * @issuer: is the certificate of a possible issuer
  *
  * This function will check if the given CRL was issued by the
  * given issuer certificate. It will return true (1) if the given CRL was issued
  * by the given issuer, and false (0) if not.
  *
  * A negative value is returned in case of an error.
  *
  **/
int gnutls_x509_crl_check_issuer( gnutls_x509_crl cert,
	gnutls_x509_crt issuer)
{
	return is_crl_issuer(cert, issuer);
}

/**
  * gnutls_x509_crl_verify - This function verifies the given crl against a given trusted one
  * @crl: is the crl to be verified
  * @CA_list: is a certificate list that is considered to be trusted one
  * @CA_list_length: holds the number of CA certificates in CA_list
  * @flags: Flags that may be used to change the verification algorithm. Use OR of the gnutls_certificate_verify_flags enumerations.
  * @verify: will hold the crl verification output.
  *
  * This function will try to verify the given crl and return it's status. 
  * See gnutls_x509_crt_list_verify() for a detailed description of
  * return values.
  *
  * Returns 0 on success and a negative value in case of an error.
  *
  **/
int gnutls_x509_crl_verify( gnutls_x509_crl crl,
	gnutls_x509_crt *CA_list, int CA_list_length,
	unsigned int flags, unsigned int *verify)
{
	/* Verify crl 
	 */
	*verify =
	    _gnutls_verify_crl2( crl, CA_list, CA_list_length, flags);

	return 0;
}
