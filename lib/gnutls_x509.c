/*
 *      Copyright (C) 2002 Nikos Mavroyanopoulos
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
#include "gnutls_auth_int.h"
#include "gnutls_errors.h"
#include <gnutls_cert.h>
#include <auth_cert.h>
#include "gnutls_dh.h"
#include "gnutls_num.h"
#include "x509_asn1.h"
#include "x509_der.h"
#include "gnutls_datum.h"
#include <gnutls_random.h>
#include <gnutls_pk.h>
#include <gnutls_algorithms.h>
#include <gnutls_global.h>
#include <gnutls_record.h>
#include <x509_verify.h>
#include <gnutls_sig.h>
#include <x509_extensions.h>
#include <gnutls_state.h>
#include <gnutls_pk.h>
#include <debug.h>

/**
  * gnutls_x509_extract_dn - This function parses an RDN sequence
  * @idn: should contain a DER encoded RDN sequence
  * @rdn: a pointer to a structure to hold the name
  *
  * This function will return the name of the given RDN sequence.
  * The name will be returned as a gnutls_dn structure.
  * Returns a negative error code in case of an error.
  *
  **/
int gnutls_x509_extract_dn(const gnutls_datum * idn, gnutls_dn * rdn)
{
	node_asn *dn;
	int result;

	if ((result =
	     asn1_create_structure(_gnutls_get_pkix(),
				   "PKIX1Implicit88.Name", &dn,
				   "dn")) != ASN_OK) {
		gnutls_assert();
		return GNUTLS_E_ASN1_ERROR;
	}

	result = asn1_get_der(dn, idn->data, idn->size);
	if (result != ASN_OK) {
		/* couldn't decode DER */
		gnutls_assert();
		asn1_delete_structure(dn);
		return GNUTLS_E_ASN1_PARSING_ERROR;
	}

	result = _gnutls_get_name_type(dn, "dn", rdn);
	asn1_delete_structure(dn);

	if (result < 0) {
		/* couldn't decode DER */
		gnutls_assert();
		return result;
	}

	return 0;
}

/**
  * gnutls_x509_extract_certificate_dn - This function returns the certificate's distinguished name
  * @cert: should contain an X.509 DER encoded certificate
  * @ret: a pointer to a structure to hold the peer's name
  *
  * This function will return the name of the certificate holder. The name is gnutls_dn structure and 
  * is a obtained by the peer's certificate. If the certificate send by the
  * peer is invalid, or in any other failure this function returns error.
  * Returns a negative error code in case of an error.
  *
  **/
int gnutls_x509_extract_certificate_dn(const gnutls_datum * cert,
					  gnutls_dn * ret)
{
	node_asn *c2;
	int result;

	memset(ret, 0, sizeof(gnutls_dn));

	if (asn1_create_structure
	    (_gnutls_get_pkix(), "PKIX1Implicit88.Certificate", &c2,
	     "certificate2")
	    != ASN_OK) {
		gnutls_assert();
		return GNUTLS_E_ASN1_ERROR;
	}


	result = asn1_get_der(c2, cert->data, cert->size);
	if (result != ASN_OK) {
		/* couldn't decode DER */

		_gnutls_log("X509_auth: Decoding error %d\n", result);

		gnutls_assert();
		asn1_delete_structure(c2);
		return GNUTLS_E_ASN1_PARSING_ERROR;
	}
	if ((result =
	     _gnutls_get_name_type(c2,
				   "certificate2.tbsCertificate.subject",
				   ret)) < 0) {
		gnutls_assert();
		asn1_delete_structure(c2);
		return result;
	}

	asn1_delete_structure(c2);

	return 0;
}

/**
  * gnutls_x509_extract_certificate_issuer_dn - This function returns the certificate's issuer distinguished name
  * @cert: should contain an X.509 DER encoded certificate
  * @ret: a pointer to a structure to hold the issuer's name
  *
  * This function will return the name of the issuer stated in the certificate. The name is a gnutls_dn structure and 
  * is a obtained by the peer's certificate. If the certificate send by the
  * peer is invalid, or in any other failure this function returns error.
  * Returns a negative error code in case of an error.
  *
  **/
int gnutls_x509_extract_certificate_issuer_dn(const gnutls_datum * cert,
						 gnutls_dn * ret)
{
	node_asn *c2;
	int result;

	memset(ret, 0, sizeof(gnutls_dn));

	if (asn1_create_structure
	    (_gnutls_get_pkix(), "PKIX1Implicit88.Certificate", &c2,
	     "certificate2")
	    != ASN_OK) {
		gnutls_assert();
		return GNUTLS_E_ASN1_ERROR;
	}

	result = asn1_get_der(c2, cert->data, cert->size);
	if (result != ASN_OK) {
		/* couldn't decode DER */

		_gnutls_log("X509_auth: Decoding error %d\n", result);

		gnutls_assert();
		asn1_delete_structure(c2);
		return GNUTLS_E_ASN1_PARSING_ERROR;
	}
	if ((result =
	     _gnutls_get_name_type(c2,
				   "certificate2.tbsCertificate.issuer",
				   ret)) < 0) {
		gnutls_assert();
		asn1_delete_structure(c2);
		return result;
	}

	asn1_delete_structure(c2);

	return 0;
}

/**
  * gnutls_x509_extract_subject_dns_name - This function returns the peer's dns name, if any
  * @cert: should contain an X.509 DER encoded certificate
  * @ret: is the place where dns name will be copied to
  * @ret_size: holds the size of ret.
  *
  * This function will return the alternative name (the dns part of it), contained in the
  * given certificate.
  * 
  * This is specified in X509v3 Certificate Extensions. 
  * GNUTLS will only return the dnsName of the Alternative name, or a negative
  * error code.
  * Returns GNUTLS_E_MEMORY_ERROR if ret_size is not enough to hold dns name,
  * or the size of dns name if everything was ok.
  *
  * If the certificate does not have a DNS name then returns GNUTLS_E_DATA_NOT_AVAILABLE;
  *
  **/
int gnutls_x509_extract_subject_dns_name(const gnutls_datum * cert,
					    char *ret, int *ret_size)
{
	int result;
	gnutls_datum dnsname;

	memset(ret, 0, *ret_size);

	if ((result =
	     _gnutls_get_extension(cert, "2 5 29 17", &dnsname)) < 0) {
		return result;
	}

	if (dnsname.size == 0) {
		return GNUTLS_E_REQUESTED_DATA_NOT_AVAILABLE;
	}

	if (*ret_size > dnsname.size) {
		*ret_size = dnsname.size;
		strcpy(ret, dnsname.data); /* FlawFinder: ignore */
		gnutls_free_datum(&dnsname);
	} else {
		*ret_size = dnsname.size;
		gnutls_free_datum(&dnsname);
		return GNUTLS_E_MEMORY_ERROR;
	}

	return *ret_size;
}

/**
  * gnutls_x509_extract_certificate_activation_time - This function returns the peer's certificate activation time
  * @cert: should contain an X.509 DER encoded certificate
  *
  * This function will return the certificate's activation time in UNIX time 
  * (ie seconds since 00:00:00 UTC January 1, 1970).
  * Returns a (time_t) -1 in case of an error.
  *
  **/
time_t gnutls_x509_extract_certificate_activation_time(const
							  gnutls_datum *
							  cert)
{
	node_asn *c2;
	int result;
	time_t ret;

	if (asn1_create_structure
	    (_gnutls_get_pkix(), "PKIX1Implicit88.Certificate", &c2,
	     "certificate2")
	    != ASN_OK) {
		gnutls_assert();
		return -1;
	}

	result = asn1_get_der(c2, cert->data, cert->size);
	if (result != ASN_OK) {
		/* couldn't decode DER */

		_gnutls_log("X509_auth: Decoding error %d\n", result);

		gnutls_assert();
		return -1;
	}

	ret = _gnutls_get_time(c2, "certificate2", "notBefore");

	asn1_delete_structure(c2);

	return ret;
}

/**
  * gnutls_x509_extract_certificate_expiration_time - This function returns the certificate's expiration time
  * @cert: should contain an X.509 DER encoded certificate
  *
  * This function will return the certificate's expiration time in UNIX time 
  * (ie seconds since 00:00:00 UTC January 1, 1970).
  * Returns a (time_t) -1 in case of an error.
  *
  **/
time_t gnutls_x509_extract_certificate_expiration_time(const
							  gnutls_datum *
							  cert)
{
	node_asn *c2;
	int result;
	time_t ret;

	if (asn1_create_structure
	    (_gnutls_get_pkix(), "PKIX1Implicit88.Certificate", &c2,
	     "certificate2")
	    != ASN_OK) {
		gnutls_assert();
		return -1;
	}

	result = asn1_get_der(c2, cert->data, cert->size);
	if (result != ASN_OK) {
		/* couldn't decode DER */

		_gnutls_log("X509_auth: Decoding error %d\n", result);

		gnutls_assert();
		return -1;
	}

	ret = _gnutls_get_time(c2, "certificate2", "notAfter");

	asn1_delete_structure(c2);

	return ret;
}

/**
  * gnutls_x509_extract_certificate_version - This function returns the certificate's version
  * @cert: is an X.509 DER encoded certificate
  *
  * This function will return the X.509 certificate's version (1, 2, 3). This is obtained by the X509 Certificate
  * Version field. Returns a negative value in case of an error.
  *
  **/
int gnutls_x509_extract_certificate_version(const gnutls_datum * cert)
{
	node_asn *c2;
	int result;

	if (asn1_create_structure
	    (_gnutls_get_pkix(), "PKIX1Implicit88.Certificate", &c2,
	     "certificate2")
	    != ASN_OK) {
		gnutls_assert();
		return GNUTLS_E_ASN1_ERROR;
	}

	result = asn1_get_der(c2, cert->data, cert->size);
	if (result != ASN_OK) {
		/* couldn't decode DER */

		_gnutls_log("X509_auth: Decoding error %d\n", result);

		gnutls_assert();
		return GNUTLS_E_ASN1_PARSING_ERROR;
	}

	result = _gnutls_get_version(c2, "certificate2");

	asn1_delete_structure(c2);

	return result;

}

#define CLEAR_CERTS for(x=0;x<peer_certificate_list_size;x++) gnutls_free_cert(peer_certificate_list[x])

/**
  * gnutls_x509pki_verify_peers - This function returns the peer's certificate status
  * @state: is a gnutls state
  *
  * This function will try to verify the peer's certificate and return it's status (TRUSTED, EXPIRED etc.). 
  * The return value (status) should be one of the CertificateStatus enumerated elements.
  * However you must also check the peer's name in order to check if the verified certificate belongs to the 
  * actual peer. Returns a negative error code in case of an error, or GNUTLS_CERT_NONE if no certificate was sent.
  *
  **/
int gnutls_x509pki_verify_peers(GNUTLS_STATE state)
{
	CERTIFICATE_AUTH_INFO info;
	const GNUTLS_CERTIFICATE_CREDENTIALS cred;
	CertificateStatus verify;
	gnutls_cert *peer_certificate_list;
	int peer_certificate_list_size, i, x, ret;

	CHECK_AUTH(GNUTLS_CRD_CERTIFICATE, GNUTLS_E_INVALID_REQUEST);

	info = _gnutls_get_auth_info(state);
	if (info == NULL)
		return GNUTLS_E_INVALID_REQUEST;

	cred = _gnutls_get_cred(state->gnutls_key, GNUTLS_CRD_CERTIFICATE, NULL);
	if (cred == NULL) {
		gnutls_assert();
		return GNUTLS_E_INSUFICIENT_CRED;
	}

	if (info->raw_certificate_list == NULL || info->ncerts == 0)
		return GNUTLS_CERT_NONE;

	/* generate a list of gnutls_certs based on the auth info
	 * raw certs.
	 */
	peer_certificate_list_size = info->ncerts;
	peer_certificate_list =
	    gnutls_calloc(1,
			  peer_certificate_list_size *
			  sizeof(gnutls_cert));
	if (peer_certificate_list == NULL) {
		gnutls_assert();
		return GNUTLS_E_MEMORY_ERROR;
	}

	for (i = 0; i < peer_certificate_list_size; i++) {
		if ((ret =
		     _gnutls_x509_cert2gnutls_cert(&peer_certificate_list[i],
					     info->
					     raw_certificate_list[i])) <
		    0) {
			gnutls_assert();
			CLEAR_CERTS;
			gnutls_free(peer_certificate_list);
			return ret;
		}
	}

	/* Verify certificate 
	 */
	verify =
	    gnutls_verify_certificate(peer_certificate_list,
				      peer_certificate_list_size,
				      cred->x509_ca_list, cred->x509_ncas, NULL, 0);

	CLEAR_CERTS;
	gnutls_free(peer_certificate_list);

	if (verify < 0) {
		gnutls_assert();
		return GNUTLS_CERT_CORRUPTED;
	}


	return verify;
}

#define CLEAR_CERTS_CA for(x=0;x<peer_certificate_list_size;x++) gnutls_free_cert(peer_certificate_list[x]); \
		for(x=0;x<ca_certificate_list_size;x++) gnutls_free_cert(ca_certificate_list[x])
/**
  * gnutls_x509pki_verify_certificate - This function verifies given certificate list
  * @cert_list: is the certificate list to be verified
  * @cert_list_length: holds the number of certificate in cert_list
  * @CA_list: is the CA list which will be used in verification
  * @CA_list_length: holds the number of CA certificate in CA_list
  * @CRL_list: not used
  * @CRL_list_length: not used
  *
  * This function will try to verify the given certificate list and return it's status (TRUSTED, EXPIRED etc.). 
  * The return value (status) should be one of the CertificateStatus enumerated elements.
  * However you must also check the peer's name in order to check if the verified certificate belongs to the 
  * actual peer. Returns a negative error code in case of an error.
  *
  **/
int gnutls_x509pki_verify_certificate( const gnutls_datum* cert_list, int cert_list_length, const gnutls_datum * CA_list, int CA_list_length, const gnutls_datum* CRL_list, int CRL_list_length)
{
	CertificateStatus verify;
	gnutls_cert *peer_certificate_list;
	gnutls_cert *ca_certificate_list;
	int peer_certificate_list_size, i, x, ret, ca_certificate_list_size;

	if (cert_list == NULL || cert_list_length == 0)
		return GNUTLS_CERT_NONE;

	/* generate a list of gnutls_certs based on the auth info
	 * raw certs.
	 */
	peer_certificate_list_size = cert_list_length;
	peer_certificate_list =
	    gnutls_calloc(1,
			  peer_certificate_list_size *
			  sizeof(gnutls_cert));
	if (peer_certificate_list == NULL) {
		gnutls_assert();
		return GNUTLS_E_MEMORY_ERROR;
	}

	ca_certificate_list_size = CA_list_length;
	ca_certificate_list =
	    gnutls_calloc(1,
			  ca_certificate_list_size *
			  sizeof(gnutls_cert));
	if (ca_certificate_list == NULL) {
		gnutls_assert();
		gnutls_free( peer_certificate_list);
		return GNUTLS_E_MEMORY_ERROR;
	}

	/* convert certA_list to gnutls_cert* list
	 */
	for (i = 0; i < peer_certificate_list_size; i++) {
		if ((ret =
		     _gnutls_x509_cert2gnutls_cert(&peer_certificate_list[i],
					     cert_list[i])) < 0) {
			gnutls_assert();
			CLEAR_CERTS_CA;
			gnutls_free( peer_certificate_list);
			gnutls_free( ca_certificate_list);
			return ret;
		}
	}

	/* convert CA_list to gnutls_cert* list
	 */
	for (i = 0; i < ca_certificate_list_size; i++) {
		if ((ret =
		     _gnutls_x509_cert2gnutls_cert(&ca_certificate_list[i],
					     CA_list[i])) < 0) {
			gnutls_assert();
			CLEAR_CERTS_CA;
			gnutls_free( peer_certificate_list);
			gnutls_free( ca_certificate_list);
			return ret;
		}
	}

	/* Verify certificate 
	 */
	verify =
	    gnutls_verify_certificate(peer_certificate_list,
				      peer_certificate_list_size,
				      ca_certificate_list, ca_certificate_list_size, NULL, 0);

	CLEAR_CERTS_CA;
	gnutls_free( peer_certificate_list);
	gnutls_free( ca_certificate_list);

	if (verify < 0) {
		gnutls_assert();
		return GNUTLS_CERT_CORRUPTED;
	}

	return verify;
}

/**
  * gnutls_x509_extract_certificate_serial - This function returns the certificate's serial number
  * @cert: is an X.509 DER encoded certificate
  * @result: The place where the serial number will be copied
  * @result_size: Holds the size of the result field.
  *
  * This function will return the X.509 certificate's serial number. 
  * This is obtained by the X509 Certificate serialNumber
  * field. Serial is not always a 32 or 64bit number. Some CAs use
  * large serial numbers, thus it may be wise to handle it as something
  * opaque. 
  * Returns a negative value in case of an error.
  *
  **/
int gnutls_x509_extract_certificate_serial(const gnutls_datum * cert, char* result, int* result_size)
{
	node_asn *c2;
	int ret;

	if (asn1_create_structure
	    (_gnutls_get_pkix(), "PKIX1Implicit88.Certificate", &c2,
	     "certificate2")
	    != ASN_OK) {
		gnutls_assert();
		return GNUTLS_E_ASN1_ERROR;
	}

	ret = asn1_get_der(c2, cert->data, cert->size);
	if (ret != ASN_OK) {
		/* couldn't decode DER */

		_gnutls_log("X509_auth: Decoding error %d\n", result);

		gnutls_assert();
		return GNUTLS_E_ASN1_PARSING_ERROR;
	}

	if ((ret = asn1_read_value(c2, "certificate2.tbsCertificate.serialNumber", result, result_size)) < 0) {
		gnutls_assert();
		asn1_delete_structure(c2);
		return GNUTLS_E_INVALID_REQUEST;
	}

	asn1_delete_structure(c2);

	return 0;

}
