/*
 *  Copyright (C) 2002,2003 Nikos Mavroyanopoulos
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

/* This file includes all functions that were in the 0.5.x and 0.8.x
 * gnutls API. They are now implemented over the new certificate parsing
 * API.
 */

#include <gnutls_global.h>
#include <gnutls_errors.h>
#include <string.h> /* memset */
#include <dn.h>
#include <libtasn1.h>
#include <gnutls/x509.h>


/**
  * gnutls_x509_extract_dn - This function parses an RDN sequence
  * @idn: should contain a DER encoded RDN sequence
  * @rdn: a pointer to a structure to hold the name
  *
  * This function will return the name of the given RDN sequence.
  * The name will be returned as a gnutls_x509_dn structure.
  * Returns a negative error code in case of an error.
  *
  **/
int gnutls_x509_extract_dn(const gnutls_datum * idn, gnutls_x509_dn * rdn)
{
	ASN1_TYPE dn = ASN1_TYPE_EMPTY;
	int result, len;

	if ((result =
	     asn1_create_element(_gnutls_get_pkix(),
				   "PKIX1.Name", &dn,
				   "dn")) != ASN1_SUCCESS) {
		return _gnutls_asn2err(result);
	}

	result = asn1_der_decoding(&dn, idn->data, idn->size, NULL);
	if (result != ASN1_SUCCESS) {
		/* couldn't decode DER */
		asn1_delete_structure(&dn);
		return _gnutls_asn2err(result);
	}

	memset( rdn, 0, sizeof(gnutls_x509_dn));

	len = sizeof(rdn->country);
	_gnutls_x509_parse_dn_oid( dn, "dn", GNUTLS_OID_X520_COUNTRY_NAME, 0, rdn->country, &len);

	len = sizeof(rdn->organization);
	_gnutls_x509_parse_dn_oid( dn, "dn", GNUTLS_OID_X520_ORGANIZATION_NAME, 0, rdn->organization, &len);

	len = sizeof(rdn->organizational_unit_name);
	_gnutls_x509_parse_dn_oid( dn, "dn", GNUTLS_OID_X520_ORGANIZATIONAL_UNIT_NAME, 0, rdn->organizational_unit_name, &len);

	len = sizeof(rdn->common_name);
	_gnutls_x509_parse_dn_oid( dn, "dn", GNUTLS_OID_X520_COMMON_NAME, 0, rdn->common_name, &len);

	len = sizeof(rdn->locality_name);
	_gnutls_x509_parse_dn_oid( dn, "dn", GNUTLS_OID_X520_LOCALITY_NAME, 0, rdn->locality_name, &len);

	len = sizeof(rdn->state_or_province_name);
	_gnutls_x509_parse_dn_oid( dn, "dn", GNUTLS_OID_X520_STATE_OR_PROVINCE_NAME, 0, rdn->state_or_province_name, &len);

	len = sizeof(rdn->email);
	_gnutls_x509_parse_dn_oid( dn, "dn", GNUTLS_OID_PKCS9_EMAIL, 0, rdn->email, &len);

	asn1_delete_structure(&dn);

	return 0;
}

/**
  * gnutls_x509_extract_certificate_dn - This function returns the certificate's distinguished name
  * @cert: should contain an X.509 DER encoded certificate
  * @ret: a pointer to a structure to hold the peer's name
  *
  * This function will return the name of the certificate holder. The name is gnutls_x509_dn structure and 
  * is a obtained by the peer's certificate. If the certificate send by the
  * peer is invalid, or in any other failure this function returns error.
  * Returns a negative error code in case of an error.
  *
  **/
int gnutls_x509_extract_certificate_dn(const gnutls_datum * cert,
					  gnutls_x509_dn * ret)
{
	gnutls_x509_certificate xcert;
	int len, result;
	
	result = gnutls_x509_certificate_init( &xcert);
	if (result < 0) return result;
	
	result = gnutls_x509_certificate_import( xcert, cert, GNUTLS_X509_FMT_DER);
	if (result < 0) {
		gnutls_x509_certificate_deinit( xcert);
		return result;
	}

	len = sizeof( ret->country);
	gnutls_x509_certificate_get_dn_by_oid( xcert, GNUTLS_OID_X520_COUNTRY_NAME, 0,
		ret->country, &len);

	len = sizeof( ret->organization);
	gnutls_x509_certificate_get_dn_by_oid( xcert, GNUTLS_OID_X520_ORGANIZATION_NAME, 0,
		ret->organization, &len);

	len = sizeof( ret->organizational_unit_name);
	gnutls_x509_certificate_get_dn_by_oid( xcert, GNUTLS_OID_X520_ORGANIZATIONAL_UNIT_NAME, 0,
		ret->organizational_unit_name, &len);

	len = sizeof( ret->common_name);
	gnutls_x509_certificate_get_dn_by_oid( xcert, GNUTLS_OID_X520_COMMON_NAME, 0,
		ret->common_name, &len);

	len = sizeof( ret->locality_name);
	gnutls_x509_certificate_get_dn_by_oid( xcert, GNUTLS_OID_X520_LOCALITY_NAME, 0,
		ret->locality_name, &len);

	len = sizeof( ret->state_or_province_name);
	gnutls_x509_certificate_get_dn_by_oid( xcert, GNUTLS_OID_X520_STATE_OR_PROVINCE_NAME, 0,
		ret->state_or_province_name, &len);

	len = sizeof( ret->email);
	gnutls_x509_certificate_get_dn_by_oid( xcert, GNUTLS_OID_PKCS9_EMAIL, 0,
		ret->email, &len);

	gnutls_x509_certificate_deinit( xcert);

	return 0;
}

/**
  * gnutls_x509_extract_certificate_issuer_dn - This function returns the certificate's issuer distinguished name
  * @cert: should contain an X.509 DER encoded certificate
  * @ret: a pointer to a structure to hold the issuer's name
  *
  * This function will return the name of the issuer stated in the certificate. The name is a gnutls_x509_dn structure and 
  * is a obtained by the peer's certificate. If the certificate send by the
  * peer is invalid, or in any other failure this function returns error.
  * Returns a negative error code in case of an error.
  *
  **/
int gnutls_x509_extract_certificate_issuer_dn(const gnutls_datum * cert,
						 gnutls_x509_dn * ret)
{
	gnutls_x509_certificate xcert;
	int len, result;
	
	result = gnutls_x509_certificate_init( &xcert);
	if (result < 0) return result;
	
	result = gnutls_x509_certificate_import( xcert, cert, GNUTLS_X509_FMT_DER);
	if (result < 0) {
		gnutls_x509_certificate_deinit( xcert);
		return result;
	}

	len = sizeof( ret->country);
	gnutls_x509_certificate_get_issuer_dn_by_oid( xcert, GNUTLS_OID_X520_COUNTRY_NAME, 0,
		ret->country, &len);

	len = sizeof( ret->organization);
	gnutls_x509_certificate_get_issuer_dn_by_oid( xcert, GNUTLS_OID_X520_ORGANIZATION_NAME, 0,
		ret->organization, &len);

	len = sizeof( ret->organizational_unit_name);
	gnutls_x509_certificate_get_issuer_dn_by_oid( xcert, GNUTLS_OID_X520_ORGANIZATIONAL_UNIT_NAME, 0,
		ret->organizational_unit_name, &len);

	len = sizeof( ret->common_name);
	gnutls_x509_certificate_get_issuer_dn_by_oid( xcert, GNUTLS_OID_X520_COMMON_NAME, 0,
		ret->common_name, &len);

	len = sizeof( ret->locality_name);
	gnutls_x509_certificate_get_issuer_dn_by_oid( xcert, GNUTLS_OID_X520_LOCALITY_NAME, 0,
		ret->locality_name, &len);

	len = sizeof( ret->state_or_province_name);
	gnutls_x509_certificate_get_issuer_dn_by_oid( xcert, GNUTLS_OID_X520_STATE_OR_PROVINCE_NAME, 0,
		ret->state_or_province_name, &len);

	len = sizeof( ret->email);
	gnutls_x509_certificate_get_issuer_dn_by_oid( xcert, GNUTLS_OID_PKCS9_EMAIL, 0,
		ret->email, &len);

	gnutls_x509_certificate_deinit( xcert);

	return 0;
}


/**
  * gnutls_x509_extract_certificate_subject_alt_name - This function returns the certificate's alternative name, if any
  * @cert: should contain an X.509 DER encoded certificate
  * @seq: specifies the sequence number of the alt name (0 for the first one, 1 for the second etc.)
  * @ret: is the place where the alternative name will be copied to
  * @ret_size: holds the size of ret.
  *
  * This function will return the alternative names, contained in the
  * given certificate.
  * 
  * This is specified in X509v3 Certificate Extensions. 
  * GNUTLS will return the Alternative name, or a negative
  * error code.
  * Returns GNUTLS_E_SHORT_MEMORY_BUFFER if ret_size is not enough to hold the alternative 
  * name, or the type of alternative name if everything was ok. The type is 
  * one of the enumerated GNUTLS_X509_SUBJECT_ALT_NAME.
  *
  * If the certificate does not have an Alternative name with the specified 
  * sequence number then returns GNUTLS_E_REQUESTED_DATA_NOT_AVAILABLE;
  *
  **/
int gnutls_x509_extract_certificate_subject_alt_name(const gnutls_datum * cert, int seq, char *ret, int *ret_size)
{
	gnutls_x509_certificate xcert;
	int result;
	
	result = gnutls_x509_certificate_init( &xcert);
	if (result < 0) return result;
	
	result = gnutls_x509_certificate_import( xcert, cert, GNUTLS_X509_FMT_DER);
	if (result < 0) {
		gnutls_x509_certificate_deinit( xcert);
		return result;
	}
	
	result = gnutls_x509_certificate_get_subject_alt_name( xcert, seq, ret, ret_size, NULL);
	
	gnutls_x509_certificate_deinit( xcert);
	
	return result;
}

/**
  * gnutls_x509_extract_certificate_ca_status - This function returns the certificate CA status
  * @cert: should contain an X.509 DER encoded certificate
  *
  * This function will return certificates CA status, by reading the 
  * basicConstraints X.509 extension. If the certificate is a CA a positive
  * value will be returned, or zero if the certificate does not have
  * CA flag set. 
  *
  * A negative value may be returned in case of parsing error.
  * If the certificate does not contain the basicConstraints extension
  * GNUTLS_E_REQUESTED_DATA_NOT_AVAILABLE will be returned.
  *
  **/
int gnutls_x509_extract_certificate_ca_status(const gnutls_datum * cert)
{
	gnutls_x509_certificate xcert;
	int result;
	
	result = gnutls_x509_certificate_init( &xcert);
	if (result < 0) return result;
	
	result = gnutls_x509_certificate_import( xcert, cert, GNUTLS_X509_FMT_DER);
	if (result < 0) {
		gnutls_x509_certificate_deinit( xcert);
		return result;
	}
	
	result = gnutls_x509_certificate_get_ca_status( xcert, NULL);
	
	gnutls_x509_certificate_deinit( xcert);
	
	return result;
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
	gnutls_x509_certificate xcert;
	time_t result;

	result = gnutls_x509_certificate_init( &xcert);
	if (result < 0) return result;
	
	result = gnutls_x509_certificate_import( xcert, cert, GNUTLS_X509_FMT_DER);
	if (result < 0) {
		gnutls_x509_certificate_deinit( xcert);
		return result;
	}
	
	result = gnutls_x509_certificate_get_activation_time( xcert);
	
	gnutls_x509_certificate_deinit( xcert);
	
	return result;
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
	gnutls_x509_certificate xcert;
	time_t result;

	result = gnutls_x509_certificate_init( &xcert);
	if (result < 0) return result;
	
	result = gnutls_x509_certificate_import( xcert, cert, GNUTLS_X509_FMT_DER);
	if (result < 0) {
		gnutls_x509_certificate_deinit( xcert);
		return result;
	}
	
	result = gnutls_x509_certificate_get_expiration_time( xcert);
	
	gnutls_x509_certificate_deinit( xcert);
	
	return result;
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
	gnutls_x509_certificate xcert;
	int result;

	result = gnutls_x509_certificate_init( &xcert);
	if (result < 0) return result;
	
	result = gnutls_x509_certificate_import( xcert, cert, GNUTLS_X509_FMT_DER);
	if (result < 0) {
		gnutls_x509_certificate_deinit( xcert);
		return result;
	}
	
	result = gnutls_x509_certificate_get_version( xcert);
	
	gnutls_x509_certificate_deinit( xcert);
	
	return result;

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
	gnutls_x509_certificate xcert;
	int ret;

	ret = gnutls_x509_certificate_init( &xcert);
	if (ret < 0) return ret;
	
	ret = gnutls_x509_certificate_import( xcert, cert, GNUTLS_X509_FMT_DER);
	if (ret < 0) {
		gnutls_x509_certificate_deinit( xcert);
		return ret;
	}
	
	ret = gnutls_x509_certificate_get_serial( xcert, result, result_size);
	
	gnutls_x509_certificate_deinit( xcert);
	
	return ret;
}

/**
  * gnutls_x509_pkcs7_extract_certificate - This function returns a certificate in a PKCS7 certificate set
  * @pkcs7_struct: should contain a PKCS7 DER formatted structure
  * @indx: contains the index of the certificate to extract
  * @certificate: the contents of the certificate will be copied there
  * @certificate_size: should hold the size of the certificate
  *
  * This function will return a certificate of the PKCS7 or RFC2630 certificate set.
  * Returns 0 on success. If the provided buffer is not long enough,
  * then GNUTLS_E_SHORT_MEMORY_BUFFER is returned.
  *
  * After the last certificate has been read GNUTLS_E_REQUESTED_DATA_NOT_AVAILABLE
  * will be returned.
  *
  **/
int gnutls_x509_pkcs7_extract_certificate(const gnutls_datum * pkcs7_struct, int indx, char* certificate, int* certificate_size)
{
	gnutls_pkcs7 pkcs7;
	int result;

	result = gnutls_pkcs7_init( &pkcs7);
	if (result < 0) return result;
	
	result = gnutls_pkcs7_import( pkcs7, pkcs7_struct, GNUTLS_X509_FMT_DER);
	if (result < 0) {
		gnutls_pkcs7_deinit( pkcs7);
		return result;
	}
	
	result = gnutls_pkcs7_get_certificate( pkcs7, indx, certificate, certificate_size);
	
	gnutls_pkcs7_deinit( pkcs7);
	
	return result;
}


/**
  * gnutls_x509_pkcs7_extract_certificate_count - This function returns the number of certificates in a PKCS7 certificate set
  * @pkcs7_struct: should contain a PKCS7 DER formatted structure
  *
  * This function will return the number of certifcates in the PKCS7 or 
  * RFC2630 certificate set.
  *
  * Returns a negative value on failure.
  *
  **/
int gnutls_x509_pkcs7_extract_certificate_count(const gnutls_datum * pkcs7_struct)
{
	gnutls_pkcs7 pkcs7;
	int result;

	result = gnutls_pkcs7_init( &pkcs7);
	if (result < 0) return result;
	
	result = gnutls_pkcs7_import( pkcs7, pkcs7_struct, GNUTLS_X509_FMT_DER);
	if (result < 0) {
		gnutls_pkcs7_deinit( pkcs7);
		return result;
	}
	
	result = gnutls_pkcs7_get_certificate_count( pkcs7);
	
	gnutls_pkcs7_deinit( pkcs7);
	
	return result;
}


/**
  * gnutls_x509_extract_certificate_pk_algorithm - This function returns the certificate's PublicKey algorithm
  * @cert: is a DER encoded X.509 certificate
  * @bits: if bits is non null it will hold the size of the parameters' in bits
  *
  * This function will return the public key algorithm of an X.509 
  * certificate.
  *
  * If bits is non null, it should have enough size to hold the parameters
  * size in bits. For RSA the bits returned is the modulus. 
  * For DSA the bits returned are of the public
  * exponent.
  *
  * Returns a member of the gnutls_pk_algorithm enumeration on success,
  * or a negative value on error.
  *
  **/
int gnutls_x509_extract_certificate_pk_algorithm( const gnutls_datum * cert, int* bits)
{
	gnutls_x509_certificate xcert;
	int result;

	result = gnutls_x509_certificate_init( &xcert);
	if (result < 0) return result;
	
	result = gnutls_x509_certificate_import( xcert, cert, GNUTLS_X509_FMT_DER);
	if (result < 0) {
		gnutls_x509_certificate_deinit( xcert);
		return result;
	}
	
	result = gnutls_x509_certificate_get_pk_algorithm( xcert, bits);
	
	gnutls_x509_certificate_deinit( xcert);
	
	return result;
}


/**
  * gnutls_x509_extract_certificate_dn_string - This function returns the certificate's distinguished name
  * @cert: should contain an X.509 DER encoded certificate
  * @buf: a pointer to a structure to hold the peer's name
  * @sizeof_buf: holds the size of 'buf'
  * @issuer: if non zero, then extract the name of the issuer, instead of the holder
  *
  * This function will copy the name of the certificate holder in the provided buffer. The name 
  * will be in the form "C=xxxx,O=yyyy,CN=zzzz" as described in RFC2253.
  *
  * Returns GNUTLS_E_SHORT_MEMORY_BUFFER if the provided buffer is not long enough,
  * and 0 on success.
  *
  **/
int gnutls_x509_extract_certificate_dn_string(char *buf, unsigned int sizeof_buf, 
   const gnutls_datum * cert, int issuer)
{
	gnutls_x509_certificate xcert;
	int result;

	result = gnutls_x509_certificate_init( &xcert);
	if (result < 0) return result;
	
	result = gnutls_x509_certificate_import( xcert, cert, GNUTLS_X509_FMT_DER);
	if (result < 0) {
		gnutls_x509_certificate_deinit( xcert);
		return result;
	}
	
	if (!issuer)
		result = gnutls_x509_certificate_get_dn( xcert, buf, &sizeof_buf);
	else
		result = gnutls_x509_certificate_get_issuer_dn( xcert, buf, &sizeof_buf);

	gnutls_x509_certificate_deinit( xcert);
	
	return result;
}
