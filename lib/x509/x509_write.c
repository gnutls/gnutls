/*
 *  Copyright (C) 2003 Nikos Mavroyanopoulos
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

/* This file contains functions to handle PKCS #10 certificate requests.
 */

#include <gnutls_int.h>

#ifdef ENABLE_PKI

#include <gnutls_datum.h>
#include <gnutls_global.h>
#include <gnutls_errors.h>
#include <common.h>
#include <gnutls_x509.h>
#include <x509_b64.h>
#include <crq.h>
#include <dn.h>
#include <mpi.h>
#include <sign.h>
#include <extensions.h>
#include <libtasn1.h>
#include <gnutls_ui.h>

static void disable_optional_stuff( gnutls_x509_crt cert);

/**
  * gnutls_x509_crt_set_dn_by_oid - This function will set the Certificate request subject's distinguished name
  * @crt: should contain a gnutls_x509_crt structure
  * @oid: holds an Object Identified in null terminated string
  * @name: a pointer to the name
  * @sizeof_name: holds the size of 'name'
  *
  * This function will set the part of the name of the Certificate subject, specified
  * by the given OID. 
  *
  * Some helper macros with popular OIDs can be found in gnutls/x509.h
  * With this function you can only set the known OIDs.
  *
  * On success zero is returned.
  *
  **/
int gnutls_x509_crt_set_dn_by_oid(gnutls_x509_crt crt, const char* oid, 
	const char *name, unsigned int sizeof_name)
{
	if (sizeof_name == 0 || name == NULL || crt == NULL) {
		return GNUTLS_E_INVALID_REQUEST;
	}
	
	return _gnutls_x509_set_dn_oid( crt->cert, "tbsCertificate.subject", oid,
		name, sizeof_name);
}

/**
  * gnutls_x509_crt_set_issuer_dn_by_oid - This function will set the Certificate request issuer's distinguished name
  * @crt: should contain a gnutls_x509_crt structure
  * @oid: holds an Object Identified in null terminated string
  * @name: a pointer to the name
  * @sizeof_name: holds the size of 'name'
  *
  * This function will set the part of the name of the Certificate issuer, specified
  * by the given OID. 
  *
  * Some helper macros with popular OIDs can be found in gnutls/x509.h
  * With this function you can only set the known OIDs.
  *
  * On success zero is returned.
  *
  **/
int gnutls_x509_crt_set_issuer_dn_by_oid(gnutls_x509_crt crt, const char* oid, 
	const char *name, unsigned int sizeof_name)
{
	if (sizeof_name == 0 || name == NULL || crt == NULL) {
		return GNUTLS_E_INVALID_REQUEST;
	}
	
	return _gnutls_x509_set_dn_oid( crt->cert, "tbsCertificate.issuer", oid,
		name, sizeof_name);
}

/**
  * gnutls_x509_crt_set_version - This function will set the Certificate request version
  * @crt: should contain a gnutls_x509_crt structure
  * @version: holds the version number. For X509v1 certificates must be 0.
  *
  * This function will set the version of the certificate request. This
  * must be zero.
  *
  * On success zero is returned.
  *
  **/
int gnutls_x509_crt_set_version(gnutls_x509_crt crt, unsigned int version)
{
int result;
uint8 null = version;

	result = asn1_write_value( crt->cert, "tbsCertificate.version", &null, 1);
	if (result != ASN1_SUCCESS) {
		gnutls_assert();
		return _gnutls_asn2err(result);
	}

	return 0;
}

/**
  * gnutls_x509_crt_set_key - This function will associate the Certificate with a key
  * @crt: should contain a gnutls_x509_crt structure
  * @key: holds a private key
  *
  * This function will set the public parameters from the given private key to the
  * certificate. Only RSA keys are currently supported.
  *
  * On success zero is returned.
  *
  **/
int gnutls_x509_crt_set_key(gnutls_x509_crt crt, gnutls_x509_privkey key)
{
int result;

	result = _gnutls_x509_encode_and_copy_PKI_params( crt->cert,
		"tbsCertificate.subjectPublicKeyInfo", key->pk_algorithm,
		key->params, key->params_size);

	if (result < 0) {
		gnutls_assert();
		return result;
	}

	return 0;
}

/**
  * gnutls_x509_crt_set_crq - This function will associate the Certificate with a request
  * @crt: should contain a gnutls_x509_crt structure
  * @crq: holds a certificate request
  *
  * This function will set the name and public parameters from the given certificate request to the
  * certificate. Only RSA keys are currently supported.
  *
  * On success zero is returned.
  *
  **/
int gnutls_x509_crt_set_crq(gnutls_x509_crt crt, gnutls_x509_crq crq)
{
int result;
int pk_algorithm;

	pk_algorithm = gnutls_x509_crq_get_pk_algorithm( crq, NULL);

	if (pk_algorithm != GNUTLS_PK_RSA) {
		gnutls_assert();
		return GNUTLS_E_UNIMPLEMENTED_FEATURE;
	}
	
	result = _gnutls_asn1_copy_node( &crt->cert, "tbsCertificate.subject",
		crq->crq, "subject");
	if (result < 0) {
		gnutls_assert();
		return result;
	}

	result = _gnutls_asn1_copy_node( &crt->cert, "tbsCertificate.subjectPublicKeyInfo",
		crq->crq, "subjectPKInfo");
	if (result < 0) {
		gnutls_assert();
		return result;
	}

	return 0;
}


/**
  * gnutls_x509_crt_set_ca_status - This function will set the basicConstraints extension
  * @crt: should contain a gnutls_x509_crt structure
  * @ca: true(1) or false(0). Depending on the Certificat authority status.
  *
  * This function will set the basicConstraints certificate extension. 
  *
  * On success zero is returned.
  *
  **/
int gnutls_x509_crt_set_ca_status(gnutls_x509_crt crt, unsigned int ca)
{
int result;
gnutls_datum der_data;

	/* generate the extension.
	 */
	result = _gnutls_x509_ext_gen_basicConstraints( ca, &der_data);
	if (result < 0) {
		gnutls_assert();
		return result;
	}

	result = _gnutls_x509_crt_set_extension( crt, "2.5.29.19", &der_data, 1);

	_gnutls_free_datum( &der_data);

	if (result < 0) {
		gnutls_assert();
		return result;
	}

	crt->use_extensions = 1;

	return 0;
}

/**
  * gnutls_x509_crt_set_subject_alt_name - This function will set the subject Alternative Name
  * @crt: should contain a gnutls_x509_crt structure
  * @type: is one of the gnutls_x509_subject_alt_name enumerations
  * @data_string: The data to be set
  *
  * This function will set the subject alternative name certificate extension. 
  *
  * On success zero is returned.
  *
  **/
int gnutls_x509_crt_set_subject_alternative_name(gnutls_x509_crt crt, gnutls_x509_subject_alt_name type,
	const char* data_string)
{
int result;
gnutls_datum der_data;
gnutls_datum dnsname;
unsigned int critical;

	/* Check if the extension already exists.
	 */
	result = _gnutls_x509_crt_get_extension(crt, "2.5.29.17", 0, &dnsname, &critical);

	if (result >= 0) _gnutls_free_datum( &dnsname);
	if (result != GNUTLS_E_REQUESTED_DATA_NOT_AVAILABLE) {
		gnutls_assert();
		return GNUTLS_E_INVALID_REQUEST;
	}

	/* generate the extension.
	 */
	result = _gnutls_x509_ext_gen_subject_alt_name( type, data_string, &der_data);
	if (result < 0) {
		gnutls_assert();
		return result;
	}

	result = _gnutls_x509_crt_set_extension( crt, "2.5.29.17", &der_data, 0);

	_gnutls_free_datum( &der_data);

	if (result < 0) {
		gnutls_assert();
		return result;
	}

	crt->use_extensions = 1;

	return 0;
}

/**
  * gnutls_x509_crt_sign - This function will sign a Certificate request with a key
  * @crt: should contain a gnutls_x509_crt structure
  * @issuer: is the certificate of the certificate issuer
  * @issuer_key: holds the issuer's private key
  *
  * This function will sign the certificate with the issuer's private key, and
  * will copy the issuer's information into the certificate.
  *
  * This must be the last step in a certificate generation since all
  * the previously set parameters are now signed.
  *
  * On success zero is returned.
  *
  **/
int gnutls_x509_crt_sign(gnutls_x509_crt crt, gnutls_x509_crt issuer, 
	gnutls_x509_privkey issuer_key)
{
int result;
gnutls_datum signature;
const char* pk;

	if (issuer_key->pk_algorithm != GNUTLS_PK_RSA) {
		gnutls_assert();
		return GNUTLS_E_UNIMPLEMENTED_FEATURE;
	}
	
	/* disable all the unneeded OPTIONAL fields.
	 */
	disable_optional_stuff( crt);
	
	/* Step 1. Copy the issuer's name into the certificate.
	 */
	result = _gnutls_asn1_copy_node( &crt->cert, "tbsCertificate.issuer",
		issuer->cert, "tbsCertificate.subject");
	if (result < 0) {
		gnutls_assert();
		return result;
	}

	/* Step 1.5. Write the signature stuff in the tbsCertificate.
	 */
	/* write the RSA OID
	 */
	pk = _gnutls_x509_sign2oid( issuer_key->pk_algorithm, GNUTLS_MAC_SHA);
	if (pk == NULL) {
		gnutls_assert();
		return GNUTLS_E_INVALID_REQUEST;
	}

	result = asn1_write_value( crt->cert, "tbsCertificate.signature.algorithm", pk, 1);
	if (result != ASN1_SUCCESS) {
		gnutls_assert();
		return _gnutls_asn2err(result);
	}

	/* disable parameters, which are not used in RSA.
	 */
	result = asn1_write_value( crt->cert, "tbsCertificate.signature.parameters", NULL, 0);
	if (result != ASN1_SUCCESS) {
		gnutls_assert();
		return _gnutls_asn2err(result);
	}


	/* Step 2. Sign the certificate.
	 */
	result = _gnutls_x509_sign_tbs( crt->cert, "tbsCertificate", GNUTLS_MAC_SHA,
		issuer_key, &signature);
	
	if (result < 0) {
		gnutls_assert();
		return result;
	}

	/* write the signature (bits)
	 */
	result = asn1_write_value( crt->cert, "signature", signature.data, signature.size*8);

	_gnutls_free_datum( &signature);

	if (result != ASN1_SUCCESS) {
		gnutls_assert();
		return _gnutls_asn2err(result);
	}

	/* Step 2. Move up and write the AlgorithmIdentifier, which is also
	 * the same. 
	 */


	/* write the RSA OID
	 */
	result = asn1_write_value( crt->cert, "signatureAlgorithm.algorithm", pk, 1);
	if (result != ASN1_SUCCESS) {
		gnutls_assert();
		return _gnutls_asn2err(result);
	}

	/* disable parameters, which are not used in RSA.
	 */
	result = asn1_write_value( crt->cert, "signatureAlgorithm.parameters", NULL, 0);
	if (result != ASN1_SUCCESS) {
		gnutls_assert();
		return _gnutls_asn2err(result);
	}

	return 0;
}

/**
  * gnutls_x509_crt_set_activation_time - This function will set the Certificate's activation time
  * @cert: should contain a gnutls_x509_crt structure
  * @act_time: The actual time
  *
  * This function will set the time this Certificate was or will be activated.
  *
  * Returns a negative value in case of an error, and 0 on success.
  *
  **/
int gnutls_x509_crt_set_activation_time(gnutls_x509_crt cert, time_t act_time)
{
	return _gnutls_x509_set_time( cert->cert, "tbsCertificate.validity.notBefore", act_time);
}

/**
  * gnutls_x509_crt_set_expiration_time - This function will set the Certificate's expiration time
  * @cert: should contain a gnutls_x509_crt structure
  * @exp_time: The actual time
  *
  * This function will set the time this Certificate will expire.
  *
  * Returns a negative value in case of an error, and 0 on success.
  *
  **/
int gnutls_x509_crt_set_expiration_time(gnutls_x509_crt cert, time_t exp_time)
{
	return _gnutls_x509_set_time( cert->cert, "tbsCertificate.validity.notAfter", exp_time);
}

/**
  * gnutls_x509_crt_set_serial - This function will set the certificate's serial number
  * @cert: should contain a gnutls_x509_crt structure
  * @serial: The serial number
  * @result_size: Holds the size of the serial field.
  *
  * This function will set the X.509 certificate's serial number. 
  * Serial is not always a 32 or 64bit number. Some CAs use
  * large serial numbers, thus it may be wise to handle it as something
  * opaque. 
  *
  * Returns a negative value in case of an error, and 0 on success.
  *
  **/
int gnutls_x509_crt_set_serial(gnutls_x509_crt cert, const unsigned char* serial, 
	size_t serial_size)
{
	int ret;

	if ((ret = asn1_write_value(cert->cert, "tbsCertificate.serialNumber", serial, serial_size)) < 0) 
	{
		gnutls_assert();
		return _gnutls_asn2err(ret);
	}

	return 0;

}

/* If OPTIONAL fields have not been initialized then
 * disable them.
 */
static void disable_optional_stuff( gnutls_x509_crt cert)
{

	asn1_write_value( cert->cert, "tbsCertificate.issuerUniqueID", NULL, 0);

	asn1_write_value( cert->cert, "tbsCertificate.subjectUniqueID", NULL, 0);

	if (cert->use_extensions == 0) {
		_gnutls_x509_log( "Disabling X.509 extensions.\n");
		asn1_write_value( cert->cert, "tbsCertificate.extensions", NULL, 0);
	}

	return;
}


#endif /* ENABLE_PKI */
