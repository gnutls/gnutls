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

/**
  * gnutls_x509_crq_init - This function initializes a gnutls_x509_crq structure
  * @crq: The structure to be initialized
  *
  * This function will initialize a PKCS10 certificate request structure. 
  *
  * Returns 0 on success.
  *
  **/
int gnutls_x509_crq_init(gnutls_x509_crq * crq)
{
	*crq = gnutls_calloc( 1, sizeof(gnutls_x509_crq_int));

	if (*crq) {
		int result = asn1_create_element(_gnutls_get_pkix(),
				     "PKIX1.CertificationRequest",
				     &((*crq)->crq));
		if (result != ASN1_SUCCESS) {
			gnutls_assert();
			return _gnutls_asn2err(result);
		}
		return 0;		/* success */
	}
	return GNUTLS_E_MEMORY_ERROR;
}

/**
  * gnutls_x509_crq_deinit - This function deinitializes memory used by a gnutls_x509_crq structure
  * @crq: The structure to be initialized
  *
  * This function will deinitialize a CRL structure. 
  *
  **/
void gnutls_x509_crq_deinit(gnutls_x509_crq crq)
{
	if (crq->crq)
		asn1_delete_structure(&crq->crq);

	gnutls_free(crq);
}

#define PEM_CRQ "CERTIFICATE REQUEST"

/**
  * gnutls_x509_crq_import - This function will import a DER or PEM encoded Certificate request
  * @crq: The structure to store the parsed certificate request.
  * @data: The DER or PEM encoded certificate.
  * @format: One of DER or PEM
  *
  * This function will convert the given DER or PEM encoded Certificate
  * to the native gnutls_x509_crq format. The output will be stored in 'cert'.
  *
  * If the Certificate is PEM encoded it should have a header of "CERTIFICATE REQUEST".
  *
  * Returns 0 on success.
  *
  **/
int gnutls_x509_crq_import(gnutls_x509_crq crq, const gnutls_datum * data,
	gnutls_x509_crt_fmt format)
{
	int result = 0, need_free = 0;
	gnutls_datum _data = { data->data, data->size };

	/* If the Certificate is in PEM format then decode it
	 */
	if (format == GNUTLS_X509_FMT_PEM) {
		opaque *out;
		
		/* Try the first header */
		result = _gnutls_fbase64_decode(PEM_CRQ, data->data, data->size,
			&out);

		if (result <= 0) {
			if (result==0) result = GNUTLS_E_INTERNAL_ERROR;
			gnutls_assert();
			return result;
		}
		
		_data.data = out;
		_data.size = result;
		
		need_free = 1;
	}

	result = asn1_der_decoding(&crq->crq, _data.data, _data.size, NULL);
	if (result != ASN1_SUCCESS) {
		result = _gnutls_asn2err(result);
		gnutls_assert();
		goto cleanup;
	}

	if (need_free) _gnutls_free_datum( &_data);

	return 0;

      cleanup:
	if (need_free) _gnutls_free_datum( &_data);
	return result;
}



/**
  * gnutls_x509_crq_get_dn - This function returns the Certificate request subject's distinguished name
  * @crq: should contain a gnutls_x509_crq structure
  * @buf: a pointer to a structure to hold the name (may be null)
  * @sizeof_buf: initialy holds the size of 'buf'
  *
  * This function will copy the name of the Certificate request subject in the provided buffer. The name 
  * will be in the form "C=xxxx,O=yyyy,CN=zzzz" as described in RFC2253.
  *
  * If buf is null then only the size will be filled.
  *
  * Returns GNUTLS_E_SHORT_MEMORY_BUFFER if the provided buffer is not long enough, and
  * in that case the sizeof_buf will be updated with the required size.
  * On success zero is returned.
  *
  **/
int gnutls_x509_crq_get_dn(gnutls_x509_crq crq, char *buf,
					 int *sizeof_buf)
{
	if (sizeof_buf == 0 || crq == NULL) {
		return GNUTLS_E_INVALID_REQUEST;
	}
	
	return _gnutls_x509_parse_dn( crq->crq, "certificationRequestInfo.subject.rdnSequence",
		buf, sizeof_buf);

		
}

/**
  * gnutls_x509_crq_get_dn_by_oid - This function returns the Certificate request subject's distinguished name
  * @crq: should contain a gnutls_x509_crq structure
  * @oid: holds an Object Identified in null terminated string
  * @indx: In case multiple same OIDs exist in the RDN, this specifies which to send. Use zero to get the first one.
  * @buf: a pointer to a structure to hold the name (may be null)
  * @sizeof_buf: initialy holds the size of 'buf'
  *
  * This function will extract the part of the name of the Certificate request subject, specified
  * by the given OID. The output will be encoded as described in RFC2253.
  *
  * Some helper macros with popular OIDs can be found in gnutls/x509.h
  *
  * If buf is null then only the size will be filled.
  *
  * Returns GNUTLS_E_SHORT_MEMORY_BUFFER if the provided buffer is not long enough, and
  * in that case the sizeof_buf will be updated with the required size.
  * On success zero is returned.
  *
  **/
int gnutls_x509_crq_get_dn_by_oid(gnutls_x509_crq crq, const char* oid, 
	int indx, char *buf, int *sizeof_buf)
{
	if (sizeof_buf == 0 || crq == NULL) {
		return GNUTLS_E_INVALID_REQUEST;
	}
	
	return _gnutls_x509_parse_dn_oid( crq->crq, "certificationRequestInfo.subject.rdnSequence", oid,
		indx, buf, sizeof_buf);

		
}

/**
  * gnutls_x509_crq_set_dn_by_oid - This function will set the Certificate request subject's distinguished name
  * @crq: should contain a gnutls_x509_crq structure
  * @oid: holds an Object Identified in null terminated string
  * @name: a pointer to the name
  * @sizeof_name: holds the size of 'name'
  *
  * This function will set the part of the name of the Certificate request subject, specified
  * by the given OID. 
  *
  * Some helper macros with popular OIDs can be found in gnutls/x509.h
  *
  * On success zero is returned.
  *
  **/
int gnutls_x509_crq_set_dn_by_oid(gnutls_x509_crq crq, const char* oid, 
	const char *name, int sizeof_name)
{
	if (sizeof_name == 0 || name == NULL || crq == NULL) {
		return GNUTLS_E_INVALID_REQUEST;
	}
	
	return _gnutls_x509_set_dn_oid( crq->crq, "certificationRequestInfo.subject.rdnSequence", oid,
		name, sizeof_name);
}

/**
  * gnutls_x509_crq_set_version - This function will set the Certificate request version
  * @crq: should contain a gnutls_x509_crq structure
  * @version: holds the version number. For v1 Requests must be 0.
  *
  * This function will set the version of the certificate request. This
  * must be zero.
  *
  * On success zero is returned.
  *
  **/
int gnutls_x509_crq_set_version(gnutls_x509_crq crq, int version)
{
int result;
uint8 null = version;

	result = asn1_write_value( crq->crq, "certificationRequestInfo.version", &null, 1);
	if (result != ASN1_SUCCESS) {
		gnutls_assert();
		return _gnutls_asn2err(result);
	}

	return 0;
}

/**
  * gnutls_x509_crq_set_key - This function will associate the Certificate request with a key
  * @crq: should contain a gnutls_x509_crq structure
  * @key: holds a private key
  *
  * This function will set the public parameters from the given private key to the
  * request.
  *
  * On success zero is returned.
  *
  **/
int gnutls_x509_crq_set_key(gnutls_x509_crq crq, gnutls_x509_privkey key)
{
const char* pk;
opaque * der;
int der_size, result;

	if (key->pk_algorithm != GNUTLS_PK_RSA) {
		gnutls_assert();
		return GNUTLS_E_UNIMPLEMENTED_FEATURE;
	}

	pk = _gnutls_x509_pk2oid( key->pk_algorithm);
	if (pk == NULL) {
		gnutls_assert();
		return GNUTLS_E_INVALID_REQUEST;
	}

	/* write the RSA OID
	 */
	result = asn1_write_value( crq->crq, "certificationRequestInfo.subjectPKInfo.algorithm.algorithm", pk, 1);
	if (result != ASN1_SUCCESS) {
		gnutls_assert();
		return _gnutls_asn2err(result);
	}

	/* disable parameters, which are not used in RSA.
	 */
	result = asn1_write_value( crq->crq, "certificationRequestInfo.subjectPKInfo.algorithm.parameters", NULL, 0);
	if (result != ASN1_SUCCESS) {
		gnutls_assert();
		return _gnutls_asn2err(result);
	}

	der_size = MAX_PARAMETER_SIZE*2 + 128;
	der = gnutls_alloca( der_size);
	if (der == NULL) {
		gnutls_assert();
		return GNUTLS_E_MEMORY_ERROR;
	}

	result = _gnutls_x509_write_rsa_params( key->params, key->params_size, der, &der_size);
	if (result < 0) {
		gnutls_assert();
		gnutls_afree(der);
		return result;
	}

	/* Write the DER parameters. (in bits)
	 */
	result = asn1_write_value( crq->crq, 
		"certificationRequestInfo.subjectPKInfo.subjectPublicKey", der, der_size*8);

	gnutls_afree(der);

	if (result != ASN1_SUCCESS) {
		gnutls_assert();
		return _gnutls_asn2err(result);
	}

	/* Step 2. Move up and write the AlgorithmIdentifier, which is also
	 * the same. Note that requests are self signed.
	 */

	/* write the RSA OID
	 */
	result = asn1_write_value( crq->crq, "signatureAlgorithm.algorithm", pk, 1);
	if (result != ASN1_SUCCESS) {
		gnutls_assert();
		return _gnutls_asn2err(result);
	}

	/* disable parameters, which are not used in RSA.
	 */
	result = asn1_write_value( crq->crq, "signatureAlgorithm.parameters", NULL, 0);
	if (result != ASN1_SUCCESS) {
		gnutls_assert();
		return _gnutls_asn2err(result);
	}

	/* FIXME: disable attributes.
	 */
	result = asn1_write_value( crq->crq, "certificationRequestInfo.attributes", NULL, 0);
	if (result != ASN1_SUCCESS) {
		gnutls_assert();
		return _gnutls_asn2err(result);
	}

	return 0;
}

/**
  * gnutls_x509_crq_sign - This function will sign a Certificate request with a key
  * @crq: should contain a gnutls_x509_crq structure
  * @key: holds a private key
  *
  * This function will sign the certificate request with a private key.
  * This must be the same key as the one used in gnutls_x509_crt_set_key() since a
  * certificate request is self signed.
  *
  * This must be the last step in a certificate request generation since all
  * the previously set parameters are now signed.
  *
  * On success zero is returned.
  *
  **/
int gnutls_x509_crq_sign(gnutls_x509_crq crq, gnutls_x509_privkey key)
{
int result;
gnutls_datum signature;

	if (key->pk_algorithm != GNUTLS_PK_RSA) {
		gnutls_assert();
		return GNUTLS_E_UNIMPLEMENTED_FEATURE;
	}

	/* Step 3. Self sign the request.
	 */
	result = _gnutls_x509_sign_tbs( crq->crq, "certificationRequestInfo", GNUTLS_MAC_SHA,
		key, &signature);
	
	if (result < 0) {
		gnutls_assert();
		return result;
	}

	/* write the signature (bits)
	 */
	result = asn1_write_value( crq->crq, "signature", signature.data, signature.size*8);

	_gnutls_free_datum( &signature);

	if (result != ASN1_SUCCESS) {
		gnutls_assert();
		return _gnutls_asn2err(result);
	}

	return 0;
}

/**
  * gnutls_x509_crq_export - This function will export the generated certificate request
  * @crq: Holds the request
  * @format: the format of output params. One of PEM or DER.
  * @output_data: will contain a certificate request PEM or DER encoded
  * @output_data_size: holds the size of output_data (and will be replaced by the actual size of parameters)
  *
  * This function will export the certificate request to a PKCS10
  *
  * If the buffer provided is not long enough to hold the output, then
  * GNUTLS_E_SHORT_MEMORY_BUFFER will be returned.
  *
  * If the structure is PEM encoded, it will have a header
  * of "BEGIN CERTIFICATE REQUEST".
  *
  * In case of failure a negative value will be returned, and
  * 0 on success.
  *
  **/
int gnutls_x509_crq_export( gnutls_x509_crq crq,
	gnutls_x509_crt_fmt format, unsigned char* output_data, int* output_data_size)
{
	return _gnutls_x509_export_int( crq->crq, format, PEM_CRQ, *output_data_size,
		output_data, output_data_size);
}
