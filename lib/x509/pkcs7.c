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

#include <libtasn1.h>
#include <gnutls_int.h>
#include <gnutls_datum.h>
#include <gnutls_global.h>
#include <gnutls_errors.h>
#include <common.h>
#include <x509_b64.h>
#include <pkcs7.h>
#include <dn.h>

/**
  * gnutls_pkcs7_init - This function initializes a gnutls_pkcs7 structure
  * @pkcs7: The structure to be initialized
  *
  * This function will initialize a PKCS7 structure. PKCS7 stands for
  * Certificate Revocation List.
  *
  * Returns 0 on success.
  *
  **/
int gnutls_pkcs7_init(gnutls_pkcs7 * pkcs7)
{
	*pkcs7 = gnutls_calloc( 1, sizeof(gnutls_pkcs7_int));

	if (*pkcs7) {
		(*pkcs7)->pkcs7 = ASN1_TYPE_EMPTY;
		return 0;		/* success */
	}
	return GNUTLS_E_MEMORY_ERROR;
}

/**
  * gnutls_pkcs7_deinit - This function deinitializes memory used by a gnutls_pkcs7 structure
  * @pkcs7: The structure to be initialized
  *
  * This function will deinitialize a PKCS7 structure. 
  *
  **/
void gnutls_pkcs7_deinit(gnutls_pkcs7 pkcs7)
{
	if (pkcs7->pkcs7)
		asn1_delete_structure(&pkcs7->pkcs7);

	gnutls_free(pkcs7);
}

/**
  * gnutls_pkcs7_import - This function will import a DER or PEM encoded PKCS7
  * @pkcs7: The structure to store the parsed PKCS7.
  * @data: The DER or PEM encoded PKCS7.
  * @format: One of DER or PEM
  *
  * This function will convert the given DER or PEM encoded PKCS7
  * to the native gnutls_pkcs7 format. The output will be stored in 'pkcs7'.
  *
  * If the PKCS7 is PEM encoded it should have a header of "X509 PKCS7", and
  * it must be a null terminated string.
  *
  * Returns 0 on success.
  *
  **/
int gnutls_pkcs7_import(gnutls_pkcs7 pkcs7, const gnutls_datum * data,
	gnutls_x509_crt_fmt format)
{
	int result = 0, need_free = 0;
	gnutls_datum _data = { data->data, data->size };

	/* If the PKCS7 is in PEM format then decode it
	 */
	if (format == GNUTLS_X509_FMT_PEM) {
		opaque *out;
		
		result = _gnutls_fbase64_decode(PEM_PKCS7, data->data, data->size,
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

	pkcs7->pkcs7 = ASN1_TYPE_EMPTY;

	result = asn1_create_element(_gnutls_get_pkix(),
				     "PKIX1.ContentInfo",
				     &pkcs7->pkcs7);
	if (result != ASN1_SUCCESS) {
		gnutls_assert();
		return _gnutls_asn2err(result);
	}

	result = asn1_der_decoding(&pkcs7->pkcs7, _data.data, _data.size, NULL);
	if (result != ASN1_SUCCESS) {
		result = _gnutls_asn2err(result);
		gnutls_assert();
		goto cleanup;
	}

	if (need_free) _gnutls_free_datum( &_data);

	return 0;

      cleanup:
	if (pkcs7->pkcs7)
		asn1_delete_structure(&pkcs7->pkcs7);
	if (need_free) _gnutls_free_datum( &_data);
	return result;
}


/**
  * gnutls_pkcs7_get_certificate - This function returns a certificate in a PKCS7 certificate set
  * @pkcs7_struct: should contain a gnutls_pkcs7 structure
  * @indx: contains the index of the certificate to extract
  * @certificate: the contents of the certificate will be copied there (may be null)
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
int gnutls_pkcs7_get_certificate(gnutls_pkcs7 pkcs7, 
	int indx, unsigned char* certificate, int* certificate_size)
{
	ASN1_TYPE c2 = ASN1_TYPE_EMPTY;
	int result, len;
	char oid[128];
	opaque *tmp = NULL;
	char root2[64];
	char counter[MAX_INT_DIGITS];
	int tmp_size;

	if (certificate_size == NULL) return GNUTLS_E_INVALID_REQUEST;

	/* root2 is used as a temp storage area
	 */
	len = sizeof(oid) - 1;
	result = asn1_read_value(pkcs7->pkcs7, "contentType", oid, &len);
	if (result != ASN1_SUCCESS) {
		gnutls_assert();
		return _gnutls_asn2err(result);
	}

	if ( strcmp( oid, "1.2.840.113549.1.7.2") != 0) {
		gnutls_assert();
		return GNUTLS_E_REQUESTED_DATA_NOT_AVAILABLE;
	}					 		 	

	tmp_size = 256; /* some initial size */
	tmp = gnutls_malloc(tmp_size);
	if (tmp==NULL) {
		gnutls_assert();
		return GNUTLS_E_MEMORY_ERROR;
	}

	result = asn1_read_value(pkcs7->pkcs7, "content", tmp, &tmp_size);
	/* FIXME: a hard coded value
	 */
	if (result==ASN1_MEM_ERROR && tmp_size > 0 && tmp_size < 50*1024) {
		tmp = gnutls_realloc_fast( tmp, tmp_size);
		if (tmp==NULL) {
			gnutls_assert();
			return GNUTLS_E_MEMORY_ERROR;
		}
		result = asn1_read_value(pkcs7->pkcs7, "content", tmp, &tmp_size);
	} 
	
	if (result != ASN1_SUCCESS) {
		gnutls_assert();
		result = _gnutls_asn2err(result);
		goto cleanup;
	}

	/* tmp, tmp_size hold the data and the size of the CertificateSet structure
	 * actually the ANY stuff.
	 */

	/* Step 1. In case of a signed structure extract certificate set.
	 */
	if ((result=asn1_create_element
	    (_gnutls_get_pkix(), "PKIX1.SignedData", &c2)) != ASN1_SUCCESS) {
		gnutls_assert();
		result = _gnutls_asn2err(result);
		goto cleanup;	}

	result = asn1_der_decoding(&c2, tmp, tmp_size, NULL);
	if (result != ASN1_SUCCESS) {
		/* couldn't decode DER */
		gnutls_assert();
		result = _gnutls_asn2err(result);
		goto cleanup;	
	}

	/* Step 2. Parse the CertificateSet 
	 */
	
	_gnutls_str_cpy( root2, sizeof(root2), "certificates.?"); 
	_gnutls_int2str( indx+1, counter);
	_gnutls_str_cat( root2, sizeof(root2), counter); 

	len = sizeof(oid) - 1;

	result = asn1_read_value(c2, root2, oid, &len);

	if (result == ASN1_VALUE_NOT_FOUND) {
		result = GNUTLS_E_REQUESTED_DATA_NOT_AVAILABLE;
		goto cleanup;	
	}
	
	if (result != ASN1_SUCCESS) {
		gnutls_assert();
		result = _gnutls_asn2err(result);
		goto cleanup;	
	}

	/* if 'Certificate' is the choice found: 
	 */
	if (strcmp( oid, "certificate") == 0) {
		int start, end;

		result = asn1_der_decoding_startEnd(c2, tmp, tmp_size, 
			root2, &start, &end);

		if (result != ASN1_SUCCESS) {
			gnutls_assert();
			result = _gnutls_asn2err(result);
			goto cleanup;
		}
			
		end = end-start+1;
		
		if ( end > *certificate_size) {
			*certificate_size = end;
			result = GNUTLS_E_SHORT_MEMORY_BUFFER;
			goto cleanup;
		}

		if (certificate)
			memcpy( certificate, &tmp[start], end);

		*certificate_size = end;

		result = 0;

	} else {
		result = GNUTLS_E_UNSUPPORTED_CERTIFICATE_TYPE;
	}

	cleanup:
		if (c2) asn1_delete_structure(&c2);
		gnutls_free(tmp);
		return result;
}


/**
  * gnutls_pkcs7_get_certificate_count - This function returns the number of certificates in a PKCS7 certificate set
  * @pkcs7_struct: should contain a gnutls_pkcs7 structure
  *
  * This function will return the number of certifcates in the PKCS7 or 
  * RFC2630 certificate set.
  *
  * Returns a negative value on failure.
  *
  **/
int gnutls_pkcs7_get_certificate_count(gnutls_pkcs7 pkcs7)
{
	ASN1_TYPE c2 = ASN1_TYPE_EMPTY;
	int result, len, count;
	char oid[64];
	opaque *tmp = NULL;
	int tmp_size;

	len = sizeof(oid) - 1;

	/* root2 is used as a temp storage area
	 */
	result = asn1_read_value(pkcs7->pkcs7, "contentType", oid, &len);
	if (result != ASN1_SUCCESS) {
		gnutls_assert();
		return _gnutls_asn2err(result);
	}

	if ( strcmp( oid, "1.2.840.113549.1.7.2") != 0) {
		gnutls_assert();
		return GNUTLS_E_REQUESTED_DATA_NOT_AVAILABLE;
	}					 		 	

	tmp_size = 256; /* some initial size */
	tmp = gnutls_malloc(tmp_size);
	if (tmp==NULL) {
		gnutls_assert();
		return GNUTLS_E_MEMORY_ERROR;
	}

	result = asn1_read_value(pkcs7->pkcs7, "content", tmp, &tmp_size);
	/* FIXME: a hard coded value
	 */
	if (result==ASN1_MEM_ERROR && tmp_size > 0 && tmp_size < 50*1024) {
		tmp = gnutls_realloc_fast( tmp, tmp_size);
		if (tmp==NULL) {
			gnutls_assert();
			return GNUTLS_E_MEMORY_ERROR;
		}
		result = asn1_read_value(pkcs7->pkcs7, "content", tmp, &tmp_size);
	} 

	if (result != ASN1_SUCCESS) {
		gnutls_assert();
		result = _gnutls_asn2err(result);
		goto cleanup;
	}

	/* tmp, tmp_size hold the data and the size of the CertificateSet structure
	 * actually the ANY stuff.
	 */

	/* Step 1. In case of a signed structure count the certificate set.
	 */
	if ((result=asn1_create_element
	    (_gnutls_get_pkix(), "PKIX1.SignedData", &c2)) != ASN1_SUCCESS) {
		gnutls_assert();
		result = _gnutls_asn2err(result);
		goto cleanup;
	}

	result = asn1_der_decoding(&c2, tmp, tmp_size, NULL);
	if (result != ASN1_SUCCESS) {
		/* couldn't decode DER */
	
		gnutls_assert();
		asn1_delete_structure(&c2);
		result = _gnutls_asn2err(result);
		goto cleanup;
	}
		
	gnutls_free(tmp);

	/* Step 2. Count the CertificateSet */
	
	result = asn1_number_of_elements( c2, "certificates", &count);

	asn1_delete_structure(&c2);
	
	if (result != ASN1_SUCCESS) {
		gnutls_assert();
		return 0; /* no certificates */
	}

	return count;
	
	cleanup:
		gnutls_free(tmp);
		return result;
}

