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

/* Functions that relate on PKCS12 packet parsing.
 */

#include <libtasn1.h>
#include <gnutls_int.h>

#ifdef ENABLE_PKI

#include <gnutls_datum.h>
#include <gnutls_global.h>
#include <gnutls_errors.h>
#include <common.h>
#include <x509_b64.h>
#include <pkcs12.h>
#include <dn.h>

#define DATA_OID "1.2.840.113549.1.7.1"
#define ENC_DATA_OID "1.2.840.113549.1.7.6"

/* Decodes the PKCS #12 auth_safe, and returns the allocated raw data,
 * which holds them. Returns an ASN1_TYPE of authenticatedSafe.
 */
static
int _decode_pkcs12_auth_safe( ASN1_TYPE pkcs12, ASN1_TYPE * authen_safe, gnutls_datum* raw) 
{
char oid[128];
ASN1_TYPE c2 = ASN1_TYPE_EMPTY;
gnutls_datum auth_safe = { NULL, 0 };
int tmp_size, len, result;

	len = sizeof(oid) - 1;
	result = asn1_read_value(pkcs12, "authSafe.contentType", oid, &len);
	if (result != ASN1_SUCCESS) {
		gnutls_assert();
		return _gnutls_asn2err(result);
	}

	if ( strcmp( oid, DATA_OID) != 0) {
		gnutls_assert();
		_gnutls_x509_log( "Unknown PKCS12 Content OID '%s'\n", oid);
		return GNUTLS_E_UNKNOWN_PKCS_CONTENT_TYPE;
	}

	/* Step 1. Read the content data
	 */

	tmp_size = 0;
	result = _gnutls_x509_read_value(pkcs12, "authSafe.content", &auth_safe, 1);
	if (result < 0) {
		gnutls_assert();
		goto cleanup;
	}

	/* Step 2. Extract the authenticatedSafe.
	 */

	if ((result=asn1_create_element
	    (_gnutls_get_pkix(), "PKIX1.pkcs-12-AuthenticatedSafe", &c2)) != ASN1_SUCCESS) {
		gnutls_assert();
		result = _gnutls_asn2err(result);
		goto cleanup;	
	}

	result = asn1_der_decoding(&c2, auth_safe.data, auth_safe.size, NULL);
	if (result != ASN1_SUCCESS) {
		gnutls_assert();
		result = _gnutls_asn2err(result);
		goto cleanup;	
	}

	if (raw == NULL) {
		_gnutls_free_datum(&auth_safe);
	} else {
		raw->data = auth_safe.data;
		raw->size = auth_safe.size;
	}

	*authen_safe = c2;

	return 0;

	cleanup:
		if (c2) asn1_delete_structure(&c2);
		_gnutls_free_datum( &auth_safe);
		return result;
}

/**
  * gnutls_pkcs12_init - This function initializes a gnutls_pkcs12 structure
  * @pkcs12: The structure to be initialized
  *
  * This function will initialize a PKCS12 structure. PKCS12 structures
  * usually contain lists of X.509 Certificates and X.509 Certificate
  * revocation lists.
  *
  * Returns 0 on success.
  *
  **/
int gnutls_pkcs12_init(gnutls_pkcs12 * pkcs12)
{
	*pkcs12 = gnutls_calloc( 1, sizeof(gnutls_pkcs12_int));

	if (*pkcs12) {
		int result = asn1_create_element(_gnutls_get_pkix(),
				     "PKIX1.pkcs-12-PFX",
				     &(*pkcs12)->pkcs12);
		if (result != ASN1_SUCCESS) {
			gnutls_assert();
			return _gnutls_asn2err(result);
		}
		return 0;		/* success */
	}
	return GNUTLS_E_MEMORY_ERROR;
}

/**
  * gnutls_pkcs12_deinit - This function deinitializes memory used by a gnutls_pkcs12 structure
  * @pkcs12: The structure to be initialized
  *
  * This function will deinitialize a PKCS12 structure. 
  *
  **/
void gnutls_pkcs12_deinit(gnutls_pkcs12 pkcs12)
{
	if (pkcs12->pkcs12)
		asn1_delete_structure(&pkcs12->pkcs12);

	gnutls_free(pkcs12);
}

/**
  * gnutls_pkcs12_import - This function will import a DER or PEM encoded PKCS12 structure
  * @pkcs12: The structure to store the parsed PKCS12.
  * @data: The DER or PEM encoded PKCS12.
  * @format: One of DER or PEM
  * @password: the password that will be used to decrypt the structure
  * @flags: an ORed sequence of gnutls_privkey_pkcs8_flags
  *
  * This function will convert the given DER or PEM encoded PKCS12
  * to the native gnutls_pkcs12 format. The output will be stored in 'pkcs12'.
  *
  * If the PKCS12 is PEM encoded it should have a header of "PKCS12".
  *
  * Returns 0 on success.
  *
  **/
int gnutls_pkcs12_import(gnutls_pkcs12 pkcs12, const gnutls_datum * data,
	gnutls_x509_crt_fmt format, const char* password, unsigned int flags)
{
	int result = 0, need_free = 0;
	gnutls_datum _data = { data->data, data->size };

	/* If the PKCS12 is in PEM format then decode it
	 */
	if (format == GNUTLS_X509_FMT_PEM) {
		opaque *out;
		
		result = _gnutls_fbase64_decode(PEM_PKCS12, data->data, data->size,
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

	result = asn1_der_decoding(&pkcs12->pkcs12, _data.data, _data.size, NULL);
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
  * gnutls_pkcs12_export - This function will export the pkcs12 structure
  * @pkcs12: Holds the pkcs12 structure
  * @format: the format of output params. One of PEM or DER.
  * @output_data: will contain a structure PEM or DER encoded
  * @output_data_size: holds the size of output_data (and will be replaced by the actual size of parameters)
  *
  * This function will export the pkcs12 structure to DER or PEM format.
  *
  * If the buffer provided is not long enough to hold the output, then
  * GNUTLS_E_SHORT_MEMORY_BUFFER will be returned.
  *
  * If the structure is PEM encoded, it will have a header
  * of "BEGIN PKCS12".
  *
  * In case of failure a negative value will be returned, and
  * 0 on success.
  *
  **/
int gnutls_pkcs12_export( gnutls_pkcs12 pkcs12,
	gnutls_x509_crt_fmt format, unsigned char* output_data, int* output_data_size)
{
	return _gnutls_x509_export_int( pkcs12->pkcs12, format, PEM_PKCS12, *output_data_size,
		output_data, output_data_size);
}

#define BAG_PKCS8_KEY "1.2.840.113549.1.12.10.1.1"
#define BAG_PKCS8_ENCRYPTED_KEY "1.2.840.113549.1.12.10.1.2"
#define BAG_CERTIFICATE "1.2.840.113549.1.12.10.1.3"
#define BAG_CRL "1.2.840.113549.1.12.10.1.4"

static int _oid2bag( const char* oid)
{
	if (strcmp(oid, BAG_PKCS8_KEY)==0) 
		return GNUTLS_BAG_PKCS8_KEY;
	if (strcmp(oid, BAG_PKCS8_ENCRYPTED_KEY)==0) 
		return GNUTLS_BAG_PKCS8_ENCRYPTED_KEY;
	if (strcmp(oid, BAG_CERTIFICATE)==0) 
		return GNUTLS_BAG_CERTIFICATE;
	if (strcmp(oid, BAG_CRL)==0) 
		return GNUTLS_BAG_CRL;
	
	return GNUTLS_E_UNKNOWN_PKCS_BAG_TYPE;

}


static
int _parse_safe_contents( ASN1_TYPE sc, const char* sc_name, gnutls_pkcs12_bag bag) 
{
char oid[128];
ASN1_TYPE c2 = ASN1_TYPE_EMPTY;
gnutls_datum content = { NULL, 0 };
int len, result;
int bag_type;

	/* Step 1. Extract the content.
	 */

	result = _gnutls_x509_read_value(sc, sc_name, &content, 1);
	if (result < 0) {
		gnutls_assert();
		goto cleanup;
	}

	/* Step 2. Extract the SEQUENCE.
	 */

	if ((result=asn1_create_element
	    (_gnutls_get_pkix(), "PKIX1.pkcs-12-SafeContents", &c2)) != ASN1_SUCCESS) {
		gnutls_assert();
		result = _gnutls_asn2err(result);
		goto cleanup;	
	}

	result = asn1_der_decoding(&c2, content.data, content.size, NULL);
	if (result != ASN1_SUCCESS) {
		gnutls_assert();
		result = _gnutls_asn2err(result);
		goto cleanup;	
	}
	_gnutls_free_datum(&content);

	len = sizeof(oid);
	result = asn1_read_value(c2, "?1.bagId", oid, &len);
	if (result != ASN1_SUCCESS) {
		gnutls_assert();
		result = _gnutls_asn2err(result);
		goto cleanup;
	}

	/* Read the Bag type
	 */
	bag_type = _oid2bag( oid);
	
	if (bag_type < 0) {
		gnutls_assert();
		goto cleanup;
	}

	/* Read the Bag Value
	 */

	result = _gnutls_x509_read_value( c2, "?1.bagValue", &bag->data, 0);
	if (result < 0) {
		gnutls_assert();
		return result;
	}

	asn1_delete_structure(&c2);

	bag->type = bag_type;

	return 0;

	cleanup:
		if (c2) asn1_delete_structure(&c2);
		_gnutls_free_datum( &content);
		return result;
}



/**
  * gnutls_pkcs12_get_bag - This function returns a Bag from a PKCS12 structure
  * @pkcs12_struct: should contain a gnutls_pkcs12 structure
  * @indx: contains the index of the bag to extract
  * @bag: An initialized bag, where the contents of the bag will be copied
  *
  * This function will return a Bag from the PKCS12 structure.
  * Returns 0 on success.
  *
  * After the last Bag has been read GNUTLS_E_REQUESTED_DATA_NOT_AVAILABLE
  * will be returned.
  *
  **/
int gnutls_pkcs12_get_bag(gnutls_pkcs12 pkcs12, 
	int indx, gnutls_pkcs12_bag bag)
{
	ASN1_TYPE c2 = ASN1_TYPE_EMPTY;
	int result, len;
	char root2[64];
	char oid[128];
	char counter[MAX_INT_DIGITS];
	gnutls_datum tmp = {NULL, 0};

	/* Step 1. decode the data.
	 */
	result = _decode_pkcs12_auth_safe( pkcs12->pkcs12, &c2, NULL);
	if (result < 0) {
		gnutls_assert();
		return result;
	}
	
	/* Step 2. Parse the AuthenticatedSafe
	 */
	
	_gnutls_str_cpy( root2, sizeof(root2), "?"); 
	_gnutls_int2str( indx+1, counter);
	_gnutls_str_cat( root2, sizeof(root2), counter); 
	_gnutls_str_cat( root2, sizeof(root2), ".contentType"); 

	len = sizeof(oid) - 1;

	result = asn1_read_value(c2, root2, oid, &len);

	if (result == ASN1_ELEMENT_NOT_FOUND) {
		result = GNUTLS_E_REQUESTED_DATA_NOT_AVAILABLE;
		goto cleanup;	
	}

	if (result != ASN1_SUCCESS) {
		gnutls_assert();
		result = _gnutls_asn2err(result);
		goto cleanup;	
	}

	/* Not encrypted Bag
	 */

	_gnutls_str_cpy( root2, sizeof(root2), "?"); 
	_gnutls_int2str( indx+1, counter);
	_gnutls_str_cat( root2, sizeof(root2), counter); 
	_gnutls_str_cat( root2, sizeof(root2), ".content"); 

	if (strcmp( oid, DATA_OID) == 0) {
		result = _parse_safe_contents( c2, root2, bag);
		goto cleanup;
	}
	
	/* ENC_DATA_OID needs decryption */

	bag->type = GNUTLS_BAG_ENCRYPTED;

	result = _gnutls_x509_read_value( c2, root2, &bag->data, 0);
	if (result < 0) {
		gnutls_assert();
		return result;
	}

	return 0;

	cleanup:
		_gnutls_free_datum( &tmp);
		if (c2) asn1_delete_structure(&c2);
		return result;
}


#endif /* ENABLE_PKI */
