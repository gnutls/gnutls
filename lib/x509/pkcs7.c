/*
 * Copyright (C) 2003-2015 Free Software Foundation, Inc.
 * Copyright (C) 2015 Red Hat, Inc.
 *
 * Author: Nikos Mavrogiannopoulos
 *
 * This file is part of GnuTLS.
 *
 * The GnuTLS is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public License
 * as published by the Free Software Foundation; either version 2.1 of
 * the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with this program.  If not, see <https://www.gnu.org/licenses/>
 *
 */

/* Functions that relate on PKCS7 certificate lists parsing.
 */

#include "gnutls_int.h"
#include <libtasn1.h>

#include <common.h>
#include <x509_b64.h>
#include <pkcs7_int.h>
#include <gnutls/pkcs7.h>

static int pkcs7_reinit(gnutls_pkcs7_t pkcs7)
{
	int result;

	if (pkcs7->content_data)
		asn1_delete_structure(&pkcs7->content_data);

	_gnutls_free_datum(&pkcs7->der_encap_data);

	asn1_delete_structure(&pkcs7->pkcs7);

	result = asn1_create_element(_gnutls_get_pkix(),
				     "PKIX1.pkcs-7-ContentInfo", &pkcs7->pkcs7);
	if (result != ASN1_SUCCESS) {
		result = _gnutls_asn2err(result);
		gnutls_assert();
		return result;
	}

	pkcs7->type = GNUTLS_PKCS7_UNINITIALIZED;

	return 0;
}

/**
 * gnutls_pkcs7_init:
 * @pkcs7: A pointer to the type to be initialized
 *
 * This function will initialize a PKCS7 structure. PKCS7 structures
 * usually contain lists of X.509 Certificates and X.509 Certificate
 * revocation lists.
 *
 * Returns: On success, %GNUTLS_E_SUCCESS (0) is returned, otherwise a
 *   negative error value.
 **/
int gnutls_pkcs7_init(gnutls_pkcs7_t * pkcs7)
{
	*pkcs7 = gnutls_calloc(1, sizeof(gnutls_pkcs7_int));

	if (*pkcs7) {
		int result = pkcs7_reinit(*pkcs7);
		if (result < 0) {
			gnutls_assert();
			gnutls_free(*pkcs7);
			return result;
		}
		return 0;	/* success */
	}
	return GNUTLS_E_MEMORY_ERROR;
}

/**
 * gnutls_pkcs7_deinit:
 * @pkcs7: the type to be deinitialized
 *
 * This function will deinitialize a PKCS7 type.
 **/
void gnutls_pkcs7_deinit(gnutls_pkcs7_t pkcs7)
{
	if (!pkcs7)
		return;

	if (pkcs7->pkcs7)
		asn1_delete_structure(&pkcs7->pkcs7);

	if (pkcs7->content_data)
		asn1_delete_structure(&pkcs7->content_data);

	_gnutls_free_datum(&pkcs7->der_encap_data);

	gnutls_free(pkcs7);
}

static int _gnutls_pkcs7_decode_plain_data(gnutls_pkcs7_t pkcs7)
{
	asn1_node c2;
	int result;
	gnutls_datum_t tmp = {NULL, 0};

	if ((result = asn1_create_element
	     (_gnutls_get_pkix(), "PKIX1.pkcs-7-Data",
	      &c2)) != ASN1_SUCCESS) {
		gnutls_assert();
		return _gnutls_asn2err(result);
	}

	/* the Data has been created, so decode it.
	 */
	result = _gnutls_x509_read_value(pkcs7->pkcs7, "content", &tmp);
	if (result < 0) {
		gnutls_assert();
		goto cleanup;
	}

	result = asn1_der_decoding(&c2, tmp.data, tmp.size, NULL);
	if (result != ASN1_SUCCESS) {
		gnutls_assert();
		result = _gnutls_asn2err(result);
		goto cleanup;
	}

	result = _gnutls_x509_read_value(c2, "", &pkcs7->der_encap_data);
	if (result < 0) {
		gnutls_assert();
		goto cleanup;
	}

	strcpy(pkcs7->encap_data_oid, DATA_OID);

	pkcs7->content_data = c2;
	gnutls_free(tmp.data);

	return 0;

 cleanup:
	gnutls_free(tmp.data);
	if (c2)
		asn1_delete_structure(&c2);
	return result;
}

/**
 * gnutls_pkcs7_import:
 * @pkcs7: The data to store the parsed PKCS7.
 * @data: The DER or PEM encoded PKCS7.
 * @format: One of DER or PEM
 *
 * This function will convert the given DER or PEM encoded PKCS7 to
 * the native #gnutls_pkcs7_t format.  The output will be stored in
 * @pkcs7. Any signed data that may be present inside the @pkcs7
 * structure, like certificates set by gnutls_pkcs7_set_crt(), will
 * be freed and overwritten by this function.
 *
 * If the PKCS7 is PEM encoded it should have a header of "PKCS7".
 *
 * Returns: On success, %GNUTLS_E_SUCCESS (0) is returned, otherwise a
 *   negative error value.
 **/
int
gnutls_pkcs7_import(gnutls_pkcs7_t pkcs7, const gnutls_datum_t * data,
		    gnutls_x509_crt_fmt_t format)
{
	int result = 0, need_free = 0;
	char data_oid[MAX_OID_SIZE];
	int len;
	gnutls_datum_t _data;

	if (pkcs7 == NULL)
		return GNUTLS_E_INVALID_REQUEST;

	_data.data = data->data;
	_data.size = data->size;

	/* If the PKCS7 is in PEM format then decode it
	 */
	if (format == GNUTLS_X509_FMT_PEM) {
		result =
		    _gnutls_fbase64_decode(PEM_PKCS7, data->data,
					   data->size, &_data);

		if (result < 0) {
			gnutls_assert();
			return result;
		}

		need_free = 1;
	}

	result = pkcs7_reinit(pkcs7);
	if (result < 0) {
		gnutls_assert();
		goto cleanup;
	}

	result = asn1_der_decoding(&pkcs7->pkcs7, _data.data, _data.size, NULL);
	if (result != ASN1_SUCCESS) {
		result = _gnutls_asn2err(result);
		gnutls_assert();
		goto cleanup;
	}

	len = MAX_OID_SIZE - 1;
	result = asn1_read_value(pkcs7->pkcs7, "contentType", data_oid, &len);
	if (result != ASN1_SUCCESS) {
		gnutls_assert();
		return _gnutls_asn2err(result);
	}

	if (strcmp(data_oid, DATA_OID) == 0) {
		pkcs7->type = GNUTLS_PKCS7_DATA;
		result = _gnutls_pkcs7_decode_plain_data(pkcs7);
	} else if (strcmp(data_oid, SIGNED_DATA_OID) == 0) {
		pkcs7->type = GNUTLS_PKCS7_SIGNED;
		result = _gnutls_pkcs7_decode_signed_data(pkcs7);
	} else if (strcmp(data_oid, DIGESTED_DATA_OID) == 0) {
		pkcs7->type = GNUTLS_PKCS7_DIGESTED;
		result = _gnutls_pkcs7_decode_digested_data(pkcs7);
	} else if (strcmp(data_oid, ENCRYPTED_DATA_OID) == 0) {
		pkcs7->type = GNUTLS_PKCS7_ENCRYPTED;
		result = _gnutls_pkcs7_decode_encrypted_data(pkcs7);
	} else {
		gnutls_assert();
		_gnutls_debug_log("Unknown PKCS7 Content OID '%s'\n", pkcs7->encap_data_oid);
		return GNUTLS_E_UNKNOWN_PKCS_CONTENT_TYPE;
	}

	if (result < 0) {
		gnutls_assert();
		goto cleanup;
	}

	result = 0;

 cleanup:
	if (need_free)
		_gnutls_free_datum(&_data);
	return result;
}

/**
 * gnutls_pkcs7_get_embedded_data:
 * @pkcs7: should contain a gnutls_pkcs7_t type
 * @flags: must be zero or %GNUTLS_PKCS7_EDATA_GET_RAW
 * @data: will hold the embedded data in the provided structure
 *
 * This function will return the data embedded in the signature of
 * the PKCS7 structure. If no data are available then
 * %GNUTLS_E_REQUESTED_DATA_NOT_AVAILABLE will be returned.
 *
 * The returned data must be de-allocated using gnutls_free().
 *
 * Note, that this function returns the exact same data that are
 * authenticated. If the %GNUTLS_PKCS7_EDATA_GET_RAW flag is provided,
 * the returned data will be including the wrapping tag/value as
 * they are encoded in the structure.
 *
 * Returns: On success, %GNUTLS_E_SUCCESS (0) is returned, otherwise a
 *   negative error value.
 *
 * Since: 3.4.8
 **/
int
gnutls_pkcs7_get_embedded_data(gnutls_pkcs7_t pkcs7, unsigned flags,
			       gnutls_datum_t *data)
{
	if (pkcs7 == NULL)
		return GNUTLS_E_INVALID_REQUEST;

	if (pkcs7->der_encap_data.size == 0)
		return gnutls_assert_val(GNUTLS_E_REQUESTED_DATA_NOT_AVAILABLE);

	if (flags & GNUTLS_PKCS7_EDATA_GET_RAW) {
		if (pkcs7->content_data == NULL)
			return gnutls_assert_val(GNUTLS_E_REQUESTED_DATA_NOT_AVAILABLE);

		return _gnutls_x509_read_value(pkcs7->content_data, "encapContentInfo.eContent", data);
	} else {
		return _gnutls_set_datum(data, pkcs7->der_encap_data.data, pkcs7->der_encap_data.size);
	}
}

/**
 * gnutls_pkcs7_get_embedded_data_oid:
 * @pkcs7: should contain a gnutls_pkcs7_t type
 *
 * This function will return the OID of the data embedded in the signature of
 * the PKCS7 structure. If no data are available then %NULL will be
 * returned. The returned value will be valid during the lifetime
 * of the @pkcs7 structure.
 *
 * Returns: On success, a pointer to an OID string, %NULL on error.
 *
 * Since: 3.5.5
 **/
const char *
gnutls_pkcs7_get_embedded_data_oid(gnutls_pkcs7_t pkcs7)
{
	if (pkcs7 == NULL || pkcs7->encap_data_oid[0] == 0)
		return NULL;

	return pkcs7->encap_data_oid;
}

/* This should be a part of pkcs7-sign.c */
static void disable_opt_fields(gnutls_pkcs7_t pkcs7)
{
	int result;
	int count;

	if (pkcs7->type != GNUTLS_PKCS7_SIGNED)
		return;

	/* disable the optional fields */
	result = asn1_number_of_elements(pkcs7->content_data, "crls", &count);
	if (result != ASN1_SUCCESS || count == 0) {
		(void)asn1_write_value(pkcs7->content_data, "crls", NULL, 0);
	}

	result =
	    asn1_number_of_elements(pkcs7->content_data, "certificates", &count);
	if (result != ASN1_SUCCESS || count == 0) {
		(void)asn1_write_value(pkcs7->content_data, "certificates", NULL, 0);
	}

	return;
}

static int reencode(gnutls_pkcs7_t pkcs7)
{
	int result;
	const char *oid;

	if (pkcs7->content_data != NULL) {
		disable_opt_fields(pkcs7);

		/* Replace the old content with the new
		 */
		result =
		    _gnutls_x509_der_encode_and_copy(pkcs7->content_data, "",
						     pkcs7->pkcs7, "content",
						     0);
		if (result < 0) {
			return gnutls_assert_val(result);
		}

		switch (pkcs7->type) {
		case GNUTLS_PKCS7_DATA:
			oid = DATA_OID;
			break;
		case GNUTLS_PKCS7_SIGNED:
			oid = SIGNED_DATA_OID;
			break;
		case GNUTLS_PKCS7_DIGESTED:
			oid = DIGESTED_DATA_OID;
			break;
		case GNUTLS_PKCS7_ENCRYPTED:
			oid = ENCRYPTED_DATA_OID;
			break;
		default:
			return gnutls_assert_val(GNUTLS_E_INTERNAL_ERROR);
		}

		/* Write the content type of the signed data
		 */
		result = asn1_write_value(pkcs7->pkcs7, "contentType", oid, 1);
		if (result != ASN1_SUCCESS) {
			gnutls_assert();
			return _gnutls_asn2err(result);
		}
	}
	return 0;
}

/**
 * gnutls_pkcs7_export:
 * @pkcs7: The pkcs7 type
 * @format: the format of output params. One of PEM or DER.
 * @output_data: will contain a structure PEM or DER encoded
 * @output_data_size: holds the size of output_data (and will be
 *   replaced by the actual size of parameters)
 *
 * This function will export the pkcs7 structure to DER or PEM format.
 *
 * If the buffer provided is not long enough to hold the output, then
 * *@output_data_size is updated and %GNUTLS_E_SHORT_MEMORY_BUFFER
 * will be returned.
 *
 * If the structure is PEM encoded, it will have a header
 * of "BEGIN PKCS7".
 *
 * Returns: On success, %GNUTLS_E_SUCCESS (0) is returned, otherwise a
 *   negative error value.
 **/
int
gnutls_pkcs7_export(gnutls_pkcs7_t pkcs7,
		    gnutls_x509_crt_fmt_t format, void *output_data,
		    size_t * output_data_size)
{
	int ret;
	if (pkcs7 == NULL)
		return GNUTLS_E_INVALID_REQUEST;

	if ((ret = reencode(pkcs7)) < 0)
		return gnutls_assert_val(ret);

	return _gnutls_x509_export_int(pkcs7->pkcs7, format, PEM_PKCS7,
				       output_data, output_data_size);
}

/**
 * gnutls_pkcs7_export2:
 * @pkcs7: The pkcs7 type
 * @format: the format of output params. One of PEM or DER.
 * @out: will contain a structure PEM or DER encoded
 *
 * This function will export the pkcs7 structure to DER or PEM format.
 *
 * The output buffer is allocated using gnutls_malloc().
 *
 * If the structure is PEM encoded, it will have a header
 * of "BEGIN PKCS7".
 *
 * Returns: On success, %GNUTLS_E_SUCCESS (0) is returned, otherwise a
 *   negative error value.
 *
 * Since: 3.1.3
 **/
int
gnutls_pkcs7_export2(gnutls_pkcs7_t pkcs7,
		     gnutls_x509_crt_fmt_t format, gnutls_datum_t * out)
{
	int ret;
	if (pkcs7 == NULL)
		return GNUTLS_E_INVALID_REQUEST;

	if ((ret = reencode(pkcs7)) < 0)
		return gnutls_assert_val(ret);

	return _gnutls_x509_export_int2(pkcs7->pkcs7, format, PEM_PKCS7, out);
}
