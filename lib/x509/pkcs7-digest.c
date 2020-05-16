/*
 * Copyright (C) 2003-2015 Free Software Foundation, Inc.
 * Copyright (C) 2015 Red Hat, Inc.
 * Copyright (C) 2020 Dmitry Baryshkov
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
#include <pkcs7_int.h>
#include <gnutls/pkcs7.h>

/* Decodes the PKCS #7 digested data, and returns an asn1_node,
 * which holds them
 */
int _gnutls_pkcs7_decode_digested_data(gnutls_pkcs7_t pkcs7)
{
	asn1_node c2;
	int len, result;
	gnutls_datum_t tmp = {NULL, 0};

	if ((result = asn1_create_element
	     (_gnutls_get_pkix(), "PKIX1.pkcs-7-DigestedData",
	      &c2)) != ASN1_SUCCESS) {
		gnutls_assert();
		return _gnutls_asn2err(result);
	}

	/* the Digested-data has been created, so
	 * decode them.
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

	/* read the encapsulated content */
	len = MAX_OID_SIZE - 1;
	result =
	    asn1_read_value(c2, "encapContentInfo.eContentType", pkcs7->encap_data_oid, &len);
	if (result != ASN1_SUCCESS) {
		gnutls_assert();
		result = _gnutls_asn2err(result);
		goto cleanup;
	}

	if (strcmp(pkcs7->encap_data_oid, DATA_OID) != 0) {
		_gnutls_debug_log
		    ("Unknown PKCS#7 Encapsulated Content OID '%s'; treating as raw data\n",
		     pkcs7->encap_data_oid);

	}

	/* Try reading as octet string according to rfc5652. If that fails, attempt
	 * a raw read according to rfc2315 */
	result = _gnutls_x509_read_string(c2, "encapContentInfo.eContent", &pkcs7->der_encap_data, ASN1_ETYPE_OCTET_STRING, 1);
	if (result < 0) {
		result = _gnutls_x509_read_value(c2, "encapContentInfo.eContent", &pkcs7->der_encap_data);
		if (result < 0) {
			pkcs7->der_encap_data.data = NULL;
			pkcs7->der_encap_data.size = 0;
		} else {
			int tag_len, len_len;
			unsigned char cls;
			unsigned long tag;

			/* we skip the embedded element's tag and length - uncharted territorry - used by MICROSOFT_CERT_TRUST_LIST */
			result = asn1_get_tag_der(pkcs7->der_encap_data.data, pkcs7->der_encap_data.size, &cls, &tag_len, &tag);
			if (result != ASN1_SUCCESS) {
				gnutls_assert();
				result = _gnutls_asn2err(result);
				goto cleanup;
			}

			result = asn1_get_length_ber(pkcs7->der_encap_data.data+tag_len, pkcs7->der_encap_data.size-tag_len, &len_len);
			if (result < 0) {
				gnutls_assert();
				result = GNUTLS_E_ASN1_DER_ERROR;
				goto cleanup;
			}

			tag_len += len_len;
			memmove(pkcs7->der_encap_data.data, &pkcs7->der_encap_data.data[tag_len], pkcs7->der_encap_data.size-tag_len);
			pkcs7->der_encap_data.size-=tag_len;
		}
	}

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
 * gnutls_pkcs7_get_digest_algo:
 * @pkcs7: should contain a #gnutls_pkcs7_t type
 *
 * This function will return digest algorithm used
 * in the DigestedData of the PKCS #7 structure.
 *
 * Returns: On success, @gnutls_digest_algorithm_t value is returned, otherwise
 *   a negative error value.
 *
 * Since: 3.7.0
 **/
int gnutls_pkcs7_get_digest_algo(gnutls_pkcs7_t pkcs7)
{
	int len, ret;
	char oid[MAX_OID_SIZE];
	gnutls_digest_algorithm_t dig;

	if (pkcs7 == NULL || pkcs7->type != GNUTLS_PKCS7_DIGESTED)
		return gnutls_assert_val(GNUTLS_E_INVALID_REQUEST);

	len = sizeof(oid) - 1;
	ret = asn1_read_value(pkcs7->content_data, "digestAlgorithm.algorithm", oid, &len);
	if (ret != ASN1_SUCCESS)
		return gnutls_assert_val(GNUTLS_E_UNKNOWN_ALGORITHM);

	dig = gnutls_oid_to_digest(oid);
	if (dig == GNUTLS_DIG_UNKNOWN)
		return gnutls_assert_val(GNUTLS_E_UNKNOWN_ALGORITHM);

	return dig;
}

/**
 * gnutls_pkcs7_verify_digest:
 * @pkcs7: should contain a #gnutls_pkcs7_t type
 * @data: The data to be verified or %NULL
 * @flags: Zero or an OR list of #gnutls_certificate_verify_flags
 *
 * This function will verify the provided data against the digest 
 * present in the DigestedData of the PKCS #7 structure. If the data
 * provided are NULL then the data in the encapsulatedContent field
 * will be used instead.
 *
 * Returns: On success, %GNUTLS_E_SUCCESS (0) is returned, otherwise a
 *   negative error value. A verification error results to a
 *   %GNUTLS_E_HASH_FAILED and the lack of encapsulated data
 *   to verify to a %GNUTLS_E_REQUESTED_DATA_NOT_AVAILABLE.
 *
 * Since: 3.7.0
 **/
int gnutls_pkcs7_verify_digest(gnutls_pkcs7_t pkcs7,
			       const gnutls_datum_t *data, unsigned flags)
{
	int len, ret;
	gnutls_datum_t tmpdata = { NULL, 0 };
	char oid[MAX_OID_SIZE];
	uint8_t hash_output[MAX_HASH_SIZE];
	gnutls_digest_algorithm_t dig;

	if (pkcs7 == NULL || pkcs7->type != GNUTLS_PKCS7_DIGESTED)
		return gnutls_assert_val(GNUTLS_E_INVALID_REQUEST);

	len = sizeof(oid) - 1;
	ret = asn1_read_value(pkcs7->content_data, "digestAlgorithm.algorithm", oid, &len);
	if (ret != ASN1_SUCCESS)
		return gnutls_assert_val(GNUTLS_E_UNKNOWN_ALGORITHM);

	dig = gnutls_oid_to_digest(oid);
	if (dig == GNUTLS_DIG_UNKNOWN)
		return gnutls_assert_val(GNUTLS_E_UNKNOWN_ALGORITHM);

	if (_gnutls_digest_is_insecure(dig) &&
	    !(flags & GNUTLS_VERIFY_ALLOW_BROKEN))
		return gnutls_assert_val(GNUTLS_E_HASH_FAILED);

	if (data == NULL || data->data == NULL)
		ret = gnutls_hash_fast(dig, pkcs7->der_encap_data.data, pkcs7->der_encap_data.size, hash_output);
	else
		ret = gnutls_hash_fast(dig, data->data, data->size, hash_output);
	if (ret < 0)
		return gnutls_assert_val(ret);

	ret = _gnutls_x509_read_value(pkcs7->content_data, "digest", &tmpdata);
	if (ret < 0)
		return gnutls_assert_val(ret);

	if (tmpdata.size != gnutls_hash_get_len(dig) ||
	    memcmp(tmpdata.data, hash_output, tmpdata.size)) {
		ret = gnutls_assert_val(GNUTLS_E_HASH_FAILED);
	}
	_gnutls_free_datum(&tmpdata);

	return ret;
}

/**
 * gnutls_pkcs7_digest:
 * @pkcs7: should contain a #gnutls_pkcs7_t type
 * @data: The data to be signed or %NULL if the data are already embedded
 * @dig: The digest algorithm to use for digesting
 * @flags: Should be zero or one of %GNUTLS_PKCS7 flags
 *
 * This function will add a digest in the provided PKCS #7 structure
 * for the provided data.
 *
 * The available flags are:
 *  %GNUTLS_PKCS7_EMBED_DATA. It is explained in the #gnutls_pkcs7_sign_flags
 *  definition.
 *
 * Returns: On success, %GNUTLS_E_SUCCESS (0) is returned, otherwise a
 *   negative error value.
 *
 * Since: 3.7.0
 **/
int gnutls_pkcs7_digest(gnutls_pkcs7_t pkcs7,
			const gnutls_datum_t *data,
			gnutls_digest_algorithm_t dig, unsigned flags)
{
	int ret, result;
	gnutls_datum_t sigdata = { NULL, 0 };
	gnutls_datum_t signature = { NULL, 0 };
	const mac_entry_st *me = hash_to_entry(dig);
	uint8_t hash_output[MAX_HASH_SIZE];
	uint8_t ver;

	if (pkcs7 == NULL || me == NULL)
		return gnutls_assert_val(GNUTLS_E_INVALID_REQUEST);

	if (pkcs7->type != GNUTLS_PKCS7_DIGESTED)
		asn1_delete_structure(&pkcs7->content_data);

	if (pkcs7->content_data == NULL) {
		result =
		    asn1_create_element(_gnutls_get_pkix(),
					"PKIX1.pkcs-7-DigestedData",
					&pkcs7->content_data);
		if (result != ASN1_SUCCESS) {
			gnutls_assert();
			ret = _gnutls_asn2err(result);
			goto cleanup;
		}

		if (!(flags & GNUTLS_PKCS7_EMBED_DATA)) {
			(void)asn1_write_value(pkcs7->content_data,
					 "encapContentInfo.eContent", NULL, 0);
		}
		pkcs7->type = GNUTLS_PKCS7_DIGESTED;
	}

	result = asn1_write_value(pkcs7->content_data, "version", &ver, 1);
	if (result != ASN1_SUCCESS) {
		ret = _gnutls_asn2err(result);
		goto cleanup;
	}

	result =
	    asn1_write_value(pkcs7->content_data,
			     "encapContentInfo.eContentType", DATA_OID,
			     0);
	if (result != ASN1_SUCCESS) {
		ret = _gnutls_asn2err(result);
		goto cleanup;
	}

	ver = 0; /* Change to 2 if eContentType is not id-data */

	if ((flags & GNUTLS_PKCS7_EMBED_DATA) && data->data) {	/* embed data */
		ret =
		    _gnutls_x509_write_string(pkcs7->content_data,
				     "encapContentInfo.eContent", data,
				     ASN1_ETYPE_OCTET_STRING);
		if (ret < 0) {
			goto cleanup;
		}
	}

	/* append digest info algorithm */
	    asn1_write_value(pkcs7->content_data,
			     "digestAlgorithm.algorithm",
			     _gnutls_x509_digest_to_oid(me), 1);
	if (result != ASN1_SUCCESS) {
		gnutls_assert();
		ret = _gnutls_asn2err(result);
		goto cleanup;
	}

	(void)asn1_write_value(pkcs7->content_data,
			 "digestAlgorithm.parameters", NULL, 0);

	if (data == NULL || data->data == NULL)
		ret = gnutls_hash_fast(dig, pkcs7->der_encap_data.data, pkcs7->der_encap_data.size, hash_output);
	else
		ret = gnutls_hash_fast(dig, data->data, data->size, hash_output);
	if (ret < 0)
		return gnutls_assert_val(ret);

	result = asn1_write_value(pkcs7->content_data, "digest", hash_output, me->output_size);
	if (result != ASN1_SUCCESS) {
		gnutls_assert();
		ret = _gnutls_asn2err(result);
		goto cleanup;
	}

	ret = 0;

 cleanup:
	gnutls_free(sigdata.data);
	gnutls_free(signature.data);
	return ret;
}
