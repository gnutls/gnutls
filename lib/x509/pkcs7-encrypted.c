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

#include "gnutls_int.h"
#include <libtasn1.h>

#include <common.h>
#include <random.h>
#include <pkcs7_int.h>
#include <gnutls/pkcs7.h>

#define RC2_40_VERSION 0xa0
/*#define RC2_64_VERSION 0x78
#define RC2_128_VERSION 0x3a*/

/* Decodes the PKCS #7 encrypted data, and returns an asn1_node,
 * which holds them
 */
int _gnutls_pkcs7_decode_encrypted_data(gnutls_pkcs7_t pkcs7)
{
	asn1_node c2;
	int len, result;
	gnutls_datum_t tmp = {NULL, 0};

	if ((result = asn1_create_element
	     (_gnutls_get_pkix(), "PKIX1.pkcs-7-EncryptedData",
	      &c2)) != ASN1_SUCCESS) {
		gnutls_assert();
		return _gnutls_asn2err(result);
	}

	/* the Encrypted-data has been created, so
	 * decode them.
	 */
	result = _gnutls_x509_read_value(pkcs7->pkcs7, "content", &tmp);
	if (result < 0) {
		gnutls_assert();
		goto error;
	}

	result = asn1_der_decoding(&c2, tmp.data, tmp.size, NULL);
	if (result != ASN1_SUCCESS) {
		gnutls_assert();
		result = _gnutls_asn2err(result);
		goto error;
	}

	/* read the encapsulated content */
	len = MAX_OID_SIZE - 1;
	result =
	    asn1_read_value(c2, "encryptedContentInfo.contentType", pkcs7->encap_data_oid, &len);
	if (result != ASN1_SUCCESS) {
		gnutls_assert();
		result = _gnutls_asn2err(result);
		goto error;
	}

	if (strcmp(pkcs7->encap_data_oid, DATA_OID) != 0) {
		_gnutls_debug_log
		    ("Unknown PKCS#7 Encapsulated Content OID '%s'; treating as raw data\n",
		     pkcs7->encap_data_oid);

	}

	pkcs7->content_data = c2;
	gnutls_free(tmp.data);

	return 0;

 error:
	gnutls_free(tmp.data);
	if (c2)
		asn1_delete_structure(&c2);
	return result;
}

/**
 * gnutls_pkcs7_encryption_info_deinit:
 * @info: should point to a #gnutls_pkcs7_encryption_info_t structure
 *
 * This function will deinitialize any allocated value in the
 * provided #gnutls_pkcs7_encryption_info_t.
 *
 * Since: 3.6.14
 **/
void gnutls_pkcs7_encryption_info_deinit(gnutls_pkcs7_encryption_info_t *info)
{
	gnutls_pkcs7_attrs_deinit(info->unprotected_attrs);
	_gnutls_free_datum(&info->enc_params);
	gnutls_free(info->enc_oid);
	memset(info, 0, sizeof(*info));
}

/**
 * gnutls_pkcs7_get_encryption_info:
 * @pkcs7: should contain a #gnutls_pkcs7_t type
 * @info: will contain the output encryption
 *
 * This function will return information about the encryption
 * in the provided PKCS #7 structure. The information should be
 * deinitialized using gnutls_pkcs7_encryption_info_deinit().
 *
 * Returns: On success, %GNUTLS_E_SUCCESS (0) is returned, otherwise a
 *   negative error value.
 *
 * Since: 3.6.14
 **/
int gnutls_pkcs7_get_encryption_info(gnutls_pkcs7_t pkcs7, gnutls_pkcs7_encryption_info_t *info)
{
	int ret, len, i;
	char oid[MAX_OID_SIZE];
	char root[256];
	gnutls_datum_t tmp = { NULL, 0 };

	if (pkcs7 == NULL || pkcs7->type != GNUTLS_PKCS7_ENCRYPTED)
		return GNUTLS_E_INVALID_REQUEST;

	memset(info, 0, sizeof(*info));

	len = sizeof(oid) - 1;
	ret = asn1_read_value(pkcs7->content_data, "encryptedContentInfo.contentEncryptionAlgorithm.algorithm", oid, &len);
	if (ret != ASN1_SUCCESS) {
		gnutls_assert();
		ret = _gnutls_asn2err(ret);
		goto fail;
	}
	info->enc_oid = gnutls_strdup(oid);

	ret = _gnutls_x509_read_value(pkcs7->content_data, "encryptedContentInfo.contentEncryptionAlgorithm.parameters", &info->enc_params);
	if (ret < 0) {
		gnutls_assert();
		goto fail;
	}

	/* read the unprotected attrs */
	for (i = 0;; i++) {
		snprintf(root, sizeof(root),
			 "unprotectedAttrs.?%u.type",
			 i + 1);
		len = sizeof(oid) - 1;
		ret = asn1_read_value(pkcs7->content_data, root, oid, &len);
		if (ret != ASN1_SUCCESS) {
			break;
		}

		snprintf(root, sizeof(root),
			 "unprotectedAttrs.?%u.values.?1",
			 i + 1);
		ret = _gnutls_x509_read_value(pkcs7->content_data, root, &tmp);
		if (ret == GNUTLS_E_ASN1_ELEMENT_NOT_FOUND) {
			tmp.data = NULL;
			tmp.size = 0;
		} else if (ret < 0) {
			gnutls_assert();
			goto fail;
		}

		ret =
		    gnutls_pkcs7_add_attr(&info->unprotected_attrs, oid, &tmp, 0);
		gnutls_free(tmp.data);

		if (ret < 0) {
			gnutls_assert();
			goto fail;
		}
	}

	return 0;

 fail:
	gnutls_free(tmp.data);
	gnutls_pkcs7_encryption_info_deinit(info);
	return ret;
}

typedef struct pkcs7_cipher_st {
	const char *name;
	unsigned int cipher;
	const char *cipher_oid;
	const char *desc;
	const char *iv_name;
} pkcs7_cipher_t;

static const pkcs7_cipher_t pkcs7_ciphers[] = {
	{
	 .name = "DES-EDE3-CBC",
	 .cipher = GNUTLS_CIPHER_3DES_CBC,
	 .cipher_oid = DES_EDE3_CBC_OID,
	 .desc = "PKIX1.pkcs-5-des-EDE3-CBC-params",
	},
	{
	 .name = "AES-128-CBC",
	 .cipher = GNUTLS_CIPHER_AES_128_CBC,
	 .cipher_oid = AES_128_CBC_OID,
	 .desc = "PKIX1.pkcs-5-aes128-CBC-params",
	},
	{
	 .name = "AES-192-CBC",
	 .cipher = GNUTLS_CIPHER_AES_192_CBC,
	 .cipher_oid = AES_192_CBC_OID,
	 .desc = "PKIX1.pkcs-5-aes192-CBC-params",
	},
	{
	 .name = "AES-256-CBC",
	 .cipher = GNUTLS_CIPHER_AES_256_CBC,
	 .cipher_oid = AES_256_CBC_OID,
	 .desc = "PKIX1.pkcs-5-aes256-CBC-params",
	},
	{
	 .name = "RC2-CBC",
	 .cipher = GNUTLS_CIPHER_RC2_40_CBC,
	 .cipher_oid = RC2_CBC_OID,
	 .desc = "PKIX1.pkcs-5-RC2-CBC-params",
	 .iv_name = "iv",
	},
	{ NULL, 0, NULL, NULL, NULL },
};

/**
 * gnutls_pkcs7_encrypt:
 * @pkcs7: Should contain a #gnutls_pkcs7_t type
 * @cipher: Cipher to be used for data encryption
 * @key: The key to be used for encryption
 * @data: The data to be encrypted
 * @unprotected_attrs: Any additional attributes to be included in the unprotected ones (or %NULL)
 * @flags: Should be zero or one of %GNUTLS_PKCS7 flags
 *
 * This function will encrypt the provided data in the provided PKCS #7 structure.
 *
 * Returns: On success, %GNUTLS_E_SUCCESS (0) is returned, otherwise a
 *   negative error value.
 *
 * Since: 3.6.14
 **/
int gnutls_pkcs7_encrypt(gnutls_pkcs7_t pkcs7,
			 gnutls_cipher_algorithm_t cipher,
			 const gnutls_datum_t *key,
			 const gnutls_datum_t *data,
			 gnutls_pkcs7_attrs_t unprotected_attrs,
			 unsigned int flags)
{
	asn1_node params_asn = NULL;
	gnutls_datum_t iv = {NULL, 0};
	gnutls_datum_t tmp = {NULL, 0};
	unsigned char ivb[64];
	const cipher_entry_st *ce = cipher_to_entry(cipher);
	unsigned char vers;
	int result;
	const pkcs7_cipher_t *pciph;

	if (pkcs7 == NULL || ce == NULL)
		return GNUTLS_E_INVALID_REQUEST;

	if (sizeof(ivb) < ce->cipher_iv)
		return gnutls_assert_val(GNUTLS_E_INTERNAL_ERROR);

	iv.data = ivb;
	iv.size = ce->cipher_iv;

	if (pkcs7->type != GNUTLS_PKCS7_ENCRYPTED)
		asn1_delete_structure(&pkcs7->content_data);

	if (pkcs7->content_data == NULL) {
		result =
		    asn1_create_element(_gnutls_get_pkix(),
					"PKIX1.pkcs-7-EncryptedData",
					&pkcs7->content_data);
		if (result != ASN1_SUCCESS) {
			gnutls_assert();
			result = _gnutls_asn2err(result);
			goto error;
		}

		pkcs7->type = GNUTLS_PKCS7_ENCRYPTED;
	}

	for (pciph = pkcs7_ciphers; pciph->cipher_oid != NULL; pciph++)
		if (pciph->cipher == cipher)
			break;
	if (pciph->cipher_oid == NULL) {
		gnutls_assert();
		result = GNUTLS_E_ENCRYPTION_FAILED;
		goto error;
	}

	result =
	    asn1_write_value(pkcs7->content_data,
			     "encryptedContentInfo.contentEncryptionAlgorithm.algorithm",
			     pciph->cipher_oid, 1);

	if (result != ASN1_SUCCESS) {
		gnutls_assert();
		result = _gnutls_asn2err(result);
		goto error;
	}

	result = asn1_create_element(_gnutls_get_pkix(), pciph->desc, &params_asn);
	if (result != ASN1_SUCCESS) {
		gnutls_assert();
		result = _gnutls_asn2err(result);
		goto error;
	}

	result = gnutls_rnd(GNUTLS_RND_RANDOM, iv.data, iv.size);
	if (result < 0) {
		gnutls_assert();
		goto error;
	}

	result = _gnutls_x509_write_value(params_asn, pciph->iv_name ? pciph->iv_name : "", &iv);
	if (result < 0) {
		gnutls_assert();
		goto error;
	}

	if (!strcmp(pciph->cipher_oid, RC2_CBC_OID)) {
		/* RC2 encodes key bits in params */
		unsigned char rc2vers[2];

		rc2vers[0] = 0;
		rc2vers[1] = RC2_40_VERSION;

		result = asn1_write_value(params_asn, "rc2ParameterVersion", rc2vers, 2);
		if (result != ASN1_SUCCESS) {
			gnutls_assert();
			result = _gnutls_asn2err(result);
			goto error;
		}
	}

	result = _gnutls_x509_der_encode_and_copy(params_asn, "",
			pkcs7->content_data,
			"encryptedContentInfo.contentEncryptionAlgorithm.parameters", 0);
	if (result < 0) {
		gnutls_assert();
		goto error;
	}

	asn1_delete_structure(&params_asn);

	result = _gnutls_pkcs7_encrypt_int(ce, key, &iv, data, &tmp);
	if (result < 0) {
		gnutls_assert();
		goto error;
	}

	result = _gnutls_x509_write_value(pkcs7->content_data,
			     "encryptedContentInfo.encryptedContent", &tmp);
	_gnutls_free_datum(&tmp);
	if (result < 0) {
		gnutls_assert();
		goto error;
	}

	result =
	    asn1_write_value(pkcs7->content_data, "encryptedContentInfo.contentType",
			     DATA_OID, 1);
	if (result != ASN1_SUCCESS) {
		gnutls_assert();
		result = _gnutls_asn2err(result);
		goto error;
	}

	result = _gnutls_pkcs7_write_attrs(pkcs7->content_data, "unprotectedAttrs",
			unprotected_attrs);
	if (result < 0) {
		gnutls_assert();
		goto error;
	}

	if (unprotected_attrs)
		vers = 2;
	else
		vers = 0;

	result = asn1_write_value(pkcs7->content_data, "version", &vers, 1);
	if (result != ASN1_SUCCESS) {
		gnutls_assert();
		result = _gnutls_asn2err(result);
		goto error;
	}

error:
	return result;
}

/**
 * gnutls_pkcs7_decrypt:
 * @pkcs7: Should contain a #gnutls_pkcs7_t type
 * @key: The key to be used for decryption
 * @out: Decrypted data
 *
 * This function will decrypt the data from the provided PKCS #7 structure.
 *
 * Returns: On success, %GNUTLS_E_SUCCESS (0) is returned, otherwise a
 *   negative error value.
 *
 * Since: 3.6.14
 **/
int gnutls_pkcs7_decrypt(gnutls_pkcs7_t pkcs7, const gnutls_datum_t *key, gnutls_datum_t *out)
{
	gnutls_pkcs7_encryption_info_t info;
	asn1_node params_asn = NULL;
	gnutls_datum_t iv = {NULL, 0};
	gnutls_datum_t tmp = {NULL, 0};
	const cipher_entry_st *ce;
	int ret;
	const pkcs7_cipher_t *pciph;

	if (pkcs7 == NULL || pkcs7->type != GNUTLS_PKCS7_ENCRYPTED)
		return GNUTLS_E_INVALID_REQUEST;

	ret = gnutls_pkcs7_get_encryption_info(pkcs7, &info);
	if (ret < 0)
		return gnutls_assert_val(ret);

	if (info.enc_oid == NULL) {
		gnutls_assert();
		ret = GNUTLS_E_DECRYPTION_FAILED;
		goto error;
	}

	for (pciph = pkcs7_ciphers; pciph->cipher_oid != NULL; pciph++)
		if (!strcmp(pciph->cipher_oid, info.enc_oid))
			break;

	if (pciph->cipher_oid == NULL) {
		gnutls_assert();
		ret = GNUTLS_E_DECRYPTION_FAILED;
		goto error;
	}

	ret = asn1_create_element(_gnutls_get_pkix(), pciph->desc, &params_asn);
	if (ret != ASN1_SUCCESS) {
		gnutls_assert();
		ret = _gnutls_asn2err(ret);
		goto error;
	}

	ret = _asn1_strict_der_decode(&params_asn, info.enc_params.data, info.enc_params.size, NULL);
	if (ret != ASN1_SUCCESS) {
		gnutls_assert();
		ret = _gnutls_asn2err(ret);
		goto error;
	}

	if (!strcmp(info.enc_oid, RC2_CBC_OID)) {
		/* RC2 encodes key bits in params */
		unsigned int vers;

		ret = _gnutls_x509_read_uint(params_asn, "rc2ParameterVersion", &vers);
		if (ret < 0) {
			gnutls_assert();
			goto error;
		}

		/* Only RC2-40-CBC is supported for now */
		if (vers != RC2_40_VERSION) {
			gnutls_assert();
			ret = GNUTLS_E_DECRYPTION_FAILED;
			goto error;
		}

		ce = cipher_to_entry(GNUTLS_CIPHER_RC2_40_CBC);
	} else if (pciph->cipher != GNUTLS_CIPHER_UNKNOWN) {
		ce = cipher_to_entry(pciph->cipher);
	} else {
		gnutls_assert();
		ret = GNUTLS_E_DECRYPTION_FAILED;
		goto error;
	}

	ret = _gnutls_x509_read_value(params_asn, pciph->iv_name ? pciph->iv_name : "", &iv);
	if (ret < 0) {
		gnutls_assert();
		goto error;
	}

	ret = _gnutls_x509_read_value(pkcs7->content_data, "encryptedContentInfo.encryptedContent", &tmp);
	if (ret < 0) {
		gnutls_assert();
		goto error;
	}

	ret = _gnutls_pkcs7_decrypt_int(ce, key, &iv, &tmp);
	if (ret < 0) {
		gnutls_assert();
		goto error;
	}

	*out = tmp;
	tmp.data = NULL;
	ret = 0;

error:
	_gnutls_free_datum(&tmp);
	_gnutls_free_datum(&iv);
	asn1_delete_structure(&params_asn);
	gnutls_pkcs7_encryption_info_deinit(&info);

	return ret;
}
