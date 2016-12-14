/*
 * Copyright (C) 2003-2014 Free Software Foundation, Inc.
 * Copyright (C) 2014 Red Hat
 * Copyright (C) 2014 Nikos Mavrogiannopoulos
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
 * along with this program.  If not, see <http://www.gnu.org/licenses/>
 *
 */

#include <gnutls_int.h>

#include <gnutls_datum.h>
#include <gnutls_global.h>
#include <gnutls_errors.h>
#include <common.h>
#include <gnutls_x509.h>
#include <x509_b64.h>
#include "x509_int.h"
#include <algorithms.h>
#include <gnutls_num.h>
#include <random.h>
#include <nettle/pbkdf2.h>

static int _decode_pkcs8_ecc_key(ASN1_TYPE pkcs8_asn,
				 gnutls_x509_privkey_t pkey);
static
int pkcs8_key_info(const gnutls_datum_t * raw_key,
		   const struct pbes2_schema_st **p,
		   struct pbkdf2_params *kdf_params,
		   char **oid);


#define PBES2_OID "1.2.840.113549.1.5.13"
#define PBKDF2_OID "1.2.840.113549.1.5.12"
#define DES_EDE3_CBC_OID "1.2.840.113549.3.7"
#define AES_128_CBC_OID "2.16.840.1.101.3.4.1.2"
#define AES_192_CBC_OID "2.16.840.1.101.3.4.1.22"
#define AES_256_CBC_OID "2.16.840.1.101.3.4.1.42"
#define DES_CBC_OID "1.3.14.3.2.7"

/* oid_pbeWithSHAAnd3_KeyTripleDES_CBC */
#define PKCS12_PBE_3DES_SHA1_OID "1.2.840.113549.1.12.1.3"
#define PKCS12_PBE_ARCFOUR_SHA1_OID "1.2.840.113549.1.12.1.1"
#define PKCS12_PBE_RC2_40_SHA1_OID "1.2.840.113549.1.12.1.6"

struct pbe_enc_params {
	gnutls_cipher_algorithm_t cipher;
	uint8_t iv[MAX_CIPHER_BLOCK_SIZE];
	int iv_size;
};

static int generate_key(schema_id schema, const char *password,
			struct pbkdf2_params *kdf_params,
			struct pbe_enc_params *enc_params,
			gnutls_datum_t * key);
static int read_pbkdf2_params(ASN1_TYPE pbes2_asn,
			      const gnutls_datum_t * der,
			      struct pbkdf2_params *params);
static int read_pbe_enc_params(ASN1_TYPE pbes2_asn,
			       const gnutls_datum_t * der,
			       struct pbe_enc_params *params);
static int decrypt_data(schema_id, ASN1_TYPE pkcs8_asn, const char *root,
			const char *password,
			const struct pbkdf2_params *kdf_params,
			const struct pbe_enc_params *enc_params,
			gnutls_datum_t * decrypted_data);
static int decode_private_key_info(const gnutls_datum_t * der,
				   gnutls_x509_privkey_t pkey);
static int write_schema_params(schema_id schema, ASN1_TYPE pkcs8_asn,
			       const char *where,
			       const struct pbkdf2_params *kdf_params,
			       const struct pbe_enc_params *enc_params);
static int encrypt_data(const gnutls_datum_t * plain,
			const struct pbe_enc_params *enc_params,
			gnutls_datum_t * key, gnutls_datum_t * encrypted);

static int read_pkcs12_kdf_params(ASN1_TYPE pbes2_asn,
				  struct pbkdf2_params *params);
static int write_pkcs12_kdf_params(ASN1_TYPE pbes2_asn,
				   const struct pbkdf2_params *params);

#define PEM_PKCS8 "ENCRYPTED PRIVATE KEY"
#define PEM_UNENCRYPTED_PKCS8 "PRIVATE KEY"

/* Returns a negative error code if the encryption schema in
 * the OID is not supported. The schema ID is returned.
 */
/* Encodes a private key to the raw format PKCS #8 needs.
 * For RSA it is a PKCS #1 DER private key and for DSA it is
 * an ASN.1 INTEGER of the x value.
 */
inline static int
_encode_privkey(gnutls_x509_privkey_t pkey, gnutls_datum_t * raw)
{
	int ret;
	ASN1_TYPE spk = ASN1_TYPE_EMPTY;

	switch (pkey->pk_algorithm) {
	case GNUTLS_PK_RSA:
	case GNUTLS_PK_EC:
		ret =
		    gnutls_x509_privkey_export2(pkey, GNUTLS_X509_FMT_DER,
					        raw);
		if (ret < 0) {
			gnutls_assert();
			goto error;
		}

		break;
	case GNUTLS_PK_DSA:
		/* DSAPublicKey == INTEGER */
		if ((ret = asn1_create_element
		     (_gnutls_get_gnutls_asn(), "GNUTLS.DSAPublicKey",
		      &spk))
		    != ASN1_SUCCESS) {
			gnutls_assert();
			return _gnutls_asn2err(ret);
		}

		ret =
		    _gnutls_x509_write_int(spk, "", pkey->params.params[4],
					   1);
		if (ret < 0) {
			gnutls_assert();
			goto error;
		}
		ret = _gnutls_x509_der_encode(spk, "", raw, 0);
		if (ret < 0) {
			gnutls_assert();
			goto error;
		}

		asn1_delete_structure2(&spk, ASN1_DELETE_FLAG_ZEROIZE);
		break;

	default:
		gnutls_assert();
		return GNUTLS_E_INVALID_REQUEST;
	}

	return 0;

      error:
	asn1_delete_structure2(&spk, ASN1_DELETE_FLAG_ZEROIZE);
	asn1_delete_structure(&spk);
	return ret;

}

/* 
 * Encodes a PKCS #1 private key to a PKCS #8 private key
 * info. The output will be allocated and stored into der. Also
 * the ASN1_TYPE of private key info will be returned.
 */
static int
encode_to_private_key_info(gnutls_x509_privkey_t pkey,
			   gnutls_datum_t * der, ASN1_TYPE * pkey_info)
{
	int result, len;
	uint8_t null = 0;
	const char *oid;
	gnutls_datum_t algo_params = { NULL, 0 };
	gnutls_datum_t algo_privkey = { NULL, 0 };

	oid = gnutls_pk_get_oid(pkey->pk_algorithm);
	if (oid == NULL) {
		gnutls_assert();
		return GNUTLS_E_UNIMPLEMENTED_FEATURE;
	}

	result =
	    _gnutls_x509_write_pubkey_params(pkey->pk_algorithm,
					     &pkey->params, &algo_params);
	if (result < 0) {
		gnutls_assert();
		return result;
	}

	if ((result =
	     asn1_create_element(_gnutls_get_pkix(),
				 "PKIX1.pkcs-8-PrivateKeyInfo",
				 pkey_info)) != ASN1_SUCCESS) {
		gnutls_assert();
		result = _gnutls_asn2err(result);
		goto error;
	}

	/* Write the version.
	 */
	result = asn1_write_value(*pkey_info, "version", &null, 1);
	if (result != ASN1_SUCCESS) {
		gnutls_assert();
		result = _gnutls_asn2err(result);
		goto error;
	}

	/* write the privateKeyAlgorithm
	 * fields. (OID+NULL data)
	 */
	result =
	    asn1_write_value(*pkey_info, "privateKeyAlgorithm.algorithm",
			     oid, 1);
	if (result != ASN1_SUCCESS) {
		gnutls_assert();
		result = _gnutls_asn2err(result);
		goto error;
	}

	result =
	    asn1_write_value(*pkey_info, "privateKeyAlgorithm.parameters",
			     algo_params.data, algo_params.size);
	_gnutls_free_key_datum(&algo_params);

	if (result != ASN1_SUCCESS) {
		gnutls_assert();
		result = _gnutls_asn2err(result);
		goto error;
	}


	/* Write the raw private key
	 */
	result = _encode_privkey(pkey, &algo_privkey);
	if (result < 0) {
		gnutls_assert();
		goto error;
	}

	result =
	    asn1_write_value(*pkey_info, "privateKey", algo_privkey.data,
			     algo_privkey.size);
	_gnutls_free_key_datum(&algo_privkey);

	if (result != ASN1_SUCCESS) {
		gnutls_assert();
		result = _gnutls_asn2err(result);
		goto error;
	}

	/* Append an empty Attributes field.
	 */
	result = asn1_write_value(*pkey_info, "attributes", NULL, 0);
	if (result != ASN1_SUCCESS) {
		gnutls_assert();
		result = _gnutls_asn2err(result);
		goto error;
	}

	/* DER Encode the generated private key info.
	 */
	len = 0;
	result = asn1_der_coding(*pkey_info, "", NULL, &len, NULL);
	if (result != ASN1_MEM_ERROR) {
		gnutls_assert();
		result = _gnutls_asn2err(result);
		goto error;
	}

	/* allocate data for the der
	 */
	der->size = len;
	der->data = gnutls_malloc(len);
	if (der->data == NULL) {
		gnutls_assert();
		return GNUTLS_E_MEMORY_ERROR;
	}

	result = asn1_der_coding(*pkey_info, "", der->data, &len, NULL);
	if (result != ASN1_SUCCESS) {
		gnutls_assert();
		result = _gnutls_asn2err(result);
		goto error;
	}

	return 0;

      error:
	asn1_delete_structure2(pkey_info, ASN1_DELETE_FLAG_ZEROIZE);
	_gnutls_free_datum(&algo_params);
	_gnutls_free_key_datum(&algo_privkey);
	return result;

}

static const struct pbes2_schema_st avail_pbes2_schemas[] =
{
	{PBES2_3DES, "PBES2-3DES-CBC", GNUTLS_PKCS_PBES2_3DES, GNUTLS_CIPHER_3DES_CBC,
		1, DES_EDE3_CBC_OID, "PKIX1.pkcs-5-des-EDE3-CBC-params"},
	{PBES2_DES, "PBES2-DES-CBC", GNUTLS_PKCS_PBES2_DES, GNUTLS_CIPHER_DES_CBC,
		1, DES_CBC_OID, "PKIX1.pkcs-5-des-CBC-params"},
	{PBES2_AES_128, "PBES2-AES128-CBC", GNUTLS_PKCS_PBES2_AES_128, GNUTLS_CIPHER_AES_128_CBC,
		1, AES_128_CBC_OID, "PKIX1.pkcs-5-aes128-CBC-params"},
	{PBES2_AES_192, "PBES2-AES192-CBC", GNUTLS_PKCS_PBES2_AES_192, GNUTLS_CIPHER_AES_192_CBC,
		1, AES_192_CBC_OID, "PKIX1.pkcs-5-aes192-CBC-params"},
	{PBES2_AES_256, "PBES2-AES256-CBC", GNUTLS_PKCS_PBES2_AES_256, GNUTLS_CIPHER_AES_256_CBC,
		1, AES_256_CBC_OID, "PKIX1.pkcs-5-aes256-CBC-params"},
	{PKCS12_ARCFOUR_SHA1, "PKCS12-ARCFOUR-SHA1", GNUTLS_PKCS_PKCS12_ARCFOUR, GNUTLS_CIPHER_ARCFOUR,
		0, PKCS12_PBE_ARCFOUR_SHA1_OID, NULL},
	{PKCS12_RC2_40_SHA1, "PKCS12-RC2-40-SHA1", GNUTLS_PKCS_PKCS12_RC2_40, GNUTLS_CIPHER_RC2_40_CBC,
		0, PKCS12_PBE_RC2_40_SHA1_OID, NULL},
	{PKCS12_3DES_SHA1, "PKCS12-3DES-SHA1", GNUTLS_PKCS_PKCS12_3DES, GNUTLS_CIPHER_3DES_CBC,
		0, PKCS12_PBE_3DES_SHA1_OID, NULL},
	{0, 0, 0}
};

#define PBES2_SCHEMA_LOOP(b) { \
	const struct pbes2_schema_st * _p; \
		for (_p=avail_pbes2_schemas;_p->schema != 0;_p++) { b; } \
	}

#define PBES2_SCHEMA_FIND_FROM_FLAGS(fl, what) \
	PBES2_SCHEMA_LOOP( if (_p->flag == fl) { what; } )

int _gnutls_pkcs_flags_to_schema(unsigned int flags)
{
	PBES2_SCHEMA_FIND_FROM_FLAGS(flags, return _p->schema;);

	gnutls_assert();
	_gnutls_debug_log
	    ("Selecting default encryption PKCS12_3DES_SHA1 (flags: %u).\n",
		     flags);
	return PKCS12_3DES_SHA1;
}

/**
 * gnutls_pkcs_schema_get_name:
 * @schema: Holds the PKCS #12 or PBES2 schema (%gnutls_pkcs_encrypt_flags_t)
 *
 * This function will return a human readable description of the
 * PKCS12 or PBES2 schema.
 *
 * Returns: a constrant string or %NULL on error.
 *
 * Since: 3.4.0
 */
const char *gnutls_pkcs_schema_get_name(unsigned int schema)
{
	PBES2_SCHEMA_FIND_FROM_FLAGS(schema, return _p->name;);
	return NULL;
}

/**
 * gnutls_pkcs_schema_get_oid:
 * @schema: Holds the PKCS #12 or PBES2 schema (%gnutls_pkcs_encrypt_flags_t)
 *
 * This function will return the object identifier of the
 * PKCS12 or PBES2 schema.
 *
 * Returns: a constrant string or %NULL on error.
 *
 * Since: 3.4.0
 */
const char *gnutls_pkcs_schema_get_oid(unsigned int schema)
{
	PBES2_SCHEMA_FIND_FROM_FLAGS(schema, return _p->oid;);
	return NULL;
}

static const struct pbes2_schema_st *cipher_to_pbes2_schema(unsigned cipher)
{
	PBES2_SCHEMA_LOOP(
		if (_p->cipher == cipher && _p->pbes2 != 0) {
			return _p;
		});

	gnutls_assert();
	return NULL;
}

/* returns the OID corresponding to given schema
 */
static int pkcs12_schema_to_oid(schema_id schema, const char **str_oid)
{
	PBES2_SCHEMA_LOOP(
		if (_p->schema == schema) {
			if (_p->pbes2 != 0) {
				*str_oid = PBES2_OID;
				return 0;
			} else {
				*str_oid =  _p->oid;
				return 0;
			}
		}
	);

	gnutls_assert();
	return GNUTLS_E_INTERNAL_ERROR;
}

static int check_pkcs12_schema(const char *oid)
{
	if (strcmp(oid, PBES2_OID) == 0)
		return PBES2_GENERIC;	/* ok */

	PBES2_SCHEMA_LOOP(if (_p->pbes2 == 0 && strcmp(oid, _p->oid) == 0) {return _p->schema;});
	_gnutls_debug_log
	    ("PKCS #12 encryption schema OID '%s' is unsupported.\n", oid);

	return GNUTLS_E_UNKNOWN_CIPHER_TYPE;
}

static const struct pbes2_schema_st *pbes2_schema_get(schema_id schema)
{
	PBES2_SCHEMA_LOOP(if (schema == _p->schema) return _p;);

	gnutls_assert();
	return NULL;
}

/* Converts an OID to a gnutls cipher type.
 */
static int
pbes2_oid_to_cipher(const char *oid, gnutls_cipher_algorithm_t * algo)
{

	*algo = 0;
	PBES2_SCHEMA_LOOP(if (_p->pbes2 != 0 && strcmp(_p->oid, oid) == 0) {
			*algo  = _p->cipher;
			return 0;
		}
	);

	_gnutls_debug_log("PKCS #8 encryption OID '%s' is unsupported.\n",
			  oid);
	return GNUTLS_E_UNKNOWN_CIPHER_TYPE;
}


/* Converts a PKCS #8 private key info to
 * a PKCS #8 EncryptedPrivateKeyInfo.
 */
static int
encode_to_pkcs8_key(schema_id schema, const gnutls_datum_t * der_key,
		    const char *password, ASN1_TYPE * out)
{
	int result;
	gnutls_datum_t key = { NULL, 0 };
	gnutls_datum_t tmp = { NULL, 0 };
	ASN1_TYPE pkcs8_asn = ASN1_TYPE_EMPTY;
	struct pbkdf2_params kdf_params;
	struct pbe_enc_params enc_params;
	const char *str_oid;


	if ((result =
	     asn1_create_element(_gnutls_get_pkix(),
				 "PKIX1.pkcs-8-EncryptedPrivateKeyInfo",
				 &pkcs8_asn)) != ASN1_SUCCESS) {
		gnutls_assert();
		result = _gnutls_asn2err(result);
		goto error;
	}

	/* Write the encryption schema OID
	 */
	result = pkcs12_schema_to_oid(schema, &str_oid);
	if (result < 0) {
		gnutls_assert();
		return result;
	}

	result =
	    asn1_write_value(pkcs8_asn, "encryptionAlgorithm.algorithm",
			     str_oid, 1);

	if (result != ASN1_SUCCESS) {
		gnutls_assert();
		result = _gnutls_asn2err(result);
		goto error;
	}

	/* Generate a symmetric key.
	 */

	result =
	    generate_key(schema, password, &kdf_params, &enc_params, &key);
	if (result < 0) {
		gnutls_assert();
		goto error;
	}

	result =
	    write_schema_params(schema, pkcs8_asn,
				"encryptionAlgorithm.parameters",
				&kdf_params, &enc_params);
	if (result < 0) {
		gnutls_assert();
		goto error;
	}

	/* Parameters have been encoded. Now
	 * encrypt the Data.
	 */
	result = encrypt_data(der_key, &enc_params, &key, &tmp);
	if (result < 0) {
		gnutls_assert();
		goto error;
	}

	/* write the encrypted data.
	 */
	result =
	    asn1_write_value(pkcs8_asn, "encryptedData", tmp.data,
			     tmp.size);
	if (result != ASN1_SUCCESS) {
		gnutls_assert();
		result = _gnutls_asn2err(result);
		goto error;
	}

	_gnutls_free_datum(&tmp);
	_gnutls_free_key_datum(&key);

	*out = pkcs8_asn;

	return 0;

      error:
	_gnutls_free_key_datum(&key);
	_gnutls_free_datum(&tmp);
	asn1_delete_structure2(&pkcs8_asn, ASN1_DELETE_FLAG_ZEROIZE);
	return result;
}


/**
 * gnutls_x509_privkey_export_pkcs8:
 * @key: Holds the key
 * @format: the format of output params. One of PEM or DER.
 * @password: the password that will be used to encrypt the key.
 * @flags: an ORed sequence of gnutls_pkcs_encrypt_flags_t
 * @output_data: will contain a private key PEM or DER encoded
 * @output_data_size: holds the size of output_data (and will be
 *   replaced by the actual size of parameters)
 *
 * This function will export the private key to a PKCS8 structure.
 * Both RSA and DSA keys can be exported. For DSA keys we use
 * PKCS #11 definitions. If the flags do not specify the encryption
 * cipher, then the default 3DES (PBES2) will be used.
 *
 * The @password can be either ASCII or UTF-8 in the default PBES2
 * encryption schemas, or ASCII for the PKCS12 schemas.
 *
 * If the buffer provided is not long enough to hold the output, then
 * *output_data_size is updated and GNUTLS_E_SHORT_MEMORY_BUFFER will
 * be returned.
 *
 * If the structure is PEM encoded, it will have a header
 * of "BEGIN ENCRYPTED PRIVATE KEY" or "BEGIN PRIVATE KEY" if
 * encryption is not used.
 *
 * Returns: In case of failure a negative error code will be
 *   returned, and 0 on success.
 **/
int
gnutls_x509_privkey_export_pkcs8(gnutls_x509_privkey_t key,
				 gnutls_x509_crt_fmt_t format,
				 const char *password,
				 unsigned int flags,
				 void *output_data,
				 size_t * output_data_size)
{
	ASN1_TYPE pkcs8_asn, pkey_info;
	int ret;
	gnutls_datum_t tmp;
	schema_id schema;

	if (key == NULL) {
		gnutls_assert();
		return GNUTLS_E_INVALID_REQUEST;
	}

	/* Get the private key info
	 * tmp holds the DER encoding.
	 */
	ret = encode_to_private_key_info(key, &tmp, &pkey_info);
	if (ret < 0) {
		gnutls_assert();
		return ret;
	}

	schema = _gnutls_pkcs_flags_to_schema(flags);

	if (((flags & GNUTLS_PKCS_PLAIN) || password == NULL)
	    && !(flags & GNUTLS_PKCS_NULL_PASSWORD)) {
		_gnutls_free_datum(&tmp);

		ret =
		    _gnutls_x509_export_int(pkey_info, format,
					    PEM_UNENCRYPTED_PKCS8,
					    output_data, output_data_size);

		asn1_delete_structure2(&pkey_info, ASN1_DELETE_FLAG_ZEROIZE);
	} else {
		asn1_delete_structure2(&pkey_info, ASN1_DELETE_FLAG_ZEROIZE);	/* we don't need it */

		ret =
		    encode_to_pkcs8_key(schema, &tmp, password,
					&pkcs8_asn);
		_gnutls_free_key_datum(&tmp);

		if (ret < 0) {
			gnutls_assert();
			return ret;
		}

		ret =
		    _gnutls_x509_export_int(pkcs8_asn, format, PEM_PKCS8,
					    output_data, output_data_size);

		asn1_delete_structure2(&pkcs8_asn, ASN1_DELETE_FLAG_ZEROIZE);
	}

	return ret;
}

/**
 * gnutls_pkcs8_info:
 * @data: Holds the PKCS #8 data
 * @format: the format of the PKCS #8 data
 * @schema: indicate the schema as one of %gnutls_pkcs_encrypt_flags_t
 * @cipher: the cipher used as %gnutls_cipher_algorithm_t
 * @salt: PBKDF2 salt (if non-NULL then @salt_size initially holds its size)
 * @salt_size: PBKDF2 salt size
 * @iter_count: PBKDF2 iteration count
 * @oid: if non-NULL it will contain an allocated null-terminated variable with the OID
 *
 * This function will provide information on the algorithms used
 * in a particular PKCS #8 structure. If the structure algorithms
 * are unknown the code %GNUTLS_E_UNKNOWN_CIPHER_TYPE will be returned,
 * and only @oid, will be set. That is, @oid will be set on encrypted PKCS #8
 * structures whether supported or not. It must be deinitialized using gnutls_free().
 * The other variables are only set on supported structures.
 *
 * Returns: %GNUTLS_E_INVALID_REQUEST if the provided structure isn't encrypted,
 *  %GNUTLS_E_UNKNOWN_CIPHER_TYPE if the structure's encryption isn't supported, or
 *  another negative error code in case of a failure. Zero on success.
 **/
int
gnutls_pkcs8_info(const gnutls_datum_t * data, gnutls_x509_crt_fmt_t format,
		  unsigned int *schema, unsigned int *cipher,
		  void *salt, unsigned int *salt_size,
		  unsigned int *iter_count,
		  char **oid)
{
	int ret = 0, need_free = 0;
	gnutls_datum_t _data;
	const struct pbes2_schema_st *p = NULL;
	struct pbkdf2_params kdf;

	if (oid)
		*oid = NULL;

	_data.data = data->data;
	_data.size = data->size;

	/* If the Certificate is in PEM format then decode it
	 */
	if (format == GNUTLS_X509_FMT_PEM) {
		/* Try the first header 
		 */
		ret =
		    _gnutls_fbase64_decode(PEM_UNENCRYPTED_PKCS8,
					   data->data, data->size, &_data);

		if (ret < 0) {	/* Try the encrypted header 
					 */
			ret =
			    _gnutls_fbase64_decode(PEM_PKCS8, data->data,
						   data->size, &_data);

			if (ret < 0) {
				gnutls_assert();
				return ret;
			}
		}

		need_free = 1;
	}

	ret = pkcs8_key_info(&_data, &p, &kdf, oid);
	if (ret == GNUTLS_E_DECRYPTION_FAILED)
		ret = GNUTLS_E_INVALID_REQUEST;
	if (ret < 0) {
		gnutls_assert();
		goto cleanup;
	}

	if (need_free)
		_gnutls_free_datum(&_data);

	if (schema)
		*schema = p->flag;

	if (cipher)
		*cipher = p->cipher;

	if (iter_count)
		*iter_count = kdf.iter_count;

	if (salt) {
		if (*salt_size >= (unsigned)kdf.salt_size) {
			memcpy(salt, kdf.salt, kdf.salt_size);
		} else {
			*salt_size = kdf.salt_size;
			return gnutls_assert_val(GNUTLS_E_SHORT_MEMORY_BUFFER);
		}
	}

	if (salt_size)
		*salt_size = kdf.salt_size;


	return 0;

      cleanup:
	if (need_free)
		_gnutls_free_datum(&_data);
	return ret;
}

/**
 * gnutls_x509_privkey_export2_pkcs8:
 * @key: Holds the key
 * @format: the format of output params. One of PEM or DER.
 * @password: the password that will be used to encrypt the key.
 * @flags: an ORed sequence of gnutls_pkcs_encrypt_flags_t
 * @out: will contain a private key PEM or DER encoded
 *
 * This function will export the private key to a PKCS8 structure.
 * Both RSA and DSA keys can be exported. For DSA keys we use
 * PKCS #11 definitions. If the flags do not specify the encryption
 * cipher, then the default 3DES (PBES2) will be used.
 *
 * The @password can be either ASCII or UTF-8 in the default PBES2
 * encryption schemas, or ASCII for the PKCS12 schemas.
 *
 * The output buffer is allocated using gnutls_malloc().
 *
 * If the structure is PEM encoded, it will have a header
 * of "BEGIN ENCRYPTED PRIVATE KEY" or "BEGIN PRIVATE KEY" if
 * encryption is not used.
 *
 * Returns: In case of failure a negative error code will be
 *   returned, and 0 on success.
 *
 * Since 3.1.3
 **/
int
gnutls_x509_privkey_export2_pkcs8(gnutls_x509_privkey_t key,
				  gnutls_x509_crt_fmt_t format,
				  const char *password,
				  unsigned int flags, gnutls_datum_t * out)
{
	ASN1_TYPE pkcs8_asn, pkey_info;
	int ret;
	gnutls_datum_t tmp;
	schema_id schema;

	if (key == NULL) {
		gnutls_assert();
		return GNUTLS_E_INVALID_REQUEST;
	}

	/* Get the private key info
	 * tmp holds the DER encoding.
	 */
	ret = encode_to_private_key_info(key, &tmp, &pkey_info);
	if (ret < 0) {
		gnutls_assert();
		return ret;
	}

	schema = _gnutls_pkcs_flags_to_schema(flags);

	if (((flags & GNUTLS_PKCS_PLAIN) || password == NULL)
	    && !(flags & GNUTLS_PKCS_NULL_PASSWORD)) {
		_gnutls_free_key_datum(&tmp);

		ret =
		    _gnutls_x509_export_int2(pkey_info, format,
					     PEM_UNENCRYPTED_PKCS8, out);

		asn1_delete_structure2(&pkey_info, ASN1_DELETE_FLAG_ZEROIZE);
	} else {
		asn1_delete_structure2(&pkey_info, ASN1_DELETE_FLAG_ZEROIZE);	/* we don't need it */

		ret =
		    encode_to_pkcs8_key(schema, &tmp, password,
					&pkcs8_asn);
		_gnutls_free_key_datum(&tmp);

		if (ret < 0) {
			gnutls_assert();
			return ret;
		}

		ret =
		    _gnutls_x509_export_int2(pkcs8_asn, format, PEM_PKCS8,
					     out);

		asn1_delete_structure2(&pkcs8_asn, ASN1_DELETE_FLAG_ZEROIZE);
	}

	return ret;
}


/* Read the parameters cipher, IV, salt etc using the given
 * schema ID. Initially the schema ID should have PBES2_GENERIC, for
 * PBES2 schemas, and will be updated by this function for details.
 */
static int
read_pkcs_schema_params(schema_id * schema, const char *password,
			const uint8_t * data, int data_size,
			struct pbkdf2_params *kdf_params,
			struct pbe_enc_params *enc_params)
{
	ASN1_TYPE pbes2_asn = ASN1_TYPE_EMPTY;
	int result;
	gnutls_datum_t tmp;
	const struct pbes2_schema_st *p;

	if (*schema == PBES2_GENERIC) {
		/* Now check the key derivation and the encryption
		 * functions.
		 */
		if ((result =
		     asn1_create_element(_gnutls_get_pkix(),
					 "PKIX1.pkcs-5-PBES2-params",
					 &pbes2_asn)) != ASN1_SUCCESS) {
			gnutls_assert();
			result = _gnutls_asn2err(result);
			goto error;
		}

		/* Decode the parameters.
		 */
		result =
		    _asn1_strict_der_decode(&pbes2_asn, data, data_size, NULL);
		if (result != ASN1_SUCCESS) {
			gnutls_assert();
			result = _gnutls_asn2err(result);
			goto error;
		}

		tmp.data = (uint8_t *) data;
		tmp.size = data_size;

		result = read_pbkdf2_params(pbes2_asn, &tmp, kdf_params);
		if (result < 0) {
			gnutls_assert();
			goto error;
		}

		result = read_pbe_enc_params(pbes2_asn, &tmp, enc_params);
		if (result < 0) {
			gnutls_assert();
			goto error;
		}

		asn1_delete_structure2(&pbes2_asn, ASN1_DELETE_FLAG_ZEROIZE);

		p = cipher_to_pbes2_schema(enc_params->cipher);
		if (p == NULL) {
			result = GNUTLS_E_INVALID_REQUEST;
			gnutls_assert();
			goto error;
		}

		*schema = p->schema;
		return 0;
	} else { /* PKCS #12 schema */
		memset(enc_params, 0, sizeof(*enc_params));

		p = pbes2_schema_get(*schema);
		if (p == NULL) {
			gnutls_assert();
			result = GNUTLS_E_UNKNOWN_CIPHER_TYPE;
			goto error;
		}
		enc_params->cipher = p->cipher;
		enc_params->iv_size = gnutls_cipher_get_iv_size(p->cipher);

		if ((result =
		     asn1_create_element(_gnutls_get_pkix(),
					 "PKIX1.pkcs-12-PbeParams",
					 &pbes2_asn)) != ASN1_SUCCESS) {
			gnutls_assert();
			result = _gnutls_asn2err(result);
			goto error;
		}

		/* Decode the parameters.
		 */
		result =
		    _asn1_strict_der_decode(&pbes2_asn, data, data_size, NULL);
		if (result != ASN1_SUCCESS) {
			gnutls_assert();
			result = _gnutls_asn2err(result);
			goto error;
		}

		result = read_pkcs12_kdf_params(pbes2_asn, kdf_params);
		if (result < 0) {
			gnutls_assert();
			goto error;
		}

		if (enc_params->iv_size) {
			result =
			    _gnutls_pkcs12_string_to_key(mac_to_entry(GNUTLS_MAC_SHA1),
			    				 2 /*IV*/,
							 kdf_params->salt,
							 kdf_params->
							 salt_size,
							 kdf_params->
							 iter_count,
							 password,
							 enc_params->
							 iv_size,
							 enc_params->iv);
			if (result < 0) {
				gnutls_assert();
				goto error;
			}

		}

		asn1_delete_structure(&pbes2_asn);

		return 0;
	}			/* switch */

 error:
	asn1_delete_structure(&pbes2_asn);
	return result;
}

	/* We've gotten this far. In the real world it's almost certain
	 * that we're dealing with a good file, but wrong password.
	 * Sadly like 90% of random data is somehow valid DER for the
	 * a first small number of bytes, so no easy way to guarantee. */
#define CHECK_ERR_FOR_ENCRYPTED(result) \
		if (result == GNUTLS_E_ASN1_ELEMENT_NOT_FOUND || \
		    result == GNUTLS_E_ASN1_IDENTIFIER_NOT_FOUND || \
		    result == GNUTLS_E_ASN1_DER_ERROR || \
		    result == GNUTLS_E_ASN1_VALUE_NOT_FOUND || \
		    result == GNUTLS_E_ASN1_GENERIC_ERROR || \
		    result == GNUTLS_E_ASN1_VALUE_NOT_VALID || \
		    result == GNUTLS_E_ASN1_TAG_ERROR || \
		    result == GNUTLS_E_ASN1_TAG_IMPLICIT || \
		    result == GNUTLS_E_ASN1_TYPE_ANY_ERROR || \
		    result == GNUTLS_E_ASN1_SYNTAX_ERROR || \
		    result == GNUTLS_E_ASN1_DER_OVERFLOW) { \
			result = GNUTLS_E_DECRYPTION_FAILED; \
		}

static int pkcs8_key_decrypt(const gnutls_datum_t * raw_key,
			     ASN1_TYPE pkcs8_asn, const char *password,
			     gnutls_x509_privkey_t pkey)
{
	int result, len;
	char enc_oid[MAX_OID_SIZE];
	gnutls_datum_t tmp;
	ASN1_TYPE pbes2_asn = ASN1_TYPE_EMPTY;
	int params_start, params_end, params_len;
	struct pbkdf2_params kdf_params;
	struct pbe_enc_params enc_params;
	schema_id schema;

	/* Check the encryption schema OID
	 */
	len = sizeof(enc_oid);
	result =
	    asn1_read_value(pkcs8_asn, "encryptionAlgorithm.algorithm",
			    enc_oid, &len);
	if (result != ASN1_SUCCESS) {
		gnutls_assert();
		goto error;
	}

	if ((result = check_pkcs12_schema(enc_oid)) < 0) {
		gnutls_assert();
		goto error;
	}

	schema = result;

	/* Get the DER encoding of the parameters.
	 */
	result =
	    asn1_der_decoding_startEnd(pkcs8_asn, raw_key->data,
				       raw_key->size,
				       "encryptionAlgorithm.parameters",
				       &params_start, &params_end);
	if (result != ASN1_SUCCESS) {
		gnutls_assert();
		result = _gnutls_asn2err(result);
		goto error;
	}
	params_len = params_end - params_start + 1;

	result =
	    read_pkcs_schema_params(&schema, password,
				    &raw_key->data[params_start],
				    params_len, &kdf_params, &enc_params);

	if (result < 0) {
		gnutls_assert();
		goto error;
	}

	/* Parameters have been decoded. Now
	 * decrypt the EncryptedData.
	 */
	result =
	    decrypt_data(schema, pkcs8_asn, "encryptedData", password,
			 &kdf_params, &enc_params, &tmp);
	if (result < 0) {
		gnutls_assert();
		goto error;
	}

	result = decode_private_key_info(&tmp, pkey);
	_gnutls_free_key_datum(&tmp);

	CHECK_ERR_FOR_ENCRYPTED(result);
	if (result < 0) {
		gnutls_assert();
		goto error;
	}

	return 0;

      error:
	asn1_delete_structure(&pbes2_asn);
	return result;
}

static
int pkcs8_key_info(const gnutls_datum_t * raw_key,
		   const struct pbes2_schema_st **p,
		   struct pbkdf2_params *kdf_params,
		   char **oid)
{
	int result, len;
	char enc_oid[MAX_OID_SIZE];
	int params_start, params_end, params_len;
	struct pbe_enc_params enc_params;
	schema_id schema;
	ASN1_TYPE pkcs8_asn = ASN1_TYPE_EMPTY;

	if ((result =
	     asn1_create_element(_gnutls_get_pkix(),
				 "PKIX1.pkcs-8-EncryptedPrivateKeyInfo",
				 &pkcs8_asn)) != ASN1_SUCCESS) {
		gnutls_assert();
		result = _gnutls_asn2err(result);
		goto error;
	}

	result =
	    _asn1_strict_der_decode(&pkcs8_asn, raw_key->data, raw_key->size,
			      NULL);
	if (result != ASN1_SUCCESS) {
		gnutls_assert();
		result = _gnutls_asn2err(result);
		CHECK_ERR_FOR_ENCRYPTED(result);
		goto error;
	}

	/* Check the encryption schema OID
	 */
	len = sizeof(enc_oid);
	result =
	    asn1_read_value(pkcs8_asn, "encryptionAlgorithm.algorithm",
			    enc_oid, &len);
	if (result != ASN1_SUCCESS) {
		gnutls_assert();
		goto error;
	}

	if (oid) {
		*oid = gnutls_strdup(enc_oid);
	}

	if ((result = check_pkcs12_schema(enc_oid)) < 0) {
		gnutls_assert();
		goto error;
	}

	schema = result;

	/* Get the DER encoding of the parameters.
	 */
	result =
	    asn1_der_decoding_startEnd(pkcs8_asn, raw_key->data,
				       raw_key->size,
				       "encryptionAlgorithm.parameters",
				       &params_start, &params_end);
	if (result != ASN1_SUCCESS) {
		gnutls_assert();
		result = _gnutls_asn2err(result);
		goto error;
	}
	params_len = params_end - params_start + 1;

	result =
	    read_pkcs_schema_params(&schema, NULL,
				    &raw_key->data[params_start],
				    params_len, kdf_params, &enc_params);

	if (result < 0) {
		gnutls_assert();
		goto error;
	}

	*p = pbes2_schema_get(schema);
	if (*p == NULL) {
		gnutls_assert();
		result = GNUTLS_E_UNKNOWN_CIPHER_TYPE;
		goto error;
	}

	result = 0;

      error:
	asn1_delete_structure2(&pkcs8_asn, ASN1_DELETE_FLAG_ZEROIZE);
	return result;
}

/* Converts a PKCS #8 key to
 * an internal structure (gnutls_private_key)
 * (normally a PKCS #1 encoded RSA key)
 */
static int
pkcs8_key_decode(const gnutls_datum_t * raw_key,
		 const char *password, gnutls_x509_privkey_t pkey,
		 unsigned int decrypt)
{
	int result;
	ASN1_TYPE pkcs8_asn = ASN1_TYPE_EMPTY;

	if ((result =
	     asn1_create_element(_gnutls_get_pkix(),
				 "PKIX1.pkcs-8-EncryptedPrivateKeyInfo",
				 &pkcs8_asn)) != ASN1_SUCCESS) {
		gnutls_assert();
		result = _gnutls_asn2err(result);
		goto error;
	}

	result =
	    _asn1_strict_der_decode(&pkcs8_asn, raw_key->data, raw_key->size,
			      NULL);
	if (result != ASN1_SUCCESS) {
		gnutls_assert();
		result = _gnutls_asn2err(result);
		goto error;
	}

	if (decrypt)
		result =
		    pkcs8_key_decrypt(raw_key, pkcs8_asn, password, pkey);
	else
		result = 0;

      error:
	asn1_delete_structure2(&pkcs8_asn, ASN1_DELETE_FLAG_ZEROIZE);
	return result;

}

/* Decodes an RSA privateKey from a PKCS8 structure.
 */
static int
_decode_pkcs8_rsa_key(ASN1_TYPE pkcs8_asn, gnutls_x509_privkey_t pkey)
{
	int ret;
	gnutls_datum_t tmp;

	ret = _gnutls_x509_read_value(pkcs8_asn, "privateKey", &tmp);
	if (ret < 0) {
		gnutls_assert();
		goto error;
	}

	pkey->key = _gnutls_privkey_decode_pkcs1_rsa_key(&tmp, pkey);
	_gnutls_free_key_datum(&tmp);

	if (pkey->key == NULL) {
		gnutls_assert();
		goto error;
	}

	ret = 0;

      error:
	return ret;
}

/* Decodes an ECC privateKey from a PKCS8 structure.
 */
static int
_decode_pkcs8_ecc_key(ASN1_TYPE pkcs8_asn, gnutls_x509_privkey_t pkey)
{
	int ret;
	gnutls_datum_t tmp;
	unsigned char oid[MAX_OID_SIZE];
	unsigned curve = GNUTLS_ECC_CURVE_INVALID;
	int len, result;

	/* openssl PKCS #8 files with ECC keys place the curve in
	 * privateKeyAlgorithm.parameters instead of the ECPrivateKey.parameters.
	 */
	len = sizeof(oid);
	result =
	    asn1_read_value(pkcs8_asn, "privateKeyAlgorithm.parameters",
			    oid, &len);
	if (result == ASN1_SUCCESS) {
		ret = _gnutls_x509_read_ecc_params(oid, len, &curve);
		if (ret < 0) {
			curve = GNUTLS_ECC_CURVE_INVALID;
		}
	}

	ret = _gnutls_x509_read_value(pkcs8_asn, "privateKey", &tmp);
	if (ret < 0) {
		gnutls_assert();
		goto error;
	}

	ret = _gnutls_privkey_decode_ecc_key(&pkey->key, &tmp, pkey, curve);
	_gnutls_free_key_datum(&tmp);

	if (ret < 0) {
		gnutls_assert();
		goto error;
	}

	ret = 0;

      error:
	return ret;
}

/* Decodes an DSA privateKey and params from a PKCS8 structure.
 */
static int
_decode_pkcs8_dsa_key(ASN1_TYPE pkcs8_asn, gnutls_x509_privkey_t pkey)
{
	int ret;
	gnutls_datum_t tmp;

	ret = _gnutls_x509_read_value(pkcs8_asn, "privateKey", &tmp);
	if (ret < 0) {
		gnutls_assert();
		goto error;
	}

	ret =
	    _gnutls_x509_read_der_int(tmp.data, tmp.size,
				      &pkey->params.params[4]);
	_gnutls_free_key_datum(&tmp);

	if (ret < 0) {
		gnutls_assert();
		goto error;
	}

	ret =
	    _gnutls_x509_read_value(pkcs8_asn,
				    "privateKeyAlgorithm.parameters",
				    &tmp);
	if (ret < 0) {
		gnutls_assert();
		goto error;
	}

	ret =
	    _gnutls_x509_read_pubkey_params(GNUTLS_PK_DSA, tmp.data,
					    tmp.size, &pkey->params);
	_gnutls_free_datum(&tmp);
	if (ret < 0) {
		gnutls_assert();
		goto error;
	}

	/* the public key can be generated as g^x mod p */
	ret = _gnutls_mpi_init(&pkey->params.params[3]);
	if (ret < 0) {
		gnutls_assert();
		goto error;
	}

	ret = _gnutls_mpi_powm(pkey->params.params[3], pkey->params.params[2],
			 pkey->params.params[4], pkey->params.params[0]);
	if (ret < 0) {
		gnutls_assert();
		goto error;
	}

	ret =
	    _gnutls_asn1_encode_privkey(GNUTLS_PK_DSA, &pkey->key,
					&pkey->params);
	if (ret < 0) {
		gnutls_assert();
		goto error;
	}

	pkey->params.algo = GNUTLS_PK_DSA;
	pkey->params.params_nr = DSA_PRIVATE_PARAMS;

	ret = 0;

      error:
	return ret;
}


static int
decode_private_key_info(const gnutls_datum_t * der,
			gnutls_x509_privkey_t pkey)
{
	int result, len;
	char oid[MAX_OID_SIZE];
	ASN1_TYPE pkcs8_asn = ASN1_TYPE_EMPTY;

	if ((result =
	     asn1_create_element(_gnutls_get_pkix(),
				 "PKIX1.pkcs-8-PrivateKeyInfo",
				 &pkcs8_asn)) != ASN1_SUCCESS) {
		gnutls_assert();
		result = _gnutls_asn2err(result);
		goto error;
	}

	result = _asn1_strict_der_decode(&pkcs8_asn, der->data, der->size, NULL);
	if (result != ASN1_SUCCESS) {
		gnutls_assert();
		result = _gnutls_asn2err(result);
		goto error;
	}

	/* Check the private key algorithm OID
	 */
	len = sizeof(oid);
	result =
	    asn1_read_value(pkcs8_asn, "privateKeyAlgorithm.algorithm",
			    oid, &len);
	if (result != ASN1_SUCCESS) {
		gnutls_assert();
		result = _gnutls_asn2err(result);
		goto error;
	}

	/* we only support RSA and DSA private keys.
	 */

	pkey->pk_algorithm = gnutls_oid_to_pk(oid);
	if (pkey->pk_algorithm == GNUTLS_PK_UNKNOWN) {
		gnutls_assert();
		_gnutls_debug_log
		    ("PKCS #8 private key OID '%s' is unsupported.\n",
		     oid);
		result = GNUTLS_E_UNKNOWN_PK_ALGORITHM;
		goto error;
	}

	/* Get the DER encoding of the actual private key.
	 */

	if (pkey->pk_algorithm == GNUTLS_PK_RSA)
		result = _decode_pkcs8_rsa_key(pkcs8_asn, pkey);
	else if (pkey->pk_algorithm == GNUTLS_PK_DSA)
		result = _decode_pkcs8_dsa_key(pkcs8_asn, pkey);
	else if (pkey->pk_algorithm == GNUTLS_PK_EC)
		result = _decode_pkcs8_ecc_key(pkcs8_asn, pkey);
	else
		return gnutls_assert_val(GNUTLS_E_UNIMPLEMENTED_FEATURE);

	if (result < 0) {
		gnutls_assert();
		return result;
	}

	result = 0;

error:
	asn1_delete_structure2(&pkcs8_asn, ASN1_DELETE_FLAG_ZEROIZE);

	return result;

}

/**
 * gnutls_x509_privkey_import_pkcs8:
 * @key: The data to store the parsed key
 * @data: The DER or PEM encoded key.
 * @format: One of DER or PEM
 * @password: the password to decrypt the key (if it is encrypted).
 * @flags: 0 if encrypted or GNUTLS_PKCS_PLAIN if not encrypted.
 *
 * This function will convert the given DER or PEM encoded PKCS8 2.0
 * encrypted key to the native gnutls_x509_privkey_t format. The
 * output will be stored in @key.  Both RSA and DSA keys can be
 * imported, and flags can only be used to indicate an unencrypted
 * key.
 *
 * The @password can be either ASCII or UTF-8 in the default PBES2
 * encryption schemas, or ASCII for the PKCS12 schemas.
 *
 * If the Certificate is PEM encoded it should have a header of
 * "ENCRYPTED PRIVATE KEY", or "PRIVATE KEY". You only need to
 * specify the flags if the key is DER encoded, since in that case
 * the encryption status cannot be auto-detected.
 *
 * If the %GNUTLS_PKCS_PLAIN flag is specified and the supplied data
 * are encrypted then %GNUTLS_E_DECRYPTION_FAILED is returned.
 *
 * Returns: On success, %GNUTLS_E_SUCCESS (0) is returned, otherwise a
 *   negative error value.
 **/
int
gnutls_x509_privkey_import_pkcs8(gnutls_x509_privkey_t key,
				 const gnutls_datum_t * data,
				 gnutls_x509_crt_fmt_t format,
				 const char *password, unsigned int flags)
{
	int result = 0, need_free = 0;
	gnutls_datum_t _data;

	if (key == NULL) {
		gnutls_assert();
		return GNUTLS_E_INVALID_REQUEST;
	}

	_data.data = data->data;
	_data.size = data->size;

	key->pk_algorithm = GNUTLS_PK_UNKNOWN;

	/* If the Certificate is in PEM format then decode it
	 */
	if (format == GNUTLS_X509_FMT_PEM) {
		/* Try the first header 
		 */
		result =
		    _gnutls_fbase64_decode(PEM_UNENCRYPTED_PKCS8,
					   data->data, data->size, &_data);

		if (result < 0) {	/* Try the encrypted header 
					 */
			result =
			    _gnutls_fbase64_decode(PEM_PKCS8, data->data,
						   data->size, &_data);

			if (result < 0) {
				gnutls_assert();
				return result;
			}
		} else if (flags == 0)
			flags |= GNUTLS_PKCS_PLAIN;

		need_free = 1;
	}

	if (key->expanded) {
		_gnutls_x509_privkey_reinit(key);
	}
	key->expanded = 1;

	/* Here we don't check for password == NULL to maintain a backwards
	 * compatibility behavior, with old versions that were encrypting using
	 * a NULL password.
	 */
	if (flags & GNUTLS_PKCS_PLAIN) {
		result = decode_private_key_info(&_data, key);
		if (result < 0) {	/* check if it is encrypted */
			if (pkcs8_key_decode(&_data, "", key, 0) == 0)
				result = GNUTLS_E_DECRYPTION_FAILED;
		}
	} else {		/* encrypted. */
		result = pkcs8_key_decode(&_data, password, key, 1);
	}

	if (result < 0) {
		gnutls_assert();
		goto cleanup;
	}

	if (need_free)
		_gnutls_free_datum(&_data);

	/* The key has now been decoded.
	 */

	return 0;

      cleanup:
	key->pk_algorithm = GNUTLS_PK_UNKNOWN;
	if (need_free)
		_gnutls_free_datum(&_data);
	return result;
}

/* Reads the PBKDF2 parameters.
 */
static int
read_pbkdf2_params(ASN1_TYPE pbes2_asn,
		   const gnutls_datum_t * der,
		   struct pbkdf2_params *params)
{
	int params_start, params_end;
	int params_len, len, result;
	ASN1_TYPE pbkdf2_asn = ASN1_TYPE_EMPTY;
	char oid[MAX_OID_SIZE];

	memset(params, 0, sizeof(*params));

	params->mac = GNUTLS_MAC_SHA1;

	/* Check the key derivation algorithm
	 */
	len = sizeof(oid);
	result =
	    asn1_read_value(pbes2_asn, "keyDerivationFunc.algorithm", oid,
			    &len);
	if (result != ASN1_SUCCESS) {
		gnutls_assert();
		return _gnutls_asn2err(result);
	}
	_gnutls_hard_log("keyDerivationFunc.algorithm: %s\n", oid);

	if (strcmp(oid, PBKDF2_OID) != 0) {
		gnutls_assert();
		_gnutls_debug_log
		    ("PKCS #8 key derivation OID '%s' is unsupported.\n",
		     oid);
		return _gnutls_asn2err(result);
	}

	result =
	    asn1_der_decoding_startEnd(pbes2_asn, der->data, der->size,
				       "keyDerivationFunc.parameters",
				       &params_start, &params_end);
	if (result != ASN1_SUCCESS) {
		gnutls_assert();
		return _gnutls_asn2err(result);
	}
	params_len = params_end - params_start + 1;

	/* Now check the key derivation and the encryption
	 * functions.
	 */
	if ((result =
	     asn1_create_element(_gnutls_get_pkix(),
				 "PKIX1.pkcs-5-PBKDF2-params",
				 &pbkdf2_asn)) != ASN1_SUCCESS) {
		gnutls_assert();
		return _gnutls_asn2err(result);
	}

	result =
	    _asn1_strict_der_decode(&pbkdf2_asn, &der->data[params_start],
			      params_len, NULL);
	if (result != ASN1_SUCCESS) {
		gnutls_assert();
		result = _gnutls_asn2err(result);
		goto error;
	}

	/* read the salt */
	params->salt_size = sizeof(params->salt);
	result =
	    asn1_read_value(pbkdf2_asn, "salt.specified", params->salt,
			    &params->salt_size);
	if (result != ASN1_SUCCESS) {
		gnutls_assert();
		result = _gnutls_asn2err(result);
		goto error;
	}
	_gnutls_hard_log("salt.specified.size: %d\n", params->salt_size);

	if (params->salt_size < 0) {
		result = gnutls_assert_val(GNUTLS_E_ILLEGAL_PARAMETER);
		goto error;
	}

	/* read the iteration count 
	 */
	result =
	    _gnutls_x509_read_uint(pbkdf2_asn, "iterationCount",
				   &params->iter_count);
	if (result != ASN1_SUCCESS) {
		gnutls_assert();
		goto error;
	}

	if (params->iter_count >= INT_MAX || params->iter_count == 0) {
		result = gnutls_assert_val(GNUTLS_E_ILLEGAL_PARAMETER);
		goto error;
	}

	_gnutls_hard_log("iterationCount: %d\n", params->iter_count);

	/* read the keylength, if it is set.
	 */
	result =
	    _gnutls_x509_read_uint(pbkdf2_asn, "keyLength",
				   &params->key_size);
	if (result < 0) {
		params->key_size = 0;
	}

	if (params->key_size > MAX_CIPHER_KEY_SIZE) {
		result = gnutls_assert_val(GNUTLS_E_ILLEGAL_PARAMETER);
		goto error;
	}

	_gnutls_hard_log("keyLength: %d\n", params->key_size);

	len = sizeof(oid);
	result =
	    asn1_read_value(pbkdf2_asn, "prf.algorithm",
			    oid, &len);
	if (result != ASN1_SUCCESS) {
		/* use the default MAC */
		result = 0;
		goto error;
	}

	params->mac = gnutls_oid_to_mac(oid);
	if (params->mac == GNUTLS_MAC_UNKNOWN) {
		gnutls_assert();
		_gnutls_debug_log("Unsupported hash algorithm: %s\n", oid);
		result = GNUTLS_E_UNKNOWN_HASH_ALGORITHM;
		goto error;
	}

	result = 0;

      error:
	asn1_delete_structure(&pbkdf2_asn);
	return result;

}

/* Reads the PBE parameters from PKCS-12 schemas (*&#%*&#% RSA).
 */
static int
read_pkcs12_kdf_params(ASN1_TYPE pbes2_asn, struct pbkdf2_params *params)
{
	int result;

	memset(params, 0, sizeof(*params));

	/* read the salt */
	params->salt_size = sizeof(params->salt);
	result =
	    asn1_read_value(pbes2_asn, "salt", params->salt,
			    &params->salt_size);
	if (result != ASN1_SUCCESS) {
		gnutls_assert();
		return _gnutls_asn2err(result);
	}

	if (params->salt_size < 0)
		return gnutls_assert_val(GNUTLS_E_ILLEGAL_PARAMETER);

	_gnutls_hard_log("salt.size: %d\n", params->salt_size);

	/* read the iteration count 
	 */
	result =
	    _gnutls_x509_read_uint(pbes2_asn, "iterations",
				   &params->iter_count);
	if (result < 0)
		return gnutls_assert_val(result);

	_gnutls_hard_log("iterationCount: %d\n", params->iter_count);

	if (params->iter_count >= INT_MAX || params->iter_count == 0)
		return gnutls_assert_val(GNUTLS_E_ILLEGAL_PARAMETER);

	params->key_size = 0;

	return 0;
}

/* Writes the PBE parameters for PKCS-12 schemas.
 */
static int
write_pkcs12_kdf_params(ASN1_TYPE pbes2_asn,
			const struct pbkdf2_params *kdf_params)
{
	int result;

	/* write the salt 
	 */
	result =
	    asn1_write_value(pbes2_asn, "salt",
			     kdf_params->salt, kdf_params->salt_size);
	if (result != ASN1_SUCCESS) {
		gnutls_assert();
		result = _gnutls_asn2err(result);
		goto error;
	}
	_gnutls_hard_log("salt.size: %d\n", kdf_params->salt_size);

	/* write the iteration count 
	 */
	result =
	    _gnutls_x509_write_uint32(pbes2_asn, "iterations",
				      kdf_params->iter_count);
	if (result < 0) {
		gnutls_assert();
		goto error;
	}
	_gnutls_hard_log("iterationCount: %d\n", kdf_params->iter_count);

	return 0;

      error:
	return result;

}


static int
read_pbe_enc_params(ASN1_TYPE pbes2_asn,
		    const gnutls_datum_t * der,
		    struct pbe_enc_params *params)
{
	int params_start, params_end;
	int params_len, len, result;
	ASN1_TYPE pbe_asn = ASN1_TYPE_EMPTY;
	char oid[MAX_OID_SIZE];
	const struct pbes2_schema_st *p;

	memset(params, 0, sizeof(*params));

	/* Check the encryption algorithm
	 */
	len = sizeof(oid);
	result =
	    asn1_read_value(pbes2_asn, "encryptionScheme.algorithm", oid,
			    &len);
	if (result != ASN1_SUCCESS) {
		gnutls_assert();
		return _gnutls_asn2err(result);
	}
	_gnutls_hard_log("encryptionScheme.algorithm: %s\n", oid);

	if ((result = pbes2_oid_to_cipher(oid, &params->cipher)) < 0) {
		gnutls_assert();
		return result;
	}

	result =
	    asn1_der_decoding_startEnd(pbes2_asn, der->data, der->size,
				       "encryptionScheme.parameters",
				       &params_start, &params_end);
	if (result != ASN1_SUCCESS) {
		gnutls_assert();
		return _gnutls_asn2err(result);
	}
	params_len = params_end - params_start + 1;

	/* Now check the encryption parameters.
	 */
	p = cipher_to_pbes2_schema(params->cipher);
	if (p == NULL) {
		gnutls_assert();
		return GNUTLS_E_INVALID_REQUEST;
	}

	if ((result =
	     asn1_create_element(_gnutls_get_pkix(),
				 p->desc, &pbe_asn)) != ASN1_SUCCESS) {
		gnutls_assert();
		return _gnutls_asn2err(result);
	}

	result =
	    _asn1_strict_der_decode(&pbe_asn, &der->data[params_start],
			      params_len, NULL);
	if (result != ASN1_SUCCESS) {
		gnutls_assert();
		result = _gnutls_asn2err(result);
		goto error;
	}

	/* read the IV */
	params->iv_size = sizeof(params->iv);
	result =
	    asn1_read_value(pbe_asn, "", params->iv, &params->iv_size);
	if (result != ASN1_SUCCESS) {
		gnutls_assert();
		result = _gnutls_asn2err(result);
		goto error;
	}
	_gnutls_hard_log("IV.size: %d\n", params->iv_size);

	result = 0;

      error:
	asn1_delete_structure(&pbe_asn);
	return result;
}

static int
decrypt_data(schema_id schema, ASN1_TYPE pkcs8_asn,
	     const char *root, const char *password,
	     const struct pbkdf2_params *kdf_params,
	     const struct pbe_enc_params *enc_params,
	     gnutls_datum_t * decrypted_data)
{
	int result;
	gnutls_datum_t enc = {NULL, 0};
	uint8_t *key = NULL;
	gnutls_datum_t dkey, d_iv;
	cipher_hd_st ch;
	int ch_init = 0;
	int key_size;
	unsigned int pass_len = 0;
	const struct pbes2_schema_st *p;
	unsigned block_size;
	const cipher_entry_st *ce;

	if (password)
		pass_len = strlen(password);

	result = _gnutls_x509_read_value(pkcs8_asn, root, &enc);
	if (result < 0) {
		gnutls_assert();
		return _gnutls_asn2err(result);
	}

	if (kdf_params->key_size == 0) {
		key_size = gnutls_cipher_get_key_size(enc_params->cipher);
	} else
		key_size = kdf_params->key_size;

	key = gnutls_malloc(key_size);
	if (key == NULL) {
		gnutls_assert();
		result = GNUTLS_E_MEMORY_ERROR;
		goto error;
	}

	/* generate the key
	 */

	p = pbes2_schema_get(schema);
	if (p != NULL && p->pbes2 != 0) { /* PBES2 */
		if (kdf_params->mac == GNUTLS_MAC_SHA1)
			pbkdf2_hmac_sha1(pass_len, (uint8_t*)password,
					 kdf_params->iter_count,
					 kdf_params->salt_size, kdf_params->salt,
					 key_size, key);
		else if (kdf_params->mac == GNUTLS_MAC_SHA256)
			pbkdf2_hmac_sha256(pass_len, (uint8_t*)password,
					 kdf_params->iter_count,
					 kdf_params->salt_size, kdf_params->salt,
					 key_size, key);
		else return gnutls_assert_val(GNUTLS_E_UNKNOWN_HASH_ALGORITHM);
	} else if (p != NULL) { /* PKCS 12 schema */
		result =
		    _gnutls_pkcs12_string_to_key(mac_to_entry(GNUTLS_MAC_SHA1),
		    			         1 /*KEY*/,
						 kdf_params->salt,
						 kdf_params->salt_size,
						 kdf_params->iter_count,
						 password, key_size, key);

		if (result < 0) {
			gnutls_assert();
			goto error;
		}
	} else {
		gnutls_assert();
		result = GNUTLS_E_UNKNOWN_CIPHER_TYPE;
		goto error;
	}

	ce = cipher_to_entry(enc_params->cipher);
	block_size = _gnutls_cipher_get_block_size(ce);

	if (ce->type == CIPHER_BLOCK && (enc.size % block_size != 0)) {
		gnutls_assert();
		result = GNUTLS_E_ILLEGAL_PARAMETER;
		goto error;
	}

	/* do the decryption.
	 */
	dkey.data = key;
	dkey.size = key_size;

	d_iv.data = (uint8_t *) enc_params->iv;
	d_iv.size = enc_params->iv_size;
	result =
	    _gnutls_cipher_init(&ch, ce, &dkey, &d_iv, 0);

	gnutls_free(key);
	key = NULL;

	if (result < 0) {
		gnutls_assert();
		goto error;
	}

	ch_init = 1;

	result = _gnutls_cipher_decrypt(&ch, enc.data, enc.size);
	if (result < 0) {
		gnutls_assert();
		goto error;
	}

	decrypted_data->data = enc.data;

	if (block_size != 1)
		decrypted_data->size = enc.size - enc.data[enc.size - 1];
	else
		decrypted_data->size = enc.size;

	_gnutls_cipher_deinit(&ch);

	return 0;

      error:
	gnutls_free(enc.data);
	gnutls_free(key);
	if (ch_init != 0)
		_gnutls_cipher_deinit(&ch);
	return result;
}


/* Writes the PBKDF2 parameters.
 */
static int
write_pbkdf2_params(ASN1_TYPE pbes2_asn,
		    const struct pbkdf2_params *kdf_params)
{
	int result;
	ASN1_TYPE pbkdf2_asn = ASN1_TYPE_EMPTY;
	uint8_t tmp[MAX_OID_SIZE];

	/* Write the key derivation algorithm
	 */
	result =
	    asn1_write_value(pbes2_asn, "keyDerivationFunc.algorithm",
			     PBKDF2_OID, 1);
	if (result != ASN1_SUCCESS) {
		gnutls_assert();
		return _gnutls_asn2err(result);
	}

	/* Now write the key derivation and the encryption
	 * functions.
	 */
	if ((result =
	     asn1_create_element(_gnutls_get_pkix(),
				 "PKIX1.pkcs-5-PBKDF2-params",
				 &pbkdf2_asn)) != ASN1_SUCCESS) {
		gnutls_assert();
		return _gnutls_asn2err(result);
	}

	result = asn1_write_value(pbkdf2_asn, "salt", "specified", 1);
	if (result != ASN1_SUCCESS) {
		gnutls_assert();
		result = _gnutls_asn2err(result);
		goto error;
	}

	/* write the salt 
	 */
	result =
	    asn1_write_value(pbkdf2_asn, "salt.specified",
			     kdf_params->salt, kdf_params->salt_size);
	if (result != ASN1_SUCCESS) {
		gnutls_assert();
		result = _gnutls_asn2err(result);
		goto error;
	}
	_gnutls_hard_log("salt.specified.size: %d\n",
			 kdf_params->salt_size);

	/* write the iteration count 
	 */
	_gnutls_write_uint32(kdf_params->iter_count, tmp);

	result = asn1_write_value(pbkdf2_asn, "iterationCount", tmp, 4);
	if (result != ASN1_SUCCESS) {
		gnutls_assert();
		result = _gnutls_asn2err(result);
		goto error;
	}
	_gnutls_hard_log("iterationCount: %d\n", kdf_params->iter_count);

	/* write the keylength, if it is set.
	 */
	result = asn1_write_value(pbkdf2_asn, "keyLength", NULL, 0);
	if (result != ASN1_SUCCESS) {
		gnutls_assert();
		result = _gnutls_asn2err(result);
		goto error;
	}

	/* We write an emptry prf.
	 */
	result = asn1_write_value(pbkdf2_asn, "prf", NULL, 0);
	if (result != ASN1_SUCCESS) {
		gnutls_assert();
		result = _gnutls_asn2err(result);
		goto error;
	}

	/* now encode them an put the DER output
	 * in the keyDerivationFunc.parameters
	 */
	result = _gnutls_x509_der_encode_and_copy(pbkdf2_asn, "",
						  pbes2_asn,
						  "keyDerivationFunc.parameters",
						  0);
	if (result < 0) {
		gnutls_assert();
		goto error;
	}

	return 0;

      error:
	asn1_delete_structure(&pbkdf2_asn);
	return result;

}


static int
write_pbe_enc_params(ASN1_TYPE pbes2_asn,
		     const struct pbe_enc_params *params)
{
	int result;
	ASN1_TYPE pbe_asn = ASN1_TYPE_EMPTY;
	const struct pbes2_schema_st *p;

	/* Write the encryption algorithm
	 */
	p = cipher_to_pbes2_schema(params->cipher);
	if (p == NULL || p->pbes2 == 0) {
		gnutls_assert();
		return GNUTLS_E_INVALID_REQUEST;
	}

	result =
	    asn1_write_value(pbes2_asn, "encryptionScheme.algorithm", p->oid,
			     1);
	if (result != ASN1_SUCCESS) {
		gnutls_assert();
		goto error;
	}
	_gnutls_hard_log("encryptionScheme.algorithm: %s\n", p->oid);

	/* Now check the encryption parameters.
	 */
	if ((result =
	     asn1_create_element(_gnutls_get_pkix(),
				 p->desc, &pbe_asn)) != ASN1_SUCCESS) {
		gnutls_assert();
		return _gnutls_asn2err(result);
	}

	/* read the salt */
	result =
	    asn1_write_value(pbe_asn, "", params->iv, params->iv_size);
	if (result != ASN1_SUCCESS) {
		gnutls_assert();
		result = _gnutls_asn2err(result);
		goto error;
	}
	_gnutls_hard_log("IV.size: %d\n", params->iv_size);

	/* now encode them an put the DER output
	 * in the encryptionScheme.parameters
	 */
	result = _gnutls_x509_der_encode_and_copy(pbe_asn, "",
						  pbes2_asn,
						  "encryptionScheme.parameters",
						  0);
	if (result < 0) {
		gnutls_assert();
		goto error;
	}

	return 0;

      error:
	asn1_delete_structure(&pbe_asn);
	return result;

}

/* Generates a key and also stores the key parameters.
 */
static int
generate_key(schema_id schema,
	     const char *password,
	     struct pbkdf2_params *kdf_params,
	     struct pbe_enc_params *enc_params, gnutls_datum_t * key)
{
	unsigned char rnd[2];
	unsigned int pass_len = 0;
	int ret;
	const struct pbes2_schema_st *p;

	if (password)
		pass_len = strlen(password);

	ret = _gnutls_rnd(GNUTLS_RND_RANDOM, rnd, 2);
	if (ret < 0) {
		gnutls_assert();
		return ret;
	}

	/* generate salt */
	kdf_params->salt_size =
	    MIN(sizeof(kdf_params->salt), (unsigned) (12 + (rnd[1] % 10)));

	p = pbes2_schema_get(schema);
	if (p != NULL && p->pbes2 != 0) { /* PBES2 */
		enc_params->cipher = p->cipher;
	} else if (p != NULL) {
		/* non PBES2 algorithms */
		enc_params->cipher = p->cipher;
		kdf_params->salt_size = 8;
	} else {
		gnutls_assert();
		return GNUTLS_E_INVALID_REQUEST;
	}

	ret = _gnutls_rnd(GNUTLS_RND_RANDOM, kdf_params->salt,
			  kdf_params->salt_size);
	if (ret < 0) {
		gnutls_assert();
		return GNUTLS_E_RANDOM_FAILED;
	}

	kdf_params->iter_count = 5*1024 + rnd[0];
	key->size = kdf_params->key_size =
	    gnutls_cipher_get_key_size(enc_params->cipher);

	enc_params->iv_size =
	    gnutls_cipher_get_iv_size(enc_params->cipher);
	key->data = gnutls_malloc(key->size);
	if (key->data == NULL) {
		gnutls_assert();
		return GNUTLS_E_MEMORY_ERROR;
	}

	/* now generate the key. 
	 */

	 if (p->pbes2 != 0) {
		pbkdf2_hmac_sha1(pass_len, (uint8_t*)password,
				 kdf_params->iter_count,
				 kdf_params->salt_size, kdf_params->salt,
				 kdf_params->key_size, key->data);

		if (enc_params->iv_size) {
			ret = _gnutls_rnd(GNUTLS_RND_NONCE,
					  enc_params->iv,
					  enc_params->iv_size);
			if (ret < 0) {
				gnutls_assert();
				return ret;
			}
		}
	} else { /* PKCS 12 schema */
		ret =
		    _gnutls_pkcs12_string_to_key(mac_to_entry(GNUTLS_MAC_SHA1),
		    				 1 /*KEY*/,
						 kdf_params->salt,
						 kdf_params->salt_size,
						 kdf_params->iter_count,
						 password,
						 kdf_params->key_size,
						 key->data);
		if (ret < 0) {
			gnutls_assert();
			return ret;
		}

		/* Now generate the IV
		 */
		if (enc_params->iv_size) {
			ret =
			    _gnutls_pkcs12_string_to_key(mac_to_entry(GNUTLS_MAC_SHA1),
							 2 /*IV*/,
							 kdf_params->salt,
							 kdf_params->
							 salt_size,
							 kdf_params->
							 iter_count,
							 password,
							 enc_params->
							 iv_size,
							 enc_params->iv);
			if (ret < 0) {
				gnutls_assert();
				return ret;
			}
		}
	}


	return 0;
}


/* Encodes the parameters to be written in the encryptionAlgorithm.parameters
 * part.
 */
static int
write_schema_params(schema_id schema, ASN1_TYPE pkcs8_asn,
		    const char *where,
		    const struct pbkdf2_params *kdf_params,
		    const struct pbe_enc_params *enc_params)
{
	int result;
	ASN1_TYPE pbes2_asn = ASN1_TYPE_EMPTY;
	const struct pbes2_schema_st *p;

	p = pbes2_schema_get(schema);

	if (p != NULL && p->pbes2 != 0) { /* PBES2 */
		if ((result =
		     asn1_create_element(_gnutls_get_pkix(),
					 "PKIX1.pkcs-5-PBES2-params",
					 &pbes2_asn)) != ASN1_SUCCESS) {
			gnutls_assert();
			return _gnutls_asn2err(result);
		}

		result = write_pbkdf2_params(pbes2_asn, kdf_params);
		if (result < 0) {
			gnutls_assert();
			goto error;
		}

		result = write_pbe_enc_params(pbes2_asn, enc_params);
		if (result < 0) {
			gnutls_assert();
			goto error;
		}

		result = _gnutls_x509_der_encode_and_copy(pbes2_asn, "",
							  pkcs8_asn, where,
							  0);
		if (result < 0) {
			gnutls_assert();
			goto error;
		}

		asn1_delete_structure(&pbes2_asn);

	} else if (p != NULL) { /* PKCS #12 */

		if ((result =
		     asn1_create_element(_gnutls_get_pkix(),
					 "PKIX1.pkcs-12-PbeParams",
					 &pbes2_asn)) != ASN1_SUCCESS) {
			gnutls_assert();
			result = _gnutls_asn2err(result);
			goto error;
		}

		result = write_pkcs12_kdf_params(pbes2_asn, kdf_params);
		if (result < 0) {
			gnutls_assert();
			goto error;
		}

		result = _gnutls_x509_der_encode_and_copy(pbes2_asn, "",
							  pkcs8_asn, where,
							  0);
		if (result < 0) {
			gnutls_assert();
			goto error;
		}

		asn1_delete_structure(&pbes2_asn);
	}

	return 0;

      error:
	asn1_delete_structure(&pbes2_asn);
	return result;

}

static int
encrypt_data(const gnutls_datum_t * plain,
	     const struct pbe_enc_params *enc_params,
	     gnutls_datum_t * key, gnutls_datum_t * encrypted)
{
	int result;
	int data_size;
	uint8_t *data = NULL;
	gnutls_datum_t d_iv;
	cipher_hd_st ch;
	int ch_init = 0;
	uint8_t pad, pad_size;

	pad_size = gnutls_cipher_get_block_size(enc_params->cipher);

	if (pad_size == 1)	/* stream */
		pad_size = 0;

	data = gnutls_malloc(plain->size + pad_size);
	if (data == NULL) {
		gnutls_assert();
		return GNUTLS_E_MEMORY_ERROR;
	}

	memcpy(data, plain->data, plain->size);

	if (pad_size > 0) {
		pad = pad_size - (plain->size % pad_size);
		if (pad == 0)
			pad = pad_size;
		memset(&data[plain->size], pad, pad);
	} else
		pad = 0;

	data_size = plain->size + pad;

	d_iv.data = (uint8_t *) enc_params->iv;
	d_iv.size = enc_params->iv_size;
	result =
	    _gnutls_cipher_init(&ch, cipher_to_entry(enc_params->cipher),
				key, &d_iv, 1);

	if (result < 0) {
		gnutls_assert();
		goto error;
	}

	ch_init = 1;

	result = _gnutls_cipher_encrypt(&ch, data, data_size);
	if (result < 0) {
		gnutls_assert();
		goto error;
	}

	encrypted->data = data;
	encrypted->size = data_size;

	_gnutls_cipher_deinit(&ch);

	return 0;

      error:
	gnutls_free(data);
	if (ch_init != 0)
		_gnutls_cipher_deinit(&ch);
	return result;
}

/* Decrypts a PKCS #7 encryptedData. The output is allocated
 * and stored in dec.
 */
int
_gnutls_pkcs7_decrypt_data(const gnutls_datum_t * data,
			   const char *password, gnutls_datum_t * dec)
{
	int result, len;
	char enc_oid[MAX_OID_SIZE];
	gnutls_datum_t tmp;
	ASN1_TYPE pbes2_asn = ASN1_TYPE_EMPTY, pkcs7_asn = ASN1_TYPE_EMPTY;
	int params_start, params_end, params_len;
	struct pbkdf2_params kdf_params;
	struct pbe_enc_params enc_params;
	schema_id schema;

	if ((result =
	     asn1_create_element(_gnutls_get_pkix(),
				 "PKIX1.pkcs-7-EncryptedData",
				 &pkcs7_asn)) != ASN1_SUCCESS) {
		gnutls_assert();
		result = _gnutls_asn2err(result);
		goto error;
	}

	result =
	    asn1_der_decoding(&pkcs7_asn, data->data, data->size, NULL);
	if (result != ASN1_SUCCESS) {
		gnutls_assert();
		result = _gnutls_asn2err(result);
		goto error;
	}

	/* Check the encryption schema OID
	 */
	len = sizeof(enc_oid);
	result =
	    asn1_read_value(pkcs7_asn,
			    "encryptedContentInfo.contentEncryptionAlgorithm.algorithm",
			    enc_oid, &len);
	if (result != ASN1_SUCCESS) {
		gnutls_assert();
		result = _gnutls_asn2err(result);
		goto error;
	}

	if ((result = check_pkcs12_schema(enc_oid)) < 0) {
		gnutls_assert();
		goto error;
	}
	schema = result;

	/* Get the DER encoding of the parameters.
	 */
	result =
	    asn1_der_decoding_startEnd(pkcs7_asn, data->data, data->size,
				       "encryptedContentInfo.contentEncryptionAlgorithm.parameters",
				       &params_start, &params_end);
	if (result != ASN1_SUCCESS) {
		gnutls_assert();
		result = _gnutls_asn2err(result);
		goto error;
	}
	params_len = params_end - params_start + 1;

	result =
	    read_pkcs_schema_params(&schema, password,
				    &data->data[params_start],
				    params_len, &kdf_params, &enc_params);
	if (result < ASN1_SUCCESS) {
		gnutls_assert();
		result = _gnutls_asn2err(result);
		goto error;
	}

	/* Parameters have been decoded. Now
	 * decrypt the EncryptedData.
	 */

	result =
	    decrypt_data(schema, pkcs7_asn,
			 "encryptedContentInfo.encryptedContent", password,
			 &kdf_params, &enc_params, &tmp);
	if (result < 0) {
		gnutls_assert();
		goto error;
	}

	asn1_delete_structure2(&pkcs7_asn, ASN1_DELETE_FLAG_ZEROIZE);

	*dec = tmp;

	return 0;

      error:
	asn1_delete_structure(&pbes2_asn);
	asn1_delete_structure2(&pkcs7_asn, ASN1_DELETE_FLAG_ZEROIZE);
	return result;
}

int
_gnutls_pkcs7_data_enc_info(const gnutls_datum_t * data, const struct pbes2_schema_st **p,
	struct pbkdf2_params *kdf_params, char **oid)
{
	int result, len;
	char enc_oid[MAX_OID_SIZE];
	ASN1_TYPE pbes2_asn = ASN1_TYPE_EMPTY, pkcs7_asn = ASN1_TYPE_EMPTY;
	int params_start, params_end, params_len;
	struct pbe_enc_params enc_params;
	schema_id schema;

	if ((result =
	     asn1_create_element(_gnutls_get_pkix(),
				 "PKIX1.pkcs-7-EncryptedData",
				 &pkcs7_asn)) != ASN1_SUCCESS) {
		gnutls_assert();
		result = _gnutls_asn2err(result);
		goto error;
	}

	result =
	    asn1_der_decoding(&pkcs7_asn, data->data, data->size, NULL);
	if (result != ASN1_SUCCESS) {
		gnutls_assert();
		result = _gnutls_asn2err(result);
		goto error;
	}

	/* Check the encryption schema OID
	 */
	len = sizeof(enc_oid);
	result =
	    asn1_read_value(pkcs7_asn,
			    "encryptedContentInfo.contentEncryptionAlgorithm.algorithm",
			    enc_oid, &len);
	if (result != ASN1_SUCCESS) {
		gnutls_assert();
		result = _gnutls_asn2err(result);
		goto error;
	}

	if (oid) {
		*oid = gnutls_strdup(enc_oid);
	}

	if ((result = check_pkcs12_schema(enc_oid)) < 0) {
		gnutls_assert();
		goto error;
	}
	schema = result;

	/* Get the DER encoding of the parameters.
	 */
	result =
	    asn1_der_decoding_startEnd(pkcs7_asn, data->data, data->size,
				       "encryptedContentInfo.contentEncryptionAlgorithm.parameters",
				       &params_start, &params_end);
	if (result != ASN1_SUCCESS) {
		gnutls_assert();
		result = _gnutls_asn2err(result);
		goto error;
	}
	params_len = params_end - params_start + 1;

	result =
	    read_pkcs_schema_params(&schema, NULL,
				    &data->data[params_start],
				    params_len, kdf_params, &enc_params);
	if (result < ASN1_SUCCESS) {
		gnutls_assert();
		result = _gnutls_asn2err(result);
		goto error;
	}

	*p = pbes2_schema_get(schema);
	if (*p == NULL) {
		gnutls_assert();
		result = GNUTLS_E_UNKNOWN_CIPHER_TYPE;
		goto error;
	}


	asn1_delete_structure2(&pkcs7_asn, ASN1_DELETE_FLAG_ZEROIZE);

	return 0;

      error:
	asn1_delete_structure(&pbes2_asn);
	asn1_delete_structure2(&pkcs7_asn, ASN1_DELETE_FLAG_ZEROIZE);
	return result;
}

/* Encrypts to a PKCS #7 encryptedData. The output is allocated
 * and stored in enc.
 */
int
_gnutls_pkcs7_encrypt_data(schema_id schema,
			   const gnutls_datum_t * data,
			   const char *password, gnutls_datum_t * enc)
{
	int result;
	gnutls_datum_t key = { NULL, 0 };
	gnutls_datum_t tmp = { NULL, 0 };
	ASN1_TYPE pkcs7_asn = ASN1_TYPE_EMPTY;
	struct pbkdf2_params kdf_params;
	struct pbe_enc_params enc_params;
	const char *str_oid;

	if ((result =
	     asn1_create_element(_gnutls_get_pkix(),
				 "PKIX1.pkcs-7-EncryptedData",
				 &pkcs7_asn)) != ASN1_SUCCESS) {
		gnutls_assert();
		result = _gnutls_asn2err(result);
		goto error;
	}

	/* Write the encryption schema OID
	 */
	result = pkcs12_schema_to_oid(schema, &str_oid);
	if (result < 0) {
		gnutls_assert();
		return result;
	}

	result =
	    asn1_write_value(pkcs7_asn,
			     "encryptedContentInfo.contentEncryptionAlgorithm.algorithm",
			     str_oid, 1);

	if (result != ASN1_SUCCESS) {
		gnutls_assert();
		result = _gnutls_asn2err(result);
		goto error;
	}

	/* Generate a symmetric key.
	 */

	result =
	    generate_key(schema, password, &kdf_params, &enc_params, &key);
	if (result < 0) {
		gnutls_assert();
		goto error;
	}

	result = write_schema_params(schema, pkcs7_asn,
				     "encryptedContentInfo.contentEncryptionAlgorithm.parameters",
				     &kdf_params, &enc_params);
	if (result < 0) {
		gnutls_assert();
		goto error;
	}

	/* Parameters have been encoded. Now
	 * encrypt the Data.
	 */
	result = encrypt_data(data, &enc_params, &key, &tmp);
	if (result < 0) {
		gnutls_assert();
		goto error;
	}

	/* write the encrypted data.
	 */
	result =
	    asn1_write_value(pkcs7_asn,
			     "encryptedContentInfo.encryptedContent",
			     tmp.data, tmp.size);
	if (result != ASN1_SUCCESS) {
		gnutls_assert();
		result = _gnutls_asn2err(result);
		goto error;
	}

	_gnutls_free_datum(&tmp);
	_gnutls_free_key_datum(&key);

	/* Now write the rest of the pkcs-7 stuff.
	 */

	result = _gnutls_x509_write_uint32(pkcs7_asn, "version", 0);
	if (result < 0) {
		gnutls_assert();
		goto error;
	}

	result =
	    asn1_write_value(pkcs7_asn, "encryptedContentInfo.contentType",
			     DATA_OID, 1);
	if (result != ASN1_SUCCESS) {
		gnutls_assert();
		result = _gnutls_asn2err(result);
		goto error;
	}

	result = asn1_write_value(pkcs7_asn, "unprotectedAttrs", NULL, 0);
	if (result != ASN1_SUCCESS) {
		gnutls_assert();
		result = _gnutls_asn2err(result);
		goto error;
	}

	/* Now encode and copy the DER stuff.
	 */
	result = _gnutls_x509_der_encode(pkcs7_asn, "", enc, 0);

	asn1_delete_structure2(&pkcs7_asn, ASN1_DELETE_FLAG_ZEROIZE);

	if (result < 0) {
		gnutls_assert();
		goto error;
	}


      error:
	_gnutls_free_key_datum(&key);
	_gnutls_free_datum(&tmp);
	asn1_delete_structure2(&pkcs7_asn, ASN1_DELETE_FLAG_ZEROIZE);
	return result;
}
