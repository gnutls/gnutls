/*
 * GnuTLS PKCS#11 support
 * Copyright (C) 2010 Free Software Foundation
 * 
 * Author: Nikos Mavrogiannopoulos
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Library General Public
 * License as published by the Free Software Foundation; either
 * version 2 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Library General Public License for more details.
 *
 * You should have received a copy of the GNU Library General Public
 * License along with this library; if not, write to the Free
 * Software Foundation, Inc., 59 Temple Place - Suite 330, Boston,
 * MA 02111-1307, USA
*/

#include <gnutls_int.h>
#include <pakchois/pakchois.h>
#include <gnutls/pkcs11.h>
#include <stdio.h>
#include <stdbool.h>
#include <string.h>
#include <gnutls_errors.h>
#include <gnutls_datum.h>
#include <pkcs11_int.h>
#include <sign.h>

struct gnutls_pkcs11_privkey_st {
	pakchois_session_t *pks;
	ck_object_handle_t privkey;
	gnutls_pk_algorithm_t pk_algorithm;
	struct pkcs11_url_info info;
};

struct privkey_find_data_st {
	gnutls_pkcs11_privkey_t privkey;
};

static int find_privkey_url(pakchois_session_t * pks,
			    struct token_info *info, void *input);

int gnutls_pkcs11_privkey_init(gnutls_pkcs11_privkey_t * key)
{
	*key = gnutls_calloc(1, sizeof(struct gnutls_pkcs11_privkey_st));
	if (*key == NULL) {
		gnutls_assert();
		return GNUTLS_E_MEMORY_ERROR;
	}
	(*key)->privkey = CK_INVALID_HANDLE;
	
	return 0;
}

void gnutls_pkcs11_privkey_deinit(gnutls_pkcs11_privkey_t key)
{
	if (key->pks) {
		pakchois_close_session(key->pks);
        }
	gnutls_free(key);
}

int gnutls_pkcs11_privkey_get_pk_algorithm(gnutls_pkcs11_privkey_t key, unsigned int *bits)
{
        if (bits)
          *bits = 0; /* FIXME */
	return key->pk_algorithm;
}

int gnutls_pkcs11_privkey_get_info(gnutls_pkcs11_privkey_t pkey,
				   gnutls_pkcs11_cert_info_t itype,
				   void *output, size_t * output_size)
{
	return pkcs11_get_info(&pkey->info, itype, output, output_size);
}

#define RETRY_BLOCK_START(key) struct privkey_find_data_st find_data; \
	int retries = 0; find_data.privkey = key; retry:


/* the rescan_slots() here is a dummy but if not
 * called my card fails to work when removed and inserted.
 * May have to do with the pkcs11 library I use.
 */
#define RETRY_CHECK(rv, label) { \
		if (token_func && (rv == CKR_SESSION_HANDLE_INVALID||rv==CKR_DEVICE_REMOVED)) { \
			pkcs11_rescan_slots(); \
			pakchois_close_session(key->pks); \
			pkcs11_rescan_slots(); \
			key->pks = NULL; \
			ret = token_func(token_data, label, retries++); \
			if (ret == 0) { \
				_pkcs11_traverse_tokens(find_privkey_url, &find_data, 1); \
				goto retry; \
			} \
		} \
	}

/**
 * gnutls_pkcs11_privkey_sign_data:
 * @signer: Holds the key
 * @digest: should be MD5 or SHA1
 * @flags: should be 0 for now
 * @data: holds the data to be signed
 * @signature: will contain the signature allocated with gnutls_malloc()
 *
 * This function will sign the given data using a signature algorithm
 * supported by the private key. Signature algorithms are always used
 * together with a hash functions.  Different hash functions may be
 * used for the RSA algorithm, but only SHA-1 for the DSA keys.
 *
 * Returns: On success, %GNUTLS_E_SUCCESS is returned, otherwise a
 *   negative error value.
 **/
int
gnutls_pkcs11_privkey_sign_data(gnutls_pkcs11_privkey_t signer,
				gnutls_digest_algorithm_t hash,
				unsigned int flags,
				const gnutls_datum_t * data,
				gnutls_datum_t * signature)
{
	int ret;
	gnutls_datum_t digest;

	switch (signer->pk_algorithm) {
	case GNUTLS_PK_RSA:
		ret = pk_pkcs1_rsa_hash(hash, data, &digest);
		if (ret < 0) {
			gnutls_assert();
			return ret;
		}
		break;
	case GNUTLS_PK_DSA:
		ret = pk_dsa_hash(data, &digest);
		if (ret < 0) {
			gnutls_assert();
			return ret;
		}

		break;
	default:
		gnutls_assert();
		return GNUTLS_E_INTERNAL_ERROR;
	}

	ret = gnutls_pkcs11_privkey_sign_hash(signer, &digest, signature);
	_gnutls_free_datum(&digest);

	if (ret < 0) {
		gnutls_assert();
		return ret;
	}

	return 0;

}


int gnutls_pkcs11_privkey_sign_hash(gnutls_pkcs11_privkey_t key,
				    const gnutls_datum_t * hash,
				    gnutls_datum_t * signature)
{
	ck_rv_t rv;
	int ret;
	struct ck_mechanism mech;
	unsigned long siglen;

	RETRY_BLOCK_START(key);

	if (key->privkey == CK_INVALID_HANDLE || key->pks == NULL) {
		gnutls_assert();
		return GNUTLS_E_PKCS11_ERROR;
	}

	mech.mechanism =
	    key->pk_algorithm == GNUTLS_PK_DSA ? CKM_DSA : CKM_RSA_PKCS;
	mech.parameter = NULL;
	mech.parameter_len = 0;

	/* Initialize signing operation; using the private key discovered
	 * earlier. */
	rv = pakchois_sign_init(key->pks, &mech, key->privkey);
	if (rv != CKR_OK) {
		RETRY_CHECK(rv, key->info.label);
		gnutls_assert();
		return GNUTLS_E_PK_SIGN_FAILED;
	}

	/* Work out how long the signature must be: */
	rv = pakchois_sign(key->pks, hash->data, hash->size, NULL,
			   &siglen);
	if (rv != CKR_OK) {
		RETRY_CHECK(rv, key->info.label);
		gnutls_assert();
		return GNUTLS_E_PK_SIGN_FAILED;
	}

	signature->data = gnutls_malloc(siglen);
	signature->size = siglen;

	rv = pakchois_sign(key->pks, hash->data, hash->size,
			   signature->data, &siglen);
	if (rv != CKR_OK) {
		gnutls_free(signature->data);
		RETRY_CHECK(rv, key->info.label);
		gnutls_assert();
		return GNUTLS_E_PK_SIGN_FAILED;
	}

	signature->size = siglen;

	return 0;
}

static int find_privkey_url(pakchois_session_t * pks,
			    struct token_info *info, void *input)
{
	struct privkey_find_data_st *find_data = input;
	struct ck_attribute a[4];
	ck_object_class_t class;
	ck_rv_t rv;
	ck_object_handle_t obj;
	unsigned long count;
	int found = 0, ret;
	ck_key_type_t keytype;

	if (info == NULL) {	/* we don't support multiple calls */
		gnutls_assert();
		return GNUTLS_E_REQUESTED_DATA_NOT_AVAILABLE;
	}

	/* do not bother reading the token if basic fields do not match
	 */
	if (find_data->privkey->info.manufacturer[0] != 0) {
		if (strcmp
		    (find_data->privkey->info.manufacturer,
		     info->tinfo.manufacturer_id) != 0)
			return GNUTLS_E_REQUESTED_DATA_NOT_AVAILABLE;
	}

	if (find_data->privkey->info.token[0] != 0) {
		if (strcmp
		    (find_data->privkey->info.token,
		     info->tinfo.label) != 0)
			return GNUTLS_E_REQUESTED_DATA_NOT_AVAILABLE;
	}

	if (find_data->privkey->info.model[0] != 0) {
		if (strcmp
		    (find_data->privkey->info.model,
		     info->tinfo.model) != 0)
			return GNUTLS_E_REQUESTED_DATA_NOT_AVAILABLE;
	}

	if (find_data->privkey->info.serial[0] != 0) {
		if (strcmp
		    (find_data->privkey->info.serial,
		     info->tinfo.serial_number) != 0)
			return GNUTLS_E_REQUESTED_DATA_NOT_AVAILABLE;
	}

	if (find_data->privkey->info.type[0] != 0) {
		if (strcmp(find_data->privkey->info.type, "cert") != 0) {
			gnutls_assert();
			return GNUTLS_E_UNIMPLEMENTED_FEATURE;
		}
	}

	/* search the token for the id */
        ret = pkcs11_login(pks, info);
        if (ret < 0) {
            gnutls_assert();
            return ret;
        }
        
	/* Find objects with cert class and X.509 cert type. */
	class = CKO_PRIVATE_KEY;

	a[0].type = CKA_CLASS;
	a[0].value = &class;
	a[0].value_len = sizeof class;

	a[1].type = CKA_ID;
	a[1].value = find_data->privkey->info.certid_raw;
	a[1].value_len = find_data->privkey->info.certid_raw_size;


	rv = pakchois_find_objects_init(pks, a, 2);
	if (rv != CKR_OK) {
		gnutls_assert();
		_gnutls_debug_log("pk11: FindObjectsInit failed.\n");
		ret = GNUTLS_E_REQUESTED_DATA_NOT_AVAILABLE;
		goto cleanup;
	}

	while (pakchois_find_objects(pks, &obj, 1, &count) == CKR_OK
	       && count == 1) {

		a[0].type = CKA_KEY_TYPE;
		a[0].value = &keytype;
		a[0].value_len = sizeof keytype;

		if (pakchois_get_attribute_value(pks, obj, a, 1) == CKR_OK) {
			if (keytype == CKK_RSA)
				find_data->privkey->pk_algorithm = GNUTLS_PK_RSA;
			else if (keytype == CKK_DSA)
				find_data->privkey->pk_algorithm = GNUTLS_PK_DSA;
			else {
				gnutls_assert();
				ret =
				    GNUTLS_E_UNSUPPORTED_CERTIFICATE_TYPE;
				goto cleanup;
			}
			find_data->privkey->pks = pks;
			find_data->privkey->privkey = obj;
			found = 1;
		} else {
			_gnutls_debug_log
			    ("pk11: Skipped cert, missing attrs.\n");
		}
	}

	if (found == 0) {
		gnutls_assert();
		ret = GNUTLS_E_REQUESTED_DATA_NOT_AVAILABLE;
	} else {
		ret = 0;
	}

      cleanup:
	pakchois_find_objects_final(pks);

	return ret;
}

int gnutls_pkcs11_privkey_import_url(gnutls_pkcs11_privkey_t pkey,
				     const char *url)
{
	int ret;
	struct privkey_find_data_st find_data;

	/* fill in the find data structure */
	find_data.privkey = pkey;

	ret = pkcs11_url_to_info(url, &pkey->info);
	if (ret < 0) {
		gnutls_assert();
		return ret;
	}

	if (pkey->info.id[0] == 0) {
		gnutls_assert();
		return GNUTLS_E_REQUESTED_DATA_NOT_AVAILABLE;
	}

	ret = _pkcs11_traverse_tokens(find_privkey_url, &find_data, 1);
	if (ret < 0) {
		gnutls_assert();
		return ret;
	}

	return 0;
}

/**
 * gnutls_pkcs11_privkey_decrypt_data:
 * @key: Holds the key
 * @flags: should be 0 for now
 * @ciphertext: holds the data to be signed
 * @plaintext: will contain the plaintext, allocated with gnutls_malloc()
 *
 * This function will decrypt the given data using the public key algorithm
 * supported by the private key. 
 *
 * Returns: On success, %GNUTLS_E_SUCCESS is returned, otherwise a
 *   negative error value.
 **/
int
gnutls_pkcs11_privkey_decrypt_data(gnutls_pkcs11_privkey_t key,
  unsigned int flags, const gnutls_datum_t * ciphertext,
				gnutls_datum_t * plaintext)
{
	ck_rv_t rv;
	int ret;
	struct ck_mechanism mech;
	unsigned long siglen;

	RETRY_BLOCK_START(key);

	if (key->privkey == CK_INVALID_HANDLE) {
		gnutls_assert();
		return GNUTLS_E_PKCS11_ERROR;
	}

	mech.mechanism =
	    key->pk_algorithm == GNUTLS_PK_DSA ? CKM_DSA : CKM_RSA_PKCS;
	mech.parameter = NULL;
	mech.parameter_len = 0;

	/* Initialize signing operation; using the private key discovered
	 * earlier. */
	rv = pakchois_decrypt_init(key->pks, &mech, key->privkey);
	if (rv != CKR_OK) {
		RETRY_CHECK(rv, key->info.label);
		gnutls_assert();
		return GNUTLS_E_PK_DECRYPTION_FAILED;
	}

	/* Work out how long the plaintext must be: */
	rv = pakchois_decrypt(key->pks, ciphertext->data, ciphertext->size, NULL,
			   &siglen);
	if (rv != CKR_OK) {
		RETRY_CHECK(rv, key->info.label);
		gnutls_assert();
		return GNUTLS_E_PK_DECRYPTION_FAILED;
	}

	plaintext->data = gnutls_malloc(siglen);
	plaintext->size = siglen;

	rv = pakchois_decrypt(key->pks, ciphertext->data, ciphertext->size,
			   plaintext->data, &siglen);
	if (rv != CKR_OK) {
		gnutls_free(plaintext->data);
		gnutls_assert();
		return GNUTLS_E_PK_DECRYPTION_FAILED;
	}

	plaintext->size = siglen;

	return 0;
}
