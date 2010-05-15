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
#include <gnutls/privkey.h>
#include <sign.h>
#include <gnutls_pk.h>
#include <x509_int.h>
#include <openpgp/openpgp_int.h>

struct gnutls_privkey_st {
	gnutls_privkey_type_t type;
	gnutls_pk_algorithm_t pk_algorithm;
	
	union {
		gnutls_x509_privkey_t x509;
		gnutls_pkcs11_privkey_t pkcs11;
		gnutls_openpgp_privkey_t openpgp;
	} key;
	
	unsigned int flags;
};

int gnutls_privkey_get_type (gnutls_privkey_t key)
{
	return key->type;
}

int gnutls_privkey_get_pk_algorithm (gnutls_privkey_t key, unsigned int* bits)
{
	switch(key->type) {
		case GNUTLS_PRIVKEY_OPENPGP:
			return gnutls_openpgp_privkey_get_pk_algorithm(key->key.openpgp, bits);
		case GNUTLS_PRIVKEY_PKCS11:
			return gnutls_pkcs11_privkey_get_pk_algorithm(key->key.pkcs11, bits);
		case GNUTLS_PRIVKEY_X509:
                        if (bits)
                                *bits = _gnutls_mpi_get_nbits (key->key.x509->params[0]);
			return gnutls_x509_privkey_get_pk_algorithm(key->key.x509);
		default:
			gnutls_assert();
			return GNUTLS_E_INVALID_REQUEST;
	}

}

int gnutls_privkey_init(gnutls_privkey_t * key)
{
	*key = gnutls_calloc(1, sizeof(struct gnutls_privkey_st));
	if (*key == NULL) {
		gnutls_assert();
		return GNUTLS_E_MEMORY_ERROR;
	}
	
	return 0;
}

void gnutls_privkey_deinit(gnutls_privkey_t key)
{
	if (key->flags & GNUTLS_PRIVKEY_IMPORT_AUTO_RELEASE)
		switch(key->type) {
			case GNUTLS_PRIVKEY_OPENPGP:
				return gnutls_openpgp_privkey_deinit(key->key.openpgp);
			case GNUTLS_PRIVKEY_PKCS11:
				return gnutls_pkcs11_privkey_deinit(key->key.pkcs11);
			case GNUTLS_PRIVKEY_X509:
				return gnutls_x509_privkey_deinit(key->key.x509);
		}
	gnutls_free(key);
}

int gnutls_privkey_import_pkcs11 (gnutls_privkey_t pkey, gnutls_pkcs11_privkey_t key, unsigned int flags)
{
	pkey->key.pkcs11 = key;
	pkey->type = GNUTLS_PRIVKEY_PKCS11;
	pkey->pk_algorithm = gnutls_pkcs11_privkey_get_pk_algorithm(key, NULL);
	pkey->flags = flags;

	return 0;
}

int gnutls_privkey_import_x509 (gnutls_privkey_t pkey, gnutls_x509_privkey_t key, unsigned int flags)
{
        pkey->key.x509 = key;
	pkey->type = GNUTLS_PRIVKEY_X509;
	pkey->pk_algorithm = gnutls_x509_privkey_get_pk_algorithm(key);
	pkey->flags = flags;

	return 0;
}

int gnutls_privkey_import_openpgp (gnutls_privkey_t pkey, gnutls_openpgp_privkey_t key, unsigned int flags)
{
	pkey->key.openpgp = key;
	pkey->type = GNUTLS_PRIVKEY_OPENPGP;
	pkey->pk_algorithm = gnutls_openpgp_privkey_get_pk_algorithm(key, NULL);
	pkey->flags = flags;
	
	return 0;
}

/**
 * gnutls_privkey_sign_data:
 * @signer: Holds the key
 * @digest: should be MD5 or SHA1
 * @flags: should be 0 for now
 * @data: holds the data to be signed
 * @signature: will contain the signature allocate with gnutls_malloc()
 *
 * This function will sign the given data using a signature algorithm
 * supported by the private key. Signature algorithms are always used
 * together with a hash functions.  Different hash functions may be
 * used for the RSA algorithm, but only SHA-1 for the DSA keys.
 *
 * If the buffer provided is not long enough to hold the output, then
 * *@signature_size is updated and %GNUTLS_E_SHORT_MEMORY_BUFFER will
 * be returned.
 *
 * Returns: On success, %GNUTLS_E_SUCCESS is returned, otherwise a
 * negative error value.
 **/
int
gnutls_privkey_sign_data(gnutls_privkey_t signer,
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

	ret = gnutls_privkey_sign_hash(signer, &digest, signature);
	_gnutls_free_datum(&digest);

	if (ret < 0) {
		gnutls_assert();
		return ret;
	}

	return 0;
}

int gnutls_privkey_sign_hash (gnutls_privkey_t key,
				 const gnutls_datum_t * hash,
				 gnutls_datum_t * signature)
{
	switch(key->type) {
		case GNUTLS_PRIVKEY_OPENPGP:
			return gnutls_openpgp_privkey_sign_hash(key->key.openpgp, hash, signature);
		case GNUTLS_PRIVKEY_PKCS11:
			return gnutls_pkcs11_privkey_sign_hash(key->key.pkcs11, hash, signature);
		case GNUTLS_PRIVKEY_X509:
			return gnutls_x509_privkey_sign_hash(key->key.x509, hash, signature);
		default:
			gnutls_assert();
			return GNUTLS_E_INVALID_REQUEST;
	}
}

int gnutls_privkey_decrypt_data(gnutls_privkey_t key,
				unsigned int flags,
				const gnutls_datum_t * ciphertext,
				gnutls_datum_t * plaintext)
{
	if (key->pk_algorithm != GNUTLS_PK_RSA) {
		gnutls_assert();
		return GNUTLS_E_INVALID_REQUEST;
	}
	
	switch(key->type) {
		case GNUTLS_PRIVKEY_OPENPGP:
			return gnutls_openpgp_privkey_decrypt_data(key->key.openpgp, flags, ciphertext, plaintext);
		case GNUTLS_PRIVKEY_X509:
			return _gnutls_pkcs1_rsa_decrypt (plaintext, ciphertext, key->key.x509->params, key->key.x509->params_size, 2);
		case GNUTLS_PRIVKEY_PKCS11:
			return gnutls_pkcs11_privkey_decrypt_data(key->key.pkcs11, flags, ciphertext, plaintext);
		default:
			gnutls_assert();
			return GNUTLS_E_INVALID_REQUEST;
	}
}



