/*
 * Copyright (C) 2013 Red Hat
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
#include <gnutls_errors.h>
#include <gnutls_cipher_int.h>
#include <gnutls_datum.h>
#include <gnutls/crypto.h>
#include <gnutls_errors.h>
#include <gnutls/abstract.h>

static int privkey_generate(gnutls_privkey_t key, gnutls_pk_algorithm_t algo, unsigned bits)
{
	gnutls_x509_privkey_t xkey;
	int ret;
	
	ret = gnutls_x509_privkey_init(&xkey);
	if (ret < 0)
		return gnutls_assert_val(ret);
	
	ret = gnutls_x509_privkey_generate(xkey, algo, bits, 0);
	if (ret < 0)
		return gnutls_assert_val(ret);

	ret = gnutls_privkey_import_x509(key, xkey, GNUTLS_PRIVKEY_IMPORT_AUTO_RELEASE);
	if (ret < 0)
		return gnutls_assert_val(ret);
		
	return 0;
}

#define DATASTR "Hello there"
static const gnutls_datum_t data = {
		.data = (void*)DATASTR,
		.size = sizeof(DATASTR)-1
};

static const gnutls_datum_t bad_data = {
		.data = (void*)DATASTR,
		.size = sizeof(DATASTR)-2
};

static int test_rsa_enc(gnutls_pk_algorithm_t pk, 
		gnutls_privkey_t key, 
		gnutls_pubkey_t pub, 
		unsigned bits,
		gnutls_digest_algorithm_t ign)
{
	int ret;
	gnutls_datum_t enc;
	gnutls_datum_t dec = {NULL, 0};
	
	ret = gnutls_pubkey_encrypt_data(pub, 0, &data, &enc);
	if (ret < 0)
		return gnutls_assert_val(ret);
		
	ret = gnutls_privkey_decrypt_data(key, 0, &enc, &dec);
	if (ret < 0) {
		gnutls_assert();
		goto cleanup;
	}
	
	if (dec.size != data.size || memcmp(dec.data, data.data, dec.size) != 0) {
		ret = GNUTLS_E_SELF_TEST_ERROR;
		gnutls_assert();
		goto cleanup;
	}

	ret = 0;
cleanup:
	gnutls_free(enc.data);
	gnutls_free(dec.data);

	if (ret == 0)
		_gnutls_debug_log("%s-%u-enc self test succeeded\n", gnutls_pk_get_name(pk), bits);
	else
		_gnutls_debug_log("%s-%u-enc self test failed\n", gnutls_pk_get_name(pk), bits);

	return ret;
}

static int test_sig(gnutls_pk_algorithm_t pk, gnutls_privkey_t key, 
					gnutls_pubkey_t pub, 
					unsigned bits,
					gnutls_digest_algorithm_t dig)
{
	int ret;
	gnutls_datum_t sig;

	ret = gnutls_privkey_sign_data(key, dig, 0, &data, &sig);
	if (ret < 0)
		return gnutls_assert_val(ret);
		
	ret = gnutls_pubkey_verify_data2(pub, gnutls_pk_to_sign(pk, dig), 0,
			&data, &sig);
	
	if (ret < 0) {
		ret = GNUTLS_E_SELF_TEST_ERROR;
		gnutls_assert();
		goto cleanup;
	}

	ret = gnutls_pubkey_verify_data2(pub, gnutls_pk_to_sign(pk, dig), 0,
			&bad_data, &sig);
	
	if (ret != GNUTLS_E_PK_SIG_VERIFY_FAILED) {
		ret = GNUTLS_E_SELF_TEST_ERROR;
		gnutls_assert();
		goto cleanup;
	}
	
	ret = 0;
cleanup:
	gnutls_free(sig.data);

	if (ret == 0)
		_gnutls_debug_log("%s-%u-sig self test succeeded\n", gnutls_pk_get_name(pk), bits);
	else
		_gnutls_debug_log("%s-%u-sig self test failed\n", gnutls_pk_get_name(pk), bits);

	return ret;
}

#define PK_TEST(pk, func, bits, dig) \
			ret = gnutls_privkey_init(&key); \
			if (ret < 0) \
				return gnutls_assert_val(ret); \
			ret = gnutls_pubkey_init(&pub); \
			if (ret < 0) { \
				gnutls_privkey_deinit(key); \
				return gnutls_assert_val(ret); \
			} \
			ret = privkey_generate(key, pk, bits); \
			if (ret < 0) { \
				gnutls_assert(); \
				goto cleanup; \
			} \
			ret = gnutls_pubkey_import_privkey(pub, key, 0, 0); \
			if (ret < 0) { \
				gnutls_assert(); \
				goto cleanup; \
			} \
			ret = func(pk, key, pub, bits, dig); \
			if (ret < 0) { \
				gnutls_assert(); \
				goto cleanup; \
			} \
			gnutls_pubkey_deinit(pub); \
			gnutls_privkey_deinit(key); \
			if (all == 0) \
				return 0
/**
 * gnutls_pk_self_test:
 * @all: if non-zero then tests to all public key algorithms are performed.
 * @pk: the algorithm to use
 *
 * This function will run self tests on the provided public key algorithm.
 *
 * Returns: Zero or a negative error code on error.
 *
 * Since: 3.3.0
 **/
int gnutls_pk_self_test(unsigned all, gnutls_pk_algorithm_t pk)
{
int ret;
gnutls_privkey_t key;
gnutls_pubkey_t pub;
	
	if (all != 0)
		pk = GNUTLS_PK_UNKNOWN;

	switch(pk) {
		case GNUTLS_PK_UNKNOWN:

		case GNUTLS_PK_RSA:
			PK_TEST(GNUTLS_PK_RSA, test_rsa_enc, 1024, 0);
			PK_TEST(GNUTLS_PK_RSA, test_sig, 1024, GNUTLS_DIG_SHA1);
		case GNUTLS_PK_DSA:
			PK_TEST(GNUTLS_PK_DSA, test_sig, 1024, GNUTLS_DIG_SHA1);
			PK_TEST(GNUTLS_PK_DSA, test_sig, 2048, GNUTLS_DIG_SHA256);
			PK_TEST(GNUTLS_PK_DSA, test_sig, 3072, GNUTLS_DIG_SHA256);
		case GNUTLS_PK_EC: /* Testing ECDSA */
			PK_TEST(GNUTLS_PK_EC, test_sig, 192, GNUTLS_DIG_SHA256);
			PK_TEST(GNUTLS_PK_EC, test_sig, 256, GNUTLS_DIG_SHA256);
			PK_TEST(GNUTLS_PK_EC, test_sig, 384, GNUTLS_DIG_SHA384);
			PK_TEST(GNUTLS_PK_EC, test_sig, 521, GNUTLS_DIG_SHA512);

			break;
			
		default:
			return gnutls_assert_val(GNUTLS_E_NO_SELF_TEST);
	}

	return 0;

cleanup:
	gnutls_pubkey_deinit(pub);
	gnutls_privkey_deinit(key);
	return ret;
}
