/*
 * Copyright (C) 2025 Red Hat, Inc.
 *
 * Author: Zoltan Fridrich
 *
 * This file is part of GnuTLS.
 *
 * GnuTLS is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 3 of the License, or
 * (at your option) any later version.
 *
 * GnuTLS is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with this program.  If not, see <https://www.gnu.org/licenses/>
 */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <unistd.h>
#include <gnutls/gnutls.h>
#include <gnutls/x509.h>
#include <gnutls/abstract.h>

/* sha1 hash of "hello" string */
const gnutls_datum_t hash_data = {
	(void *)"\xaa\xf4\xc6\x1d\xdc\xc5\xe8\xa2\xda\xbe"
		"\xde\x0f\x3b\x48\x2c\xd9\xae\xa9\x43\x4d",
	20
};

const gnutls_datum_t raw_data = { (void *)"hello there", 11 };

static int test_encrypt_decrypt(gnutls_pubkey_t *pubkey,
				gnutls_privkey_t *privkey)
{
	int ret;
	gnutls_datum_t out = { NULL, 0 };
	gnutls_datum_t out2 = { NULL, 0 };

	ret = gnutls_pubkey_encrypt_data(*pubkey, 0, &hash_data, &out);
	if (ret < 0) {
		fprintf(stderr, "gnutls_pubkey_encrypt_data: %s\n",
			gnutls_strerror(ret));
		return ret;
	}

	ret = gnutls_privkey_decrypt_data(*privkey, 0, &out, &out2);
	if (ret < 0) {
		fprintf(stderr, "gnutls_privkey_decrypt_data: %s\n",
			gnutls_strerror(ret));
		return ret;
	}

	if (out2.size != hash_data.size) {
		fprintf(stderr, "Decrypted data don't match original (1)\n");
		return -1;
	}

	if (memcmp(out2.data, hash_data.data, hash_data.size) != 0) {
		fprintf(stderr, "Decrypted data don't match original (2)\n");
		return -1;
	}

	/* try again with fixed length API */
	memset(out2.data, 'A', out2.size);
	ret = gnutls_privkey_decrypt_data2(*privkey, 0, &out, out2.data,
					   out2.size);
	if (ret < 0) {
		fprintf(stderr, "gnutls_privkey_decrypt_data: %s\n",
			gnutls_strerror(ret));
		return ret;
	}

	if (memcmp(out2.data, hash_data.data, hash_data.size) != 0) {
		fprintf(stderr, "Decrypted data don't match original (2b)\n");
		return -1;
	}

	gnutls_free(out.data);
	gnutls_free(out2.data);

	ret = gnutls_pubkey_encrypt_data(*pubkey, 0, &raw_data, &out);
	if (ret < 0) {
		fprintf(stderr, "gnutls_pubkey_encrypt_data: %s\n",
			gnutls_strerror(ret));
		return ret;
	}

	ret = gnutls_privkey_decrypt_data(*privkey, 0, &out, &out2);
	if (ret < 0) {
		fprintf(stderr, "gnutls_privkey_decrypt_data: %s\n",
			gnutls_strerror(ret));
		return ret;
	}

	if (out2.size != raw_data.size) {
		fprintf(stderr, "Decrypted data don't match original (3)\n");
		return -1;
	}

	if (memcmp(out2.data, raw_data.data, raw_data.size) != 0) {
		fprintf(stderr, "Decrypted data don't match original (4)\n");
		return -1;
	}

	/* try again with fixed length API */
	memset(out2.data, 'A', out2.size);
	ret = gnutls_privkey_decrypt_data2(*privkey, 0, &out, out2.data,
					   out2.size);
	if (ret < 0) {
		fprintf(stderr, "gnutls_privkey_decrypt_data: %s\n",
			gnutls_strerror(ret));
		return ret;
	}

	if (memcmp(out2.data, raw_data.data, raw_data.size) != 0) {
		fprintf(stderr, "Decrypted data don't match original (4b)\n");
		return -1;
	}

	printf("ok\n");

	gnutls_free(out.data);
	gnutls_free(out2.data);

	return 0;
}

static int generate_rsa_keys(gnutls_pubkey_t *pubkey, gnutls_privkey_t *privkey)
{
	int ret = 0;

	ret = gnutls_pubkey_init(pubkey);
	if (ret < 0) {
		fprintf(stderr, "gnutls_pubkey_init: %s\n",
			gnutls_strerror(ret));
		return ret;
	}

	ret = gnutls_privkey_init(privkey);
	if (ret < 0) {
		fprintf(stderr, "gnutls_privkey_init: %s\n",
			gnutls_strerror(ret));
		return ret;
	}

	ret = gnutls_privkey_generate(*privkey, GNUTLS_PK_RSA, 2048, 0);
	if (ret < 0) {
		fprintf(stderr, "gnutls_privkey_generate: %s\n",
			gnutls_strerror(ret));
		return ret;
	}

	ret = gnutls_pubkey_import_privkey(*pubkey, *privkey,
					   GNUTLS_KEY_DATA_ENCIPHERMENT, 0);
	if (ret < 0) {
		fprintf(stderr, "gnutls_pubkey_import_privkey: %s\n",
			gnutls_strerror(ret));
		return ret;
	}

	return ret;
}

static int test_rsa(void)
{
	int ret = 0;
	gnutls_pubkey_t pubkey = NULL;
	gnutls_privkey_t privkey = NULL;

	ret = generate_rsa_keys(&pubkey, &privkey);
	if (ret < 0) {
		fprintf(stderr, "Failed to generate RSA keys\n");
		return ret;
	}

	printf("Testing RSA encrypt-decrypt\n");
	ret = test_encrypt_decrypt(&pubkey, &privkey);

	gnutls_privkey_deinit(privkey);
	gnutls_pubkey_deinit(pubkey);
	return ret;
}

static int test_rsa_oaep(void)
{
	int ret = 0;
	gnutls_pubkey_t pubkey = NULL;
	gnutls_privkey_t privkey = NULL;
	gnutls_x509_spki_t spki;
	const gnutls_datum_t label = { (void *)"label", 5 };

	ret = gnutls_x509_spki_init(&spki);
	if (ret < 0) {
		fprintf(stderr, "gnutls_x509_spki_init: %s\n",
			gnutls_strerror(ret));
		return ret;
	}

	ret = gnutls_x509_spki_set_rsa_oaep_params(spki, GNUTLS_DIG_SHA512,
						   &label);
	if (ret < 0) {
		fprintf(stderr, "gnutls_x509_spki_set_rsa_oaep_params: %s\n",
			gnutls_strerror(ret));
		return ret;
	}

	ret = generate_rsa_keys(&pubkey, &privkey);
	if (ret < 0) {
		fprintf(stderr, "Failed to generate RSA keys\n");
		return ret;
	}

	ret = gnutls_privkey_set_spki(privkey, spki, 0);
	if (ret < 0) {
		fprintf(stderr, "gnutls_privkey_set_spki: %s\n",
			gnutls_strerror(ret));
		return ret;
	}

	ret = gnutls_pubkey_set_spki(pubkey, spki, 0);
	if (ret < 0) {
		fprintf(stderr, "gnutls_pubkey_set_spki: %s\n",
			gnutls_strerror(ret));
		return ret;
	}

	printf("Testing RSA OAEP encrypt-decrypt\n");
	ret = test_encrypt_decrypt(&pubkey, &privkey);

	gnutls_x509_spki_deinit(spki);
	gnutls_privkey_deinit(privkey);
	gnutls_pubkey_deinit(pubkey);
	return ret;
}

static int test_ec_keygen(gnutls_ecc_curve_t curve)
{
	int ret;
	gnutls_privkey_t privkey;

	printf("Testing ECDSA key generation\n");

	ret = gnutls_privkey_init(&privkey);
	if (ret < 0) {
		fprintf(stderr, "gnutls_privkey_init: %s\n",
			gnutls_strerror(ret));
		return ret;
	}

	ret = gnutls_privkey_generate(privkey, GNUTLS_PK_EC,
				      GNUTLS_CURVE_TO_BITS(curve), 0);
	if (ret < 0) {
		fprintf(stderr, "gnutls_privkey_generate: %s\n",
			gnutls_strerror(ret));
		return ret;
	}

	printf("ok\n");

	gnutls_privkey_deinit(privkey);
	return 0;
}

int main(void)
{
	int ret;

	gnutls_global_init();

	ret = test_rsa();
	if (ret < 0)
		goto cleanup;

	ret = test_rsa_oaep();
	if (ret < 0)
		goto cleanup;

	ret = test_ec_keygen(GNUTLS_ECC_CURVE_SECP256R1);
	if (ret < 0)
		goto cleanup;

cleanup:
	gnutls_global_deinit();
	return ret;
}
