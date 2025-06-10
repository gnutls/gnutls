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

#include <assert.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <gnutls/gnutls.h>
#include <gnutls/crypto.h>

static int test_cipher(const char *alg_str, int alg)
{
	int ret;
	gnutls_cipher_hd_t ch;
	gnutls_datum_t key, iv;
	uint8_t key16[64], iv16[32], ptext[128], data[128];

	key.data = key16;
	key.size = gnutls_cipher_get_key_size(alg);
	assert(key.size <= sizeof(key16));

	iv.data = iv16;
	iv.size = gnutls_cipher_get_iv_size(alg);
	assert(iv.size <= sizeof(iv16));

	memset(iv.data, 0xff, iv.size);
	memset(key.data, 0xfe, key.size);
	memset(ptext, 0xfa, sizeof(ptext));
	memset(data, 0xfa, sizeof(data));

	printf("Testing %s encrypt-decrypt\n", alg_str);

	ret = gnutls_cipher_init(&ch, alg, &key, &iv);
	if (ret < 0) {
		fprintf(stderr, "gnutls_cipher_init: %s\n",
			gnutls_strerror(ret));
		return ret;
	}

	ret = gnutls_cipher_encrypt(ch, data, sizeof(data));
	if (ret < 0) {
		fprintf(stderr, "gnutls_cipher_encrypt: %s\n",
			gnutls_strerror(ret));
		return ret;
	}

	ret = gnutls_cipher_decrypt(ch, data, sizeof(data));
	if (ret < 0) {
		fprintf(stderr, "gnutls_cipher_decrypt: %s\n",
			gnutls_strerror(ret));
		return ret;
	}

	if (memcmp(data, ptext, sizeof(ptext)) != 0) {
		fprintf(stderr, "Decrypted data don't match original\n");
		return -1;
	}

	printf("ok\n");

	gnutls_cipher_deinit(ch);
	return 0;
}

static int test_aead(const char *alg_str, int alg)
{
	int ret;
	gnutls_aead_cipher_hd_t ch;
	gnutls_datum_t key, iv;
	size_t out_len, ctext_len, tag_len;
	uint8_t key16[64], iv16[32], auth[32], ptext[128];
	uint8_t ctext[128 + 32] = { 0 };
	uint8_t out[128] = { 0 };

	key.data = key16;
	key.size = gnutls_cipher_get_key_size(alg);
	assert(key.size <= sizeof(key16));

	iv.data = iv16;
	iv.size = gnutls_cipher_get_iv_size(alg);
	assert(iv.size <= sizeof(iv16));

	tag_len = gnutls_cipher_get_tag_size(alg);

	memset(iv.data, 0xff, iv.size);
	memset(key.data, 0xfe, key.size);
	memset(ptext, 0xfa, sizeof(ptext));
	memset(auth, 0xfb, sizeof(auth));

	printf("Testing %s AEAD encrypt-decrypt\n", alg_str);

	ret = gnutls_aead_cipher_init(&ch, alg, &key);
	if (ret < 0) {
		fprintf(stderr, "gnutls_aead_cipher_init: %s\n",
			gnutls_strerror(ret));
		return ret;
	}

	ctext_len = sizeof(ctext);
	ret = gnutls_aead_cipher_encrypt(ch, iv.data, iv.size, auth,
					 sizeof(auth), tag_len, ptext,
					 sizeof(ptext), ctext, &ctext_len);
	if (ret < 0) {
		fprintf(stderr, "gnutls_aead_cipher_encrypt: %s\n",
			gnutls_strerror(ret));
		return ret;
	}

	if (ctext_len != sizeof(ptext) + tag_len) {
		fprintf(stderr, "output ciphertext length mismatch\n");
		return -1;
	}

	out_len = sizeof(out);
	ret = gnutls_aead_cipher_decrypt(ch, iv.data, iv.size, auth,
					 sizeof(auth), tag_len, ctext,
					 ctext_len, out, &out_len);
	if (ret < 0) {
		fprintf(stderr, "gnutls_aead_cipher_decrypt\n");
		return ret;
	}

	if (out_len != sizeof(ptext) ||
	    memcmp(out, ptext, sizeof(ptext)) != 0) {
		fprintf(stderr, "mismatch of decrypted data\n");
		return -1;
	}

	printf("ok\n");

	gnutls_aead_cipher_deinit(ch);
	return 0;
}

int main(void)
{
	int ret;

	gnutls_global_init();

	ret = test_cipher("aes128-cbc", GNUTLS_CIPHER_AES_128_CBC);
	if (ret < 0)
		goto cleanup;
	ret = test_cipher("aes192-cbc", GNUTLS_CIPHER_AES_192_CBC);
	if (ret < 0)
		goto cleanup;
	ret = test_cipher("aes256-cbc", GNUTLS_CIPHER_AES_256_CBC);
	if (ret < 0)
		goto cleanup;
	ret = test_aead("aes128-gcm", GNUTLS_CIPHER_AES_128_GCM);
	if (ret < 0)
		goto cleanup;
	ret = test_aead("aes192-gcm", GNUTLS_CIPHER_AES_192_GCM);
	if (ret < 0)
		goto cleanup;
	ret = test_aead("aes256-gcm", GNUTLS_CIPHER_AES_256_GCM);
	if (ret < 0)
		goto cleanup;

cleanup:
	gnutls_global_deinit();
	return ret;
}
