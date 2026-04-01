/*
 * Copyright (C) 2022 Red Hat, Inc.
 *
 * Author: Daiki Ueno
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

#include "config.h"

#include <gnutls/crypto.h>
#include <limits.h>
#include <stdint.h>
#include <stdio.h>
#include "utils.h"

static void tls_log_func(int level, const char *str)
{
	fprintf(stderr, "<%d>| %s", level, str);
}

#define CLAMP(x, b) (((x) + (b)) / (b)) * (b)

static void start(gnutls_cipher_algorithm_t algo, size_t plaintext_size,
		  unsigned int flags)
{
	int ret;
	gnutls_cipher_hd_t ch;
	uint8_t key16[64];
	uint8_t iv16[32];
	uint8_t plaintext[128];
	uint8_t plaintext2[128];
	uint8_t ciphertext[128];
	size_t block_size;
	size_t size;
	size_t ciphertext_size;
	gnutls_datum_t key, iv;

	success("%s %zu %u\n", gnutls_cipher_get_name(algo), plaintext_size,
		flags);

	block_size = gnutls_cipher_get_block_size(algo);

	key.data = key16;
	key.size = gnutls_cipher_get_key_size(algo);
	assert(key.size <= sizeof(key16));

	iv.data = iv16;
	iv.size = gnutls_cipher_get_iv_size(algo);
	assert(iv.size <= sizeof(iv16));

	memset(iv.data, 0xff, iv.size);
	memset(key.data, 0xfe, key.size);
	memset(plaintext, 0xfa, sizeof(plaintext));

	ret = gnutls_cipher_init(&ch, algo, &key, &iv);
	if (ret < 0) {
		fail("gnutls_cipher_init failed\n");
	}

	/* Check overflow if PKCS#7 is requested */
	if (flags & GNUTLS_CIPHER_PADDING_PKCS7) {
		ret = gnutls_cipher_encrypt3(ch, plaintext, SIZE_MAX, NULL,
					     &size, flags);
		if (ret != GNUTLS_E_INVALID_REQUEST) {
			fail("gnutls_cipher_encrypt3 succeeded\n");
		}
	}

	/* Get the ciphertext size */
	ret = gnutls_cipher_encrypt3(ch, plaintext, plaintext_size, NULL,
				     &ciphertext_size, flags);
	if (ret < 0) {
		fail("gnutls_cipher_encrypt3 failed\n");
	}

	if (flags & GNUTLS_CIPHER_PADDING_PKCS7) {
		if (ciphertext_size <= plaintext_size) {
			fail("no padding appended\n");
		}
		if (ciphertext_size != CLAMP(plaintext_size, block_size)) {
			fail("size does not match: %zu (expected %zu)\n",
			     ciphertext_size,
			     CLAMP(plaintext_size, block_size));
		}
	} else {
		if (ciphertext_size != plaintext_size) {
			fail("size does not match: %zu (expected %zu)\n",
			     ciphertext_size, plaintext_size);
		}
	}

	/* Encrypt with padding */
	ret = gnutls_cipher_encrypt3(ch, plaintext, plaintext_size, ciphertext,
				     &ciphertext_size, flags);
	if (ret < 0) {
		fail("gnutls_cipher_encrypt3 failed\n");
	}

	/* Decrypt with padding */
	size = ciphertext_size;
	ret = gnutls_cipher_decrypt3(ch, ciphertext, ciphertext_size,
				     plaintext2, &size, flags);
	if (ret < 0) {
		fail("gnutls_cipher_decrypt3 failed\n");
	}

	if (size != plaintext_size) {
		fail("size does not match: %zu (expected %zu)\n", size,
		     plaintext_size);
	}

	if (memcmp(plaintext2, plaintext, size) != 0) {
		fail("plaintext does not match\n");
	}

	if ((flags & GNUTLS_CIPHER_PADDING_PKCS7) &&
	    plaintext_size % block_size != 0) {
		/* Encrypt with manual padding */
		memset(&plaintext[plaintext_size],
		       ciphertext_size - plaintext_size,
		       ciphertext_size - plaintext_size);
		/* Insert a wrong padding byte */
		plaintext[plaintext_size] = block_size;
		ret = gnutls_cipher_encrypt3(ch, plaintext, ciphertext_size,
					     ciphertext, &ciphertext_size, 0);
		if (ret < 0) {
			fail("gnutls_cipher_encrypt3 failed\n");
		}

		/* Decrypt with padding */
		size = ciphertext_size;
		ret = gnutls_cipher_decrypt3(ch, ciphertext, ciphertext_size,
					     plaintext, &size, flags);
		if (ret != GNUTLS_E_DECRYPTION_FAILED) {
			fail("gnutls_cipher_decrypt3 succeeded\n");
		}
	}

	gnutls_cipher_deinit(ch);
}

void doit(void)
{
	int ret;

	gnutls_global_set_log_function(tls_log_func);
	if (debug) {
		gnutls_global_set_log_level(4711);
	}

	ret = global_init();
	if (ret < 0) {
		fail("Cannot initialize library\n");
	}

	start(GNUTLS_CIPHER_AES_128_CBC, 0, GNUTLS_CIPHER_PADDING_PKCS7);
	start(GNUTLS_CIPHER_AES_128_CBC, 11, GNUTLS_CIPHER_PADDING_PKCS7);
	start(GNUTLS_CIPHER_AES_128_CBC, 77, GNUTLS_CIPHER_PADDING_PKCS7);
	start(GNUTLS_CIPHER_AES_128_CBC, 80, GNUTLS_CIPHER_PADDING_PKCS7);

	start(GNUTLS_CIPHER_AES_128_CBC, 0, 0);
	start(GNUTLS_CIPHER_AES_128_CBC, 80, 0);

	gnutls_global_deinit();
}
