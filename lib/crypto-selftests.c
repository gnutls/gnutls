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
#include <random.h>
#include <crypto.h>

/* This does check the AES and SHA implementation against test vectors.
 * This should not run under valgrind in order to use the native
 * cpu instructions (AES-NI or padlock).
 */

struct cipher_vectors_st {
	const uint8_t *key;
	unsigned int key_size;

	const uint8_t *plaintext;
	unsigned int plaintext_size;
	const uint8_t *ciphertext;	/* also of plaintext_size */

	const uint8_t *iv;
	unsigned int iv_size;
};

struct cipher_aead_vectors_st {
	const uint8_t *key;
	unsigned int key_size;

	const uint8_t *auth;
	unsigned int auth_size;

	const uint8_t *plaintext;
	unsigned int plaintext_size;
	const uint8_t *ciphertext;	/* also of plaintext_size */

	unsigned int iv_size;
	const uint8_t *iv;
	const uint8_t *tag;
};

const struct cipher_aead_vectors_st aes128_gcm_vectors[] = {
	{
	 .key = (void *)
	 "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00",
	 .key_size = 16,
	 .auth = NULL,
	 .auth_size = 0,
	 .plaintext = NULL,
	 .plaintext_size = 0,
	 .ciphertext = NULL,
	 .iv_size = 12,
	 .iv = (void *) "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00",
	 .tag = (void *)
	 "\x58\xe2\xfc\xce\xfa\x7e\x30\x61\x36\x7f\x1d\x57\xa4\xe7\x45\x5a"},
	{
	 .key = (void *)
	 "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00",
	 .key_size = 16,
	 .auth = NULL,
	 .auth_size = 0,
	 .plaintext = (void *)
	 "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00",
	 .plaintext_size = 16,
	 .ciphertext = (void *)
	 "\x03\x88\xda\xce\x60\xb6\xa3\x92\xf3\x28\xc2\xb9\x71\xb2\xfe\x78",
	 .iv_size = 12,
	 .iv = (void *) "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00",
	 .tag = (void *)
	 "\xab\x6e\x47\xd4\x2c\xec\x13\xbd\xf5\x3a\x67\xb2\x12\x57\xbd\xdf"},
	{
	 .key = (void *)
	 "\xfe\xff\xe9\x92\x86\x65\x73\x1c\x6d\x6a\x8f\x94\x67\x30\x83\x08",
	 .key_size = 16,
	 .auth = (void *)
	 "\xfe\xed\xfa\xce\xde\xad\xbe\xef\xfe\xed\xfa\xce\xde\xad\xbe\xef\xab\xad\xda\xd2",
	 .auth_size = 20,
	 .plaintext = (void *)
	 "\xd9\x31\x32\x25\xf8\x84\x06\xe5\xa5\x59\x09\xc5\xaf\xf5\x26\x9a\x86\xa7\xa9\x53\x15\x34\xf7\xda\x2e\x4c\x30\x3d\x8a\x31\x8a\x72\x1c\x3c\x0c\x95\x95\x68\x09\x53\x2f\xcf\x0e\x24\x49\xa6\xb5\x25\xb1\x6a\xed\xf5\xaa\x0d\xe6\x57\xba\x63\x7b\x39",
	 .plaintext_size = 60,
	 .ciphertext = (void *)
	 "\x42\x83\x1e\xc2\x21\x77\x74\x24\x4b\x72\x21\xb7\x84\xd0\xd4\x9c\xe3\xaa\x21\x2f\x2c\x02\xa4\xe0\x35\xc1\x7e\x23\x29\xac\xa1\x2e\x21\xd5\x14\xb2\x54\x66\x93\x1c\x7d\x8f\x6a\x5a\xac\x84\xaa\x05\x1b\xa3\x0b\x39\x6a\x0a\xac\x97\x3d\x58\xe0\x91",
	 .iv_size = 12,
	 .iv = (void *) "\xca\xfe\xba\xbe\xfa\xce\xdb\xad\xde\xca\xf8\x88",
	 .tag = (void *)
	 "\x5b\xc9\x4f\xbc\x32\x21\xa5\xdb\x94\xfa\xe9\x5a\xe7\x12\x1a\x47"}
};

const struct cipher_aead_vectors_st aes256_gcm_vectors[] = {
	{
	 .key = (void *)
	 "\xfe\xff\xe9\x92\x86\x65\x73\x1c\x6d\x6a\x8f\x94\x67\x30\x83\x08\xfe\xff\xe9\x92\x86\x65\x73\x1c\x6d\x6a\x8f\x94\x67\x30\x83\x08",
	 .key_size = 32,
	 .auth = NULL,
	 .auth_size = 0,
	 .plaintext = (uint8_t*)"\xd9\x31\x32\x25\xf8\x84\x06\xe5\xa5\x59\x09\xc5\xaf\xf5\x26\x9a\x86\xa7\xa9\x53\x15\x34\xf7\xda\x2e\x4c\x30\x3d\x8a\x31\x8a\x72\x1c\x3c\x0c\x95\x95\x68\x09\x53\x2f\xcf\x0e\x24\x49\xa6\xb5\x25\xb1\x6a\xed\xf5\xaa\x0d\xe6\x57\xba\x63\x7b\x39\x1a\xaf\xd2\x55",
	 .plaintext_size = 64,
	 .ciphertext = (uint8_t*)"\x52\x2d\xc1\xf0\x99\x56\x7d\x07\xf4\x7f\x37\xa3\x2a\x84\x42\x7d\x64\x3a\x8c\xdc\xbf\xe5\xc0\xc9\x75\x98\xa2\xbd\x25\x55\xd1\xaa\x8c\xb0\x8e\x48\x59\x0d\xbb\x3d\xa7\xb0\x8b\x10\x56\x82\x88\x38\xc5\xf6\x1e\x63\x93\xba\x7a\x0a\xbc\xc9\xf6\x62\x89\x80\x15\xad",
	 .iv_size = 12,
	 .iv = (void *) "\xca\xfe\xba\xbe\xfa\xce\xdb\xad\xde\xca\xf8\x88",
	 .tag = (void *)
	 "\xb0\x94\xda\xc5\xd9\x34\x71\xbd\xec\x1a\x50\x22\x70\xe3\xcc\x6c"},

};

const struct cipher_vectors_st aes128_cbc_vectors[] = {
	{
	 .key = (uint8_t *)
	 "\x2b\x7e\x15\x16\x28\xae\xd2\xa6\xab\xf7\x15\x88\x09\xcf\x4f\x3c",
	 .key_size = 16,
	 .plaintext_size = 16,
	 .plaintext = (uint8_t *)
	 "\x6b\xc1\xbe\xe2\x2e\x40\x9f\x96\xe9\x3d\x7e\x11\x73\x93\x17\x2a",
	 .ciphertext = (uint8_t *)
	 "\x76\x49\xab\xac\x81\x19\xb2\x46\xce\xe9\x8e\x9b\x12\xe9\x19\x7d",
	 .iv_size = 16,
	 .iv = (uint8_t *)
	 "\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0A\x0B\x0C\x0D\x0E\x0F",
	},
	{
	 .key = (uint8_t *)
	 "\x2b\x7e\x15\x16\x28\xae\xd2\xa6\xab\xf7\x15\x88\x09\xcf\x4f\x3c",
	 .key_size = 16,
	 .plaintext_size = 16,
	 .plaintext = (uint8_t *)
	 "\xae\x2d\x8a\x57\x1e\x03\xac\x9c\x9e\xb7\x6f\xac\x45\xaf\x8e\x51",
	 .ciphertext = (uint8_t *)
	 "\x50\x86\xcb\x9b\x50\x72\x19\xee\x95\xdb\x11\x3a\x91\x76\x78\xb2",
	 .iv_size = 16,
	 .iv = (uint8_t *)
	 "\x76\x49\xab\xac\x81\x19\xb2\x46\xce\xe9\x8e\x9b\x12\xe9\x19\x7d",
	 },
};

const struct cipher_vectors_st aes192_cbc_vectors[] = {
	{
	 .key = (uint8_t *)
	 "\x8e\x73\xb0\xf7\xda\x0e\x64\x52\xc8\x10\xf3\x2b\x80\x90\x79\xe5\x62\xf8\xea\xd2\x52\x2c\x6b\x7b",
	 .key_size = 24,
	 .plaintext_size = 16,
	 .plaintext = (uint8_t *)
	 "\x6b\xc1\xbe\xe2\x2e\x40\x9f\x96\xe9\x3d\x7e\x11\x73\x93\x17\x2a",
	 .ciphertext = (uint8_t *)
	 "\x4f\x02\x1d\xb2\x43\xbc\x63\x3d\x71\x78\x18\x3a\x9f\xa0\x71\xe8",
	 .iv_size = 16,
	 .iv = (uint8_t *)
	 "\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0A\x0B\x0C\x0D\x0E\x0F",
    },
	{
	 .key = (uint8_t *)
	 "\x8e\x73\xb0\xf7\xda\x0e\x64\x52\xc8\x10\xf3\x2b\x80\x90\x79\xe5\x62\xf8\xea\xd2\x52\x2c\x6b\x7b",
	 .key_size = 24,
	 .plaintext_size = 16,
	 .plaintext = (uint8_t *)
	 "\xae\x2d\x8a\x57\x1e\x03\xac\x9c\x9e\xb7\x6f\xac\x45\xaf\x8e\x51",
	 .ciphertext = (uint8_t *)
	 "\xb4\xd9\xad\xa9\xad\x7d\xed\xf4\xe5\xe7\x38\x76\x3f\x69\x14\x5a",
	 .iv_size = 16,
	 .iv = (uint8_t *)
	 "\x4F\x02\x1D\xB2\x43\xBC\x63\x3D\x71\x78\x18\x3A\x9F\xA0\x71\xE8",
	 },
};

const struct cipher_vectors_st aes256_cbc_vectors[] = {
	{
	 .key = (uint8_t *)
	 "\x60\x3d\xeb\x10\x15\xca\x71\xbe\x2b\x73\xae\xf0\x85\x7d\x77\x81\x1f\x35\x2c\x07\x3b\x61\x08\xd7\x2d\x98\x10\xa3\x09\x14\xdf\xf4",
	 .key_size = 32,
	 .plaintext_size = 16,
	 .plaintext = (uint8_t *)
	 "\x6b\xc1\xbe\xe2\x2e\x40\x9f\x96\xe9\x3d\x7e\x11\x73\x93\x17\x2a",
	 .ciphertext = (uint8_t *)
	 "\xF5\x8C\x4C\x04\xD6\xE5\xF1\xBA\x77\x9E\xAB\xFB\x5F\x7B\xFB\xD6",
	 .iv_size = 16,
	 .iv = (uint8_t *)
	 "\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0A\x0B\x0C\x0D\x0E\x0F",
    },
	{
	 .key = (uint8_t *)
	 "\x60\x3d\xeb\x10\x15\xca\x71\xbe\x2b\x73\xae\xf0\x85\x7d\x77\x81\x1f\x35\x2c\x07\x3b\x61\x08\xd7\x2d\x98\x10\xa3\x09\x14\xdf\xf4",
	 .key_size = 32,
	 .plaintext_size = 16,
	 .plaintext = (uint8_t *)
	 "\xae\x2d\x8a\x57\x1e\x03\xac\x9c\x9e\xb7\x6f\xac\x45\xaf\x8e\x51",
	 .ciphertext = (uint8_t *)
	 "\x9c\xfc\x4e\x96\x7e\xdb\x80\x8d\x67\x9f\x77\x7b\xc6\x70\x2c\x7d",
	 .iv_size = 16,
	 .iv = (uint8_t *)
	 "\xF5\x8C\x4C\x04\xD6\xE5\xF1\xBA\x77\x9E\xAB\xFB\x5F\x7B\xFB\xD6",
	 },
};

const struct cipher_vectors_st tdes_cbc_vectors[] = {
/* First 2 from https://www.cosic.esat.kuleuven.be/nessie/testvectors/bc/des/Triple-Des-3-Key-192-64.unverified.test-vectors */
	{
	 .key = (uint8_t *)
	 "\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0A\x0B\x0C\x0D\x0E\x0F\x10\x11\x12\x13\x14\x15\x16\x17",
	 .key_size = 24,
	 .plaintext_size = 8,
	 .plaintext = (uint8_t *)
	 "\x98\x26\x62\x60\x55\x53\x24\x4D",
	 .ciphertext = (uint8_t *)
	 "\x00\x11\x22\x33\x44\x55\x66\x77",
	 .iv_size = 8,
	 .iv = (uint8_t *)
	 "\x00\x00\x00\x00\x00\x00\x00\x00",
	},
	{
	 .key = (uint8_t *)
	 "\x2B\xD6\x45\x9F\x82\xC5\xB3\x00\x95\x2C\x49\x10\x48\x81\xFF\x48\x2B\xD6\x45\x9F\x82\xC5\xB3\x00",
	 .key_size = 24,
	 .plaintext_size = 8,
	 .plaintext = (uint8_t *)
	 "\x85\x98\x53\x8A\x8E\xCF\x11\x7D",
	 .ciphertext = (uint8_t *)
	 "\xEA\x02\x47\x14\xAD\x5C\x4D\x84",
	 .iv_size = 8,
	 .iv = (uint8_t *)
	 "\x00\x00\x00\x00\x00\x00\x00\x00",
	},
};

static int test_cipher(gnutls_cipher_algorithm_t cipher,
		const struct cipher_vectors_st *vectors,
		size_t vectors_size)
{
	gnutls_cipher_hd_t hd;
	int ret;
	unsigned int i;
	uint8_t tmp[128];
	gnutls_datum_t key, iv;

	for (i = 0; i < vectors_size; i++) {
		key.data = (void *) vectors[i].key;
		key.size = vectors[i].key_size;

		iv.data = (void *) vectors[i].iv;
		iv.size = gnutls_cipher_get_iv_size(cipher);
		
		if (iv.size != vectors[i].iv_size)
			return gnutls_assert_val(GNUTLS_E_SELF_TEST_ERROR);

		ret =
		    gnutls_cipher_init(&hd, cipher, &key, &iv);
		if (ret < 0) {
			_gnutls_debug_log("error initializing: %s\n",
					  gnutls_cipher_get_name(cipher));
			return gnutls_assert_val(GNUTLS_E_SELF_TEST_ERROR);
		}

		ret =
		    gnutls_cipher_encrypt2(hd,
					   vectors[i].plaintext,
					   vectors[i].plaintext_size, 
					   tmp, sizeof(tmp));
		if (ret < 0)
			return 0;

		gnutls_cipher_deinit(hd);

		if (memcmp
		    (tmp, vectors[i].ciphertext,
		     vectors[i].plaintext_size) != 0) {
			_gnutls_debug_log("%s test vector %d failed!\n",
					  gnutls_cipher_get_name(cipher), i);
		}
	}

	iv.size = gnutls_cipher_get_iv_size(cipher);

	for (i = 0; i < vectors_size; i++) {
		key.data = (void *) vectors[i].key;
		key.size = vectors[i].key_size;

		iv.data = (void *) vectors[i].iv;

		ret =
		    gnutls_cipher_init(&hd, cipher, &key, &iv);
		if (ret < 0)
			return gnutls_assert_val(GNUTLS_E_SELF_TEST_ERROR);

		ret =
		    gnutls_cipher_decrypt2(hd,
					   vectors[i].
					   ciphertext, 16, tmp,
					   sizeof(tmp));
		if (ret < 0) {
			_gnutls_debug_log("%s decryption of test vector %d failed!\n",
					  gnutls_cipher_get_name(cipher), i);
			return gnutls_assert_val(GNUTLS_E_SELF_TEST_ERROR);
		}

		gnutls_cipher_deinit(hd);

		if (memcmp(tmp, vectors[i].plaintext, vectors[i].plaintext_size) != 0) {
			_gnutls_debug_log("%s test vector %d failed!\n",
					  gnutls_cipher_get_name(cipher), i);
			return gnutls_assert_val(GNUTLS_E_SELF_TEST_ERROR);
		}
	}

    _gnutls_debug_log
			    ("%s self check was successful\n",
			         gnutls_cipher_get_name(cipher));

	return 0;

}

/* AEAD modes */
static int test_cipher_aead(gnutls_cipher_algorithm_t cipher, 
		const struct cipher_aead_vectors_st* vectors,
		size_t vectors_size)
{
	gnutls_cipher_hd_t hd;
	int ret;
	unsigned int i;
	uint8_t tmp[128];
	gnutls_datum_t key, iv;

	for (i = 0; i < vectors_size; i++) {
		memset(tmp, 0, sizeof(tmp));
		key.data = (void *) vectors[i].key;
		key.size = vectors[i].key_size;

		iv.data = (void *) vectors[i].iv;
		iv.size = gnutls_cipher_get_iv_size(cipher);

		if (iv.size != vectors[i].iv_size)
			return gnutls_assert_val(GNUTLS_E_SELF_TEST_ERROR);

		ret =
		    gnutls_cipher_init(&hd, cipher, &key, &iv);
		if (ret < 0) {
			_gnutls_debug_log("error initializing: %s\n",
					  gnutls_cipher_get_name(cipher));
			return gnutls_assert_val(GNUTLS_E_SELF_TEST_ERROR);
		}

		if (vectors[i].auth_size > 0) {
			ret =
			    gnutls_cipher_add_auth(hd,
						   vectors[i].
						   auth,
						   vectors[i].
						   auth_size);

			if (ret < 0)
				return
				    gnutls_assert_val
				    (GNUTLS_E_SELF_TEST_ERROR);
		}

		if (vectors[i].plaintext_size > 0) {
			ret =
			    gnutls_cipher_encrypt2(hd,
						   vectors[i].
						   plaintext,
						   vectors
						   [i].plaintext_size, tmp,
						   sizeof(tmp));
			if (ret < 0)
				return
				    gnutls_assert_val
				    (GNUTLS_E_SELF_TEST_ERROR);
		}


		if (vectors[i].plaintext_size > 0)
			if (memcmp
			    (tmp, vectors[i].ciphertext,
			     vectors[i].plaintext_size) != 0) {
				_gnutls_debug_log
				    ("%s test vector %d failed!\n",
  				      gnutls_cipher_get_name(cipher), i);
				return
				    gnutls_assert_val
				    (GNUTLS_E_SELF_TEST_ERROR);
			}

		gnutls_cipher_tag(hd, tmp, 16);
		if (memcmp(tmp, vectors[i].tag, 16) != 0) {
			_gnutls_debug_log
			    ("%s test vector %d failed (tag)!\n",
			         gnutls_cipher_get_name(cipher), i);
			return gnutls_assert_val(GNUTLS_E_SELF_TEST_ERROR);
		}

		gnutls_cipher_deinit(hd);
	}

    _gnutls_debug_log
			    ("%s self check was successful\n",
			         gnutls_cipher_get_name(cipher));

	return 0;

}

#if 0
struct hash_vectors_st {
	const char *name;
	int algorithm;
	const uint8_t *key;	/* if hmac */
	unsigned int key_size;
	const uint8_t *plaintext;
	unsigned int plaintext_size;
	const uint8_t *output;
	unsigned int output_size;
} hash_vectors[] = {
	{
		.name = "SHA1",.algorithm = GNUTLS_MAC_SHA1,.key =
		    NULL,.plaintext =
		    (uint8_t *) "what do ya want for nothing?",.
		    plaintext_size =
		    sizeof("what do ya want for nothing?") - 1,.output =
		    (uint8_t *)
	"\x8f\x82\x03\x94\xf9\x53\x35\x18\x20\x45\xda\x24\xf3\x4d\xe5\x2b\xf8\xbc\x34\x32",.
		    output_size = 20,}
	, {
		.name = "SHA1",.algorithm = GNUTLS_MAC_SHA1,.key =
		    NULL,.plaintext = (uint8_t *)
		    "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopqabcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopqabcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq",.
		    plaintext_size =
		    sizeof
		    ("abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopqabcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopqabcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq")
		    - 1,.output = (uint8_t *)
	"\xbe\xae\xd1\x6d\x65\x8e\xc7\x92\x9e\xdf\xd6\x2b\xfa\xfe\xac\x29\x9f\x0d\x74\x4d",.
		    output_size = 20,}
	, {
		.name = "SHA256",.algorithm = GNUTLS_MAC_SHA256,.key =
		    NULL,.plaintext = (uint8_t *)
		    "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq",.
		    plaintext_size =
		    sizeof
		    ("abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq")
		    - 1,.output = (uint8_t *)
	"\x24\x8d\x6a\x61\xd2\x06\x38\xb8\xe5\xc0\x26\x93\x0c\x3e\x60\x39\xa3\x3c\xe4\x59\x64\xff\x21\x67\xf6\xec\xed\xd4\x19\xdb\x06\xc1",.
		    output_size = 32,}
	, {
		.name = "SHA256",.algorithm = GNUTLS_MAC_SHA256,.key =
		    NULL,.plaintext = (uint8_t *)
		    "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopqabcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopqabcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq",.
		    plaintext_size =
		    sizeof
		    ("abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopqabcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopqabcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq")
		    - 1,.output = (uint8_t *)
	"\x50\xea\x82\x5d\x96\x84\xf4\x22\x9c\xa2\x9f\x1f\xec\x51\x15\x93\xe2\x81\xe4\x6a\x14\x0d\x81\xe0\x00\x5f\x8f\x68\x86\x69\xa0\x6c",.
		    output_size = 32,}
	, {
		.name = "SHA512",.algorithm = GNUTLS_MAC_SHA512,.key =
		    NULL,.plaintext = (uint8_t *)
		    "abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu",.
		    plaintext_size =
		    sizeof
		    ("abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu")
		    - 1,.output = (uint8_t *)
	"\x8e\x95\x9b\x75\xda\xe3\x13\xda\x8c\xf4\xf7\x28\x14\xfc\x14\x3f\x8f\x77\x79\xc6\xeb\x9f\x7f\xa1\x72\x99\xae\xad\xb6\x88\x90\x18\x50\x1d\x28\x9e\x49\x00\xf7\xe4\x33\x1b\x99\xde\xc4\xb5\x43\x3a\xc7\xd3\x29\xee\xb6\xdd\x26\x54\x5e\x96\xe5\x5b\x87\x4b\xe9\x09",.
		    output_size = 64,}
	, {
		.name = "HMAC-MD5",.algorithm = GNUTLS_MAC_MD5,.key =
		    (uint8_t *) "Jefe",.key_size = 4,.plaintext =
		    (uint8_t *)
		    "what do ya want for nothing?",.plaintext_size =
		    sizeof("what do ya want for nothing?") - 1,.output =
		    (uint8_t *)
	"\x75\x0c\x78\x3e\x6a\xb0\xb5\x03\xea\xa8\x6e\x31\x0a\x5d\xb7\x38",.
		    output_size = 16,}
	,
	    /* from rfc4231 */
	{
		.name = "HMAC-SHA2-224",.algorithm =
		    GNUTLS_MAC_SHA224,.key = (uint8_t *)
		    "\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b",.
		    key_size = 20,.plaintext =
		    (uint8_t *) "Hi There",.plaintext_size =
		    sizeof("Hi There") - 1,.output = (uint8_t *)
	"\x89\x6f\xb1\x12\x8a\xbb\xdf\x19\x68\x32\x10\x7c\xd4\x9d\xf3\x3f\x47\xb4\xb1\x16\x99\x12\xba\x4f\x53\x68\x4b\x22",.
		    output_size = 28,}
	, {
		.name = "HMAC-SHA2-256",.algorithm =
		    GNUTLS_MAC_SHA256,.key = (uint8_t *)
		    "\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b",.
		    key_size = 20,.plaintext =
		    (uint8_t *) "Hi There",.plaintext_size =
		    sizeof("Hi There") - 1,.output = (uint8_t *)
	"\xb0\x34\x4c\x61\xd8\xdb\x38\x53\x5c\xa8\xaf\xce\xaf\x0b\xf1\x2b\x88\x1d\xc2\x00\xc9\x83\x3d\xa7\x26\xe9\x37\x6c\x2e\x32\xcf\xf7",.
		    output_size = 32,}
	, {
		.name = "HMAC-SHA2-384",.algorithm =
		    GNUTLS_MAC_SHA384,.key = (uint8_t *)
		    "\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b",.
		    key_size = 20,.plaintext =
		    (uint8_t *) "Hi There",.plaintext_size =
		    sizeof("Hi There") - 1,.output = (uint8_t *)
	"\xaf\xd0\x39\x44\xd8\x48\x95\x62\x6b\x08\x25\xf4\xab\x46\x90\x7f\x15\xf9\xda\xdb\xe4\x10\x1e\xc6\x82\xaa\x03\x4c\x7c\xeb\xc5\x9c\xfa\xea\x9e\xa9\x07\x6e\xde\x7f\x4a\xf1\x52\xe8\xb2\xfa\x9c\xb6",.
		    output_size = 48,}
	, {
		.name = "HMAC-SHA2-512",.algorithm =
		    GNUTLS_MAC_SHA512,.key = (uint8_t *)
		    "\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b",.
		    key_size = 20,.plaintext =
		    (uint8_t *) "Hi There",.plaintext_size =
		    sizeof("Hi There") - 1,.output = (uint8_t *)
	"\x87\xaa\x7c\xde\xa5\xef\x61\x9d\x4f\xf0\xb4\x24\x1a\x1d\x6c\xb0\x23\x79\xf4\xe2\xce\x4e\xc2\x78\x7a\xd0\xb3\x05\x45\xe1\x7c\xde\xda\xa8\x33\xb7\xd6\xb8\xa7\x02\x03\x8b\x27\x4e\xae\xa3\xf4\xe4\xbe\x9d\x91\x4e\xeb\x61\xf1\x70\x2e\x69\x6c\x20\x3a\x12\x68\x54",.
		    output_size = 64,}
,};

#define HASH_DATA_SIZE 64

/* SHA1 and other hashes */
static int test_hash(void)
{
	uint8_t data[HASH_DATA_SIZE];
	unsigned int i, j;
	int ret;
	size_t data_size;

	fprintf(stdout, "Tests on Hashes\n");
	for (i = 0; i < sizeof(hash_vectors) / sizeof(hash_vectors[0]);
	     i++) {

		fprintf(stdout, "\t%s: ", hash_vectors[i].name);
		/* import key */
		if (hash_vectors[i].key != NULL) {
#if 0
			ret =
			    gnutls_hmac_fast(hash_vectors[i].algorithm,
					     hash_vectors[i].key,
					     hash_vectors[i].key_size,
					     hash_vectors[i].plaintext,
					     hash_vectors[i].
					     plaintext_size, data);
			if (ret < 0) {
				fprintf(stderr, "Error: %s:%d\n", __func__,
					__LINE__);
				return 1;
			}
#else
			gnutls_hmac_hd_t hd;

			ret =
			    gnutls_hmac_init(&hd,
					     hash_vectors[i].algorithm,
					     hash_vectors[i].key,
					     hash_vectors[i].key_size);
			if (ret < 0) {
				fprintf(stderr, "Error: %s:%d\n", __func__,
					__LINE__);
				return 1;
			}

			ret =
			    gnutls_hmac(hd, hash_vectors[i].plaintext,
					hash_vectors[i].plaintext_size -
					1);
			if (ret < 0) {
				fprintf(stderr, "Error: %s:%d\n", __func__,
					__LINE__);
				return 1;
			}

			ret =
			    gnutls_hmac(hd,
					&hash_vectors[i].
					plaintext[hash_vectors[i].
						  plaintext_size - 1], 1);
			if (ret < 0) {
				fprintf(stderr, "Error: %s:%d\n", __func__,
					__LINE__);
				return 1;
			}

			gnutls_hmac_output(hd, data);
			gnutls_hmac_deinit(hd, NULL);
#endif

			data_size =
			    gnutls_hmac_get_len(hash_vectors[i].algorithm);
			if (ret < 0) {
				fprintf(stderr, "Error: %s:%d\n", __func__,
					__LINE__);
				return 1;
			}
		} else {
			gnutls_hash_hd_t hd;
			ret =
			    gnutls_hash_init(&hd,
					     hash_vectors[i].algorithm);
			if (ret < 0) {
				fprintf(stderr, "Error: %s:%d\n", __func__,
					__LINE__);
				return 1;
			}

			ret = gnutls_hash(hd,
					  hash_vectors[i].plaintext, 1);
			if (ret < 0) {
				fprintf(stderr, "Error: %s:%d\n", __func__,
					__LINE__);
				return 1;
			}

			ret = gnutls_hash(hd,
					  &hash_vectors[i].plaintext[1],
					  hash_vectors[i].plaintext_size -
					  1);
			if (ret < 0) {
				fprintf(stderr, "Error: %s:%d\n", __func__,
					__LINE__);
				return 1;
			}

			gnutls_hash_output(hd, data);
			gnutls_hash_deinit(hd, NULL);

			data_size =
			    gnutls_hash_get_len(hash_vectors[i].algorithm);
			if (ret < 0) {
				fprintf(stderr, "Error: %s:%d\n", __func__,
					__LINE__);
				return 1;
			}
		}

		if (data_size != hash_vectors[i].output_size ||
		    memcmp(data, hash_vectors[i].output,
			   hash_vectors[i].output_size) != 0) {
			fprintf(stderr, "HASH test vector %d failed!\n",
				i);

			fprintf(stderr, "Output[%d]: ", (int) data_size);
			for (j = 0; j < data_size; j++)
				fprintf(stderr, "%.2x:", (int) data[j]);
			fprintf(stderr, "\n");

			fprintf(stderr, "Expected[%d]: ",
				hash_vectors[i].output_size);
			for (j = 0; j < hash_vectors[i].output_size; j++)
				fprintf(stderr, "%.2x:",
					(int) hash_vectors[i].output[j]);
			fprintf(stderr, "\n");
			return 1;
		}

		fprintf(stdout, "ok\n");
	}

	fprintf(stdout, "\n");

	return 0;

}
#endif

/**
 * gnutls_cipher_self_test:
 * @cipher: the encryption algorithm to use
 *
 * This function will run self tests on the provided cipher.
 *
 * Returns: Zero or a negative error code on error.
 *
 * Since: 3.3.0
 **/
int gnutls_cipher_self_test(gnutls_cipher_algorithm_t cipher)
{
	switch (cipher) {
		case GNUTLS_CIPHER_AES_128_CBC:
			return test_cipher(cipher, aes128_cbc_vectors, sizeof(aes128_cbc_vectors)/sizeof(aes128_cbc_vectors[0]));

		case GNUTLS_CIPHER_AES_192_CBC:
			return test_cipher(cipher, aes192_cbc_vectors, sizeof(aes192_cbc_vectors)/sizeof(aes192_cbc_vectors[0]));

		case GNUTLS_CIPHER_AES_256_CBC:
			return test_cipher(cipher, aes256_cbc_vectors, sizeof(aes256_cbc_vectors)/sizeof(aes256_cbc_vectors[0]));

		case GNUTLS_CIPHER_AES_128_GCM:
			return test_cipher_aead(cipher, aes128_gcm_vectors, sizeof(aes128_gcm_vectors)/sizeof(aes128_gcm_vectors[0]));

		case GNUTLS_CIPHER_AES_256_GCM:
			return test_cipher_aead(cipher, aes256_gcm_vectors, sizeof(aes256_gcm_vectors)/sizeof(aes256_gcm_vectors[0]));

		case GNUTLS_CIPHER_3DES_CBC:
			return test_cipher(cipher, tdes_cbc_vectors, sizeof(tdes_cbc_vectors)/sizeof(tdes_cbc_vectors[0]));
		default:
			return gnutls_assert_val(GNUTLS_E_NO_SELF_TEST);
	}
}

/**
 * gnutls_mac_self_test:
 * @mac: the message authentication algorithm to use
 *
 * This function will run self tests on the provided mac.
 *
 * Returns: Zero or a negative error code on error.
 *
 * Since: 3.3.0
 **/
int gnutls_mac_self_test(gnutls_mac_algorithm_t mac)
{

}

/**
 * gnutls_digest_self_test:
 * @digest: the digest algorithm to use
 *
 * This function will run self tests on the provided digest.
 *
 * Returns: Zero or a negative error code on error.
 *
 * Since: 3.3.0
 **/
int gnutls_digest_self_test(gnutls_digest_algorithm_t digest)
{

}
