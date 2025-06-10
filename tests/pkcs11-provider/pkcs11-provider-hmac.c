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

static int test_mac(gnutls_mac_algorithm_t alg, const char *key,
		    size_t key_size, const char *ptext, size_t ptext_size,
		    const char *exp_digest)
{
	int ret = 0;
	size_t digest_size = 0;
	uint8_t *digest = NULL;
	gnutls_hmac_hd_t hd = NULL;

	digest_size = gnutls_hmac_get_len(alg);
	digest = gnutls_malloc(digest_size);
	assert(digest != NULL);

	printf("Testing mac %s\n", gnutls_mac_get_name(alg));

	ret = gnutls_hmac_init(&hd, alg, key, key_size);
	if (ret < 0) {
		fprintf(stderr, "gnutls_hmac_init: %s\n", gnutls_strerror(ret));
		goto cleanup;
	}

	ret = gnutls_hmac(hd, ptext, ptext_size / 2);
	if (ret < 0) {
		fprintf(stderr, "gnutls_hmac: %s\n", gnutls_strerror(ret));
		goto cleanup;
	}

	ret = gnutls_hmac(hd, ptext + (ptext_size / 2),
			  ptext_size - (ptext_size / 2));
	if (ret < 0) {
		fprintf(stderr, "gnutls_hmac: %s\n", gnutls_strerror(ret));
		goto cleanup;
	}

	gnutls_hmac_output(hd, digest);

	if (memcmp(digest, exp_digest, digest_size) != 0) {
		fprintf(stderr, "hmac: digest data don't match\n");
		ret = -1;
		goto cleanup;
	}

	ret = gnutls_hmac_fast(alg, key, key_size, ptext, ptext_size, digest);
	if (ret < 0) {
		fprintf(stderr, "gnutls_hmac_fast: %s\n", gnutls_strerror(ret));
		goto cleanup;
	}

	if (memcmp(digest, exp_digest, digest_size) != 0) {
		fprintf(stderr, "hmac_fast: digest data don't match\n");
		ret = -1;
		goto cleanup;
	}

	printf("ok\n");

cleanup:
	gnutls_hmac_deinit(hd, NULL);
	gnutls_free(digest);
	return ret;
}

static int test_hash(gnutls_digest_algorithm_t alg, const char *alg_str,
		     const char *text, size_t text_size, const char *exp_digest)
{
	int ret = 0;
	size_t digest_size = 0;
	uint8_t *digest = NULL;
	gnutls_hash_hd_t hd = NULL;

	digest_size = gnutls_hash_get_len(alg);
	digest = gnutls_malloc(digest_size);
	assert(digest != NULL);

	printf("Testing hash %s\n", alg_str);

	ret = gnutls_hash_init(&hd, alg);
	if (ret < 0) {
		fprintf(stderr, "gnutls_hash_init: %s\n", gnutls_strerror(ret));
		goto cleanup;
	}

	ret = gnutls_hash(hd, text, text_size / 2);
	if (ret < 0) {
		fprintf(stderr, "gnutls_hash: %s\n", gnutls_strerror(ret));
		goto cleanup;
	}

	ret = gnutls_hash(hd, text + (text_size / 2),
			  text_size - (text_size / 2));
	if (ret < 0) {
		fprintf(stderr, "gnutls_hash: %s\n", gnutls_strerror(ret));
		goto cleanup;
	}

	gnutls_hash_output(hd, digest);

	if (memcmp(digest, exp_digest, digest_size) != 0) {
		fprintf(stderr, "hash: digest data don't match\n");
		ret = -1;
		goto cleanup;
	}

	ret = gnutls_hash_fast(alg, text, text_size, digest);
	if (ret < 0) {
		fprintf(stderr, "gnutls_hash_fast: %s\n", gnutls_strerror(ret));
		goto cleanup;
	}

	if (memcmp(digest, exp_digest, digest_size) != 0) {
		fprintf(stderr, "hash_fast: digest data don't match\n");
		ret = -1;
		goto cleanup;
	}

	printf("ok\n");

cleanup:
	gnutls_hash_deinit(hd, NULL);
	gnutls_free(digest);
	return ret;
}

/*
static int test_hkdf(gnutls_mac_algorithm_t mac, const char *ikm_hex,
		     const char *salt_hex, const char *info_hex, size_t length,
		     const char *prk_hex, const char *okm_hex)
{
	int ret = 0;
	uint8_t buf[1024];
	gnutls_datum_t hex, ikm, salt, info, prk, okm;

	printf("Testing HKDF %s\n", gnutls_mac_get_name(mac));

	hex.data = (void *)ikm_hex;
	hex.size = strlen(ikm_hex);
	ret = gnutls_hex_decode2(&hex, &ikm);
	if (ret < 0) {
		fprintf(stderr, "gnutls_hex_decode2: %s\n",
			gnutls_strerror(ret));
		return ret;
	}

	hex.data = (void *)salt_hex;
	hex.size = strlen(salt_hex);
	ret = gnutls_hex_decode2(&hex, &salt);
	if (ret < 0) {
		fprintf(stderr, "gnutls_hex_decode2: %s\n",
			gnutls_strerror(ret));
		gnutls_free(ikm.data);
		return ret;
	}

	ret = gnutls_hkdf_extract(mac, &ikm, &salt, buf);
	gnutls_free(ikm.data);
	gnutls_free(salt.data);
	if (ret < 0) {
		fprintf(stderr, "gnutls_hkdf_extract: %s\n",
			gnutls_strerror(ret));
		return ret;
	}

	prk.data = buf;
	prk.size = strlen(prk_hex) / 2;
	ret = gnutls_hex_encode2(&prk, &hex);
	if (ret < 0) {
		fprintf(stderr, "gnutls_hex_encode2: %s\n",
			gnutls_strerror(ret));
		return ret;
	}

	if (strcmp((char *)hex.data, prk_hex) != 0) {
		fprintf(stderr, "HKDF: prk doesn't match: %s != %s\n",
			(char *)hex.data, prk_hex);
		gnutls_free(hex.data);
		return -1;
	}

	gnutls_free(hex.data);

	hex.data = (void *)info_hex;
	hex.size = strlen(info_hex);
	ret = gnutls_hex_decode2(&hex, &info);
	if (ret < 0) {
		fprintf(stderr, "gnutls_hex_decode2: %s\n",
			gnutls_strerror(ret));
		return ret;
	}
	ret = gnutls_hkdf_expand(mac, &prk, &info, buf, length);
	gnutls_free(info.data);
	if (ret < 0) {
		fprintf(stderr, "gnutls_hkdf_expand: %s\n",
			gnutls_strerror(ret));
		return ret;
	}

	okm.data = buf;
	okm.size = strlen(okm_hex) / 2;
	ret = gnutls_hex_encode2(&okm, &hex);
	if (ret < 0) {
		fprintf(stderr, "gnutls_hex_encode2: %s\n",
			gnutls_strerror(ret));
		return ret;
	}

	if (strcmp((char *)hex.data, okm_hex) != 0) {
		fprintf(stderr, "HKDF: okm doesn't match: %s != %s\n",
			(char *)hex.data, okm_hex);
		gnutls_free(hex.data);
		return -1;
	}

	gnutls_free(hex.data);
	return 0;
}

static int test_pbkdf2(gnutls_mac_algorithm_t mac, const char *ikm_hex,
		       const char *salt_hex, unsigned iter_count, size_t length,
		       const char *okm_hex)
{
	int ret = 0;
	uint8_t buf[1024];
	gnutls_datum_t hex, ikm, salt, okm;

	printf("Testing PBKDF2 %s\n", gnutls_mac_get_name(mac));

	hex.data = (void *)ikm_hex;
	hex.size = strlen(ikm_hex);
	ret = gnutls_hex_decode2(&hex, &ikm);
	if (ret < 0) {
		fprintf(stderr, "gnutls_hex_decode2: %s\n",
			gnutls_strerror(ret));
		return ret;
	}

	hex.data = (void *)salt_hex;
	hex.size = strlen(salt_hex);
	ret = gnutls_hex_decode2(&hex, &salt);
	if (ret < 0) {
		fprintf(stderr, "gnutls_hex_decode2: %s\n",
			gnutls_strerror(ret));
		gnutls_free(ikm.data);
		return ret;
	}

	ret = gnutls_pbkdf2(mac, &ikm, &salt, iter_count, buf, length);
	gnutls_free(ikm.data);
	gnutls_free(salt.data);
	if (ret < 0) {
		fprintf(stderr, "gnutls_pbkdf2: %s\n", gnutls_strerror(ret));
		return ret;
	}

	okm.data = buf;
	okm.size = length;
	ret = gnutls_hex_encode2(&okm, &hex);
	if (ret < 0) {
		fprintf(stderr, "gnutls_hex_encode2: %s\n",
			gnutls_strerror(ret));
		return ret;
	}

	if (strcmp((char *)hex.data, okm_hex) != 0) {
		fprintf(stderr, "PBKDF2: okm doesn't match: %s != %s\n",
			(char *)hex.data, okm_hex);
		gnutls_free(hex.data);
		return -1;
	}

	gnutls_free(hex.data);
	return 0;
}
*/

static int test_macs(void)
{
	return test_mac(GNUTLS_MAC_SHA1, "keykeykeykeykeykeyke", 20, "abcdefgh",
			8,
			"\x30\x7d\xac\x31\x1e\x38\xfa\x70\x92\x30"
			"\xdd\x27\x97\x27\x32\x45\x4b\x39\x74\x39") < 0 ||
	       test_mac(GNUTLS_MAC_SHA224, "keykeykeykeykeykeykeykeykeyk", 28,
			"abcdefgh", 8,
			"\x91\xa1\x39\x7d\x2b\xf7\xcd\xdd\x45\x57"
			"\x64\x04\x6f\x65\x89\x96\xd5\x1c\x43\x2b"
			"\xe1\x59\x10\xe8\xf4\x65\x1e\x46") < 0 ||
	       test_mac(GNUTLS_MAC_SHA256, "keykeykeykeykeykeykeykeykeykeyke",
			32, "abcdefgh", 8,
			"\xde\xa4\xbf\x53\x29\x54\x17\xb2\xdb\xb6"
			"\x75\x14\x31\x12\x49\x75\xb1\xea\x5f\x59"
			"\x5b\x13\x52\x6a\x31\x21\xf4\x93\x93\x38"
			"\xfc\x82") < 0 ||
	       test_mac(GNUTLS_MAC_SHA384,
			"keykeykeykeykeykeykeykeykeykeykeykeykeykeykeykey", 48,
			"abcdefgh", 8,
			"\x3a\x83\xdb\x7e\x5d\xdc\x03\x24\x23\x00"
			"\x0a\x9e\x8a\x81\x4f\x5b\x52\xb9\x49\x9e"
			"\xb1\xf0\x73\xc2\x5c\x9f\xb9\x38\xc4\x99"
			"\x13\x80\x22\x6f\x08\xda\x0b\xc0\x56\x40"
			"\xf4\x09\x26\x60\xb8\xd5\xec\x74") < 0 ||
	       test_mac(
		       GNUTLS_MAC_SHA512,
		       "keykeykeykeykeykeykeykeykeykeykeykeykeykeykeykeykeykeykeykeykeyk",
		       64, "abcdefgh", 8,
		       "\xc9\x59\x6c\xd2\x87\x90\x75\xd2\xff\x6a"
		       "\x55\x57\x0b\x52\xff\xf9\x0b\x44\xe1\x8d"
		       "\x3f\xec\x5d\xc4\x10\x77\x25\x3b\x60\x6c"
		       "\x14\x0d\x8c\x8d\x29\x08\xbd\x8c\xcf\x7e"
		       "\x5a\x18\x90\xc0\x6f\x86\xf4\xd0\xe6\x33"
		       "\xc2\x93\x59\xbf\x8d\x11\x5a\x2d\xa1\x73"
		       "\xee\x7c\x82\x67") < 0 ||
	       test_mac(GNUTLS_MAC_AES_CMAC_128, "keykeykeykeykeyk", 16,
			"abcdefgh", 8,
			"\xbe\x1a\xf8\xa3\xd3\x6e\x0d\xbb\x33\x34"
			"\xf8\xc5\xe5\xe0\x11\x35") < 0 ||
	       test_mac(GNUTLS_MAC_AES_CMAC_256,
			"keykeykeykeykeykeykeykeykeykeyke", 32, "abcdefgh", 8,
			"\x3d\x9c\xe6\xe1\x51\x6f\x17\x86\xb4\x19"
			"\x4a\x3d\x30\xa8\x08\xf9") < 0;
}

static int test_hashes(void)
{
	return test_hash(GNUTLS_DIG_SHA1, "sha1", "abcdefgh", 8,
			 "\x42\x5a\xf1\x2a\x07\x43\x50\x2b\x32\x2e"
			 "\x93\xa0\x15\xbc\xf8\x68\xe3\x24\xd5\x6a") < 0 ||
	       test_hash(GNUTLS_DIG_SHA224, "sha224", "abcdefgh", 8,
			 "\x17\xeb\x7d\x40\xf0\x35\x6f\x85\x98\xe8"
			 "\x9e\xaf\xad\x5f\x6c\x75\x9b\x1f\x82\x29"
			 "\x75\xd9\xc9\xb7\x37\xc8\xa5\x17") < 0 ||
	       test_hash(GNUTLS_DIG_SHA256, "sha256", "abcdefgh", 8,
			 "\x9c\x56\xcc\x51\xb3\x74\xc3\xba\x18\x92"
			 "\x10\xd5\xb6\xd4\xbf\x57\x79\x0d\x35\x1c"
			 "\x96\xc4\x7c\x02\x19\x0e\xcf\x1e\x43\x06"
			 "\x35\xab") < 0 ||
	       test_hash(GNUTLS_DIG_SHA384, "sha384", "abcdefgh", 8,
			 "\x90\x00\xcd\x7c\xad\xa5\x9d\x1d\x2e\xb8"
			 "\x29\x12\xf7\xf2\x4e\x5e\x69\xcc\x55\x17"
			 "\xf6\x82\x83\xb0\x05\xfa\x27\xc2\x85\xb6"
			 "\x1e\x05\xed\xf1\xad\x1a\x8a\x9b\xde\xd6"
			 "\xfd\x29\xeb\x87\xd7\x5a\xd8\x06") < 0 ||
	       test_hash(GNUTLS_DIG_SHA512, "sha512", "abcdefgh", 8,
			 "\xa3\xa8\xc8\x1b\xc9\x7c\x25\x60\x01\x0d"
			 "\x73\x89\xbc\x88\xaa\xc9\x74\xa1\x04\xe0"
			 "\xe2\x38\x12\x20\xc6\xe0\x84\xc4\xdc\xcd"
			 "\x1d\x2d\x17\xd4\xf8\x6d\xb3\x1c\x2a\x85"
			 "\x1d\xc8\x0e\x66\x81\xd7\x47\x33\xc5\x5d"
			 "\xcd\x03\xdd\x96\xf6\x06\x2c\xdd\xa1\x2a"
			 "\x29\x1a\xe6\xce") < 0;
	/*
	       test_hash(GNUTLS_DIG_SHA3_224, "sha3-224",
		         "abcdefgh", 8,
			 "\x48\xbf\x2e\x86\x40\xcf\xfe\x77\xb6\x7c"
			 "\x61\x82\xa6\xa4\x7f\x8b\x5a\xf7\x3f\x60"
			 "\xbd\x20\x4e\xf3\x48\x37\x1d\x03") < 0 ||
	       test_hash(GNUTLS_DIG_SHA3_256, "sha3-256",
		         "abcdefgh", 8,
			 "\x3e\x20\x20\x72\x5a\x38\xa4\x8e\xb3\xbb"
			 "\xf7\x57\x67\xf0\x3a\x22\xc6\xb3\xf4\x1f"
			 "\x45\x9c\x83\x13\x09\xb0\x64\x33\xec\x64"
			 "\x97\x79") < 0 ||
	       test_hash(GNUTLS_DIG_SHA3_384, "sha3-384",
		         "abcdefgh", 8,
			 "\xf4\xd9\xfc\x5e\x9f\x44\xeb\x87\xfe\x96"
			 "\x8f\xc8\xe4\xe4\x69\x1e\xb1\xda\xb6\xd8"
			 "\x21\xfb\x77\x55\x0b\x52\x7f\x71\xcc\xfb"
			 "\x1b\xa0\x43\x85\x1b\xb0\x54\xf2\x81\x36"
			 "\x4c\x44\xd8\x54\x19\x04\xdb\x5a") < 0 ||
	       test_hash(GNUTLS_DIG_SHA3_512, "sha3-512",
		         "abcdefgh", 8,
			 "\xc9\xf2\x5e\xee\x75\xab\x4c\xf9\xa8\xcf"
			 "\xd4\x4f\x49\x92\xb2\x82\x07\x9b\x64\xd9"
			 "\x46\x47\xed\xbd\x88\xe8\x18\xe4\x4f\x70"
			 "\x1e\xde\xb4\x50\x81\x8f\x72\x72\xcb\xa7"
			 "\xa2\x02\x05\xb3\x67\x1c\xe1\x99\x1c\xe9"
			 "\xa6\xd2\xdf\x8d\xba\xd6\xe0\xbb\x3e\x50"
			 "\x49\x3d\x7f\xa7") < 0;
	*/
}

/*
static int test_kdfs(void)
{
	return test_hkdf(GNUTLS_MAC_SHA256,
			 "0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b",
			 "000102030405060708090a0b0c", "f0f1f2f3f4f5f6f7f8f9",
			 42,
			 "077709362c2e32df0ddc3f0dc47bba6390b6c73bb"
			 "50f9c3122ec844ad7c2b3e5",
			 "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf"
			 "1a5a4c5db02d56ecc4c5bf34007208d5b887185865") < 0 ||
	       test_pbkdf2(GNUTLS_MAC_SHA1, "70617373776f7264", "73616c74",
			   4096, 20,
			   "4b007901b765489abead49d926f721d065a429c1") < 0;
}
*/

int main(void)
{
	int ret;

	gnutls_global_init();

	ret = test_macs();
	if (ret < 0)
		goto cleanup;
	ret = test_hashes();
	if (ret < 0)
		goto cleanup;
	/*
	ret = test_kdfs();
	if (ret < 0)
		goto cleanup;
	*/

cleanup:
	gnutls_global_deinit();
	return ret;
}
