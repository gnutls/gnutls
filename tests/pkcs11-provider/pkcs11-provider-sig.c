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
#include "common-key-tests.h"

/* sha1 hash of "hello" string */
const gnutls_datum_t sha1_hash_data = {
	(void *)"\xaa\xf4\xc6\x1d\xdc\xc5\xe8\xa2\xda\xbe"
		"\xde\x0f\x3b\x48\x2c\xd9\xae\xa9\x43\x4d",
	20
};

const gnutls_datum_t sha256_hash_data = {
	(void *)"\x2c\xf2\x4d\xba\x5f\xb0\xa3\x0e\x26\xe8\x3b\x2a\xc5\xb9\xe2\x9e"
		"\x1b\x16\x1e\x5c\x1f\xa7\x42\x5e\x73\x04\x33\x62\x93\x8b\x98\x24",
	32
};

const gnutls_datum_t sha256_invalid_hash_data = {
	(void *)"\x2c\xf2\x4d\xba\x5f\xb1\xa3\x0e\x26\xe8\x3b\x2a\xc5\xb9\xe2\x9e"
		"\x1b\x16\x1e\x5c\x1f\xa3\x42\x5e\x73\x04\x33\x62\x93\x8b\x98\x24",
	32
};

const gnutls_datum_t sha1_invalid_hash_data = {
	(void *)"\xaa\xf4\xc6\x1d\xdc\xca\xe8\xa2\xda\xbe"
		"\xde\x0f\x3b\x48\x2c\xb9\xae\xa9\x43\x4d",
	20
};

const gnutls_datum_t raw_data = { (void *)"hello", 5 };

#define tests common_key_tests

int main(void)
{
	gnutls_x509_privkey_t key;
	gnutls_x509_crt_t crt;
	gnutls_pubkey_t pubkey;
	gnutls_privkey_t privkey;
	gnutls_sign_algorithm_t sign_algo;
	gnutls_datum_t signature;
	gnutls_datum_t signature2;
	int ret;
	size_t i;
	const gnutls_datum_t *hash_data;
	const gnutls_datum_t *invalid_hash_data;

	gnutls_global_init();

	for (i = 0; i < sizeof(tests) / sizeof(tests[0]); i++) {
		if (tests[i].pk != GNUTLS_PK_RSA &&
		    tests[i].pk != GNUTLS_PK_RSA_PSS &&
		    tests[i].pk != GNUTLS_PK_ECDSA)
			continue;

		printf("testing: %s - %s\n", tests[i].name,
		       gnutls_sign_algorithm_get_name(tests[i].sigalgo));

		if (tests[i].digest == GNUTLS_DIG_SHA1) {
			hash_data = &sha1_hash_data;
			invalid_hash_data = &sha1_invalid_hash_data;
		} else {
			hash_data = &sha256_hash_data;
			invalid_hash_data = &sha256_invalid_hash_data;
		}

		ret = gnutls_x509_privkey_init(&key);
		if (ret < 0) {
			fprintf(stderr, "gnutls_x509_privkey_init: %s\n",
				gnutls_strerror(ret));
			return EXIT_FAILURE;
		}

		ret = gnutls_x509_privkey_import(key, &tests[i].key,
						 GNUTLS_X509_FMT_PEM);
		if (ret < 0) {
			fprintf(stderr, "gnutls_x509_privkey_import: %s\n",
				gnutls_strerror(ret));
			return EXIT_FAILURE;
		}

		ret = gnutls_pubkey_init(&pubkey);
		if (ret < 0) {
			fprintf(stderr, "gnutls_privkey_init: %s\n",
				gnutls_strerror(ret));
			return EXIT_FAILURE;
		}

		ret = gnutls_privkey_init(&privkey);
		if (ret < 0) {
			fprintf(stderr, "gnutls_pubkey_init: %s\n",
				gnutls_strerror(ret));
			return EXIT_FAILURE;
		}

		ret = gnutls_privkey_import_x509(privkey, key, 0);
		if (ret < 0) {
			fprintf(stderr, "gnutls_privkey_import_x509: %s\n",
				gnutls_strerror(ret));
			return EXIT_FAILURE;
		}

		ret = gnutls_privkey_sign_hash(privkey, tests[i].digest,
					       tests[i].sign_flags, hash_data,
					       &signature2);
		if (ret < 0) {
			fprintf(stderr, "gnutls_privkey_sign_hash: %s\n",
				gnutls_strerror(ret));
			return EXIT_FAILURE;
		}

		ret = gnutls_privkey_sign_data(privkey, tests[i].digest,
					       tests[i].sign_flags, &raw_data,
					       &signature);
		if (ret < 0) {
			fprintf(stderr, "gnutls_x509_privkey_sign_hash: %s\n",
				gnutls_strerror(ret));
			return EXIT_FAILURE;
		}

		ret = gnutls_x509_crt_init(&crt);
		if (ret < 0) {
			fprintf(stderr, "gnutls_x509_crt_init: %s\n",
				gnutls_strerror(ret));
			return EXIT_FAILURE;
		}

		ret = gnutls_x509_crt_import(crt, &tests[i].cert,
					     GNUTLS_X509_FMT_PEM);
		if (ret < 0) {
			fprintf(stderr, "gnutls_x509_crt_import: %s\n",
				gnutls_strerror(ret));
			return EXIT_FAILURE;
		}

		ret = gnutls_pubkey_import_x509(pubkey, crt, 0);
		if (ret < 0) {
			fprintf(stderr, "gnutls_x509_pubkey_import: %s\n",
				gnutls_strerror(ret));
			return EXIT_FAILURE;
		}

		ret = gnutls_pubkey_verify_hash2(
			pubkey, tests[i].sigalgo,
			GNUTLS_VERIFY_ALLOW_SIGN_WITH_SHA1, hash_data,
			&signature);
		if (ret < 0) {
			fprintf(stderr, "gnutls_x509_pubkey_verify_hash2: %s\n",
				gnutls_strerror(ret));
			return EXIT_FAILURE;
		}

		ret = gnutls_pubkey_verify_hash2(
			pubkey, tests[i].sigalgo,
			GNUTLS_VERIFY_ALLOW_SIGN_WITH_SHA1, hash_data,
			&signature2);
		if (ret < 0) {
			fprintf(stderr,
				"gnutls_x509_pubkey_verify_hash-1 (hashed data): %s\n",
				gnutls_strerror(ret));
			return EXIT_FAILURE;
		}

		/* should fail */
		ret = gnutls_pubkey_verify_hash2(
			pubkey, tests[i].sigalgo,
			GNUTLS_VERIFY_ALLOW_SIGN_WITH_SHA1, invalid_hash_data,
			&signature2);
		if (ret != GNUTLS_E_PK_SIG_VERIFY_FAILED) {
			fprintf(stderr,
				"gnutls_x509_pubkey_verify_hash-2 (hashed data): %s\n",
				gnutls_strerror(ret));
			return EXIT_FAILURE;
		}

		sign_algo = gnutls_pk_to_sign(
			gnutls_pubkey_get_pk_algorithm(pubkey, NULL),
			tests[i].digest);

		ret = gnutls_pubkey_verify_hash2(
			pubkey, sign_algo, GNUTLS_VERIFY_ALLOW_SIGN_WITH_SHA1,
			hash_data, &signature2);
		if (ret < 0) {
			fprintf(stderr,
				"gnutls_x509_pubkey_verify_hash2-1 (hashed data): %s\n",
				gnutls_strerror(ret));
			return EXIT_FAILURE;
		}

		/* should fail */
		ret = gnutls_pubkey_verify_hash2(
			pubkey, sign_algo, GNUTLS_VERIFY_ALLOW_SIGN_WITH_SHA1,
			invalid_hash_data, &signature2);
		if (ret != GNUTLS_E_PK_SIG_VERIFY_FAILED) {
			fprintf(stderr,
				"gnutls_x509_pubkey_verify_hash2-2 (hashed data): %s\n",
				gnutls_strerror(ret));
			return EXIT_FAILURE;
		}

		/* test the raw interface */
		gnutls_free(signature.data);

		if (gnutls_pubkey_get_pk_algorithm(pubkey, NULL) ==
		    GNUTLS_PK_RSA) {
			ret = gnutls_privkey_sign_hash(
				privkey, tests[i].digest,
				GNUTLS_PRIVKEY_SIGN_FLAG_TLS1_RSA, hash_data,
				&signature);
			if (ret < 0) {
				fprintf(stderr,
					"gnutls_privkey_sign_hash: %s\n",
					gnutls_strerror(ret));
				return EXIT_FAILURE;
			}

			sign_algo = gnutls_pk_to_sign(
				gnutls_pubkey_get_pk_algorithm(pubkey, NULL),
				tests[i].digest);

			ret = gnutls_pubkey_verify_hash2(
				pubkey, sign_algo,
				GNUTLS_PUBKEY_VERIFY_FLAG_TLS1_RSA, hash_data,
				&signature);
			if (ret < 0) {
				fprintf(stderr,
					"gnutls_pubkey_verify_hash-3 (raw hashed data): %s\n",
					gnutls_strerror(ret));
				return EXIT_FAILURE;
			}

			gnutls_free(signature.data);
			/* test the legacy API */
			ret = gnutls_privkey_sign_raw_data(
				privkey, 0, hash_data, &signature);
			if (ret < 0) {
				fprintf(stderr,
					"gnutls_privkey_sign_raw_data: %s\n",
					gnutls_strerror(ret));
				return EXIT_FAILURE;
			}

			ret = gnutls_pubkey_verify_hash2(
				pubkey, sign_algo,
				GNUTLS_PUBKEY_VERIFY_FLAG_TLS1_RSA, hash_data,
				&signature);
			if (ret < 0) {
				fprintf(stderr,
					"gnutls_pubkey_verify_hash-4 (legacy raw hashed data): %s\n",
					gnutls_strerror(ret));
				return EXIT_FAILURE;
			}
		}
		gnutls_free(signature.data);
		gnutls_free(signature2.data);
		gnutls_x509_privkey_deinit(key);
		gnutls_x509_crt_deinit(crt);
		gnutls_privkey_deinit(privkey);
		gnutls_pubkey_deinit(pubkey);
	}

	gnutls_global_deinit();
}
