/*
 * Copyright (C) 2026 Red Hat, Inc.
 *
 * Authors: Zoltan Fridrich, Conor Tull
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
 * You should have received a copy of the GNU General Public License
 * along with GnuTLS.  If not, see <https://www.gnu.org/licenses/>.
 */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <gnutls/abstract.h>

#include "utils.h"

#define ECPOINT_RAW_DATA                                                    \
	0xd7, 0x5a, 0x98, 0x01, 0x82, 0xb1, 0x0a, 0xb7, 0xd5, 0x4b, 0xfe,   \
		0xd3, 0xc9, 0x64, 0x07, 0x3a, 0x0e, 0xe1, 0x72, 0xf3, 0xda, \
		0xa6, 0x23, 0x25, 0xaf, 0x02, 0x1a, 0x68, 0xf7, 0x07, 0x51, \
		0x1a

int _gnutls_pubkey_import_ecc_eddsa(gnutls_pubkey_t key,
				    const gnutls_datum_t *parameters,
				    const gnutls_datum_t *ecpoint);

static const unsigned char ecpoint_raw_data[] = { ECPOINT_RAW_DATA };
static const unsigned char ecpoint_bitstring_data[] = { 0x03, 0x21, 0x00,
							ECPOINT_RAW_DATA };
static const unsigned char ecpoint_octetstring_data[] = { 0x04, 0x20,
							  ECPOINT_RAW_DATA };

static const gnutls_datum_t ecpoint_raw = { (unsigned char *)ecpoint_raw_data,
					    sizeof(ecpoint_raw_data) };
static const gnutls_datum_t ecpoint_bitstring = {
	(unsigned char *)ecpoint_bitstring_data, sizeof(ecpoint_bitstring_data)
};
static const gnutls_datum_t ecpoint_octetstring = {
	(unsigned char *)ecpoint_octetstring_data,
	sizeof(ecpoint_octetstring_data)
};

static const unsigned char ed25519_params_der[] = { 0x06, 0x03, 0x2B, 0x65,
						    0x70 };
static const gnutls_datum_t params = { (unsigned char *)ed25519_params_der,
				       sizeof(ed25519_params_der) };

static void test_eddsa_encoding(const char *name, const gnutls_datum_t *ecpoint,
				const gnutls_datum_t *expected)
{
	int ret;
	gnutls_pubkey_t pubkey;
	gnutls_pk_algorithm_t pk_alg;
	gnutls_datum_t exported = { NULL, 0 };

	success("Testing: EdDSA %s encoding\n", name);

	assert(gnutls_pubkey_init(&pubkey) >= 0);
	ret = _gnutls_pubkey_import_ecc_eddsa(pubkey, &params, ecpoint);
	if (ret < 0)
		fail("failed to import public key: %s\n", gnutls_strerror(ret));

	pk_alg = gnutls_pubkey_get_pk_algorithm(pubkey, NULL);
	if (pk_alg != GNUTLS_PK_EDDSA_ED25519)
		fail("imported key has the wrong id: %s != EdDSA (Ed25519)\n",
		     gnutls_pk_get_name(pk_alg));

	ret = gnutls_pubkey_export_ecc_raw(pubkey, NULL, &exported, NULL);
	if (ret < 0)
		fail("failed to export public key: %s\n", gnutls_strerror(ret));

	if (exported.size != expected->size ||
	    memcmp(exported.data, expected->data, expected->size) != 0) {
		success("exported data:\n");
		hexprint(exported.data, exported.size);
		success("expected data:\n");
		hexprint(expected->data, expected->size);
		fail("exported key does not match the expected result\n");
	}

	success("success\n");

	gnutls_free(exported.data);
	gnutls_pubkey_deinit(pubkey);
}

void doit(void)
{
	test_eddsa_encoding("raw", &ecpoint_raw, &ecpoint_raw);
	test_eddsa_encoding("bit string", &ecpoint_bitstring, &ecpoint_raw);
	test_eddsa_encoding("octet string", &ecpoint_octetstring, &ecpoint_raw);
}
