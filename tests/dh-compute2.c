/*
 * Copyright (C) 2019-2023 Red Hat, Inc.
 *
 * Author: Simo Sorce, Daiki Ueno
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

/* This program tests functionality of DH exchanges, with public API */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <gnutls/gnutls.h>
#include <gnutls/abstract.h>
#include <stdbool.h>
#include <string.h>
#include <stdlib.h>
#include "utils.h"

static void params(gnutls_dh_params_t *dh_params, const gnutls_datum_t *p,
		   const gnutls_datum_t *q, const gnutls_datum_t *g)
{
	int ret;

	ret = gnutls_dh_params_init(dh_params);
	if (ret != 0)
		fail("error\n");

	ret = gnutls_dh_params_import_raw3(*dh_params, p, q, g);
	if (ret != 0)
		fail("error\n");
}

static void genkey(const gnutls_dh_params_t dh_params, gnutls_datum_t *priv_key,
		   gnutls_datum_t *pub_key)
{
	int ret;
	gnutls_privkey_t privkey;
	gnutls_keygen_data_st data;

	ret = gnutls_privkey_init(&privkey);
	if (ret != 0)
		fail("error\n");

	data.type = GNUTLS_KEYGEN_DH;
	data.data = (unsigned char *)dh_params;
	ret = gnutls_privkey_generate2(privkey, GNUTLS_PK_DH, 0, 0, &data, 1);
	if (ret != 0)
		fail("error\n");

	ret = gnutls_privkey_export_dh_raw(privkey, NULL, NULL, NULL, pub_key,
					   priv_key, 0);
	if (ret != 0)
		fail("error: %s\n", gnutls_strerror(ret));

	gnutls_privkey_deinit(privkey);
}

static void compute_key(const char *name, const gnutls_dh_params_t dh_params,
			const gnutls_datum_t *priv_key,
			const gnutls_datum_t *pub_key,
			const gnutls_datum_t *peer_key, int expect_error,
			gnutls_datum_t *result, bool expect_success)
{
	gnutls_datum_t Z = { 0 };
	bool success;
	int ret;
	gnutls_privkey_t privkey;
	gnutls_pubkey_t pubkey;
	gnutls_datum_t prime, generator;
	unsigned int bits;

	ret = gnutls_privkey_init(&privkey);
	if (ret != 0)
		fail("error\n");

	ret = gnutls_dh_params_export_raw(dh_params, &prime, &generator, &bits);
	if (ret != 0)
		fail("error\n");

	ret = gnutls_privkey_import_dh_raw(privkey, &prime, NULL, &generator,
					   NULL, priv_key);
	if (ret != 0)
		fail("error\n");

	ret = gnutls_pubkey_init(&pubkey);
	if (ret != 0)
		fail("error\n");

	ret = gnutls_pubkey_import_dh_raw(pubkey, &prime, NULL, &generator,
					  pub_key);
	if (ret != 0)
		fail("error\n");

	ret = gnutls_privkey_derive_secret(privkey, pubkey, NULL, &Z, 0);
	if (ret != 0)
		fail("error\n");

	if (result) {
		success = (Z.size != result->size &&
			   memcmp(Z.data, result->data, Z.size));
		if (success != expect_success)
			fail("%s: failed to match result\n", name);
	}
	gnutls_free(Z.data);
	gnutls_free(prime.data);
	gnutls_free(generator.data);
	gnutls_privkey_deinit(privkey);
	gnutls_pubkey_deinit(pubkey);
}

struct dh_test_data {
	const char *name;
	const gnutls_datum_t prime;
	const gnutls_datum_t q;
	const gnutls_datum_t generator;
	const gnutls_datum_t peer_key;
	int expected_error;
	gnutls_fips140_operation_state_t fips_state_genkey;
	gnutls_fips140_operation_state_t fips_state_compute_key;
};

void doit(void)
{
	struct dh_test_data test_data[] = {
		{
			"Legal Input",
			gnutls_ffdhe_2048_group_prime,
			gnutls_ffdhe_2048_group_q,
			gnutls_ffdhe_2048_group_generator,
			{ (void *)"\x02", 1 },
			0,
			GNUTLS_FIPS140_OP_APPROVED,
			GNUTLS_FIPS140_OP_APPROVED,
		},
		{ NULL }
	};

	for (int i = 0; test_data[i].name != NULL; i++) {
		gnutls_datum_t priv_key, pub_key;
		gnutls_dh_params_t dh_params;
		gnutls_fips140_context_t fips_context;
		int ret;

		if (gnutls_fips140_mode_enabled()) {
			ret = gnutls_fips140_context_init(&fips_context);
			if (ret < 0) {
				fail("Cannot initialize FIPS context\n");
			}
		}

		fips_push_context(fips_context);
		params(&dh_params, &test_data[i].prime, &test_data[i].q,
		       &test_data[i].generator);
		fips_pop_context(fips_context, GNUTLS_FIPS140_OP_INITIAL);

		success("%s genkey\n", test_data[i].name);

		fips_push_context(fips_context);
		genkey(dh_params, &priv_key, &pub_key);
		fips_pop_context(fips_context, test_data[i].fips_state_genkey);

		success("%s compute_key\n", test_data[i].name);

		fips_push_context(fips_context);
		compute_key(test_data[i].name, dh_params, &priv_key, &pub_key,
			    &test_data[i].peer_key, test_data[i].expected_error,
			    NULL, 0);
		fips_pop_context(fips_context,
				 test_data[i].fips_state_compute_key);

		gnutls_dh_params_deinit(dh_params);
		gnutls_free(priv_key.data);
		gnutls_free(pub_key.data);

		if (gnutls_fips140_mode_enabled()) {
			gnutls_fips140_context_deinit(fips_context);
		}
	}

	success("all ok\n");
}
