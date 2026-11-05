/*
 * Copyright (C) 2026 Mohammadreza Khellat.
 *
 * Author: Mohammadreza Khellat
 *
 * This file is part of GnuTLS.
 *
 * GnuTLS is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 3 of the License, or
 * (at your option) any later version.
 */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <gnutls/gnutls.h>
#include <gnutls/x509.h>
#include <gnutls/abstract.h>

#include "utils.h"
#include "cert-common.h"

static void test_one(gnutls_pk_algorithm_t algo, const gnutls_datum_t *cert,
		     size_t expected_size)
{
	gnutls_x509_crt_t crt = NULL;
	gnutls_pubkey_t pub = NULL, pub2 = NULL;
	gnutls_datum_t raw = { NULL, 0 }, raw2 = { NULL, 0 };
	gnutls_pk_algorithm_t got;
	unsigned int bits = 0;
	int ret;

	ret = gnutls_x509_crt_init(&crt);
	if (ret < 0)
		fail("crt_init: %s\n", gnutls_strerror(ret));

	ret = gnutls_x509_crt_import(crt, cert, GNUTLS_X509_FMT_PEM);
	if (ret < 0)
		fail("crt_import: %s\n", gnutls_strerror(ret));

	ret = gnutls_pubkey_init(&pub);
	if (ret < 0)
		fail("pubkey_init: %s\n", gnutls_strerror(ret));

	ret = gnutls_pubkey_import_x509(pub, crt, 0);
	if (ret < 0)
		fail("pubkey_import_x509: %s\n", gnutls_strerror(ret));

	got = gnutls_pubkey_get_pk_algorithm(pub, &bits);
	if (got != algo)
		fail("unexpected pk algorithm %d (want %d)\n", got, algo);

	ret = gnutls_pubkey_export_mldsa_raw(pub, &raw);
	if (ret < 0)
		fail("export_mldsa_raw: %s\n", gnutls_strerror(ret));

	if (raw.size != expected_size)
		fail("raw size %u != expected %zu\n", raw.size, expected_size);

	ret = gnutls_pubkey_init(&pub2);
	if (ret < 0)
		fail("pubkey_init2: %s\n", gnutls_strerror(ret));

	ret = gnutls_pubkey_import_mldsa_raw(pub2, algo, &raw);
	if (ret < 0)
		fail("import_mldsa_raw: %s\n", gnutls_strerror(ret));

	ret = gnutls_pubkey_export_mldsa_raw(pub2, &raw2);
	if (ret < 0)
		fail("re-export_mldsa_raw: %s\n", gnutls_strerror(ret));

	if (raw2.size != raw.size || memcmp(raw2.data, raw.data, raw.size) != 0)
		fail("round-trip mismatch\n");

	/* Wrong algorithm / size must fail. */
	ret = gnutls_pubkey_import_mldsa_raw(pub2, GNUTLS_PK_RSA, &raw);
	if (ret >= 0)
		fail("import with RSA should fail\n");

	gnutls_free(raw.data);
	gnutls_free(raw2.data);
	gnutls_pubkey_deinit(pub);
	gnutls_pubkey_deinit(pub2);
	gnutls_x509_crt_deinit(crt);
}

void doit(void)
{
	global_init();

	test_one(GNUTLS_PK_MLDSA44, &server_ca3_ml_dsa_44_cert, 1312);
	test_one(GNUTLS_PK_MLDSA65, &server_ca3_ml_dsa_65_cert, 1952);
	test_one(GNUTLS_PK_MLDSA87, &server_ca3_ml_dsa_87_cert, 2592);

	gnutls_global_deinit();
}
