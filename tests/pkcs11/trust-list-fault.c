/*
 * Copyright (C) 2026 Red Hat, Inc.
 *
 * Author: Alexander Sosedkin
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

#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#if defined(_WIN32)

int main(void)
{
	exit(77);
}

#else

#include <gnutls/gnutls.h>
#include <gnutls/x509.h>

#define CONFIG_NAME "softhsm-trust-list-fault"
#define CONFIG CONFIG_NAME ".config"

#include "cert-common.h"
#include "pkcs11/softhsm.h"
#include "utils.h"

/* This tests exercises a specific oversight from #1819:
 * cleanup problems after a failure mid-gnutls_x509_crt_list_import_pkcs11.
 * Needs ASAN.
 */

static void tls_log_func(int level, const char *str)
{
	fprintf(stderr, "|<%d>| %s", level, str);
}

#define PIN "1234"

static int pin_func(void *userdata, int attempt, const char *url,
		    const char *label, unsigned flags, char *pin,
		    size_t pin_max)
{
	if (attempt == 0) {
		strcpy(pin, PIN);
		return 0;
	}
	return -1;
}

void doit(void)
{
	char buf[512];
	int ret;
	const char *lib, *bin;
	gnutls_x509_crt_t crt;
	gnutls_x509_trust_list_t tl;
	unsigned int i;
	unsigned char id_buf[4];
	const unsigned int num_certs = 3;

	if (gnutls_fips140_mode_enabled())
		exit(77);

	/* this must be called once in the program */
	global_init();

	/* check if softhsm module is loadable */
	lib = softhsm_lib();

	/* initialize SoftHSM token that libpkcs11mock2.so internally uses */
	bin = softhsm_bin();

	set_softhsm_conf(CONFIG);
	lib = getenv("P11MOCKLIB5");
	if (lib == NULL) {
		fail("P11MOCKLIB5 is not set\n");
		exit(1);
	}

	/* point to SoftHSM token that libpkcs11mock5.so internally uses */
	set_softhsm_conf(CONFIG);
	snprintf(buf, sizeof(buf),
		 "%s --init-token --slot 0 --label test --so-pin " PIN
		 " --pin " PIN,
		 bin);
	system(buf);

	gnutls_pkcs11_set_pin_function(pin_func, NULL);
	gnutls_global_set_log_function(tls_log_func);
	if (debug) {
		gnutls_global_set_log_level(4711);
		setenv("P11MOCKLIB5_DEBUG", "1", 1);
	}

	/* 3x adds use 14 C_GetAttributeValue each, last one being data read.
         * 3x removals use 14 C_GetAttributeValue each,
         * 70th is the data read of the second removal.
         */
	setenv("P11MOCKLIB5_FAULT", "C_GetAttributeValue:70:0", 1);

	ret = gnutls_pkcs11_add_provider(lib, NULL);
	if (ret < 0) {
		fail("gnutls_pkcs11_add_provider: %s\n", gnutls_strerror(ret));
		exit(1);
	}

	/* initialize softhsm token */
	ret = gnutls_pkcs11_token_init(SOFTHSM_URL, PIN, "test");
	if (ret < 0) {
		fail("gnutls_pkcs11_token_init: %s\n", gnutls_strerror(ret));
		exit(1);
	}

	/* Import ca_cert 100 times with label "same", each with a unique ID */
	ret = gnutls_x509_crt_init(&crt);
	if (ret < 0) {
		fail("gnutls_x509_crt_init: %s\n", gnutls_strerror(ret));
		exit(1);
	}

	ret = gnutls_x509_crt_import(crt, &ca_cert, GNUTLS_X509_FMT_PEM);
	if (ret < 0) {
		fail("gnutls_x509_crt_import: %s\n", gnutls_strerror(ret));
		exit(1);
	}

	for (i = 0; i < num_certs; i++) {
		gnutls_datum_t id;

		assert(i <= 0xff);
		id_buf[0] = id_buf[1] = id_buf[2] = 0;
		id_buf[3] = i;
		id.data = id_buf;
		id.size = sizeof(id_buf);

		ret = gnutls_pkcs11_copy_x509_crt2(
			SOFTHSM_URL, crt, "same", &id,
			GNUTLS_PKCS11_OBJ_FLAG_MARK_TRUSTED |
				GNUTLS_PKCS11_OBJ_FLAG_LOGIN_SO);
		if (ret < 0) {
			fail("gnutls_pkcs11_copy_x509_crt2 [%u]: %s\n", i,
			     gnutls_strerror(ret));
			exit(1);
		}
	}

	gnutls_x509_crt_deinit(crt);

	ret = gnutls_x509_trust_list_init(&tl, 0);
	if (ret < 0) {
		fail("gnutls_x509_trust_list_init: %s\n", gnutls_strerror(ret));
		exit(1);
	}

	/* Add all certs (same label) to the trust list */
	ret = gnutls_x509_trust_list_add_trust_file(
		tl, SOFTHSM_URL ";object=same", NULL, 0, 0, 0);
	if (ret < 0) {
		fail("gnutls_x509_trust_list_add_trust_file: %s\n",
		     gnutls_strerror(ret));
		exit(1);
	}
	if ((unsigned int)ret != num_certs) {
		fail("expected %u certs added, got %d\n", num_certs, ret);
		exit(1);
	}
	success("added %d certs with label 'same' to trust list\n", ret);

	/* Attempt removing all certs from the trust list.
	 * The second one will fail to read due to failure injection.
	 */
	ret = gnutls_x509_trust_list_remove_trust_file(
		tl, SOFTHSM_URL ";object=same", 0);
	if (ret != GNUTLS_E_ASN1_TAG_ERROR) {
		fail("gnutls_x509_trust_list_remove_trust_file: %s\n",
		     gnutls_strerror(ret));
		exit(1);
	}

	gnutls_x509_trust_list_deinit(tl, 1);

	gnutls_global_deinit();

	remove(CONFIG);
}

#endif /* _WIN32 */
