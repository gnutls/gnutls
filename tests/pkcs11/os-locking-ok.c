/*
 * Copyright (C) 2025 Red Hat, Inc.
 *
 * Author: Daiki Ueno
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

#if defined(_WIN32)

int main(void)
{
	exit(77);
}

#else

#include <string.h>
#include <unistd.h>
#include <gnutls/gnutls.h>

#include "cert-common.h"
#include "pkcs11/softhsm.h"
#include "utils.h"

/* This program tests that a module can be initialized with
 * CKF_OS_LOCKING_OK, even if it's not supported by the module.
 */

static void tls_log_func(int level, const char *str)
{
	fprintf(stderr, "server|<%d>| %s", level, str);
}

#define PIN "1234"

#define CONFIG_NAME "softhsm-os-locking-ok"
#define CONFIG CONFIG_NAME ".config"

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

static void test(const char *provider)
{
	int ret;
	gnutls_x509_trust_list_t tl;

	gnutls_pkcs11_init(GNUTLS_PKCS11_FLAG_MANUAL, NULL);

	success("test with %s\n", provider);

	if (debug) {
		gnutls_global_set_log_function(tls_log_func);
		gnutls_global_set_log_level(4711);
	}

	/* point to SoftHSM token that libpkcs11mock4.so internally uses */
	setenv(SOFTHSM_ENV, CONFIG, 1);

	gnutls_pkcs11_set_pin_function(pin_func, NULL);

	ret = gnutls_pkcs11_add_provider(provider, "trusted");
	if (ret != 0) {
		fail("gnutls_pkcs11_add_provider: %s\n", gnutls_strerror(ret));
	}

	/* initialize softhsm token */
	ret = gnutls_pkcs11_token_init(SOFTHSM_URL, PIN, "test");
	if (ret < 0) {
		fail("gnutls_pkcs11_token_init: %s\n", gnutls_strerror(ret));
	}

	ret = gnutls_pkcs11_token_set_pin(SOFTHSM_URL, NULL, PIN,
					  GNUTLS_PIN_USER);
	if (ret < 0) {
		fail("gnutls_pkcs11_token_set_pin: %s\n", gnutls_strerror(ret));
	}

	gnutls_x509_trust_list_init(&tl, 0);

	ret = gnutls_x509_trust_list_add_trust_file(tl, SOFTHSM_URL, NULL, 0, 0,
						    0);
	if (ret < 0) {
		fail("gnutls_x509_trust_list_add_trust_file\n");
	}

	gnutls_x509_trust_list_deinit(tl, 0);

	gnutls_pkcs11_deinit();
}

void doit(void)
{
	const char *bin;
	const char *lib;
	char buf[128];

	if (gnutls_fips140_mode_enabled())
		exit(77);

	/* this must be called once in the program */
	global_init();

	/* we call gnutls_pkcs11_init manually */
	gnutls_pkcs11_deinit();

	/* check if softhsm module is loadable */
	lib = softhsm_lib();

	/* initialize SoftHSM token that libpkcs11mock4.so internally uses */
	bin = softhsm_bin();

	set_softhsm_conf(CONFIG);
	snprintf(buf, sizeof(buf),
		 "%s --init-token --slot 0 --label test --so-pin " PIN
		 " --pin " PIN,
		 bin);
	system(buf);

	test(lib);

	lib = getenv("P11MOCKLIB4");
	if (lib == NULL) {
		fail("P11MOCKLIB4 is not set\n");
	}

	set_softhsm_conf(CONFIG);
	snprintf(buf, sizeof(buf),
		 "%s --init-token --slot 0 --label test --so-pin " PIN
		 " --pin " PIN,
		 bin);
	system(buf);

	test(lib);
}
#endif /* _WIN32 */
