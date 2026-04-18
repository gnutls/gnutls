/*
 * Copyright (C) 2026 Ghadi Elie Rahme.
 *
 * Author: Ghadi Elie Rahme
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
#include <assert.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/wait.h>

#include <gnutls/gnutls.h>
#include <gnutls/pkcs11.h>
#ifndef CRYPTOKI_GNU
#define CRYPTOKI_GNU
#endif
#include <p11-kit/pkcs11.h>

#include "utils.h"

/* Tests whether gnutls_pkcs11_obj_get_pk_algorithm returns valid
 * algorithm and bit count for a private key object. */

#if defined(HAVE___REGISTER_ATFORK)

#ifdef _WIN32
#define P11LIB "libpkcs11mock1.dll"
#else
#include <dlfcn.h>
#define P11LIB "libpkcs11mock1.so"
#endif

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
	int ret;
	const char *lib;
	gnutls_pkcs11_obj_t obj;
	unsigned int bits;

	ret = global_init();
	if (ret != 0) {
		fail("%d: %s\n", ret, gnutls_strerror(ret));
		exit(1);
	}

	gnutls_global_set_log_function(tls_log_func);
	if (debug)
		gnutls_global_set_log_level(4711);

	lib = getenv("P11MOCKLIB1");
	if (lib == NULL)
		lib = P11LIB;

	ret = gnutls_pkcs11_init(GNUTLS_PKCS11_FLAG_MANUAL, NULL);
	if (ret != 0) {
		fail("%d: %s\n", ret, gnutls_strerror(ret));
		exit(1);
	}

	ret = gnutls_pkcs11_add_provider(lib, NULL);
	if (ret != 0) {
		fail("%d: %s\n", ret, gnutls_strerror(ret));
		exit(1);
	}

	/* Test NULL obj parameter */
	ret = gnutls_pkcs11_obj_get_pk_algorithm(NULL, &bits);
	assert(ret == GNUTLS_E_INVALID_REQUEST);

	assert(gnutls_pkcs11_obj_init(&obj) >= 0);

	gnutls_pkcs11_obj_set_pin_function(obj, pin_func, NULL);

	/* Test NULL bits parameter */
	ret = gnutls_pkcs11_obj_import_url(obj,
					   "pkcs11:object=test;type=private",
					   GNUTLS_PKCS11_OBJ_FLAG_LOGIN);
	assert(ret >= 0);

	ret = gnutls_pkcs11_obj_get_pk_algorithm(obj, NULL);
	assert(ret == GNUTLS_E_INVALID_REQUEST);

	/* Test with an RSA private key object */
	bits = 0;
	ret = gnutls_pkcs11_obj_get_pk_algorithm(obj, &bits);
	if (ret < 0) {
		fail("gnutls_pkcs11_obj_get_pk_algorithm: %s\n",
		     gnutls_strerror(ret));
		exit(1);
	}

	if (ret != GNUTLS_PK_RSA) {
		fail("expected algorithm %d (RSA), got %d\n", GNUTLS_PK_RSA,
		     ret);
		exit(1);
	}

	if (bits == 0) {
		fail("expected non-zero bit count for RSA key\n");
		exit(1);
	}

	if (debug)
		printf("pk algorithm: %s, bits: %u\n",
		       gnutls_pk_algorithm_get_name(ret), bits);

	gnutls_pkcs11_obj_deinit(obj);
	gnutls_pkcs11_deinit();
	gnutls_global_deinit();
}
#else
void doit(void)
{
	exit(77);
}
#endif
