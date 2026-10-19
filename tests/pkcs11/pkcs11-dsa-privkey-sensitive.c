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
 * You should have received a copy of the GNU General Public License
 * along with GnuTLS.  If not, see <https://www.gnu.org/licenses/>.
 */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <assert.h>
#include <unistd.h>

#include <gnutls/gnutls.h>
#include <gnutls/pkcs11.h>

#ifdef _WIN32

void doit(void)
{
	exit(77);
}

#else

#include "../utils.h"
#include "softhsm.h"

/* Tests whether gnutls_pkcs11_obj_get_pk_algorithm() reports the correct
 * algorithm and bit length for DSA private keys stored in a token,
 * including keys marked as sensitive (i.e., CKA_VALUE cannot be read).
 */

#define CONFIG_NAME "softhsm-dsa-privkey-sensitive"
#define CONFIG CONFIG_NAME ".config"
#define PIN "1234"
#define TOKEN_URL "pkcs11:token=test"

static void tls_log_func(int level, const char *str)
{
	fprintf(stderr, "|<%d>| %s", level, str);
}

static int pin_func(void *userdata, int attempt, const char *url,
		    const char *label, unsigned flags, char *pin,
		    size_t pin_max)
{
	strcpy(pin, PIN);
	return 0;
}

static void test_dsa_key(const char *label, unsigned expected_bits,
			 bool sensitive)
{
	gnutls_pkcs11_obj_t obj;
	gnutls_datum_t pubkey = { NULL, 0 };
	unsigned int flags = GNUTLS_PKCS11_OBJ_FLAG_LOGIN;
	unsigned int bits = 0;
	char url[128];
	int ret;

	flags |= sensitive ? GNUTLS_PKCS11_OBJ_FLAG_MARK_SENSITIVE :
			     GNUTLS_PKCS11_OBJ_FLAG_MARK_NOT_SENSITIVE;

	ret = gnutls_pkcs11_privkey_generate3(TOKEN_URL, GNUTLS_PK_DSA,
					      expected_bits, label, NULL,
					      GNUTLS_X509_FMT_DER, &pubkey, 0,
					      flags);
	if (ret < 0)
		fail("%s: gnutls_pkcs11_privkey_generate3: %s\n", label,
		     gnutls_strerror(ret));
	gnutls_free(pubkey.data);

	assert(snprintf(url, sizeof(url), TOKEN_URL ";object=%s;type=private",
			label) < (int)sizeof(url));

	assert(gnutls_pkcs11_obj_init(&obj) >= 0);
	gnutls_pkcs11_obj_set_pin_function(obj, pin_func, NULL);

	ret = gnutls_pkcs11_obj_import_url(obj, url,
					   GNUTLS_PKCS11_OBJ_FLAG_LOGIN);
	if (ret < 0)
		fail("%s: gnutls_pkcs11_obj_import_url: %s\n", label,
		     gnutls_strerror(ret));

	ret = gnutls_pkcs11_obj_get_pk_algorithm(obj, &bits);
	if (ret < 0)
		fail("%s: gnutls_pkcs11_obj_get_pk_algorithm: %s\n", label,
		     gnutls_strerror(ret));

	if (ret != GNUTLS_PK_DSA)
		fail("%s: expected algorithm %s, got %s (%d)\n", label,
		     gnutls_pk_get_name(GNUTLS_PK_DSA), gnutls_pk_get_name(ret),
		     ret);

	if (bits != expected_bits)
		fail("%s: expected %u bits, got %u\n", label, expected_bits,
		     bits);

	success("%s: %s key, %u bits\n", label, gnutls_pk_get_name(ret), bits);

	gnutls_pkcs11_obj_deinit(obj);
}

void doit(void)
{
	char buf[256];
	const char *lib, *bin;
	int ret;

	if (gnutls_fips140_mode_enabled())
		exit(77);

	bin = softhsm_bin();
	lib = softhsm_lib();

	ret = global_init();
	if (ret != 0)
		fail("%d: %s\n", ret, gnutls_strerror(ret));

	gnutls_global_set_log_function(tls_log_func);
	if (debug)
		gnutls_global_set_log_level(4711);

	set_softhsm_conf(CONFIG);
	snprintf(buf, sizeof(buf),
		 "%s --init-token --slot 0 --label test --so-pin " PIN
		 " --pin " PIN,
		 bin);
	system(buf);

	ret = gnutls_pkcs11_init(GNUTLS_PKCS11_FLAG_MANUAL, NULL);
	if (ret != 0)
		fail("%d: %s\n", ret, gnutls_strerror(ret));

	ret = gnutls_pkcs11_add_provider(lib, NULL);
	if (ret != 0)
		fail("%d: %s\n", ret, gnutls_strerror(ret));

	gnutls_pkcs11_set_pin_function(pin_func, NULL);

	test_dsa_key("dsa-sensitive", 2048, true);
	test_dsa_key("dsa-non-sensitive", 2048, false);

	gnutls_pkcs11_deinit();
	gnutls_global_deinit();
	remove(CONFIG);
}
#endif
