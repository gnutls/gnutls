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
#include <gnutls/gnutls.h>
#include <gnutls/crypto.h>
#include <unistd.h>
#include <gnutls_errors.h>
#include <fips.h>
#include <stdio.h>
#include <random.h>
#include <gnutls/fips140.h>
#include <dlfcn.h>

#ifdef ENABLE_FIPS140

#define FIPS_KERNEL_FILE "/proc/sys/crypto/fips_enabled"
#define FIPS_SYSTEM_FILE "/etc/system-fips"

unsigned int _gnutls_fips_mode = FIPS_STATE_POWERON;

unsigned _gnutls_fips_mode_enabled(void)
{
unsigned f1p, f2p;
FILE* fd;

	fd = fopen(FIPS_KERNEL_FILE, "r");
	if (fd != NULL) {
		f1p = fgetc(fd);
		fclose(fd);
		
		if (f1p == '1') f1p = 1;
		else f1p = 0;
	}

	f2p = !access(FIPS_SYSTEM_FILE, R_OK);

	if (f1p != 0 && f2p != 0) {
		_gnutls_debug_log("FIPS140-2 mode enabled\n");
		return 1;
	}

	if (f2p != 0) {
		/* a funny state where self tests are performed
		 * and ignored */
		_gnutls_switch_fips_state(FIPS_STATE_ZOMBIE);
		_gnutls_debug_log("FIPS140-2 ZOMBIE mode enabled\n");
		return 1;
	}

	return 0;
}

static const char fips_key[] = "orboDeJITITejsirpADONivirpUkvarP";

#define HMAC_SUFFIX ".hmac"
#define HMAC_SIZE 32
#define HMAC_ALGO GNUTLS_MAC_SHA256

/* Run an HMAC using the key above on the library binary data. 
 * Returns true success and false on error.
 */
static unsigned check_binary_integrity(void)
{
	int ret;
	Dl_info info;
	unsigned prev;
	char mac_file[GNUTLS_PATH_MAX];
	uint8_t hmac[HMAC_SIZE];
	uint8_t new_hmac[HMAC_SIZE];
	size_t hmac_size;
	gnutls_datum_t data;

	ret = dladdr("gnutls_global_init", &info);
	if (ret == 0)
		return gnutls_assert_val(0);

	_gnutls_debug_log("Loading: %s\n", info.dli_fname);
	ret = gnutls_load_file(info.dli_fname, &data);
	if (ret < 0)
		return gnutls_assert_val(0);

	prev = _gnutls_get_fips_state();
	_gnutls_switch_fips_state(FIPS_STATE_OPERATIONAL);
	ret = gnutls_hmac_fast(HMAC_ALGO, fips_key, sizeof(fips_key)-1,
		data.data, data.size, new_hmac);
	_gnutls_switch_fips_state(prev);
	
	gnutls_free(data.data);

	if (ret < 0)
		return gnutls_assert_val(0);

	/* now open the .hmac file and compare */
	snprintf(mac_file, sizeof(mac_file), "%s"HMAC_SUFFIX, info.dli_fname);
	
	ret = gnutls_load_file(mac_file, &data);
	if (ret < 0) {
		_gnutls_debug_log("Could not open %s%s for MAC testing: %s\n", info.dli_fname, HMAC_SUFFIX, gnutls_strerror(ret));
		return gnutls_assert_val(0);
	}

	hmac_size = sizeof(hmac);
	ret = _gnutls_hex2bin((void*)data.data, data.size, hmac, &hmac_size);
	gnutls_free(data.data);

	if (ret < 0) {
		_gnutls_debug_log("Could not convert hex data to binary for MAC testing.\n");
		return gnutls_assert_val(0);
	}

	if (hmac_size != sizeof(hmac) ||
			memcmp(hmac, new_hmac, sizeof(hmac)) != 0) {
		_gnutls_debug_log("Calculated MAC does not match\n");
		return gnutls_assert_val(0);
	}
	_gnutls_debug_log("Successfully verified library MAC\n");
	
	return 1;
}

int _gnutls_fips_perform_self_checks(void)
{
	int ret;

	_gnutls_switch_fips_state(FIPS_STATE_SELFTEST);

	/* Tests the FIPS algorithms */

	/* ciphers */
	ret = gnutls_cipher_self_test(0, GNUTLS_CIPHER_AES_128_CBC);
	if (ret < 0) {
		gnutls_assert();
		goto error;
	}

	ret = gnutls_cipher_self_test(0, GNUTLS_CIPHER_AES_192_CBC);
	if (ret < 0) {
		gnutls_assert();
		goto error;
	}

	ret = gnutls_cipher_self_test(0, GNUTLS_CIPHER_AES_256_CBC);
	if (ret < 0) {
		gnutls_assert();
		goto error;
	}

	ret = gnutls_cipher_self_test(0, GNUTLS_CIPHER_3DES_CBC);
	if (ret < 0) {
		gnutls_assert();
		goto error;
	}

	ret = gnutls_cipher_self_test(0, GNUTLS_CIPHER_AES_128_GCM);
	if (ret < 0) {
		gnutls_assert();
		goto error;
	}

	ret = gnutls_cipher_self_test(0, GNUTLS_CIPHER_AES_256_GCM);
	if (ret < 0) {
		gnutls_assert();
		goto error;
	}

	/* MAC (includes message digest test) */
	ret = gnutls_mac_self_test(0, GNUTLS_MAC_MD5);
	if (ret < 0) {
		gnutls_assert();
		goto error;
	}

	ret = gnutls_mac_self_test(0, GNUTLS_MAC_SHA1);
	if (ret < 0) {
		gnutls_assert();
		goto error;
	}

	ret = gnutls_mac_self_test(0, GNUTLS_MAC_SHA224);
	if (ret < 0) {
		gnutls_assert();
		goto error;
	}

	ret = gnutls_mac_self_test(0, GNUTLS_MAC_SHA256);
	if (ret < 0) {
		gnutls_assert();
		goto error;
	}

	ret = gnutls_mac_self_test(0, GNUTLS_MAC_SHA384);
	if (ret < 0) {
		gnutls_assert();
		goto error;
	}

	ret = gnutls_mac_self_test(0, GNUTLS_MAC_SHA512);
	if (ret < 0) {
		gnutls_assert();
		goto error;
	}

	/* PK */
	ret = gnutls_pk_self_test(0, GNUTLS_PK_RSA);
	if (ret < 0) {
		gnutls_assert();
		goto error;
	}

	ret = gnutls_pk_self_test(0, GNUTLS_PK_DSA);
	if (ret < 0) {
		gnutls_assert();
		goto error;
	}

	ret = gnutls_pk_self_test(0, GNUTLS_PK_EC);
	if (ret < 0) {
		gnutls_assert();
		goto error;
	}

	if (_gnutls_rnd_ops.self_test == NULL) {
		gnutls_assert();
		goto error;
	}
        
	ret = _gnutls_rnd_ops.self_test();
	if (ret < 0) {
		gnutls_assert();
		goto error;
	}

	ret = check_binary_integrity();
	if (ret == 0) {
		gnutls_assert();
		goto error;
	}

	return 0;
error:
	_gnutls_switch_fips_state(FIPS_STATE_ERROR);
	_gnutls_audit_log(NULL, "FIPS140-2 self testing failed\n");

	return GNUTLS_E_SELF_TEST_ERROR;
}
#endif

/**
 * gnutls_fips140_mode_enabled:
 *
 * Checks whether this library is in FIPS140 mode.
 *
 * Returns: return non-zero if true or zero if false.
 *
 * Since: 3.3.0
 **/
int gnutls_fips140_mode_enabled(void)
{
#ifdef ENABLE_FIPS140

	return _gnutls_fips_mode_enabled();
#else
	return 0;
#endif
}

void _gnutls_fips140_simulate_error(void)
{
#ifdef ENABLE_FIPS140
	_gnutls_switch_fips_state(FIPS_STATE_ERROR);
#endif
}
