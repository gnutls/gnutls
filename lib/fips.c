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

#ifdef ENABLE_FIPS140

# include <gnutls_int.h>
# include <gnutls/gnutls.h>
# include <unistd.h>

unsigned int _gnutls_fips_mode = STATE_POWERON;

unsigned _gnutls_fips_mode_enabled(void)
{
	/* FIXME: There are some subtle differences here. Check it out later */
	if (access("/proc/sys/crypto/fips_enabled", R_OK) == 0 &&
		access("/etc/system-fips", R_OK) == 0)
		return 1;
	
	return 0;
}

int _gnutls_fips_perform_self_checks(void)
{
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

	ret = gnutls_pk_self_test(0, GNUTLS_PK_ECDSA);
	if (ret < 0) {
		gnutls_assert();
		goto error;
	}

	return 0;
error:
	_gnutls_switch_fips_state(FIPS_STATE_ERROR);
	return gnutls_assert_val(GNUTLS_E_SELF_TEST_ERR);
}

#endif
