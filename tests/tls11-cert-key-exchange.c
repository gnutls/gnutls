/*
 * Copyright (C) 2015-2017 Red Hat, Inc.
 *
 * Author: Nikos Mavrogiannopoulos
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
 * along with GnuTLS; if not, write to the Free Software Foundation,
 * Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301, USA
 */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

/* This program tests the various certificate key exchange methods supported
 * in gnutls */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <gnutls/gnutls.h>
#include "utils.h"
#include "common-cert-key-exchange.h"
#include "cert-common.h"

void doit(void)
{
	global_init();

	try("TLS 1.1 with anon-ecdh", "NORMAL:-VERS-ALL:+VERS-TLS1.1:-KX-ALL:+ANON-ECDH", GNUTLS_KX_ANON_ECDH, GNUTLS_SIGN_UNKNOWN, GNUTLS_SIGN_UNKNOWN);
	try("TLS 1.1 with anon-dh", "NORMAL:-VERS-ALL:+VERS-TLS1.1:-KX-ALL:+ANON-DH", GNUTLS_KX_ANON_DH, GNUTLS_SIGN_UNKNOWN, GNUTLS_SIGN_UNKNOWN);
	try("TLS 1.1 with dhe-rsa no cert", "NORMAL:-VERS-ALL:+VERS-TLS1.1:-KX-ALL:+DHE-RSA", GNUTLS_KX_DHE_RSA, GNUTLS_SIGN_UNKNOWN, GNUTLS_SIGN_UNKNOWN);
	try("TLS 1.1 with ecdhe x25519 rsa no cert", "NORMAL:-VERS-ALL:+VERS-TLS1.1:-KX-ALL:+ECDHE-RSA:-CURVE-ALL:+CURVE-X25519", GNUTLS_KX_ECDHE_RSA, GNUTLS_SIGN_UNKNOWN, GNUTLS_SIGN_UNKNOWN);
	try("TLS 1.1 with ecdhe rsa no cert", "NORMAL:-VERS-ALL:+VERS-TLS1.1:-KX-ALL:+ECDHE-RSA", GNUTLS_KX_ECDHE_RSA, GNUTLS_SIGN_UNKNOWN, GNUTLS_SIGN_UNKNOWN);
	try_with_key("TLS 1.1 with ecdhe ecdsa no cert", "NORMAL:-VERS-ALL:+VERS-TLS1.1:-KX-ALL:+ECDHE-ECDSA", GNUTLS_KX_ECDHE_ECDSA, GNUTLS_SIGN_UNKNOWN, GNUTLS_SIGN_UNKNOWN,
		&server_ca3_localhost_ecc_cert, &server_ca3_ecc_key, NULL, NULL, 0);

	try("TLS 1.1 with rsa no cert", "NORMAL:-VERS-ALL:+VERS-TLS1.1:-KX-ALL:+RSA", GNUTLS_KX_RSA, GNUTLS_SIGN_UNKNOWN, GNUTLS_SIGN_UNKNOWN);

	try_cli("TLS 1.1 with dhe-rsa cert", "NORMAL:-VERS-ALL:+VERS-TLS1.1:-KX-ALL:+DHE-RSA", GNUTLS_KX_DHE_RSA, GNUTLS_SIGN_UNKNOWN, GNUTLS_SIGN_UNKNOWN, USE_CERT);
	try_cli("TLS 1.1 with ecdhe-rsa cert", "NORMAL:-VERS-ALL:+VERS-TLS1.1:-KX-ALL:+ECDHE-RSA", GNUTLS_KX_ECDHE_RSA, GNUTLS_SIGN_UNKNOWN, GNUTLS_SIGN_UNKNOWN, USE_CERT);
	try_cli("TLS 1.1 with rsa cert", "NORMAL:-VERS-ALL:+VERS-TLS1.1:-KX-ALL:+RSA", GNUTLS_KX_RSA, GNUTLS_SIGN_UNKNOWN, GNUTLS_SIGN_UNKNOWN, USE_CERT);
	try_with_key("TLS 1.1 with ecdhe ecdsa cert", "NORMAL:-VERS-ALL:+VERS-TLS1.1:-KX-ALL:+ECDHE-ECDSA", GNUTLS_KX_ECDHE_ECDSA, GNUTLS_SIGN_UNKNOWN, GNUTLS_SIGN_UNKNOWN,
		&server_ca3_localhost_ecc_cert, &server_ca3_ecc_key, &cli_ca3_cert, &cli_ca3_key, USE_CERT);

	try_cli("TLS 1.1 with dhe-rsa ask cert", "NORMAL:-VERS-ALL:+VERS-TLS1.1:-KX-ALL:+DHE-RSA", GNUTLS_KX_DHE_RSA, GNUTLS_SIGN_UNKNOWN, GNUTLS_SIGN_UNKNOWN, ASK_CERT);
	try_cli("TLS 1.1 with ecdhe-rsa ask cert", "NORMAL:-VERS-ALL:+VERS-TLS1.1:-KX-ALL:+ECDHE-RSA", GNUTLS_KX_ECDHE_RSA, GNUTLS_SIGN_UNKNOWN, GNUTLS_SIGN_UNKNOWN, ASK_CERT);
	try_cli("TLS 1.1 with rsa ask cert", "NORMAL:-VERS-ALL:+VERS-TLS1.1:-KX-ALL:+RSA", GNUTLS_KX_RSA, GNUTLS_SIGN_UNKNOWN, GNUTLS_SIGN_UNKNOWN, ASK_CERT);
	try_with_key("TLS 1.1 with ecdhe ecdsa cert", "NORMAL:-VERS-ALL:+VERS-TLS1.1:-KX-ALL:+ECDHE-ECDSA", GNUTLS_KX_ECDHE_ECDSA, GNUTLS_SIGN_UNKNOWN, GNUTLS_SIGN_UNKNOWN,
		&server_ca3_localhost_ecc_cert, &server_ca3_ecc_key, &cli_ca3_cert, &cli_ca3_key, ASK_CERT);

#ifdef ENABLE_GOST
	if (!gnutls_fips140_mode_enabled()) {
		try_with_key("TLS 1.1 with gost01 no cert", "NORMAL:-VERS-ALL:+VERS-TLS1.1:-KX-ALL:+VKO-GOST-01", GNUTLS_KX_VKO_GOST_01, GNUTLS_SIGN_UNKNOWN, GNUTLS_SIGN_UNKNOWN,
			&server_ca3_gost01_cert, &server_ca3_gost01_key, NULL, NULL, 0);
		try_with_key("TLS 1.1 with gost01 ask cert", "NORMAL:-VERS-ALL:+VERS-TLS1.1:-KX-ALL:+VKO-GOST-01", GNUTLS_KX_VKO_GOST_01, GNUTLS_SIGN_UNKNOWN, GNUTLS_SIGN_UNKNOWN,
			&server_ca3_gost01_cert, &server_ca3_gost01_key, NULL, NULL, ASK_CERT);
		try_with_key("TLS 1.1 with gost01 use cert", "NORMAL:-VERS-ALL:+VERS-TLS1.1:-KX-ALL:+VKO-GOST-01", GNUTLS_KX_VKO_GOST_01, GNUTLS_SIGN_UNKNOWN, GNUTLS_SIGN_UNKNOWN,
			&server_ca3_gost01_cert, &server_ca3_gost01_key, &cligost01_ca3_cert, &cligost01_ca3_key, USE_CERT);
		try_with_key("TLS 1.1 with gost12 256 no cert", "NORMAL:-VERS-ALL:+VERS-TLS1.1:-KX-ALL:+VKO-GOST-12", GNUTLS_KX_VKO_GOST_12, GNUTLS_SIGN_UNKNOWN, GNUTLS_SIGN_UNKNOWN,
			&server_ca3_gost12_256_cert, &server_ca3_gost12_256_key, NULL, NULL, 0);
		try_with_key("TLS 1.1 with gost12 256 ask cert", "NORMAL:-VERS-ALL:+VERS-TLS1.1:-KX-ALL:+VKO-GOST-12", GNUTLS_KX_VKO_GOST_12, GNUTLS_SIGN_UNKNOWN, GNUTLS_SIGN_UNKNOWN,
			&server_ca3_gost12_256_cert, &server_ca3_gost12_256_key, NULL, NULL, ASK_CERT);
		try_with_key("TLS 1.1 with gost12 256 use cert", "NORMAL:-VERS-ALL:+VERS-TLS1.1:-KX-ALL:+VKO-GOST-12", GNUTLS_KX_VKO_GOST_12, GNUTLS_SIGN_UNKNOWN, GNUTLS_SIGN_UNKNOWN,
			&server_ca3_gost12_256_cert, &server_ca3_gost12_256_key, &cligost12_256_ca3_cert, &cligost12_256_ca3_key, USE_CERT);
		try_with_key("TLS 1.1 with gost12 256 use cert gost01", "NORMAL:-VERS-ALL:+VERS-TLS1.1:-KX-ALL:+VKO-GOST-12", GNUTLS_KX_VKO_GOST_12, GNUTLS_SIGN_UNKNOWN, GNUTLS_SIGN_UNKNOWN,
			&server_ca3_gost12_256_cert, &server_ca3_gost12_256_key, &cligost01_ca3_cert, &cligost01_ca3_key, USE_CERT);
		try_with_key("TLS 1.1 with gost12 512 no cert", "NORMAL:-VERS-ALL:+VERS-TLS1.1:-KX-ALL:+VKO-GOST-12", GNUTLS_KX_VKO_GOST_12, GNUTLS_SIGN_UNKNOWN, GNUTLS_SIGN_UNKNOWN,
			&server_ca3_gost12_512_cert, &server_ca3_gost12_512_key, NULL, NULL, 0);
		try_with_key("TLS 1.1 with gost12 512 ask cert", "NORMAL:-VERS-ALL:+VERS-TLS1.1:-KX-ALL:+VKO-GOST-12", GNUTLS_KX_VKO_GOST_12, GNUTLS_SIGN_UNKNOWN, GNUTLS_SIGN_UNKNOWN,
			&server_ca3_gost12_512_cert, &server_ca3_gost12_512_key, NULL, NULL, ASK_CERT);
		try_with_key("TLS 1.1 with gost12 512 use cert", "NORMAL:-VERS-ALL:+VERS-TLS1.1:-KX-ALL:+VKO-GOST-12", GNUTLS_KX_VKO_GOST_12, GNUTLS_SIGN_UNKNOWN, GNUTLS_SIGN_UNKNOWN,
			&server_ca3_gost12_512_cert, &server_ca3_gost12_512_key, &cligost12_512_ca3_cert, &cligost12_512_ca3_key, USE_CERT);
		try_with_key("TLS 1.1 with gost12 512 use cert gost01", "NORMAL:-VERS-ALL:+VERS-TLS1.1:-KX-ALL:+VKO-GOST-12", GNUTLS_KX_VKO_GOST_12, GNUTLS_SIGN_UNKNOWN, GNUTLS_SIGN_UNKNOWN,
			&server_ca3_gost12_512_cert, &server_ca3_gost12_512_key, &cligost01_ca3_cert, &cligost01_ca3_key, USE_CERT);
		try_with_key("TLS 1.1 with gost12 512 use cert gost12 256", "NORMAL:-VERS-ALL:+VERS-TLS1.1:-KX-ALL:+VKO-GOST-12", GNUTLS_KX_VKO_GOST_12, GNUTLS_SIGN_UNKNOWN, GNUTLS_SIGN_UNKNOWN,
			&server_ca3_gost12_512_cert, &server_ca3_gost12_512_key, &cligost12_256_ca3_cert, &cligost12_256_ca3_key, USE_CERT);
	}
#endif
	gnutls_global_deinit();
}
