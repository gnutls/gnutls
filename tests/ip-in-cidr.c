/*
 * Copyright (C) 2016 Red Hat, Inc.
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

#include <config.h>
#include <stdarg.h>
#include <stddef.h>
#include <setjmp.h>
#include <limits.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <gnutls/gnutls.h>
#include <gnutls/x509.h>

#ifndef _WIN32
# include <cmocka.h>
# include <arpa/inet.h>

#define _gnutls_hard_log(...) 
#define _gnutls_ip_to_string(...) 
#define _gnutls_cidr_to_string(...) 
#include "../lib/x509/ip-in-cidr.h"

#define _MATCH_FUNC(fname, CIDR, IP, status) \
static void fname(void **glob_state) \
{ \
	gnutls_datum_t dcidr; \
	const char cidr[] = CIDR; \
	const char ip[] = IP; \
	char xip[4]; \
	gnutls_datum_t dip = {(unsigned char*)xip, sizeof(xip)}; \
	assert_int_equal(gnutls_x509_cidr_to_rfc5280format(cidr, &dcidr), 0); \
	assert_int_equal(inet_pton(AF_INET, ip, xip), 1); \
	assert_int_equal(ip_in_cidr(&dip, &dcidr), status); \
	gnutls_free(dcidr.data); \
}

#define MATCH_FUNC_OK(fname, CIDR, IP) _MATCH_FUNC(fname, CIDR, IP, 1)
#define MATCH_FUNC_NOT_OK(fname, CIDR, IP) _MATCH_FUNC(fname, CIDR, IP, 0)

MATCH_FUNC_OK(check_ip1_match, "192.168.1.0/24", "192.168.1.128");
MATCH_FUNC_OK(check_ip2_match, "192.168.1.0/24", "192.168.1.1");
MATCH_FUNC_OK(check_ip3_match, "192.168.1.0/24", "192.168.1.0");
MATCH_FUNC_OK(check_ip4_match, "192.168.1.0/28", "192.168.1.0");
MATCH_FUNC_OK(check_ip5_match, "192.168.1.0/28", "192.168.1.14");

MATCH_FUNC_NOT_OK(check_ip1_not_match, "192.168.1.0/24", "192.168.2.128");
MATCH_FUNC_NOT_OK(check_ip2_not_match, "192.168.1.0/24", "192.168.128.1");
MATCH_FUNC_NOT_OK(check_ip3_not_match, "192.168.1.0/24", "193.168.1.0");
MATCH_FUNC_NOT_OK(check_ip4_not_match, "192.168.1.0/28", "192.168.1.16");
MATCH_FUNC_NOT_OK(check_ip5_not_match, "192.168.1.0/28", "192.168.1.64");
MATCH_FUNC_NOT_OK(check_ip6_not_match, "192.168.1.0/24", "10.0.0.0");
MATCH_FUNC_NOT_OK(check_ip7_not_match, "192.168.1.0/24", "192.169.1.0");

int main(void)
{
	const struct CMUnitTest tests[] = {
		cmocka_unit_test(check_ip1_match),
		cmocka_unit_test(check_ip2_match),
		cmocka_unit_test(check_ip3_match),
		cmocka_unit_test(check_ip4_match),
		cmocka_unit_test(check_ip5_match),
		cmocka_unit_test(check_ip1_not_match),
		cmocka_unit_test(check_ip2_not_match),
		cmocka_unit_test(check_ip3_not_match),
		cmocka_unit_test(check_ip4_not_match),
		cmocka_unit_test(check_ip5_not_match),
		cmocka_unit_test(check_ip6_not_match),
		cmocka_unit_test(check_ip7_not_match),
	};
	return cmocka_run_group_tests(tests, NULL, NULL);
}
#else
int main(void)
{
	exit(77);
}
#endif
