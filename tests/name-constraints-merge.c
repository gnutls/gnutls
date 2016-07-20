/*
 * Copyright (C) 2016 Red Hat, Inc.
 *
 * Authors: Nikos Mavrogiannopoulos, Martin Ukrop
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

/* Parts copied from GnuTLS example programs. */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <unistd.h>
#include "../lib/gnutls_int.h"
#include "../lib/x509/x509_int.h"

#include "utils.h"

/* Test for name constraints PKIX extension.
 */

static void check_for_error(int ret) {
	if (ret != GNUTLS_E_SUCCESS)
		fail("error in %d: %s\n", __LINE__, gnutls_strerror(ret));
}

#define NAME_ACCEPTED 1
#define NAME_REJECTED 0

static void check_test_result(int ret, int expected_outcome, gnutls_datum_t *tested_data) {
	if (expected_outcome == NAME_ACCEPTED ? ret == 0 : ret != 0) {
		if (expected_outcome == NAME_ACCEPTED) {
			fail("Checking \"%.*s\" should have succeeded.\n", tested_data->size, tested_data->data);
		} else {
			fail("Checking \"%.*s\" should have failed.\n", tested_data->size, tested_data->data);
		}
	}
}

static void set_name(const char *name, gnutls_datum_t *datum) {
	datum->data = (unsigned char*) name;
	datum->size = strlen((char*) name);
}

static void tls_log_func(int level, const char *str)
{
	fprintf(stderr, "<%d>| %s", level, str);
}

void doit(void)
{
	int ret;
	gnutls_x509_name_constraints_t nc1, nc2;
	gnutls_datum_t name;

	gnutls_global_set_log_function(tls_log_func);
	if (debug)
		gnutls_global_set_log_level(6);

	/* 0: test the merge permitted name constraints
	 * NC1: permitted DNS org
	 *      permitted DNS ccc.com
	 *      permitted email ccc.com
	 * NC2: permitted DNS org
	 *      permitted DNS aaa.bbb.ccc.com
	 */

	ret = gnutls_x509_name_constraints_init(&nc1);
	check_for_error(ret);

	ret = gnutls_x509_name_constraints_init(&nc2);
	check_for_error(ret);

	set_name("org", &name);
	ret = gnutls_x509_name_constraints_add_permitted(nc1, GNUTLS_SAN_DNSNAME, &name);
	check_for_error(ret);

	set_name("ccc.com", &name);
	ret = gnutls_x509_name_constraints_add_permitted(nc1, GNUTLS_SAN_DNSNAME, &name);
	check_for_error(ret);

	set_name("ccc.com", &name);
	ret = gnutls_x509_name_constraints_add_permitted(nc1, GNUTLS_SAN_RFC822NAME, &name);
	check_for_error(ret);

	set_name("org", &name);
	ret = gnutls_x509_name_constraints_add_permitted(nc2, GNUTLS_SAN_DNSNAME, &name);
	check_for_error(ret);

	set_name("aaa.bbb.ccc.com", &name);
	ret = gnutls_x509_name_constraints_add_permitted(nc2, GNUTLS_SAN_DNSNAME, &name);
	check_for_error(ret);

	ret = _gnutls_x509_name_constraints_merge(nc1, nc2);
	check_for_error(ret);

	/* unrelated */
	set_name("xxx.example.com", &name);
	ret = gnutls_x509_name_constraints_check(nc1, GNUTLS_SAN_DNSNAME, &name);
	check_test_result(ret, NAME_REJECTED, &name);

	set_name("example.org", &name);
	ret = gnutls_x509_name_constraints_check(nc1, GNUTLS_SAN_DNSNAME, &name);
	check_test_result(ret, NAME_ACCEPTED, &name);

	set_name("com", &name);
	ret = gnutls_x509_name_constraints_check(nc1, GNUTLS_SAN_DNSNAME, &name);
	check_test_result(ret, NAME_REJECTED, &name);

	set_name("xxx.com", &name);
	ret = gnutls_x509_name_constraints_check(nc1, GNUTLS_SAN_DNSNAME, &name);
	check_test_result(ret, NAME_REJECTED, &name);

	set_name("ccc.com", &name);
	ret = gnutls_x509_name_constraints_check(nc1, GNUTLS_SAN_DNSNAME, &name);
	check_test_result(ret, NAME_REJECTED, &name);

	/* check intersection of permitted */
	set_name("xxx.aaa.bbb.ccc.com", &name);
	ret = gnutls_x509_name_constraints_check(nc1, GNUTLS_SAN_DNSNAME, &name);
	check_test_result(ret, NAME_ACCEPTED, &name);

	set_name("aaa.bbb.ccc.com", &name);
	ret = gnutls_x509_name_constraints_check(nc1, GNUTLS_SAN_DNSNAME, &name);
	check_test_result(ret, NAME_ACCEPTED, &name);

	set_name("xxx.bbb.ccc.com", &name);
	ret = gnutls_x509_name_constraints_check(nc1, GNUTLS_SAN_DNSNAME, &name);
	check_test_result(ret, NAME_REJECTED, &name);

	set_name("xxx.ccc.com", &name);
	ret = gnutls_x509_name_constraints_check(nc1, GNUTLS_SAN_DNSNAME, &name);
	check_test_result(ret, NAME_REJECTED, &name);

	set_name("ccc.com", &name);
	ret = gnutls_x509_name_constraints_check(nc1, GNUTLS_SAN_DNSNAME, &name);
	check_test_result(ret, NAME_REJECTED, &name);

	set_name("ccc.com", &name);
	ret = gnutls_x509_name_constraints_check(nc1, GNUTLS_SAN_RFC822NAME, &name);
	check_test_result(ret, NAME_ACCEPTED, &name);

	set_name("xxx.ccc.com", &name);
	ret = gnutls_x509_name_constraints_check(nc1, GNUTLS_SAN_RFC822NAME, &name);
	check_test_result(ret, NAME_REJECTED, &name);

	gnutls_x509_name_constraints_deinit(nc1);
	gnutls_x509_name_constraints_deinit(nc2);

	/* 1: test the merge of excluded name constraints
	 * NC1: denied DNS example.com
	 * NC2: denied DNS example.net
	 */

	ret = gnutls_x509_name_constraints_init(&nc1);
	check_for_error(ret);

	ret = gnutls_x509_name_constraints_init(&nc2);
	check_for_error(ret);

	set_name("example.com", &name);
	ret = gnutls_x509_name_constraints_add_excluded(nc1, GNUTLS_SAN_DNSNAME, &name);
	check_for_error(ret);

	set_name("example.net", &name);
	ret = gnutls_x509_name_constraints_add_excluded(nc2, GNUTLS_SAN_DNSNAME, &name);
	check_for_error(ret);

	ret = _gnutls_x509_name_constraints_merge(nc1, nc2);
	check_for_error(ret);

	set_name("xxx.example.com", &name);
	ret = gnutls_x509_name_constraints_check(nc1, GNUTLS_SAN_DNSNAME, &name);
	check_test_result(ret, NAME_REJECTED, &name);

	set_name("xxx.example.net", &name);
	ret = gnutls_x509_name_constraints_check(nc1, GNUTLS_SAN_DNSNAME, &name);
	check_test_result(ret, NAME_REJECTED, &name);

	set_name("example.com", &name);
	ret = gnutls_x509_name_constraints_check(nc1, GNUTLS_SAN_DNSNAME, &name);
	check_test_result(ret, NAME_REJECTED, &name);

	set_name("example.net", &name);
	ret = gnutls_x509_name_constraints_check(nc1, GNUTLS_SAN_DNSNAME, &name);
	check_test_result(ret, NAME_REJECTED, &name);

	set_name("example.org", &name);
	ret = gnutls_x509_name_constraints_check(nc1, GNUTLS_SAN_DNSNAME, &name);
	check_test_result(ret, NAME_ACCEPTED, &name);

	gnutls_x509_name_constraints_deinit(nc1);
	gnutls_x509_name_constraints_deinit(nc2);

	if (debug)
		success("Test success.\n");
}
