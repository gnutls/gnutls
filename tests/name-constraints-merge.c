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

static void tls_log_func(int level, const char *str)
{
	fprintf(stderr, "<%d>| %s", level, str);
}

/* deny */
const gnutls_datum_t example_com = { (void*)"example.com", sizeof("example.com")-1 };
const gnutls_datum_t example_net = { (void*)"example.net", sizeof("example.net")-1 };

/* allowed */
const gnutls_datum_t org = { (void*)"org", sizeof("org")-1 };
const gnutls_datum_t ccc_com = { (void*)"ccc.com", sizeof("ccc.com")-1 };
const gnutls_datum_t aaa_bbb_ccc_com = { (void*)"aaa.bbb.ccc.com", sizeof("aaa.bbb.ccc.com")-1 };

void doit(void)
{
	int ret;
	gnutls_x509_name_constraints_t nc;
	gnutls_x509_name_constraints_t nc2;
	gnutls_datum_t name;

	/* this must be called once in the program
	 */
	global_init();

	gnutls_global_set_log_function(tls_log_func);
	if (debug)
		gnutls_global_set_log_level(6);

	/* 0: test the merge permitted */

	ret = gnutls_x509_name_constraints_init(&nc);
	if (ret < 0)
		fail("error in %d: %s\n", __LINE__, gnutls_strerror(ret));

	ret = gnutls_x509_name_constraints_init(&nc2);
	if (ret < 0)
		fail("error in %d: %s\n", __LINE__, gnutls_strerror(ret));


	/* nc: dnsName: .org + ccc.com, rfc822Name: ccc.com */
	ret = gnutls_x509_name_constraints_add_permitted(nc, GNUTLS_SAN_DNSNAME,
		&org);
	if (ret < 0)
		fail("error in %d: %s\n", __LINE__, gnutls_strerror(ret));

	ret = gnutls_x509_name_constraints_add_permitted(nc, GNUTLS_SAN_DNSNAME,
		&ccc_com);
	if (ret < 0)
		fail("error in %d: %s\n", __LINE__, gnutls_strerror(ret));

	ret = gnutls_x509_name_constraints_add_permitted(nc, GNUTLS_SAN_RFC822NAME,
		&ccc_com);
	if (ret < 0)
		fail("error in %d: %s\n", __LINE__, gnutls_strerror(ret));

	/* nc2: dnsName: .org + aaa.bbb.ccc.com */
	ret = gnutls_x509_name_constraints_add_permitted(nc2, GNUTLS_SAN_DNSNAME,
		&org);
	if (ret < 0)
		fail("error in %d: %s\n", __LINE__, gnutls_strerror(ret));

	ret = gnutls_x509_name_constraints_add_permitted(nc2, GNUTLS_SAN_DNSNAME,
		&aaa_bbb_ccc_com);
	if (ret < 0)
		fail("error in %d: %s\n", __LINE__, gnutls_strerror(ret));

	/* intersection: permit: aaa.bbb.ccc.com */
	ret = _gnutls_x509_name_constraints_merge(nc, nc2);
	if (ret < 0)
		fail("error in %d: %s\n", __LINE__, gnutls_strerror(ret));


	/* unrelated */
	name.data = (unsigned char*)"xxx.example.com";
	name.size = strlen((char*)name.data);
	ret = gnutls_x509_name_constraints_check(nc, GNUTLS_SAN_DNSNAME, &name);
	if (ret != 0)
		fail("Checking domain should have failed\n");

	name.data = (unsigned char*)"example.org";
	name.size = strlen((char*)name.data);
	ret = gnutls_x509_name_constraints_check(nc, GNUTLS_SAN_DNSNAME, &name);
	if (ret == 0)
		fail("Checking %s should have succeeded\n", name.data);

	name.data = (unsigned char*)"com";
	name.size = strlen((char*)name.data);
	ret = gnutls_x509_name_constraints_check(nc, GNUTLS_SAN_DNSNAME, &name);
	if (ret != 0)
		fail("Checking %s should have failed\n", name.data);

	name.data = (unsigned char*)"xxx.com";
	name.size = strlen((char*)name.data);
	ret = gnutls_x509_name_constraints_check(nc, GNUTLS_SAN_DNSNAME, &name);
	if (ret != 0)
		fail("Checking %s should have failed\n", name.data);

	name.data = (unsigned char*)"ccc.com";
	name.size = strlen((char*)name.data);
	ret = gnutls_x509_name_constraints_check(nc, GNUTLS_SAN_DNSNAME, &name);
	if (ret != 0)
		fail("Checking %s should have failed\n", name.data);


	/* check intersection of permitted */
	name.data = (unsigned char*)"xxx.aaa.bbb.ccc.com";
	name.size = strlen((char*)name.data);
	ret = gnutls_x509_name_constraints_check(nc, GNUTLS_SAN_DNSNAME, &name);
	if (ret == 0)
		fail("Checking %s should have succeeded\n", name.data);

	name.data = (unsigned char*)"aaa.bbb.ccc.com";
	name.size = strlen((char*)name.data);
	ret = gnutls_x509_name_constraints_check(nc, GNUTLS_SAN_DNSNAME, &name);
	if (ret == 0)
		fail("Checking %s should have succeeded\n", name.data);

	name.data = (unsigned char*)"xxx.bbb.ccc.com";
	name.size = strlen((char*)name.data);
	ret = gnutls_x509_name_constraints_check(nc, GNUTLS_SAN_DNSNAME, &name);
	if (ret != 0)
		fail("Checking %s should have failed\n", name.data);

	name.data = (unsigned char*)"xxx.ccc.com";
	name.size = strlen((char*)name.data);
	ret = gnutls_x509_name_constraints_check(nc, GNUTLS_SAN_DNSNAME, &name);
	if (ret != 0)
		fail("Checking %s should have failed\n", name.data);

	name.data = (unsigned char*)"ccc.com";
	name.size = strlen((char*)name.data);
	ret = gnutls_x509_name_constraints_check(nc, GNUTLS_SAN_DNSNAME, &name);
	if (ret != 0)
		fail("Checking %s should have failed\n", name.data);

	name.data = (unsigned char*)"ccc.com";
	name.size = strlen((char*)name.data);
	ret = gnutls_x509_name_constraints_check(nc, GNUTLS_SAN_RFC822NAME, &name);
	if (ret == 0)
		fail("Checking %s should have succeeded\n", name.data);

	name.data = (unsigned char*)"xxx.ccc.com";
	name.size = strlen((char*)name.data);
	ret = gnutls_x509_name_constraints_check(nc, GNUTLS_SAN_RFC822NAME, &name);
	if (ret != 0)
		fail("Checking %s should have failed\n", name.data);

	gnutls_x509_name_constraints_deinit(nc);
	gnutls_x509_name_constraints_deinit(nc2);

	/* 1: test the merge of name constraints with excluded */

	ret = gnutls_x509_name_constraints_init(&nc);
	if (ret < 0)
		fail("error in %d: %s\n", __LINE__, gnutls_strerror(ret));

	ret = gnutls_x509_name_constraints_init(&nc2);
	if (ret < 0)
		fail("error in %d: %s\n", __LINE__, gnutls_strerror(ret));

	ret = gnutls_x509_name_constraints_add_excluded(nc, GNUTLS_SAN_DNSNAME,
		&example_com);
	if (ret < 0)
		fail("error in %d: %s\n", __LINE__, gnutls_strerror(ret));

	ret = gnutls_x509_name_constraints_add_excluded(nc2, GNUTLS_SAN_DNSNAME,
		&example_net);
	if (ret < 0)
		fail("error in %d: %s\n", __LINE__, gnutls_strerror(ret));


	/* intersection: permit: example.com and example.net denied */
	ret = _gnutls_x509_name_constraints_merge(nc, nc2);
	if (ret < 0)
		fail("error in %d: %s\n", __LINE__, gnutls_strerror(ret));


	/* check the union */
	name.data = (unsigned char*)"xxx.example.com";
	name.size = strlen((char*)name.data);
	ret = gnutls_x509_name_constraints_check(nc, GNUTLS_SAN_DNSNAME, &name);
	if (ret != 0)
		fail("Checking domain should have failed\n");

	name.data = (unsigned char*)"xxx.example.net";
	name.size = strlen((char*)name.data);
	ret = gnutls_x509_name_constraints_check(nc, GNUTLS_SAN_DNSNAME, &name);
	if (ret != 0)
		fail("Checking domain should have failed\n");

	name.data = (unsigned char*)"example.com";
	name.size = strlen((char*)name.data);
	ret = gnutls_x509_name_constraints_check(nc, GNUTLS_SAN_DNSNAME, &name);
	if (ret != 0)
		fail("Checking domain should have failed\n");

	name.data = (unsigned char*)"example.net";
	name.size = strlen((char*)name.data);
	ret = gnutls_x509_name_constraints_check(nc, GNUTLS_SAN_DNSNAME, &name);
	if (ret != 0)
		fail("Checking domain should have failed\n");


	/* check an allowed name */
	name.data = (unsigned char*)"example.org";
	name.size = strlen((char*)name.data);
	ret = gnutls_x509_name_constraints_check(nc, GNUTLS_SAN_DNSNAME, &name);
	if (ret == 0)
		fail("Checking %s should have succeeded\n", name.data);

	gnutls_x509_name_constraints_deinit(nc);
	gnutls_x509_name_constraints_deinit(nc2);

	gnutls_global_deinit();

	if (debug)
		success("success");
}
