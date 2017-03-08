/*
 * Copyright (C) 2012 Free Software Foundation, Inc.
 * Copyright (C) 2012-2015 Nikos Mavrogiannopoulos
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

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <gnutls/gnutls.h>

#include "utils.h"

static void
try_prio(const char *prio, unsigned expected_cs, unsigned expected_ciphers, unsigned line)
{
	int ret;
	gnutls_priority_t p;
	const char *err;
	const unsigned int *t;
	unsigned i, si, count = 0;

	/* this must be called once in the program
	 */
	global_init();

	ret = gnutls_priority_init(&p, prio, &err);
	if (ret < 0) {
		fprintf(stderr, "error: %s: %s\n", gnutls_strerror(ret),
			err);
		exit(1);
	}

	for (i = 0;; i++) {
		ret = gnutls_priority_get_cipher_suite_index(p, i, &si);
		if (ret == GNUTLS_E_UNKNOWN_CIPHER_SUITE)
			continue;
		else if (ret == GNUTLS_E_REQUESTED_DATA_NOT_AVAILABLE)
			break;
		else if (ret == 0) {
			count++;
			/* fprintf(stderr, "%s\n", gnutls_cipher_suite_info(si, NULL, NULL, NULL, NULL, NULL)); */
		}

	}

	ret = gnutls_priority_cipher_list(p, &t);
	if ((unsigned) ret != expected_ciphers) {
#if 0
		for (i = 0; i < ret; i++)
			fprintf(stderr, "%s\n",
				gnutls_cipher_get_name(t[i]));
#endif
		fail("%s:%d: expected %d ciphers, found %d\n", prio, line, expected_ciphers,
		     ret);
		exit(1);
	}

	gnutls_priority_deinit(p);

	/* fprintf(stderr, "count: %d\n", count); */

	if (debug)
		success("finished: %s\n", prio);

	if (count != expected_cs) {
		fail("%s:%d: expected %d ciphersuites, found %d\n", prio, line, expected_cs,
		     count);
		exit(1);
	}
}


void doit(void)
{
	const int null = 4;
	int sec128_cs = 53;
	int sec256_cs = 22;
	int normal_cs = 53;
	int normal_ciphers = 11;
	int pfs_cs = 39;

	if (gnutls_fips140_mode_enabled()) {
		normal_cs = 30;
		normal_ciphers = 6;
		pfs_cs = 22;
		sec256_cs = 11;
		sec128_cs = 30;
	}

	try_prio("NORMAL", normal_cs, normal_ciphers, __LINE__);
	try_prio("NORMAL:-MAC-ALL:+MD5:+MAC-ALL", normal_cs, normal_ciphers, __LINE__);

	if (!gnutls_fips140_mode_enabled()) {
		try_prio("PFS", pfs_cs, normal_ciphers, __LINE__);
		try_prio("NORMAL:+CIPHER-ALL", normal_cs, 11, __LINE__);	/* all (except null) */
		try_prio("NORMAL:-CIPHER-ALL:+NULL", null, 1, __LINE__);	/* null */
		try_prio("NORMAL:-CIPHER-ALL:+NULL:+CIPHER-ALL", normal_cs + null, 12, __LINE__);	/* should be null + all */
		try_prio("NORMAL:-CIPHER-ALL:+NULL:+CIPHER-ALL:-CIPHER-ALL:+AES-128-CBC", 8, 1, __LINE__);	/* should be null + all */
	}

	try_prio("PERFORMANCE", normal_cs, normal_ciphers, __LINE__);
	try_prio("SECURE256", sec256_cs, 6, __LINE__);
	try_prio("SECURE128", sec128_cs, 11, __LINE__);
	try_prio("SECURE128:+SECURE256", sec128_cs, 11, __LINE__);	/* should be the same as SECURE128 */
	try_prio("SECURE128:+SECURE256:+NORMAL", normal_cs, 11, __LINE__);	/* should be the same as NORMAL */
	try_prio("SUITEB192", 1, 1, __LINE__);
	try_prio("SUITEB128", 2, 2, __LINE__);
	/* check legacy strings */
	try_prio("NORMAL:+RSA-EXPORT:+ARCFOUR-40", normal_cs, normal_ciphers, __LINE__);
}

