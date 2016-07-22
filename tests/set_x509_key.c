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
#if !defined(_WIN32)
#include <netinet/in.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <arpa/inet.h>
#endif
#include <unistd.h>
#include <assert.h>
#include <time.h>
#include <gnutls/gnutls.h>
#include <gnutls/abstract.h>
#include <gnutls/x509.h>

#include "cert-common.h"
#include "utils.h"

/* Test for gnutls_certificate_set_key()
 *
 */

static void tls_log_func(int level, const char *str)
{
	fprintf(stderr, "<%d>| %s", level, str);
}

static time_t mytime(time_t * t)
{
	time_t then = 1461671166;
	if (t)
		*t = then;

	return then;
}

static void basic(void)
{
	gnutls_certificate_credentials_t x509_cred;
	gnutls_certificate_credentials_t clicred;
	gnutls_pcert_st pcert_list[16];
	gnutls_privkey_t key;
	unsigned pcert_list_size;
	const char *names[] = {"localhost", "localhost2"};
	gnutls_datum_t tcert;
	int ret;

	/* this must be called once in the program
	 */
	global_init();

	gnutls_global_set_time_function(mytime);

	gnutls_global_set_log_function(tls_log_func);
	if (debug)
		gnutls_global_set_log_level(6);

	assert(gnutls_certificate_allocate_credentials(&clicred) >= 0);
	assert(gnutls_certificate_allocate_credentials(&x509_cred)>=0);
	assert(gnutls_privkey_init(&key)>=0);

	ret = gnutls_certificate_set_x509_trust_mem(clicred, &ca_cert, GNUTLS_X509_FMT_PEM);
	if (ret < 0)
		fail("set_x509_trust_file failed: %s\n", gnutls_strerror(ret));

	pcert_list_size = sizeof(pcert_list)/sizeof(pcert_list[0]);
	ret = gnutls_pcert_list_import_x509_raw(pcert_list, &pcert_list_size,
		&server_cert, GNUTLS_X509_FMT_PEM, 0);
	if (ret < 0) {
		fail("error in gnutls_pcert_list_import_x509_raw: %s\n", gnutls_strerror(ret));
	}

	ret = gnutls_privkey_import_x509_raw(key, &server_key, GNUTLS_X509_FMT_PEM, NULL, 0);
	if (ret < 0) {
		fail("error in key import: %s\n", gnutls_strerror(ret));
	}

	ret = gnutls_certificate_set_key(x509_cred, names, 2, pcert_list,
				pcert_list_size, key);
	if (ret < 0) {
		fail("error in gnutls_certificate_set_key: %s\n", gnutls_strerror(ret));
		exit(1);
	}

	/* verify whether the stored certificate match the ones we have */
	ret = gnutls_certificate_get_crt_raw(x509_cred, 0, 0, &tcert);
	if (ret < 0) {
		fail("error in %d: %s\n", __LINE__, gnutls_strerror(ret));
		exit(1);
	}

	if (tcert.size != pcert_list[0].cert.size || memcmp(tcert.data, pcert_list[0].cert.data, tcert.size) != 0) {
		fail("error in %d: %s\n", __LINE__, "cert don't match");
		exit(1);
	}

	ret = gnutls_certificate_get_crt_raw(x509_cred, 0, 1, &tcert);
	if (ret < 0) {
		fail("error in %d: %s\n", __LINE__, gnutls_strerror(ret));
		exit(1);
	}

	if (tcert.size != pcert_list[1].cert.size || memcmp(tcert.data, pcert_list[1].cert.data, tcert.size) != 0) {
		fail("error in %d: %s\n", __LINE__, "ca cert don't match");
		exit(1);
	}

	test_cli_serv(x509_cred, clicred, "NORMAL", "localhost", NULL, NULL, NULL);

	gnutls_certificate_free_credentials(x509_cred);
	gnutls_certificate_free_credentials(clicred);

	gnutls_global_deinit();

	if (debug)
		success("success");
}

static void auto_parse(void)
{
	gnutls_certificate_credentials_t x509_cred, clicred;
	gnutls_pcert_st pcert_list[16];
	gnutls_privkey_t key;
	gnutls_pcert_st second_pcert;
	gnutls_privkey_t second_key;
	unsigned pcert_list_size;
	int ret;

	/* this must be called once in the program
	 */
	global_init();

	gnutls_global_set_time_function(time);

	gnutls_global_set_log_function(tls_log_func);
	if (debug)
		gnutls_global_set_log_level(6);

	assert(gnutls_certificate_allocate_credentials(&x509_cred)>=0);
	assert(gnutls_privkey_init(&key)>=0);

	assert(gnutls_certificate_allocate_credentials(&clicred) >= 0);

	ret = gnutls_certificate_set_x509_trust_mem(clicred, &ca3_cert, GNUTLS_X509_FMT_PEM);
	if (ret < 0)
		fail("set_x509_trust_file failed: %s\n", gnutls_strerror(ret));

	pcert_list_size = sizeof(pcert_list)/sizeof(pcert_list[0]);
	ret = gnutls_pcert_list_import_x509_raw(pcert_list, &pcert_list_size,
		&server_ca3_localhost_cert, GNUTLS_X509_FMT_PEM, 0);
	if (ret < 0) {
		fail("error in gnutls_pcert_list_import_x509_raw: %s\n", gnutls_strerror(ret));
	}

	ret = gnutls_privkey_import_x509_raw(key, &server_ca3_key, GNUTLS_X509_FMT_PEM, NULL, 0);
	if (ret < 0) {
		fail("error in key import: %s\n", gnutls_strerror(ret));
	}

	ret = gnutls_certificate_set_key(x509_cred, NULL, 0, pcert_list,
				pcert_list_size, key);
	if (ret < 0) {
		fail("error in gnutls_certificate_set_key: %s\n", gnutls_strerror(ret));
		exit(1);
	}

	/* set the ECC key */
	assert(gnutls_privkey_init(&second_key)>=0);

	pcert_list_size = 1;
	ret = gnutls_pcert_list_import_x509_raw(&second_pcert, &pcert_list_size,
		&server_ca3_localhost6_cert, GNUTLS_X509_FMT_PEM, 0);
	if (ret < 0) {
		fail("error in gnutls_pcert_list_import_x509_raw: %s\n", gnutls_strerror(ret));
	}

	ret = gnutls_privkey_import_x509_raw(second_key, &server_ca3_key, GNUTLS_X509_FMT_PEM, NULL, 0);
	if (ret < 0) {
		fail("error in key import: %s\n", gnutls_strerror(ret));
	}

	ret = gnutls_certificate_set_key(x509_cred, NULL, 0, &second_pcert,
				1, second_key);
	if (ret < 0) {
		fail("error in gnutls_certificate_set_key: %s\n", gnutls_strerror(ret));
		exit(1);
	}

	test_cli_serv(x509_cred, clicred, "NORMAL", "localhost", NULL, NULL, NULL); /* the DNS name of the first cert */
	test_cli_serv(x509_cred, clicred, "NORMAL", "localhost6", NULL, NULL, NULL); /* the DNS name of ECC cert */
	test_cli_serv(x509_cred, clicred, "NORMAL", "www.none.org", NULL, NULL, NULL); /* the DNS name of ECC cert */

	gnutls_certificate_free_credentials(x509_cred);
	gnutls_certificate_free_credentials(clicred);

	gnutls_global_deinit();

	if (debug)
		success("success");
}

void doit(void)
{
	basic();
	auto_parse();
}
