/*
 * Copyright (C) 2008-2012 Free Software Foundation, Inc.
 * Copyright (C) 2018 Red Hat, Inc.
 *
 * Author: Simon Josefsson, Nikos Mavrogiannopoulos
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

#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <gnutls/gnutls.h>
#include <gnutls/crypto.h>
#include <gnutls/abstract.h>

#define RANDOMIZE
#include "cert-common.h"
#include "cmocka-common.h"

/* This tests the GNUTLS_AUTO_REAUTH flag functionality under non-blocking mode.
 */
static void tls_log_func(int level, const char *str)
{
	fprintf(stderr, "<%d>| %s", level, str);
}

#define MAX_BUF 1024
#define MSG \
	"Hello TLS, and hi and how are you and more data here... and more... and even more and even more more data..."

#define MAX_HSK_MESSAGES 16
static unsigned hsk_types[MAX_HSK_MESSAGES];
static unsigned hsk_count = 0;

static int hsk_callback(gnutls_session_t session, unsigned int htype,
			unsigned post, unsigned int incoming,
			const gnutls_datum_t *msg)
{
	assert_int_equal(post, GNUTLS_HOOK_POST);
	if (!incoming)
		return 0;
	assert_true(hsk_count < MAX_HSK_MESSAGES);
	hsk_types[hsk_count++] = htype;
	return 0;
}

static unsigned int cert_asked = 0;

static int cert_callback(gnutls_session_t session,
			 const gnutls_datum_t *req_ca_rdn, int nreqs,
			 const gnutls_pk_algorithm_t *sign_algos,
			 int sign_algos_length, gnutls_pcert_st **pcert,
			 unsigned int *pcert_length, gnutls_privkey_t *pkey)
{
	cert_asked = 1;
	*pcert_length = 0;
	*pcert = NULL;
	*pkey = NULL;

	return 0;
}

static void async_handshake(void **glob_state, const char *prio, unsigned rehsk)
{
	/* Server stuff. */
	gnutls_certificate_credentials_t serverx509cred;
	gnutls_session_t server;
	int sret, cret;
	/* Client stuff. */
	gnutls_certificate_credentials_t clientx509cred;
	gnutls_session_t client;
	/* Need to enable anonymous KX specifically. */
	char buffer[MAX_BUF + 1];
	int ret, transferred = 0, msglen;

	/* General init. */
	reset_buffers();
	cert_asked = 0;
	gnutls_global_init();
	gnutls_global_set_log_function(tls_log_func);

	/* Init server */
	assert_return_code(
		gnutls_certificate_allocate_credentials(&serverx509cred), 0);
	assert_return_code(gnutls_certificate_set_x509_key_mem(
				   serverx509cred, &server_cert, &server_key,
				   GNUTLS_X509_FMT_PEM),
			   0);
	ret = gnutls_init(&server, GNUTLS_SERVER | GNUTLS_POST_HANDSHAKE_AUTH);
	assert_return_code(ret, 0);

	ret = gnutls_priority_set_direct(server, prio, NULL);
	assert_return_code(ret, 0);

	ret = gnutls_credentials_set(server, GNUTLS_CRD_CERTIFICATE,
				     serverx509cred);
	assert_return_code(ret, 0);

	gnutls_transport_set_push_function(server, server_push);
	gnutls_transport_set_pull_function(server, server_pull);
	gnutls_transport_set_ptr(server, server);

	hsk_count = 0;
	gnutls_handshake_set_hook_function(server, GNUTLS_HANDSHAKE_ANY,
					   GNUTLS_HOOK_POST, hsk_callback);

	/* Init client */

	ret = gnutls_certificate_allocate_credentials(&clientx509cred);
	assert_return_code(ret, 0);

	gnutls_certificate_set_retrieve_function2(clientx509cred,
						  cert_callback);

	ret = gnutls_init(&client, GNUTLS_CLIENT | GNUTLS_AUTO_REAUTH |
					   GNUTLS_POST_HANDSHAKE_AUTH);
	ret = gnutls_priority_set_direct(client, prio, NULL);
	assert_return_code(ret, 0);

	ret = gnutls_credentials_set(client, GNUTLS_CRD_CERTIFICATE,
				     clientx509cred);
	assert_return_code(ret, 0);

	gnutls_transport_set_push_function(client, client_push);
	gnutls_transport_set_pull_function(client, client_pull);
	gnutls_transport_set_ptr(client, client);

	HANDSHAKE(client, server);

	if (rehsk == 1) {
		char b[1];

		assert_int_equal(hsk_count, 3);
		assert_int_equal(hsk_types[0], GNUTLS_HANDSHAKE_CLIENT_HELLO);
		assert_int_equal(hsk_types[1],
				 GNUTLS_HANDSHAKE_CLIENT_KEY_EXCHANGE);
		assert_int_equal(hsk_types[2], GNUTLS_HANDSHAKE_FINISHED);

		/* initiate a rehandshake on the server */
		do {
			sret = gnutls_rehandshake(server);
		} while (sret == GNUTLS_E_AGAIN ||
			 sret == GNUTLS_E_INTERRUPTED);
		assert_return_code(sret, 0);

		/* spin until both process it */
		do {
			/* drive client so that it AUTO_REAUTHs */
			cret = gnutls_record_recv(client, b, 1);
			assert_true(cret == GNUTLS_E_AGAIN ||
				    cret == GNUTLS_E_INTERRUPTED);

			sret = gnutls_record_recv(server, b, 1);
		} while (sret != GNUTLS_E_REHANDSHAKE);
		assert_int_equal(hsk_count, 3); /* CH isn't processed yet */

		/* drive rehandshake to completion */
		do {
			cret = gnutls_record_recv(client, b, 1);
			assert_true(cret == GNUTLS_E_AGAIN ||
				    cret == GNUTLS_E_INTERRUPTED);

			sret = gnutls_handshake(server);
		} while (hsk_count < 6 || (sret == GNUTLS_E_AGAIN ||
					   sret == GNUTLS_E_INTERRUPTED));
		assert_return_code(sret, 0);
		assert_int_equal(hsk_count, 6);
		assert_int_equal(hsk_types[3], GNUTLS_HANDSHAKE_CLIENT_HELLO);
		assert_int_equal(hsk_types[4],
				 GNUTLS_HANDSHAKE_CLIENT_KEY_EXCHANGE);
		assert_int_equal(hsk_types[5], GNUTLS_HANDSHAKE_FINISHED);
	} else {
		char b[1];

		assert_int_equal(hsk_count, 2);
		assert_int_equal(hsk_types[0], GNUTLS_HANDSHAKE_CLIENT_HELLO);
		assert_int_equal(hsk_types[1], GNUTLS_HANDSHAKE_FINISHED);

		gnutls_certificate_server_set_request(server,
						      GNUTLS_CERT_REQUEST);

		bool reauth_succeeded = false;
		do {
			cret = gnutls_record_recv(client, b, 1);
			assert_true(cret == GNUTLS_E_AGAIN ||
				    cret == GNUTLS_E_INTERRUPTED);
			if (!reauth_succeeded)
				sret = gnutls_reauth(server, 0);
			if (sret == 0)
				reauth_succeeded = 1;
		} while (hsk_count < 4 || (sret == GNUTLS_E_AGAIN ||
					   sret == GNUTLS_E_INTERRUPTED));
		assert_return_code(sret, 0);
		assert_int_equal(hsk_count, 4);
		assert_int_equal(hsk_types[2],
				 GNUTLS_HANDSHAKE_CERTIFICATE_PKT);
		assert_int_equal(hsk_types[3], GNUTLS_HANDSHAKE_FINISHED);
	}
	assert_return_code(cert_asked, 1);

	msglen = strlen(MSG);
	TRANSFER(client, server, MSG, msglen, buffer, MAX_BUF);

	do {
		cret = gnutls_bye(client, GNUTLS_SHUT_WR);
	} while (cret == GNUTLS_E_AGAIN || cret == GNUTLS_E_INTERRUPTED);
	assert_return_code(cret, 0);
	do {
		sret = gnutls_bye(server, GNUTLS_SHUT_WR);
	} while (sret == GNUTLS_E_AGAIN || sret == GNUTLS_E_INTERRUPTED);
	assert_return_code(sret, 0);

	gnutls_deinit(client);
	gnutls_deinit(server);

	gnutls_certificate_free_credentials(serverx509cred);
	gnutls_certificate_free_credentials(clientx509cred);

	gnutls_global_deinit();
}

static void tls12_async_handshake(void **glob_state)
{
	async_handshake(glob_state, "NORMAL:-VERS-ALL:+VERS-TLS1.2", 1);
}

static void tls13_async_handshake(void **glob_state)
{
	async_handshake(glob_state, "NORMAL:-VERS-ALL:+VERS-TLS1.3", 0);
}

int main(void)
{
	const struct CMUnitTest tests[] = {
		cmocka_unit_test(tls12_async_handshake),
		cmocka_unit_test(tls13_async_handshake),
	};
	return cmocka_run_group_tests(tests, NULL, NULL);
}
