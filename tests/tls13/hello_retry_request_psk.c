/*
 * Copyright (C) 2017-2025 Red Hat, Inc.
 *
 * Author: Nikos Mavrogiannopoulos, Daiki Ueno
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

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>

#include <string.h>
#include <gnutls/gnutls.h>
#include <assert.h>

#include "cert-common.h"
#include "utils.h"
#include "tls13/ext-parse.h"
#include "eagain-common.h"

/* This program exercises the case where a TLS 1.3 handshake ends up
 * with HRR, and the first CH includes PSK while the 2nd CH omits
 * it */

const char *testname = "hello entry request";

const char *side = "";

#define myfail(fmt, ...) fail("%s: " fmt, testname, ##__VA_ARGS__)

static void tls_log_func(int level, const char *str)
{
	fprintf(stderr, "%s|<%d>| %s", side, level, str);
}

struct ctx_st {
	unsigned hrr_seen;
	unsigned hello_counter;
};

static int pskfunc(gnutls_session_t session, const char *username,
		   gnutls_datum_t *key)
{
	if (debug)
		printf("psk: username %s\n", username);
	key->data = gnutls_malloc(4);
	key->data[0] = 0xDE;
	key->data[1] = 0xAD;
	key->data[2] = 0xBE;
	key->data[3] = 0xEF;
	key->size = 4;
	return 0;
}

static int hello_callback(gnutls_session_t session, unsigned int htype,
			  unsigned post, unsigned int incoming,
			  const gnutls_datum_t *msg)
{
	struct ctx_st *ctx = gnutls_session_get_ptr(session);
	assert(ctx != NULL);

	if (htype == GNUTLS_HANDSHAKE_HELLO_RETRY_REQUEST)
		ctx->hrr_seen = 1;

	if (htype == GNUTLS_HANDSHAKE_CLIENT_HELLO) {
		if (post == GNUTLS_HOOK_POST)
			ctx->hello_counter++;
		else {
			/* Unset the PSK credential to omit the extension */
			gnutls_credentials_set(session, GNUTLS_CRD_PSK, NULL);
		}
	}

	return 0;
}

void doit(void)
{
	int sret, cret;
	gnutls_psk_server_credentials_t scred;
	gnutls_psk_client_credentials_t ccred;
	gnutls_certificate_credentials_t ccred2;
	gnutls_session_t server, client;
	/* Need to enable anonymous KX specifically. */
	const gnutls_datum_t key = { (void *)"DEADBEEF", 8 };

	struct ctx_st ctx;
	memset(&ctx, 0, sizeof(ctx));

	global_init();

	gnutls_global_set_log_function(tls_log_func);
	if (debug)
		gnutls_global_set_log_level(9);

	/* Init server */
	assert(gnutls_psk_allocate_server_credentials(&scred) >= 0);
	gnutls_psk_set_server_credentials_function(scred, pskfunc);

	gnutls_init(&server, GNUTLS_SERVER);

	assert(gnutls_priority_set_direct(
		       server,
		       "NORMAL:-VERS-ALL:+VERS-TLS1.3:-GROUP-ALL:+GROUP-X25519:+DHE-PSK",
		       NULL) >= 0);

	gnutls_credentials_set(server, GNUTLS_CRD_PSK, scred);
	gnutls_transport_set_push_function(server, server_push);
	gnutls_transport_set_pull_function(server, server_pull);
	gnutls_transport_set_ptr(server, server);

	/* Init client */
	assert(gnutls_psk_allocate_client_credentials(&ccred) >= 0);
	gnutls_psk_set_client_credentials(ccred, "test", &key,
					  GNUTLS_PSK_KEY_HEX);
	assert(gnutls_certificate_allocate_credentials(&ccred2) >= 0);

	assert(gnutls_init(&client, GNUTLS_CLIENT | GNUTLS_KEY_SHARE_TOP) >= 0);

	gnutls_session_set_ptr(client, &ctx);

	cret = gnutls_priority_set_direct(
		client,
		"NORMAL:-VERS-ALL:+VERS-TLS1.3:-GROUP-ALL:+GROUP-SECP256R1:+GROUP-X25519:+DHE-PSK",
		NULL);
	if (cret < 0)
		myfail("cannot set TLS 1.3 priorities\n");

	gnutls_credentials_set(client, GNUTLS_CRD_PSK, ccred);
	gnutls_credentials_set(client, GNUTLS_CRD_CERTIFICATE, ccred2);
	gnutls_transport_set_push_function(client, client_push);
	gnutls_transport_set_pull_function(client, client_pull);
	gnutls_transport_set_ptr(client, client);

	gnutls_handshake_set_hook_function(client, GNUTLS_HANDSHAKE_ANY,
					   GNUTLS_HOOK_BOTH, hello_callback);

	HANDSHAKE_EXPECT(client, server, GNUTLS_E_AGAIN,
			 GNUTLS_E_INSUFFICIENT_CREDENTIALS);

	assert(ctx.hrr_seen != 0);

	gnutls_bye(client, GNUTLS_SHUT_WR);
	gnutls_bye(server, GNUTLS_SHUT_WR);

	gnutls_deinit(client);
	gnutls_deinit(server);

	gnutls_psk_free_server_credentials(scred);
	gnutls_psk_free_client_credentials(ccred);
	gnutls_certificate_free_credentials(ccred2);

	gnutls_global_deinit();
	reset_buffers();
}
