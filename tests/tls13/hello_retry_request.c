/*
 * Copyright (C) 2017-2018 Red Hat, Inc.
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

/* This program tests whether the version in Hello Retry Request message
 * is the expected */

const char *testname = "hello entry request";

const char *side = "";

#define myfail(fmt, ...) fail("%s: " fmt, testname, ##__VA_ARGS__)

static void tls_log_func(int level, const char *str)
{
	fprintf(stderr, "%s|<%d>| %s", side, level, str);
}

#define HANDSHAKE_SESSION_ID_POS 34
#define MAX_EXT_TYPES 64

struct ctx_st {
	unsigned hrr_seen;
	unsigned hello_counter;
	uint8_t session_id[32];
	size_t session_id_len;
	unsigned extensions[MAX_EXT_TYPES];
	size_t extensions_size1;
	size_t extensions_size2;
};

static int ext_callback(void *_ctx, unsigned tls_id, const unsigned char *data,
			unsigned size)
{
	struct ctx_st *ctx = _ctx;
	if (ctx->hello_counter == 0) {
		assert(ctx->extensions_size1 < MAX_EXT_TYPES);
		ctx->extensions[ctx->extensions_size1++] = tls_id;
	} else {
		assert(ctx->extensions_size2 < MAX_EXT_TYPES);
		if (tls_id != ctx->extensions[ctx->extensions_size2]) {
			fail("extension doesn't match at position %zu, %u != %u\n",
			     ctx->extensions_size2, tls_id,
			     ctx->extensions[ctx->extensions_size2]);
		}
		ctx->extensions_size2++;
	}
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

	if (htype == GNUTLS_HANDSHAKE_CLIENT_HELLO &&
	    post == GNUTLS_HOOK_POST) {
		size_t session_id_len;
		uint8_t *session_id;
		unsigned pos = HANDSHAKE_SESSION_ID_POS;
		gnutls_datum_t mmsg;
		int ret;

		assert(msg->size > pos + 1);
		session_id_len = msg->data[pos];
		session_id = &msg->data[pos + 1];

		SKIP8(pos, msg->size);
		SKIP16(pos, msg->size);
		SKIP8(pos, msg->size);

		mmsg.data = &msg->data[pos];
		mmsg.size = msg->size - pos;

		if (ctx->hello_counter > 0) {
			assert(msg->size > 4);
			if (msg->data[0] != 0x03 || msg->data[1] != 0x03) {
				fail("version is %d.%d expected 3.3\n",
				     (int)msg->data[0], (int)msg->data[1]);
			}

			if (session_id_len != ctx->session_id_len ||
			    memcmp(session_id, ctx->session_id,
				   session_id_len) != 0) {
				fail("different legacy_session_id is sent after HRR\n");
			}
		}

		ctx->session_id_len = session_id_len;
		memcpy(ctx->session_id, session_id, session_id_len);

		ret = gnutls_ext_raw_parse(ctx, ext_callback, &mmsg, 0);
		if (ret < 0) {
			fail("unable to parse extensions: %s\n",
			     gnutls_strerror(ret));
		}

		ctx->hello_counter++;
	}

	return 0;
}

void doit(void)
{
	int sret, cret;
	gnutls_certificate_credentials_t scred, ccred;
	gnutls_session_t server, client;

	struct ctx_st ctx;
	memset(&ctx, 0, sizeof(ctx));

	global_init();

	gnutls_global_set_log_function(tls_log_func);
	if (debug)
		gnutls_global_set_log_level(9);

	/* Init server */
	assert(gnutls_certificate_allocate_credentials(&scred) >= 0);
	assert(gnutls_certificate_set_x509_key_mem(scred, &server_cert,
						   &server_key,
						   GNUTLS_X509_FMT_PEM) >= 0);

	gnutls_init(&server, GNUTLS_SERVER);

	assert(gnutls_priority_set_direct(
		       server,
		       "NORMAL:-VERS-ALL:+VERS-TLS1.3:-GROUP-ALL:+GROUP-X25519",
		       NULL) >= 0);

	gnutls_credentials_set(server, GNUTLS_CRD_CERTIFICATE, scred);
	gnutls_transport_set_push_function(server, server_push);
	gnutls_transport_set_pull_function(server, server_pull);
	gnutls_transport_set_ptr(server, server);

	/* Init client */
	assert(gnutls_certificate_allocate_credentials(&ccred) >= 0);

	assert(gnutls_init(&client, GNUTLS_CLIENT | GNUTLS_KEY_SHARE_TOP) >= 0);

	gnutls_session_set_ptr(client, &ctx);

	cret = gnutls_priority_set_direct(
		client,
		"NORMAL:-VERS-ALL:+VERS-TLS1.3:-GROUP-ALL:+GROUP-SECP256R1:+GROUP-X25519",
		NULL);
	if (cret < 0)
		myfail("cannot set TLS 1.3 priorities\n");

	gnutls_credentials_set(client, GNUTLS_CRD_CERTIFICATE, ccred);
	gnutls_transport_set_push_function(client, client_push);
	gnutls_transport_set_pull_function(client, client_pull);
	gnutls_transport_set_ptr(client, client);

	gnutls_handshake_set_hook_function(client, GNUTLS_HANDSHAKE_ANY,
					   GNUTLS_HOOK_BOTH, hello_callback);

	HANDSHAKE(client, server);

	assert(ctx.hrr_seen != 0);

	if (gnutls_group_get(server) != GNUTLS_GROUP_X25519)
		myfail("group doesn't match the expected: %s\n",
		       gnutls_group_get_name(gnutls_group_get(server)));

	if (ctx.extensions_size1 != ctx.extensions_size2)
		myfail("the number of extensions don't match in second Client Hello: %zu != %zu\n",
		       ctx.extensions_size1, ctx.extensions_size2);

	gnutls_bye(client, GNUTLS_SHUT_WR);
	gnutls_bye(server, GNUTLS_SHUT_WR);

	gnutls_deinit(client);
	gnutls_deinit(server);

	gnutls_certificate_free_credentials(scred);
	gnutls_certificate_free_credentials(ccred);

	gnutls_global_deinit();
	reset_buffers();
}
