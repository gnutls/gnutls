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
#include <string.h>
#include <errno.h>
#include <gnutls/gnutls.h>
#include <gnutls/crypto.h>
#include <assert.h>
#include "cert-common.h"

#include "utils.h"
#define RANDOMIZE
#include "eagain-common.h"

const char *side = "";

static void tls_log_func(int level, const char *str)
{
	fprintf(stderr, "%s|<%d>| %s", side, level, str);
}

#define MAX_BUF 1024
#define MSG \
	"Hello TLS, and hi and how are you and more data here... and more... and even more and even more more data..."

#ifdef USE_KTLS
/* For ktls flavour of the test, the test needs to be run with the kTLS enabled
 * option in the GnuTLS configuration file, in the case of the GnuTLS testing,
 * the shell script `tests/ktls_keyupdate.sh` does just that.
 */

#include "ktls_utils.h"

#define RUN(s, n)                                         \
	{                                                 \
		int ret;                                  \
		int cfd, sfd;                             \
		if ((ret = create_sockets(&cfd, &sfd))) { \
			fail("kTLS: %s\n", errors[ret]);  \
			exit(1);                          \
		}                                         \
		run(s, n, cfd, sfd);                      \
		close(cfd);                               \
		close(sfd);                               \
	}

/* We could check specificaly but given how the setting of new keys work, let's
 * check if something had gone sideways on both the receive and sending sockets.
 */
#define CHECK_KTLS_ENABLED(session)                             \
	switch (gnutls_transport_is_ktls_enabled(session)) {    \
	case GNUTLS_KTLS_RECV:                                  \
		fail("kTLS: Only recv support is initiated\n"); \
		break;                                          \
	case GNUTLS_KTLS_SEND:                                  \
		fail("kTLS: Only send support is initiated\n"); \
		break;                                          \
	case GNUTLS_KTLS_DUPLEX:                                \
		break;                                          \
	default:                                                \
		fail("kTLS: dissabled\n");                      \
	}

/* ktls needs to use real sockets */
char *errors[] = { "", "Failed to create the socket pair",
		   "Failed to set the socket non-blocking" };

inline static int create_sockets(int *cfd, int *sfd)
{
	int ret = create_socket_pair(cfd, sfd);
	if (ret)
		return 1;

	if (set_nonblocking(*cfd) || set_nonblocking(*sfd))
		return 2;

	return 0;
}

#else /* non-kTLS */

#define RUN(s, n) run(s, n, -1, -1)
#define CHECK_KTLS_ENABLED(session) /* No-op */

#endif /* non-kTLS */

static unsigned key_update_msg_inc = 0;
static unsigned key_update_msg_out = 0;

static int hsk_callback(gnutls_session_t session, unsigned int htype,
			unsigned post, unsigned int incoming,
			const gnutls_datum_t *msg)
{
	assert(post == GNUTLS_HOOK_PRE);

	assert(msg->size == 1);

	if (htype == GNUTLS_HANDSHAKE_KEY_UPDATE) {
		if (incoming)
			key_update_msg_inc++;
		else
			key_update_msg_out++;
	}

	return 0;
}

static void run(const char *name, unsigned test, int cfd, int sfd)
{
	/* Server stuff. */
	gnutls_certificate_credentials_t ccred;
	gnutls_certificate_credentials_t scred;
	gnutls_session_t server;
	int sret, cret;
	/* Client stuff. */
	gnutls_session_t client;
	/* Need to enable anonymous KX specifically. */
	char buffer[MAX_BUF + 1];
	int ret, transferred = 0;

	/* General init. */
	global_init();
	gnutls_global_set_log_function(tls_log_func);
	if (debug)
		gnutls_global_set_log_level(9);

	/* Init server */
	assert(gnutls_certificate_allocate_credentials(&scred) >= 0);
	assert(gnutls_certificate_set_x509_key_mem(
		       scred, &server_ca3_localhost_cert, &server_ca3_key,
		       GNUTLS_X509_FMT_PEM) >= 0);

	assert(gnutls_init(&server, GNUTLS_SERVER) >= 0);
	ret = gnutls_priority_set_direct(
		server, "NORMAL:-VERS-TLS-ALL:+VERS-TLS1.3", NULL);
	if (ret < 0)
		exit(1);

	gnutls_credentials_set(server, GNUTLS_CRD_CERTIFICATE, scred);
#ifdef USE_KTLS
	/* for kTLS you can't use custom push/pull functions */
	gnutls_transport_set_int(server, sfd);
#else
	gnutls_transport_set_push_function(server, server_push);
	gnutls_transport_set_pull_function(server, server_pull);
	gnutls_transport_set_ptr(server, server);
#endif

	/* Init client */
	assert(gnutls_certificate_allocate_credentials(&ccred) >= 0);
	assert(gnutls_certificate_set_x509_trust_mem(ccred, &ca3_cert,
						     GNUTLS_X509_FMT_PEM) >= 0);

	gnutls_init(&client, GNUTLS_CLIENT);
	ret = gnutls_priority_set_direct(
		client, "NORMAL:-VERS-TLS-ALL:+VERS-TLS1.3", NULL);
	assert(ret >= 0);

	ret = gnutls_credentials_set(client, GNUTLS_CRD_CERTIFICATE, ccred);
	if (ret < 0)
		exit(1);

#ifdef USE_KTLS
	/* for kTLS you can't use custom push/pull functions */
	gnutls_transport_set_int(client, cfd);
#else
	gnutls_transport_set_push_function(client, client_push);
	gnutls_transport_set_pull_function(client, client_pull);
	gnutls_transport_set_ptr(client, client);
#endif

	HANDSHAKE(client, server);
	if (debug)
		success("Handshake established\n");

	/* check kTLS initialization (both send and recv should be supported)*/
	CHECK_KTLS_ENABLED(client);
	CHECK_KTLS_ENABLED(server);

	switch (test) {
	case 0:
	case 1:
		success("%s: updating client's key\n", name);
		do {
			ret = gnutls_session_key_update(client, 0);
		} while (ret == GNUTLS_E_AGAIN || ret == GNUTLS_E_INTERRUPTED);

		CHECK_KTLS_ENABLED(client);
		CHECK_KTLS_ENABLED(server);

		/* server receives the client key update and sends data */
		TRANSFER(client, server, MSG, strlen(MSG), buffer, MAX_BUF);
		TRANSFER(server, client, MSG, strlen(MSG), buffer, MAX_BUF);
		EMPTY_BUF(server, client, buffer, MAX_BUF);

		if (test != 0)
			break;
		sec_sleep(2);
		FALLTHROUGH;
	case 2:
		success("%s: updating server's key\n", name);

		do {
			ret = gnutls_session_key_update(server, 0);
		} while (ret == GNUTLS_E_AGAIN || ret == GNUTLS_E_INTERRUPTED);
		if (ret < 0)
			fail("error in key update: %s\n", gnutls_strerror(ret));

		CHECK_KTLS_ENABLED(server);
		CHECK_KTLS_ENABLED(client);

		/* client receives the key update and sends data */
		TRANSFER(client, server, MSG, strlen(MSG), buffer, MAX_BUF);
		TRANSFER(server, client, MSG, strlen(MSG), buffer, MAX_BUF);
		EMPTY_BUF(server, client, buffer, MAX_BUF);

		if (test != 0)
			break;
		sec_sleep(2);
		FALLTHROUGH;
	case 3:
		success("%s: updating client's key and asking server\n", name);
		do {
			ret = gnutls_session_key_update(client, GNUTLS_KU_PEER);
		} while (ret == GNUTLS_E_AGAIN || ret == GNUTLS_E_INTERRUPTED);
		if (ret < 0)
			fail("error in key update: %s\n", gnutls_strerror(ret));

		CHECK_KTLS_ENABLED(client);
		CHECK_KTLS_ENABLED(server);

		/* server receives the client key update and sends data */
		TRANSFER(client, server, MSG, strlen(MSG), buffer, MAX_BUF);
		TRANSFER(server, client, MSG, strlen(MSG), buffer, MAX_BUF);
		EMPTY_BUF(server, client, buffer, MAX_BUF);

		if (test != 0)
			break;
		sec_sleep(2);
		FALLTHROUGH;
	case 4:
		success("%s: updating server's key and asking client\n", name);
		do {
			ret = gnutls_session_key_update(server, GNUTLS_KU_PEER);
		} while (ret == GNUTLS_E_AGAIN || ret == GNUTLS_E_INTERRUPTED);
		if (ret < 0)
			fail("error in key update: %s\n", gnutls_strerror(ret));

		CHECK_KTLS_ENABLED(server);
		CHECK_KTLS_ENABLED(client);

		TRANSFER(client, server, MSG, strlen(MSG), buffer, MAX_BUF);
		TRANSFER(server, client, MSG, strlen(MSG), buffer, MAX_BUF);
		EMPTY_BUF(server, client, buffer, MAX_BUF);

		sec_sleep(2);
		break;
	case 5:
		success("%s: client cork\n", name);
		gnutls_record_cork(client);

		/* server sends key update */
		do {
			ret = gnutls_session_key_update(server, GNUTLS_KU_PEER);
		} while (ret == GNUTLS_E_AGAIN || ret == GNUTLS_E_INTERRUPTED);
		if (ret < 0)
			fail("error in key update: %s\n", gnutls_strerror(ret));

		/* client has data in the corked buffer */
		do {
			ret = gnutls_record_send(client, MSG, strlen(MSG));
		} while (ret == GNUTLS_E_AGAIN || ret == GNUTLS_E_INTERRUPTED);
		if (ret < 0)
			fail("cannot send: %s\n", gnutls_strerror(ret));

		/* client receives key update */
		EMPTY_BUF(server, client, buffer, MAX_BUF);

		CHECK_KTLS_ENABLED(server);
		CHECK_KTLS_ENABLED(client);

		/* client uncorks and sends key update */
		do {
			ret = gnutls_record_uncork(client, GNUTLS_RECORD_WAIT);
		} while (ret == GNUTLS_E_AGAIN || ret == GNUTLS_E_INTERRUPTED);
		if (ret < 0)
			fail("cannot send: %s\n", gnutls_strerror(ret));

		CHECK_KTLS_ENABLED(server);
		CHECK_KTLS_ENABLED(client);

		EMPTY_BUF(server, client, buffer, MAX_BUF);

		sec_sleep(2);
		break;
	case 6:
		key_update_msg_inc = 0;
		key_update_msg_out = 0;

		success("%s: callbacks are called\n", name);

		gnutls_handshake_set_hook_function(client, -1, GNUTLS_HOOK_PRE,
						   hsk_callback);
		gnutls_handshake_set_hook_function(server, -1, GNUTLS_HOOK_PRE,
						   hsk_callback);

		do {
			ret = gnutls_session_key_update(client, GNUTLS_KU_PEER);
		} while (ret == GNUTLS_E_AGAIN || ret == GNUTLS_E_INTERRUPTED);
		if (ret < 0)
			fail("error in key update: %s\n", gnutls_strerror(ret));

		CHECK_KTLS_ENABLED(server);
		CHECK_KTLS_ENABLED(client);

		/* server receives the client key update and sends data */
		TRANSFER(client, server, MSG, strlen(MSG), buffer, MAX_BUF);
		TRANSFER(server, client, MSG, strlen(MSG), buffer, MAX_BUF);
		EMPTY_BUF(server, client, buffer, MAX_BUF);

		assert(key_update_msg_inc == 2);
		assert(key_update_msg_out == 2);
		break;
	}

	gnutls_bye(client, GNUTLS_SHUT_WR);
	gnutls_bye(server, GNUTLS_SHUT_WR);

	gnutls_deinit(client);
	gnutls_deinit(server);

	gnutls_certificate_free_credentials(scred);
	gnutls_certificate_free_credentials(ccred);

	gnutls_global_deinit();
	reset_buffers();
}

void doit(void)
{
	RUN("single", 1);
	RUN("single", 2);
	RUN("single", 3);
	RUN("single", 4);
	RUN("single", 5);
	RUN("single", 6);
	RUN("all", 0); /* all one after each other */
}
