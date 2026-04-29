/*
 * Copyright (C) 2004-2012 Free Software Foundation, Inc.
 * Copyright (C) 2013 Adam Sampson <ats@offog.org>
 * Copyright (C) 2019 Free Software Foundation, Inc.
 *
 * Author: Simon Josefsson, Ander Juaristi
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
 * along with GnuTLS.  If not, see <https://www.gnu.org/licenses/>.
 */

/* Parts copied from pskself.c. */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>

#if defined(_WIN32)

/* socketpair isn't supported on Win32. */
int main(int argc, char **argv)
{
	exit(77);
}

#else

#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#if !defined(_WIN32)
#include <sys/wait.h>
#endif
#include <unistd.h>
#include <gnutls/gnutls.h>

#include "utils.h"
#include "extras/hex.h"
#include "cert-common.h"

/* A very basic TLS client, with PSK authentication.
 */

const char *side = "";

static void tls_log_func(int level, const char *str)
{
	fprintf(stderr, "%s|<%d>| %s", side, level, str);
}

#define MAX_BUF 1024
#define MSG "Hello TLS"

static void client(int sd, const char *prio, bool exp_hint, bool rsa)
{
	int ret, ii;
	gnutls_session_t session;
	char buffer[MAX_BUF + 1];
	gnutls_psk_client_credentials_t pskcred;
	gnutls_certificate_credentials_t xcred = NULL;
	/* Need to enable anonymous KX specifically. */
	const gnutls_datum_t key = { (void *)"DEAD00BEEF", 10 };
	gnutls_datum_t user;
	const char *hint;

	global_init();
	gnutls_global_set_log_function(tls_log_func);
	if (debug)
		gnutls_global_set_log_level(4711);

	side = "client";

	user.data = gnutls_malloc(5);
	assert(user.data != NULL);

	user.data[0] = 0xCA;
	user.data[1] = 0xFE;
	user.data[2] = 0x00;
	user.data[3] = 0xCA;
	user.data[4] = 0xFE;
	user.size = 5;

	gnutls_psk_allocate_client_credentials(&pskcred);
	ret = gnutls_psk_set_client_credentials2(pskcred, &user, &key,
						 GNUTLS_PSK_KEY_HEX);
	if (ret < 0) {
		fail("client: Could not set PSK\n");
		gnutls_perror(ret);
		goto end;
	}

	/* Initialize TLS session
	 */
	gnutls_init(&session, GNUTLS_CLIENT);

	/* Use default priorities */
	gnutls_priority_set_direct(session, prio, NULL);

	/* put the anonymous credentials to the current session
	 */
	gnutls_credentials_set(session, GNUTLS_CRD_PSK, pskcred);

	if (rsa) {
		gnutls_certificate_allocate_credentials(&xcred);
		gnutls_credentials_set(session, GNUTLS_CRD_CERTIFICATE, xcred);
	}

	gnutls_transport_set_int(session, sd);

	/* Perform the TLS handshake
	 */
	ret = gnutls_handshake(session);

	if (ret < 0) {
		fail("client: Handshake failed\n");
		gnutls_perror(ret);
		goto end;
	} else {
		if (debug)
			success("client: Handshake was completed\n");
	}

	/* check the hint */
	if (exp_hint) {
		hint = gnutls_psk_client_get_hint(session);
		if (hint == NULL || strcmp(hint, "hint") != 0) {
			fail("client: hint is not the expected: %s\n",
			     gnutls_psk_client_get_hint(session));
			goto end;
		}
	}

	gnutls_record_send(session, MSG, strlen(MSG));

	ret = gnutls_record_recv(session, buffer, MAX_BUF);
	if (ret == 0) {
		if (debug)
			success("client: Peer has closed the TLS connection\n");
		goto end;
	} else if (ret < 0) {
		fail("client: Error: %s\n", gnutls_strerror(ret));
		goto end;
	}

	if (debug) {
		printf("- Received %d bytes: ", ret);
		for (ii = 0; ii < ret; ii++) {
			fputc(buffer[ii], stdout);
		}
		fputs("\n", stdout);
	}

	gnutls_bye(session, GNUTLS_SHUT_RDWR);

end:

	close(sd);

	gnutls_deinit(session);

	gnutls_free(user.data);
	gnutls_psk_free_client_credentials(pskcred);
	if (xcred)
		gnutls_certificate_free_credentials(xcred);

	gnutls_global_deinit();
}

/* This is a sample TLS 1.0 echo server, for PSK authentication.
 */

#define MAX_BUF 1024

/* These are global */

static int pskfunc(gnutls_session_t session, const gnutls_datum_t *username,
		   gnutls_datum_t *key)
{
	const unsigned char expected_user[] = { 0xCA, 0xFE, 0x00, 0xCA, 0xFE };
	const unsigned char expected_key[] = { 0xDE, 0xAD, 0x00, 0xBE, 0xEF };

	if (debug)
		printf("psk: Got username with length %d\n", username->size);

	/* verify callback received full 5-byte username (#1850) */
	if (username->size != 5 ||
	    memcmp(username->data, expected_user, 5) != 0)
		fail("pskfunc: username mismatch: got %u bytes, expected 5\n",
		     username->size);

	key->data = gnutls_malloc(5);
	memcpy(key->data, expected_key, 5);
	key->size = 5;

	return 0;
}

static void server(int sd, const char *prio, bool rsa)
{
	gnutls_psk_server_credentials_t server_pskcred;
	gnutls_certificate_credentials_t serverx509cred = NULL;
	int ret;
	gnutls_session_t session;
	gnutls_datum_t psk_username;
	char buffer[MAX_BUF + 1];
	const char expected_psk_username[] = { 0xCA, 0xFE, 0x00, 0xCA, 0xFE };

	/* this must be called once in the program
	 */
	global_init();
	gnutls_global_set_log_function(tls_log_func);
	if (debug)
		gnutls_global_set_log_level(4711);

	side = "server";

	gnutls_psk_allocate_server_credentials(&server_pskcred);
	gnutls_psk_set_server_credentials_hint(server_pskcred, "hint");
	gnutls_psk_set_server_credentials_function2(server_pskcred, pskfunc);

	if (rsa) {
		gnutls_certificate_allocate_credentials(&serverx509cred);
		gnutls_certificate_set_x509_key_mem(serverx509cred,
						    &server_cert, &server_key,
						    GNUTLS_X509_FMT_PEM);
	}

	gnutls_init(&session, GNUTLS_SERVER);

	/* avoid calling all the priority functions, since the defaults
	 * are adequate.
	 */
	gnutls_priority_set_direct(session, prio, NULL);

	gnutls_credentials_set(session, GNUTLS_CRD_PSK, server_pskcred);
	if (serverx509cred)
		gnutls_credentials_set(session, GNUTLS_CRD_CERTIFICATE,
				       serverx509cred);

	gnutls_transport_set_int(session, sd);
	ret = gnutls_handshake(session);
	if (ret < 0) {
		close(sd);
		gnutls_deinit(session);
		fail("server: Handshake has failed (%s)\n\n",
		     gnutls_strerror(ret));
		return;
	}

	if (debug) {
		success("server: Handshake was completed\n");

		if (gnutls_psk_server_get_username(session))
			fail("server: gnutls_psk_server_get_username() should have returned NULL\n");
		if (gnutls_psk_server_get_username2(session, &psk_username) < 0)
			fail("server: Could not get PSK username\n");

		if (psk_username.size != 5 ||
		    memcmp(psk_username.data, expected_psk_username, 5))
			fail("server: Unexpected PSK username\n");

		success("server: PSK username length: %d\n", psk_username.size);
	}

	/* see the Getting peer's information example */
	/* print_info(session); */

	for (;;) {
		memset(buffer, 0, MAX_BUF + 1);
		gnutls_record_set_timeout(session, 10000);
		ret = gnutls_record_recv(session, buffer, MAX_BUF);

		if (ret == 0) {
			if (debug)
				success("server: Peer has closed the GnuTLS connection\n");
			break;
		} else if (ret < 0) {
			fail("server: Received corrupted data(%d). Closing...\n",
			     ret);
			break;
		} else if (ret > 0) {
			/* echo data back to the client
			 */
			gnutls_record_send(session, buffer, strlen(buffer));
		}
	}
	/* do not wait for the peer to close the connection.
	 */
	gnutls_bye(session, GNUTLS_SHUT_WR);

	close(sd);
	gnutls_deinit(session);

	gnutls_psk_free_server_credentials(server_pskcred);
	if (serverx509cred)
		gnutls_certificate_free_credentials(serverx509cred);

	gnutls_global_deinit();

	if (debug)
		success("server: finished\n");
}

static void run_test(const char *prio, bool exp_hint, bool rsa)
{
	pid_t child;
	int err;
	int sockets[2];

	success("trying with %s\n", prio);

	err = socketpair(AF_UNIX, SOCK_STREAM, 0, sockets);
	if (err == -1) {
		perror("socketpair");
		fail("socketpair failed\n");
		return;
	}

	child = fork();
	if (child < 0) {
		perror("fork");
		fail("fork");
		return;
	}

	if (child) {
		int status;
		/* parent */
		close(sockets[1]);
		server(sockets[0], prio, rsa);
		wait(&status);
		check_wait_status(status);
	} else {
		close(sockets[0]);
		client(sockets[1], prio, exp_hint, rsa);
		exit(0);
	}
}

void doit(void)
{
	run_test("NORMAL:-VERS-ALL:+VERS-TLS1.2:-KX-ALL:+PSK", true, false);
	run_test("NORMAL:-VERS-ALL:+VERS-TLS1.2:-KX-ALL:+ECDHE-PSK", true,
		 false);
	run_test("NORMAL:-VERS-ALL:+VERS-TLS1.2:-KX-ALL:+DHE-PSK", true, false);

	run_test("NORMAL:-VERS-ALL:+VERS-TLS1.2:+PSK", false, false);
	run_test("NORMAL:-VERS-ALL:+VERS-TLS1.2:"
		 "-GROUP-ALL:+GROUP-FFDHE2048:+DHE-PSK",
		 false, false);
	run_test("NORMAL:-VERS-ALL:+VERS-TLS1.2:"
		 "-GROUP-ALL:+GROUP-SECP256R1:+ECDHE-PSK",
		 false, false);
	run_test("NORMAL:-VERS-ALL:+VERS-TLS1.3:+PSK", false, false);
	run_test("NORMAL:-VERS-ALL:+VERS-TLS1.3:"
		 "-GROUP-ALL:+GROUP-FFDHE2048:+DHE-PSK",
		 false, false);
	run_test("NORMAL:-VERS-ALL:+VERS-TLS1.3:"
		 "-GROUP-ALL:+GROUP-SECP256R1:+ECDHE-PSK",
		 false, false);
	/* the following should work once we support PSK without DH */
	run_test("NORMAL:-VERS-ALL:+VERS-TLS1.3:-GROUP-ALL:+PSK", false, false);

	run_test("NORMAL:-KX-ALL:+PSK", false, false);
	run_test("NORMAL:-KX-ALL:+ECDHE-PSK", false, false);
	run_test("NORMAL:-KX-ALL:+DHE-PSK", false, false);

	/* RSA-PSK */
	run_test("NORMAL:-VERS-ALL:+VERS-TLS1.2:-KX-ALL:+RSA-PSK", false, true);
}

#endif /* _WIN32 */
