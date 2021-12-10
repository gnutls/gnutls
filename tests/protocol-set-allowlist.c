/*
 * Copyright (C) 2021 Red Hat, Inc.
 *
 * Author: Alexander Sosedkin
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

#include <errno.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <sys/types.h>

#include <gnutls/gnutls.h>
#include <gnutls/x509.h>

#include "utils.h"

/*
 * This is not a test by itself.
 * This is a helper for the real test in protocol-set-allowlist.sh.
 * It executes sequences of commands like:
 *     > connect -> connection established: (TLS1.2)-(RSA)-(AES-128-GCM)
 *     > protocol_set_disabled TLS1.2 -> OK
 *     > connect -> bad priority: (actually, any arrow-less text can go here)
 * where `connect` connects to $TEST_SERVER_PORT using $TEST_SERVER_CA,
 * and gnutls_protocol_set_enabled simply call the underlying API.
 * leaving the outer test to check return code and output:
 *     connect -> connection established: (TLS1.2)-(RSA)-(AES-128-GCM)
 *     protocol_set_disabled TLS1.2 -> OK
 *     connect -> bad priority: No or insufficient priorities were set.
 */

#define _assert(cond, format, ...) if (!(cond)) \
	_fail("Assertion `" #cond "` failed: " format "\n", ##__VA_ARGS__)
#define _check(cond) if (!(cond)) _fail("Assertion `" #cond "` failed.")

unsigned parse_port(const char* port_str);
gnutls_protocol_t parse_protocol(const char* name);
void test_echo_server(gnutls_session_t session);
void cmd_connect(const char* ca_file, unsigned port);
void cmd_protocol_set_disabled(const char* name);
void cmd_protocol_set_enabled(const char* name);
const char* unprefix(const char* s, const char* prefix);


unsigned parse_port(const char* port_str)
{
	unsigned port;
	errno = 0;
	port = strtoul(port_str, NULL, 10);
	_assert(!errno, "Could not parse port value '%s'\n", port_str);
	_assert(0 < port && port < (1UL << 16), "Invalid port %u\n", port);
	return port;
}


gnutls_protocol_t parse_protocol(const char* name)
{
	gnutls_protocol_t p;
	p = gnutls_protocol_get_id(name);
	_assert(p != GNUTLS_VERSION_UNKNOWN, "Unknown protocol `%s`", name);
	return p;
}


void test_echo_server(gnutls_session_t session)
{
	const char buf_out[] = "1234567\n";
	char buf_in[sizeof(buf_out) - 1];
	unsigned rd = 0, wr = 0;
	unsigned LEN = sizeof(buf_out) - 1;
	int r;

	do {
                r = gnutls_record_send(session, buf_out + wr, LEN - wr);
		if (r == GNUTLS_E_AGAIN || r == GNUTLS_E_INTERRUPTED)
			continue;
		_assert(r > 0, "error in send: %s\n", gnutls_strerror(r));
		wr += r;
        } while(r > 0 && wr < LEN);
	_assert(wr == LEN, "error sending all data (%u/%u)\n", wr, LEN);

	do {
                r = gnutls_record_recv(session, buf_in + rd, LEN - rd);
		if (r == GNUTLS_E_AGAIN || r == GNUTLS_E_INTERRUPTED)
			continue;
		_assert(r > 0, "error in recv: %s\n", gnutls_strerror(r));
		rd += r;
        } while(r > 0 && rd < LEN);
	_assert(rd == LEN, "error receiving all data (%u/%u)\n", rd, LEN);
	_assert(!gnutls_record_check_pending(session), "data left unreceived");

	_assert(!memcmp(buf_in, buf_out, LEN), "send/recv data mismatch\n");
}

void cmd_connect(const char* ca_file, unsigned port)
{
	char* desc;
	int sock, r;
	gnutls_session_t session;
	gnutls_certificate_credentials_t cred;
	int sock_flags = 1;

	_check(gnutls_init(&session, GNUTLS_CLIENT) >= 0);
	r = gnutls_set_default_priority(session);
	if (r < 0) {
		printf("connect -> bad priority: %s\n", gnutls_strerror(r));
		gnutls_deinit(session);
		return;
	}

	_check(gnutls_server_name_set(session, GNUTLS_NAME_DNS,
				"example.com", strlen("example.com")) >= 0);
	gnutls_session_set_verify_cert(session, "example.com", 0);

	_check(gnutls_certificate_allocate_credentials(&cred) >= 0);
	_check(gnutls_certificate_set_x509_trust_file(cred,
			ca_file, GNUTLS_X509_FMT_PEM) == 1);
	_check(gnutls_credentials_set(session,
			GNUTLS_CRD_CERTIFICATE, cred) >= 0);

	sock = tcp_connect("127.0.0.1", port);
	_assert(sock != -1, "Connection to 127.0.0.1:%u has failed!", port);
	_assert(setsockopt(sock, IPPROTO_TCP, TCP_NODELAY,
			&sock_flags, sizeof(int)) == 0, "setsockopt failed");

	gnutls_transport_set_int(session, sock);
	gnutls_handshake_set_timeout(session, GNUTLS_DEFAULT_HANDSHAKE_TIMEOUT);
	do {
		r = gnutls_handshake(session);
	} while (r < 0 && !gnutls_error_is_fatal(r));

	if (r >= 0) {
		desc = gnutls_session_get_desc(session);
		_check(desc);
		printf("connect -> connection established: %s\n", desc);
		gnutls_free(desc);
	} else {
		printf("connect -> handshake failed: %s\n", gnutls_strerror(r));
	}

	gnutls_bye(session, GNUTLS_SHUT_RDWR);
	shutdown(sock, SHUT_RDWR);
	close(sock);
	gnutls_certificate_free_credentials(cred);
	gnutls_deinit(session);
}


void cmd_protocol_set_disabled(const char* name)
{
	_check(gnutls_protocol_set_enabled(parse_protocol(name), 0) >= 0);
	printf("protocol_set_disabled %s -> OK\n", name);
}


void cmd_protocol_set_enabled(const char* name)
{
	_check(gnutls_protocol_set_enabled(parse_protocol(name), 1) >= 0);
	printf("protocol_set_enabled %s -> OK\n", name);
}


// Returns 0 if `s` doesn't start with `prefix`, pointer past prefix otherwise.
const char* unprefix(const char* s, const char* prefix)
{
	while (*s && *prefix && *s == *prefix)
		s++, prefix++;
	return *prefix ? NULL : s;
}


#define MAX_CMD_LEN 127
void doit(void)
{
	unsigned port;
	const char* port_str;
	const char* ca_file;
	const char* p;
	char cmd_buf[MAX_CMD_LEN + 1];
	char* e;

	ca_file = getenv("TEST_SERVER_CA");
	_assert(ca_file, "TEST_SERVER_CA is not set");
	port_str = getenv("TEST_SERVER_PORT");
	_assert(port_str, "TEST_SERVER_PORT is not set");
	port = parse_port(port_str);

	_check(gnutls_global_init() >= 0);

	while (!feof(stdin)) {
		memset(cmd_buf, '\0', MAX_CMD_LEN + 1);
		fgets(cmd_buf, MAX_CMD_LEN, stdin);
		e = strchr(cmd_buf, '\n');
		if (e)
			*e = '\0';
		if (!*cmd_buf)
			continue;
		else if (!strcmp(cmd_buf, "> connect"))
			cmd_connect(ca_file, port);
		else if ((p = unprefix(cmd_buf, "> protocol_set_disabled ")))
			cmd_protocol_set_disabled(p);
		else if ((p = unprefix(cmd_buf, "> protocol_set_enabled ")))
			cmd_protocol_set_enabled(p);
		else if ((p = unprefix(cmd_buf, "> ")))
			_fail("Unknown command `%s`\n", p);
		else
			_fail("Invalid line `%s`, does not start with `> `\n",
					cmd_buf);
	}

	gnutls_global_deinit();
	exit(0);
}
