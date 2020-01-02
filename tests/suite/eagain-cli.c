/*
 * Copyright (C) 2008-2012 Free Software Foundation, Inc.
 * Copyright (C) 2018-2020 Red Hat, Inc.
 * Copyright (C) 2010 Mike Blumenkrantz
 *
 * This file is part of GnuTLS.
 *
 * GnuTLS is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * GnuTLS is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <https://www.gnu.org/licenses/>.
 */

#include <config.h>
#include <fcntl.h>
#include <netinet/tcp.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <errno.h>
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "../utils.h"
#include <gnutls/gnutls.h>
#include <assert.h>
#include <sys/time.h>
#include <ev.h>

static int done = 0;
EV_P;
ev_io remote_w;
gnutls_session_t session;

static const char
*SSL_GNUTLS_PRINT_HANDSHAKE_STATUS(gnutls_handshake_description_t status)
{
	return gnutls_handshake_description_get_name(status);
}

/* Connects to the peer and returns a socket
 * descriptor.
 */
static int tcp_connect(void)
{
	const char *PORT = getenv("PORT");
	const char *SERVER = "127.0.0.1";	//verisign.com
	int err, sd;
	int flag = 1, curstate = 0;
	struct sockaddr_in sa;

	/* sets some fd options such as nonblock */
	sd = socket(AF_INET, SOCK_STREAM, 0);
	setsockopt(sd, SOL_SOCKET, SO_REUSEADDR, (const void *)&curstate,
		   sizeof(curstate));


	memset(&sa, '\0', sizeof(sa));
	sa.sin_family = AF_INET;
	sa.sin_port = htons(atoi(PORT));

	inet_pton(AF_INET, SERVER, &sa.sin_addr);

	err = connect(sd, (struct sockaddr *)&sa, sizeof(sa));
	if ((err < 0) && (errno != EINPROGRESS)) {
		fprintf(stderr, "Connect error\n");
		exit(1);
	}

	/* lower the send buffers to force EAGAIN */
	assert(setsockopt(sd, IPPROTO_TCP, TCP_NODELAY, (char *)&flag, sizeof(int)) >= 0);
	assert(fcntl(sd, F_SETFL, O_NONBLOCK)>=0);

	return sd;
}

static void tcp_close(int sd)
{
	shutdown(sd, SHUT_RDWR);	/* no more receptions */
	close(sd);
}

/* We provide this helper to ensure that we test EAGAIN while writing
 * even on a reliable connection */
static ssize_t
_client_push(gnutls_transport_ptr_t tr, const void *data, size_t len)
{
	struct timeval tv;

	assert(gettimeofday(&tv, NULL) >= 0);

	if (tv.tv_usec % 2 == 0) {
		errno = EAGAIN;
		return -1;
	}

	return send((unsigned long)tr, data, len, 0);
}

static ssize_t
_client_pull(gnutls_transport_ptr_t tr, void *data, size_t len)
{
	struct timeval tv;

	assert(gettimeofday(&tv, NULL) >= 0);

	if (tv.tv_usec % 2 == 0) {
		errno = EAGAIN;
		return -1;
	}

	return recv((unsigned long)tr, data, len, 0);
}

static int _client_pull_timeout(gnutls_transport_ptr_t ptr,
				unsigned int ms)
{
	return gnutls_system_recv_timeout(ptr, ms);
}

static void _process_data(EV_P_ ev_io * w, int revents)
{
	static int ret = -1, lastret = 0;
	static unsigned int count = 0;
	static int prev_direction;

	if (!done && (revents & (EV_WRITE|EV_READ))) {
		if (lastret == GNUTLS_E_AGAIN) {
			if (revents & EV_WRITE) {
				assert(prev_direction == 1);
			}
			if (revents & EV_READ) {
				assert(prev_direction == 0);
			}
		}

		lastret = ret;
		ret = gnutls_handshake(session);
		count++;

		if (gnutls_record_get_direction(session)) {
			ev_io_stop(EV_A_ &remote_w);
			ev_io_set(&remote_w, gnutls_transport_get_int(session), EV_WRITE);
			ev_io_start(EV_A_ &remote_w);
			prev_direction = 1;
		} else {
			ev_io_stop(EV_A_ &remote_w);
			ev_io_set(&remote_w, gnutls_transport_get_int(session), EV_READ);
			ev_io_start(EV_A_ &remote_w);
			prev_direction = 0;
		}
		/* avoid printing messages infinity times */
		if (lastret != ret && ret != 0 && ret != GNUTLS_E_AGAIN) {
			fprintf(stderr, "gnutls returned with: %s - %s\n",
				gnutls_strerror_name(ret),
				gnutls_strerror(ret));
			if ((ret == GNUTLS_E_WARNING_ALERT_RECEIVED)
			    || (ret == GNUTLS_E_FATAL_ALERT_RECEIVED))
				fprintf(stderr, "Also received alert: %s\n",
				       gnutls_alert_get_name
				       (gnutls_alert_get(session)));
			fprintf(stderr, "last out: %s\n",
			       SSL_GNUTLS_PRINT_HANDSHAKE_STATUS
			       (gnutls_handshake_get_last_out(session)));
			fprintf(stderr, "last in: %s\n",
			       SSL_GNUTLS_PRINT_HANDSHAKE_STATUS
			       (gnutls_handshake_get_last_in(session)));
		}

		if (gnutls_error_is_fatal(ret)) {
			fprintf(stderr, "yarrr this be an error!");
			exit(1);
		}

	}

	if (ret == GNUTLS_E_SUCCESS) {
		count = 0;
		ret = -1;
		done = 1;
		lastret = 0;
		ev_io_stop(EV_A_ & remote_w);
	}

	return;
}

static void try(const char *name, const char *prio)
{
	gnutls_certificate_credentials_t c_certcred;
	int sd, i, ret;

	global_init();

	gnutls_certificate_allocate_credentials(&c_certcred);

	printf("%s: testing priority %s\n", name, prio);
	loop = EV_DEFAULT;

	for (i = 0; i < 4; i++) {
		done = 0;

		assert(gnutls_init(&session, GNUTLS_CLIENT) >= 0);
		gnutls_transport_set_push_function(session, _client_push);
		gnutls_transport_set_pull_function(session, _client_pull);
		gnutls_transport_set_pull_timeout_function(session, _client_pull_timeout);
		gnutls_handshake_set_timeout(session,
					     GNUTLS_DEFAULT_HANDSHAKE_TIMEOUT);

		assert(gnutls_priority_set_direct(session, prio, NULL) >= 0);
		gnutls_credentials_set(session, GNUTLS_CRD_CERTIFICATE,
				       c_certcred);
		gnutls_server_name_set(session, GNUTLS_NAME_DNS,
				       "localhost", strlen("localhost"));

		sd = tcp_connect();

		/* associate gnutls with socket */
		gnutls_transport_set_int(session, sd);

		/* add a callback for data being available for send/receive on socket */
		ev_io_init(&remote_w, _process_data, sd, EV_WRITE);
		ev_io_start(EV_A_ & remote_w);

		/* begin main loop */
		ev_loop(EV_A_ 0);

		do {
			ret = gnutls_bye(session, GNUTLS_SHUT_RDWR);
		} while (ret == GNUTLS_E_AGAIN || ret == GNUTLS_E_INTERRUPTED);

		gnutls_deinit(session);
		session = NULL;

		tcp_close(sd);
	}

	ev_loop_destroy(loop);
	gnutls_certificate_free_credentials(c_certcred);

	return;
}

int main(void)
{
	try("tls 1.2 (dhe)", "NORMAL:-VERS-TLS-ALL:+VERS-TLS1.2:-KX-ALL:+DHE-RSA");
	try("tls 1.2 (rsa)", "NORMAL:-VERS-TLS-ALL:+VERS-TLS1.2:-KX-ALL:+RSA");
	try("tls 1.3", "NORMAL:-VERS-TLS-ALL:+VERS-TLS1.3");
	try("default", "NORMAL");
	return 0;
}
