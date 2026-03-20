/*
 * Copyright (C) 2026 Red Hat, Inc.
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
 * You should have received a copy of the GNU Lesser General Public License
 * along with this program.  If not, see <https://www.gnu.org/licenses/>
 */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <stdio.h>
#include <stdlib.h>

#if defined(_WIN32)

int main(void)
{
	exit(77);
}

#else

#include <assert.h>
#include <errno.h>
#include <stdbool.h>
#include <stdint.h>
#include <string.h>
#include <gnutls/gnutls.h>
#include <gnutls/dtls.h>
#include "cert-common.h"
#include "utils.h"

#include "attribute.h"

static void server_log_func(int level, const char *str)
{
	fprintf(stderr, "server|<%d>| %s", level, str);
}

static void client_log_func(int level, const char *str)
{
	fprintf(stderr, "client|<%d>| %s", level, str);
}

#define QUEUE_SIZE 1024
#define PACKET_SIZE 2048

typedef struct {
	uint8_t buf[PACKET_SIZE];
	size_t len;
} packet_t;
typedef struct {
	packet_t packets[QUEUE_SIZE];
	size_t head;
	size_t tail;
} queue_t;

static queue_t c2s, s2c;

static int queue_put(queue_t *q, const void *buf, size_t len)
{
	assert(len <= PACKET_SIZE);
	memcpy(q->packets[q->tail].buf, buf, len);
	q->packets[q->tail].len = len;
	q->tail++;
	q->tail %= QUEUE_SIZE;
	assert(q->tail != q->head);
	return len;
}

static ssize_t queue_get(queue_t *q, gnutls_session_t s, void *buf, size_t len)
{
	if (q->head == q->tail) {
		gnutls_transport_set_errno(s, EAGAIN);
		return -1;
	}
	size_t n = q->packets[q->head].len;
	memcpy(buf, q->packets[q->head].buf, n);
	q->head++;
	q->head %= QUEUE_SIZE;
	return n;
}

static void queue_reset(queue_t *q)
{
	q->head = q->tail = 0;
}

static int pull_timeout(gnutls_transport_ptr_t tr, unsigned ms)
{
	return 1;
}

static ssize_t server_pull(gnutls_transport_ptr_t tr, void *b, size_t l)
{
	return queue_get(&c2s, (gnutls_session_t)tr, b, l);
}

static ssize_t client_pull(gnutls_transport_ptr_t tr, void *b, size_t l)
{
	return queue_get(&s2c, (gnutls_session_t)tr, b, l);
}

static ssize_t server_push(gnutls_transport_ptr_t tr, const void *b, size_t l)
{
	return queue_put(&s2c, b, l);
}

static ssize_t client_push_normal(gnutls_transport_ptr_t tr, const void *b,
				  size_t l)
{
	return queue_put(&c2s, b, l);
}

static void test(gnutls_push_func client_push)
{
	gnutls_session_t client, server;
	gnutls_certificate_credentials_t ccred, scred;
	int cr = 0, sr = 0;
	bool cdone = false, sdone = false;

	if (debug)
		gnutls_global_set_log_level(4711);

	gnutls_certificate_allocate_credentials(&scred);
	gnutls_certificate_set_x509_key_mem(scred, &server_cert, &server_key,
					    GNUTLS_X509_FMT_PEM);
	gnutls_certificate_allocate_credentials(&ccred);

	gnutls_init(&server, GNUTLS_SERVER | GNUTLS_DATAGRAM);
	gnutls_init(&client, GNUTLS_CLIENT | GNUTLS_DATAGRAM);

	gnutls_priority_set_direct(server, "NORMAL:-VERS-ALL:+VERS-DTLS1.2",
				   NULL);
	gnutls_priority_set_direct(client, "NORMAL:-VERS-ALL:+VERS-DTLS1.2",
				   NULL);

	gnutls_credentials_set(server, GNUTLS_CRD_CERTIFICATE, scred);
	gnutls_credentials_set(client, GNUTLS_CRD_CERTIFICATE, ccred);

	gnutls_dtls_set_timeouts(client, get_dtls_retransmit_timeout(),
				 get_timeout());
	gnutls_dtls_set_timeouts(server, get_dtls_retransmit_timeout(),
				 get_timeout());

	gnutls_transport_set_ptr(client, client);
	gnutls_transport_set_push_function(client, client_push);
	gnutls_transport_set_pull_function(client, client_pull);
	gnutls_transport_set_pull_timeout_function(client, pull_timeout);

	gnutls_transport_set_ptr(server, server);
	gnutls_transport_set_push_function(server, server_push);
	gnutls_transport_set_pull_function(server, server_pull);
	gnutls_transport_set_pull_timeout_function(server, pull_timeout);

	while (!cdone || !sdone) {
		gnutls_global_set_log_function(client_log_func);
		if (!cdone)
			cr = gnutls_handshake(client);
		if (!cr || gnutls_error_is_fatal(cr))
			cdone = true;

		gnutls_global_set_log_function(server_log_func);
		if (!sdone)
			sr = gnutls_handshake(server);
		if (!sr || gnutls_error_is_fatal(sr))
			sdone = true;
	}

	if (cr)
		fail("client: %s\n", gnutls_strerror(cr));
	if (sr)
		fail("server: %s\n", gnutls_strerror(sr));

	success("OK\n");

	queue_reset(&c2s);
	queue_reset(&s2c);

	gnutls_deinit(client);
	gnutls_deinit(server);
	gnutls_certificate_free_credentials(ccred);
	gnutls_certificate_free_credentials(scred);
}

void doit(void)
{
	global_init();
	test(client_push_normal);
	gnutls_global_deinit();
}

#endif /* _WIN32 */
