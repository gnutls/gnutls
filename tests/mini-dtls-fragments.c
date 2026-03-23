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

static int c2s_pull_timeout_once(gnutls_transport_ptr_t tr, unsigned ms)
{
	return c2s.head != c2s.tail ? 1 : 0;
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

static void write_u16(uint8_t *p, uint16_t val)
{
	p[0] = val >> 8;
	p[1] = val & 0xff;
}

static void write_u24(uint8_t *p, uint32_t val)
{
	p[0] = (val >> 16) & 0xff;
	p[1] = (val >> 8) & 0xff;
	p[2] = val & 0xff;
}

static void write_u48(uint8_t *p, uint64_t seq)
{
	int i;
	for (i = 5; i >= 0; i--) {
		p[i] = seq & 0xff;
		seq >>= 8;
	}
}

static uint64_t read_u48(const uint8_t *p)
{
	uint64_t seq = 0;
	int i;
	for (i = 5; i >= 0; i--) {
		seq <<= 8;
		seq |= p[i];
	}
	return seq;
}

static void make_0frag(uint8_t *dst, const uint8_t *src)
{
	memcpy(dst, src, 13 + 12);
	dst[13 + 6] = dst[13 + 7] = dst[13 + 8] = 0; /* frag offset = 0 */
	dst[13 + 9] = dst[13 + 10] = dst[13 + 11] = 0; /* frag length = 0 */
	/* record payload length: just the 12-byte handshake header, no data */
	dst[11] = 0;
	dst[12] = 12;
}

ATTRIBUTE_NONNULL((2))
static ssize_t client_push_inj0(gnutls_transport_ptr_t tr, const void *d_,
				size_t l)
{
	static uint32_t seq = 0;
	const uint8_t *d = (const uint8_t *)d_;
	uint8_t frag[13 + 12];
	uint8_t *b;

	if (l < 13) /* too short for a DTLS record header */
		return queue_put(&c2s, d, l);
	if (!(d[3] == 0 && d[4] == 0)) /* not epoch 0: encrypted, don't touch */
		return queue_put(&c2s, d, l);

	b = malloc(l);
	assert(b);
	memcpy(b, d, l);

	if (l >= 13 + 12 && d[0] == 22) { /* handshake record: inject 0-frag */
		make_0frag(frag, d);
		write_u48(frag + 5, seq++); /* 0-frag first */
		queue_put(&c2s, frag, sizeof(frag));

		write_u48(b + 5, seq++); /* real second */
		queue_put(&c2s, b, l);
	} else { /* other (e.g. CCS): just renumber */
		write_u48(b + 5, seq++);
		queue_put(&c2s, b, l);
	}

	free(b);
	return l;
}

static void test(gnutls_push_func client_push, bool expect_success)
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

		if (c2s.head == c2s.tail && s2c.head == s2c.tail)
			break; /* speed the test up */
	}

	if (expect_success) {
		if (cr)
			fail("client: %s\n", gnutls_strerror(cr));
		if (sr)
			fail("server: %s\n", gnutls_strerror(sr));

	} else {
		if (cr == 0 && sr == 0)
			fail("handshake unexpectedly succeeded: %s / %s\n",
			     gnutls_strerror(cr), gnutls_strerror(sr));
	}

	success("OK\n");

	queue_reset(&c2s);
	queue_reset(&s2c);

	gnutls_deinit(client);
	gnutls_deinit(server);
	gnutls_certificate_free_credentials(ccred);
	gnutls_certificate_free_credentials(scred);
}

static void test_malicious1816(void)
{
	/* dgram1: msg_len=50, frag_offset=25, frag_len=25 */
	static const uint8_t dgram1_hdr[] = {
		0x16, /* type: handshake */
		0xfe, 0xfd, /* version: DTLS 1.2 */
		0x00, 0x00, /* epoch: 0 */
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, /* seq: 0 */
		0x00, 0x25, /* record_length: 37 */
		0x01, /* msg_type: ClientHello */
		0x00, 0x00, 0x32, /* msg_length: 50 */
		0x00, 0x00, /* msg_seq: 0 */
		0x00, 0x00, 0x19, /* frag_offset: 25 */
		0x00, 0x00, 0x19, /* frag_length: 25 */
	};
	/* dgram2: msg_len=3000, frag_offset=0, frag_len=48 */
	static const uint8_t dgram2_hdr[] = {
		0x16, /* type: handshake */
		0xfe, 0xfd, /* version: DTLS 1.2 */
		0x00, 0x00, /* epoch: 0 */
		0x00, 0x00, 0x00, 0x00, 0x00, 0x01, /* seq: 1 */
		0x00, 0x3c, /* record_length: 60 */
		0x01, /* msg_type: ClientHello */
		0x00, 0x0b, 0xb8, /* msg_length: 3000 */
		0x00, 0x00, /* msg_seq: 0 */
		0x00, 0x00, 0x00, /* frag_offset: 0 */
		0x00, 0x00, 0x30, /* frag_length: 48 */
	};
	/* dgram3: msg_len=3000, frag_offset=40, frag_len=1475 */
	static const uint8_t dgram3_hdr[] = {
		0x16, /* type: handshake */
		0xfe, 0xfd, /* version: DTLS 1.2 */
		0x00, 0x00, /* epoch: 0 */
		0x00, 0x00, 0x00, 0x00, 0x00, 0x02, /* seq: 2 */
		0x05, 0xcf, /* record_length: 1487 */
		0x01, /* msg_type: ClientHello */
		0x00, 0x0b, 0xb8, /* msg_length: 3000 */
		0x00, 0x00, /* msg_seq: 0 */
		0x00, 0x00, 0x28, /* frag_offset: 40 */
		0x00, 0x05, 0xc3, /* frag_length: 1475 */
	};
	/* dgram4: msg_len=3000, frag_offset=1500, frag_len=1475 */
	static const uint8_t dgram4_hdr[] = {
		0x16, /* type: handshake */
		0xfe, 0xfd, /* version: DTLS 1.2 */
		0x00, 0x00, /* epoch: 0 */
		0x00, 0x00, 0x00, 0x00, 0x00, 0x03, /* seq: 3 */
		0x05, 0xcf, /* record_length: 1487 */
		0x01, /* msg_type: ClientHello */
		0x00, 0x0b, 0xb8, /* msg_length: 3000 */
		0x00, 0x00, /* msg_seq: 0 */
		0x00, 0x05, 0xdc, /* frag_offset: 1500 */
		0x00, 0x05, 0xc3, /* frag_length: 1475 */
	};
	gnutls_session_t server;
	gnutls_certificate_credentials_t scred;
	uint8_t dgram[1500];
	int sr;

	if (debug)
		gnutls_global_set_log_level(4711);

	gnutls_certificate_allocate_credentials(&scred);
	gnutls_certificate_set_x509_key_mem(scred, &server_cert, &server_key,
					    GNUTLS_X509_FMT_PEM);

	gnutls_init(&server, GNUTLS_SERVER | GNUTLS_DATAGRAM);
	gnutls_priority_set_direct(server, "NORMAL:+VERS-DTLS1.2", NULL);
	gnutls_credentials_set(server, GNUTLS_CRD_CERTIFICATE, scred);

	gnutls_dtls_set_timeouts(server, get_dtls_retransmit_timeout(),
				 get_timeout());

	gnutls_transport_set_ptr(server, server);
	gnutls_transport_set_push_function(server, server_push);
	gnutls_transport_set_pull_function(server, server_pull);
	gnutls_transport_set_pull_timeout_function(server,
						   c2s_pull_timeout_once);

	memset(dgram, 0, sizeof(dgram));
	memcpy(dgram, dgram1_hdr, 25);
	queue_put(&c2s, dgram, 25 + 25);

	memset(dgram, 0, sizeof(dgram));
	memcpy(dgram, dgram2_hdr, 25);
	queue_put(&c2s, dgram, 25 + 48);

	memset(dgram, 0, sizeof(dgram));
	memcpy(dgram, dgram3_hdr, 25);
	queue_put(&c2s, dgram, 25 + 1475);

	memset(dgram, 0, sizeof(dgram));
	memcpy(dgram, dgram4_hdr, 25);
	queue_put(&c2s, dgram, 25 + 1475);

	gnutls_global_set_log_function(server_log_func);
	do {
		sr = gnutls_handshake(server); /* invalid write if vulnerable */
	} while (c2s.head != c2s.tail && !gnutls_error_is_fatal(sr));
	if (sr != GNUTLS_E_UNEXPECTED_PACKET_LENGTH)
		fail("server: expected GNUTLS_E_UNEXPECTED_PACKET_LENGTH, "
		     "got: %s\n",
		     gnutls_strerror(sr));

	success("OK\n");

	queue_reset(&c2s);
	queue_reset(&s2c);

	gnutls_deinit(server);
	gnutls_certificate_free_credentials(scred);
}

static ssize_t queue_put_renumbered(queue_t *q, const uint8_t *data, size_t l,
				    int delta_n)
{
	if (delta_n == 0 || l < 13 || data[3] != 0 || data[4] != 0)
		return queue_put(&c2s, data, l);

	uint8_t *p = malloc(l);
	assert(p);
	memcpy(p, data, l);
	write_u48(p + 5, read_u48(p + 5) + delta_n);
	ssize_t ret = queue_put(q, p, l);
	free(p);
	return ret;
}

static void split_client_hello(const uint8_t *data, size_t len, uint8_t **frag1,
			       size_t *frag1_len, uint8_t **frag2,
			       size_t *frag2_len)
{
	size_t body_size = len - 25;
	*frag1_len = 13 + 12 + 1;
	*frag2_len = 13 + 12 + (body_size - 1);

	*frag1 = malloc(13 + 12 + 1);
	assert(*frag1);
	*frag2 = malloc(13 + 12 + body_size - 1);
	assert(*frag2);

	/* first fragment: record header + handshake header + first body byte */
	memcpy(*frag1, data, 13); /* record header */
	write_u16(*frag1 + 11, 12 + 1); /* record length */
	memcpy(*frag1 + 13, data + 13, 12); /* handshake header */
	write_u24(*frag1 + 19, 0); /* fragment_offset = 0 */
	write_u24(*frag1 + 22, 1); /* fragment_length = 1 */
	(*frag1)[25] = data[25]; /* first body byte */

	/* second fragment: record header + handshake header + remaining body */
	memcpy(*frag2, data, 13); /* record header */
	write_u16(*frag2 + 11, *frag2_len - 13); /* record length */
	write_u48(*frag2 + 5, read_u48(*frag2 + 5) + 1); /* sequence number */
	memcpy(*frag2 + 13, data + 13, 12); /* handshake header */
	write_u24(*frag2 + 19, 1); /* fragment_offset = 1 */
	write_u24(*frag2 + 22, body_size - 1); /* shortened fragment_length */
	memcpy(*frag2 + 25, data + 26, body_size - 1); /* remaining body */
}

static ssize_t client_push_split_hello(gnutls_transport_ptr_t tr, const void *b,
				       size_t l)
{
	static int seq_offset = 0; /* for renumbering follow-up epoch0 ones */

	const uint8_t *data = (const uint8_t *)b;
	uint8_t *frag1, *frag2;
	size_t frag1_len, frag2_len;

	/* Pass through anything that isn't an epoch0 ClientHello with body */
	if (l < 13 + 12 + 1 || /* too short for DTLS record header */
	    data[0] != 22 || /* not a handshake record */
	    data[3] != 0 || data[4] != 0 || /* not epoch 0 */
	    data[13] != 1) /* not ClientHello */
		return queue_put_renumbered(&c2s, b, l, seq_offset);

	/* epoch0 Client Hello: special treatment of splitting into fragments */
	split_client_hello(data, l, &frag1, &frag1_len, &frag2, &frag2_len);
	queue_put(&c2s, frag1, frag1_len);
	queue_put(&c2s, frag2, frag2_len);
	free(frag1);
	free(frag2);
	seq_offset++;
	return l;
}

static ssize_t client_push_split_hello_bad_seq(gnutls_transport_ptr_t tr,
					       const void *b, size_t l)
{
	/* gnutls wasn't matching on message_seq on merging, see #1839 */
	static int seq_offset = 0; /* for renumbering follow-up epoch0 ones */

	const uint8_t *data = (const uint8_t *)b;
	uint8_t *frag1, *frag2;
	size_t frag1_len, frag2_len;

	/* Pass through anything that isn't an epoch0 ClientHello with body */
	if (l < 13 + 12 + 1 || /* too short for DTLS record header */
	    data[0] != 22 || /* not a handshake record */
	    data[3] != 0 || data[4] != 0 || /* not epoch 0 */
	    data[13] != 1) /* not ClientHello */
		return queue_put_renumbered(&c2s, b, l, seq_offset);

	/* epoch0 Client Hello: special treatment of splitting into fragments */
	split_client_hello(data, l, &frag1, &frag1_len, &frag2, &frag2_len);
	queue_put(&c2s, frag1, frag1_len);
	frag2[18]++; /* WRONG, message_seq mismatch must be rejected, #1839 */
	queue_put(&c2s, frag2, frag2_len);
	free(frag1);
	free(frag2);
	seq_offset++;
	return l;
}

static void test_malicious1811(void)
{
	static const uint8_t dgram[] = {
		22, /* type = handshake */
		0xfe, 0xfd, /* version = DTLS 1.2 */
		0x00, 0x00, /* epoch = 0 */
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, /* seq = 0 */
		0x00, 0x0c, /* record length = 12 */

		0x01, /* type = ClientHello */
		0xff, 0xff, 0xff, /* length = 0xffffff (!) */
		0x00, 0x00, /* msg seq = 0 */
		0x00, 0x00, 0x02, /* frag_offset = 2 (!) */
		0x00, 0x00, 0x00, /* frag_length = 0 (!) */
	};
	gnutls_session_t server;
	gnutls_certificate_credentials_t scred;
	int sr;

	if (debug)
		gnutls_global_set_log_level(4711);

	gnutls_certificate_allocate_credentials(&scred);
	gnutls_certificate_set_x509_key_mem(scred, &server_cert, &server_key,
					    GNUTLS_X509_FMT_PEM);

	gnutls_init(&server, GNUTLS_SERVER | GNUTLS_DATAGRAM);
	gnutls_priority_set_direct(server, "NORMAL:+VERS-DTLS1.2", NULL);
	gnutls_credentials_set(server, GNUTLS_CRD_CERTIFICATE, scred);

	gnutls_dtls_set_timeouts(server, get_dtls_retransmit_timeout(),
				 get_timeout());

	gnutls_transport_set_ptr(server, server);
	gnutls_transport_set_push_function(server, server_push);
	gnutls_transport_set_pull_function(server, server_pull);
	gnutls_transport_set_pull_timeout_function(server,
						   c2s_pull_timeout_once);

	queue_put(&c2s, dgram, sizeof(dgram));

	gnutls_global_set_log_function(server_log_func);
	do {
		sr = gnutls_handshake(server); /* crashes if vulnerable */
	} while (c2s.head != c2s.tail && !gnutls_error_is_fatal(sr));
	if (gnutls_error_is_fatal(sr))
		fail("server: %s\n", gnutls_strerror(sr));

	success("OK\n");

	queue_reset(&c2s);
	queue_reset(&s2c);

	gnutls_deinit(server);
	gnutls_certificate_free_credentials(scred);
}

void doit(void)
{
	global_init();
	success("normal:\n");
	test(client_push_normal, true);
	success("valid 0-len fragments injected every 2nd push in epoch0:\n");
	test(client_push_inj0, true);
	success("malicious reassembly bug exploitation (#1816):\n");
	test_malicious1816();
	success("split client hello smoke-test\n");
	test(client_push_split_hello, true);
	success("split client hello smoke-test and mangle sequence number\n");
	test(client_push_split_hello_bad_seq, false);
	success("malicious injection aiming for an underflow (#1811):\n");
	test_malicious1811();
	gnutls_global_deinit();
}

#endif /* _WIN32 */
