/*
 * Copyright (C) 2017 Nikos Mavrogiannopoulos
 *
 * Permission is hereby granted, free of charge, to any person obtaining a
 * copy of this software and associated documentation files (the "Software"),
 * to deal in the Software without restriction, including without limitation
 * the rights to use, copy, modify, merge, publish, distribute, sublicense,
 * and/or sell copies of the Software, and to permit persons to whom the
 * Software is furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
 * FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER
 * DEALINGS IN THE SOFTWARE.
 *
 */

#include <assert.h>
#include <fcntl.h>
#include <stdint.h>
#include <sys/types.h>
#include <unistd.h>
#include <string.h>
#include <stdlib.h>

#include <gnutls/gnutls.h>

struct mem_st {
	const uint8_t *data;
	size_t size;
};

#define MIN(x,y) ((x)<(y)?(x):(y))
static ssize_t
client_push(gnutls_transport_ptr_t tr, const void *data, size_t len)
{
	return len;
}

static ssize_t client_pull(gnutls_transport_ptr_t tr, void *data, size_t len)
{
	struct mem_st *p = (struct mem_st *)tr;

	if (p->size == 0) {
		return 0;
	}

	len = MIN(len, p->size);
	memcpy(data, p->data, len);

	p->size -= len;
	p->data += len;

	return len;
}

int client_pull_timeout_func(gnutls_transport_ptr_t tr, unsigned int ms)
{
	struct mem_st *p = (struct mem_st *)tr;

	if (p->size > 0)
		return 1;	/* available data */
	else
		return 0;	/* timeout */
}

#ifdef __cplusplus
extern "C"
#endif
int LLVMFuzzerTestOneInput(const uint8_t * data, size_t size)
{
	int res;
	gnutls_session_t session;
	gnutls_psk_client_credentials_t pcred;
	struct mem_st memdata;
	gnutls_datum_t pskkey;

	pskkey.data = (unsigned char*)"\x8a\x77\x59\xb3\xf2\x69\x83\xc4\x53\xe4\x48\x06\x0b\xde\x89\x81";
	pskkey.size = 16;

	res = gnutls_init(&session, GNUTLS_CLIENT);
	assert(res >= 0);

	res = gnutls_psk_allocate_client_credentials(&pcred);
	assert(res >= 0);

	res = gnutls_psk_set_client_credentials(pcred, "test", &pskkey, GNUTLS_PSK_KEY_RAW);
	assert(res >= 0);

	res = gnutls_credentials_set(session, GNUTLS_CRD_PSK, pcred);
	assert(res >= 0);

	res = gnutls_priority_set_direct(session, "NORMAL:-KX-ALL:+ECDHE-PSK:+DHE-PSK:+PSK", NULL);
	assert(res >= 0);

	memdata.data = data;
	memdata.size = size;

	gnutls_transport_set_push_function(session, client_push);
	gnutls_transport_set_pull_function(session, client_pull);
	gnutls_transport_set_pull_timeout_function(session,
						   client_pull_timeout_func);
	gnutls_transport_set_ptr(session, &memdata);

	do {
		res = gnutls_handshake(session);
	} while (res < 0 && gnutls_error_is_fatal(res) == 0);
	if (res >= 0) {
		while (true) {
			char buf[16384];
			res = gnutls_record_recv(session, buf, sizeof(buf));
			if (res <= 0) {
				break;
			}
		}
	}

	gnutls_deinit(session);
	gnutls_psk_free_client_credentials(pcred);
	return 0;
}
