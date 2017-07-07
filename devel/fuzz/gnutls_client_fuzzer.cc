/*
# Copyright 2016 Google Inc.
# Copyright 2017 Red Hat, Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
################################################################################
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
	gnutls_certificate_credentials_t xcred;
	struct mem_st memdata;
	uint16_t tag;

	if (size < 2)
		abort();

	memcpy(&tag, data, 2);
	data += 2;
	size -= 2;

	if (tag != 0)		/* ignore */
		return 0;

	res = gnutls_init(&session, GNUTLS_CLIENT);
	assert(res >= 0);

	res = gnutls_certificate_allocate_credentials(&xcred);
	assert(res >= 0);
	res = gnutls_credentials_set(session, GNUTLS_CRD_CERTIFICATE, xcred);
	assert(res >= 0);

	res = gnutls_set_default_priority(session);
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
	gnutls_certificate_free_credentials(xcred);
	return 0;
}
