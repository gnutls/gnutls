/*
 * Copyright (C) 2008-2016 Free Software Foundation, Inc.
 * Copyright (C) 2016 Red Hat, Inc.
 *
 * Author: Simon Josefsson, Nikos Mavrogiannopoulos
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

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <assert.h>
#include <gnutls/gnutls.h>
#include "utils.h"
#include "eagain-common.h"

const char *side = NULL;

void
test_cli_serv(gnutls_certificate_credentials_t server_cred,
	      gnutls_certificate_credentials_t client_cred,
	      const char *prio, const char *host, 
	      void *priv, callback_func *client_cb, callback_func *server_cb)
{
	int exit_code = EXIT_SUCCESS;
	int ret;
	/* Server stuff. */
	gnutls_session_t server;
	int sret = GNUTLS_E_AGAIN;
	/* Client stuff. */
	gnutls_session_t client;
	int cret = GNUTLS_E_AGAIN;

	/* General init. */
	reset_buffers();

	/* Init server */
	gnutls_init(&server, GNUTLS_SERVER);
	gnutls_credentials_set(server, GNUTLS_CRD_CERTIFICATE,
				server_cred);
	gnutls_priority_set_direct(server, prio, NULL);
	gnutls_transport_set_push_function(server, server_push);
	gnutls_transport_set_pull_function(server, server_pull);
	gnutls_transport_set_ptr(server, server);

	ret = gnutls_init(&client, GNUTLS_CLIENT);
	if (ret < 0)
		exit(1);


	assert(gnutls_server_name_set(client, GNUTLS_NAME_DNS, host, strlen(host))>=0);

	ret = gnutls_credentials_set(client, GNUTLS_CRD_CERTIFICATE,
				client_cred);
	if (ret < 0)
		exit(1);

	gnutls_priority_set_direct(client, prio, NULL);
	gnutls_transport_set_push_function(client, client_push);
	gnutls_transport_set_pull_function(client, client_pull);
	gnutls_transport_set_ptr(client, client);

	HANDSHAKE(client, server);

	/* check the number of certificates received and verify */
	{
		gnutls_typed_vdata_st data[2];
		unsigned status;

		memset(data, 0, sizeof(data));

		data[0].type = GNUTLS_DT_DNS_HOSTNAME;
		data[0].data = (void*)host;

		data[1].type = GNUTLS_DT_KEY_PURPOSE_OID;
		data[1].data = (void*)GNUTLS_KP_TLS_WWW_SERVER;

		ret = gnutls_certificate_verify_peers(client, data, 2, &status);
		if (ret < 0) {
			fail("could not verify certificate: %s\n", gnutls_strerror(ret));
			exit(1);
		}

		if (status != 0) {
			gnutls_datum_t t;
			assert(gnutls_certificate_verification_status_print(status, GNUTLS_CRT_X509, &t, 0)>=0);
			fail("could not verify certificate for '%s': %.4x: %s\n", host, status, t.data);
			gnutls_free(t.data);
			exit(1);
		}

		/* check gnutls_certificate_verify_peers3 */
		ret = gnutls_certificate_verify_peers3(client, host, &status);
		if (ret < 0) {
			fail("could not verify certificate: %s\n", gnutls_strerror(ret));
			exit(1);
		}

		if (status != 0) {
			gnutls_datum_t t;
			assert(gnutls_certificate_verification_status_print(status, GNUTLS_CRT_X509, &t, 0)>=0);
			fail("could not verify certificate3: %.4x: %s\n", status, t.data);
			gnutls_free(t.data);
			exit(1);
		}
	}

	if (client_cb)
		client_cb(client, priv);
	if (server_cb)
		server_cb(server, priv);

	gnutls_bye(client, GNUTLS_SHUT_RDWR);
	gnutls_bye(server, GNUTLS_SHUT_RDWR);

	gnutls_deinit(client);
	gnutls_deinit(server);

	if (debug > 0) {
		if (exit_code == 0)
			puts("Self-test successful");
		else
			puts("Self-test failed");
	}
}
