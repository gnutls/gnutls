/*
 * Copyright (C) 2001-2012 Free Software Foundation, Inc.
 * Copyright (C) 2017 Red Hat, Inc.
 *
 * Author: Nikos Mavrogiannopoulos
 *
 * This file is part of GnuTLS.
 *
 * The GnuTLS is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public License
 * as published by the Free Software Foundation; either version 2.1 of
 * the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>
 *
 */

/* This file contains the code for the Max Record Size TLS extension.
 */

#include "gnutls_int.h"
#include "errors.h"
#include "num.h"
#include <extensions.h>
#include <ext/supported_versions.h>

static int supported_versions_recv_params(gnutls_session_t session,
					  const uint8_t * data,
					  size_t data_size);
static int supported_versions_send_params(gnutls_session_t session,
					  gnutls_buffer_st * extdata);

const extension_entry_st ext_mod_supported_versions = {
	.name = "Supported Versions",
	.tls_id = 43,
	.gid = GNUTLS_EXTENSION_SUPPORTED_VERSIONS,
	.validity = GNUTLS_EXT_FLAG_CLIENT_HELLO,
	.parse_type = GNUTLS_EXT_MANDATORY, /* force parsing prior to EXT_TLS extensions */

	.recv_func = supported_versions_recv_params,
	.send_func = supported_versions_send_params,
	.pack_func = NULL,
	.unpack_func = NULL,
	.deinit_func = NULL,
	.cannot_be_overriden = 1
};

/* Only client sends this extension. */
static int
supported_versions_recv_params(gnutls_session_t session,
			       const uint8_t * data, size_t _data_size)
{
	ssize_t data_size = _data_size;
	uint8_t major, minor;
	gnutls_protocol_t proto;
	ssize_t bytes;
	int ret;

	if (session->security_parameters.entity == GNUTLS_SERVER) {
		DECR_LEN(data_size, 1);
		bytes = data[0];
		data++;

		if (bytes % 2 == 1)
			return gnutls_assert_val(GNUTLS_E_UNEXPECTED_PACKET_LENGTH);

		DECR_LEN(data_size, bytes);

		if (data_size != 0)
			return gnutls_assert_val(GNUTLS_E_UNEXPECTED_PACKET_LENGTH);

		while (bytes > 0) {
			major = data[0];
			minor = data[1];
			data += 2;
			bytes -= 2;

			proto = _gnutls_version_get(major, minor);

			if (_gnutls_version_is_supported(session, proto)) {
				ret = _gnutls_set_current_version(session, proto);
				if (ret < 0)
					return gnutls_assert_val(ret);

				_gnutls_handshake_log("EXT[%p]: Negotiated version: %d.%d\n",
						      session, (int)major, (int)minor);
				return 0;
			}
		}

		/* if we are here, none of the versions were acceptable */
		return gnutls_assert_val(GNUTLS_E_UNSUPPORTED_VERSION_PACKET);
	} else {
		/* a server should never send this message */
		gnutls_assert();
		return GNUTLS_E_RECEIVED_ILLEGAL_EXTENSION;
	}

	return 0;
}

/* returns data_size or a negative number on failure
 */
static int
supported_versions_send_params(gnutls_session_t session,
			       gnutls_buffer_st * extdata)
{
	uint8_t versions[32];
	size_t versions_size;
	int ret;

	/* this function sends the client extension data (dnsname) */
	if (session->security_parameters.entity == GNUTLS_CLIENT) {
		ret = _gnutls_write_supported_versions(session, versions, sizeof(versions));
		if (ret <= 0) /* if this function doesn't succeed do not send anything */
			return 0;

		versions_size = ret;

		ret = _gnutls_buffer_append_data_prefix(extdata, 8, versions, versions_size);
		if (ret < 0)
			return gnutls_assert_val(ret);

		return versions_size+2;
	}

	return 0;
}
