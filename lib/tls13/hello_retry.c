/*
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

#include "gnutls_int.h"
#include "errors.h"
#include "hello_ext.h"
#include "handshake.h"
#include "tls13/hello_retry.h"
#include "auth/cert.h"
#include "mbuffers.h"

int _gnutls13_send_hello_retry_request(gnutls_session_t session, unsigned again)
{
	int ret;
	mbuffer_st *bufel = NULL;
	gnutls_buffer_st buf;
	const version_entry_st *ver;

	if (again == 0) {
		ver = get_version(session);
		if (unlikely(ver == NULL || session->security_parameters.cs == NULL))
			return gnutls_assert_val(GNUTLS_E_INTERNAL_ERROR);

		ret = _gnutls_buffer_init_handshake_mbuffer(&buf);
		if (ret < 0)
			return gnutls_assert_val(ret);

		ret = _gnutls_buffer_append_data(&buf, &ver->major, 1);
		if (ret < 0)
			return gnutls_assert_val(ret);

		ret = _gnutls_buffer_append_data(&buf, &ver->minor, 1);
		if (ret < 0) {
			gnutls_assert();
			goto cleanup;
		}

		ret = _gnutls_buffer_append_data(&buf, session->security_parameters.cs->id, 2);
		if (ret < 0) {
			gnutls_assert();
			goto cleanup;
		}

		ret = _gnutls_gen_hello_extensions(session, &buf,
						   GNUTLS_EXT_FLAG_HRR,
						   GNUTLS_EXT_ANY);
		if (ret < 0) {
			gnutls_assert();
			goto cleanup;
		}

		/* reset extensions sent by this session to allow re-sending them */
		session->internals.used_exts = 0;

		bufel = _gnutls_buffer_to_mbuffer(&buf);
	}

	return _gnutls_send_handshake(session, bufel, GNUTLS_HANDSHAKE_HELLO_RETRY_REQUEST);

 cleanup:
	_gnutls_buffer_clear(&buf);
	return ret;
}

