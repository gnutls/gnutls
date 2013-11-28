/*
 * Copyright (C) 2000-2012 Free Software Foundation, Inc.
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

#include <gnutls_int.h>
#include <gnutls_errors.h>
#include <gnutls_dh.h>

/*-
 * _gnutls_get_dh_params - Returns the DH parameters pointer
 * @dh_params: is an DH parameters structure, or NULL.
 * @func: is a callback function to receive the parameters or NULL.
 * @session: a gnutls session.
 *
 * This function will return the dh parameters pointer.
 -*/
gnutls_dh_params_t
_gnutls_get_dh_params(gnutls_dh_params_t dh_params,
		      gnutls_params_function * func,
		      gnutls_session_t session)
{
	gnutls_params_st params;
	int ret;

	/* if cached return the cached */
	if (session->internals.params.dh_params)
		return session->internals.params.dh_params;

	if (dh_params) {
		session->internals.params.dh_params = dh_params;
	} else if (func) {
		ret = func(session, GNUTLS_PARAMS_DH, &params);
		if (ret == 0 && params.type == GNUTLS_PARAMS_DH) {
			session->internals.params.dh_params =
			    params.params.dh;
			session->internals.params.free_dh_params =
			    params.deinit;
		}
	}

	return session->internals.params.dh_params;
}
