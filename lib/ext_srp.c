/*
 *      Copyright (C) 2001 Nikos Mavroyanopoulos
 *
 * This file is part of GNUTLS.
 *
 * GNUTLS is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * GNUTLS is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA
 */

#include <defines.h>
#include "gnutls_int.h"
#include "gnutls_auth_int.h"
#include "auth_srp.h"

int _gnutls_srp_recv_params( GNUTLS_STATE state, const opaque* data, int data_size) {
	if (state->security_parameters.entity == GNUTLS_SERVER) {
		if (data_size > 0) {
			state->gnutls_key->username = gnutls_malloc(data_size+1);
			memcpy(state->gnutls_key->username, data, data_size);
			state->gnutls_key->username[data_size]=0; /* null terminated */
		}
	}
	return 0;
}

/* returns data_size or a negative number on failure
 * data is allocated localy
 */
int _gnutls_srp_send_params( GNUTLS_STATE state, opaque** data) {
	/* this function sends the client extension data (username) */
	if (state->security_parameters.entity == GNUTLS_CLIENT) {
		SRP_CLIENT_CREDENTIALS* cred = _gnutls_get_kx_cred( state->gnutls_key, GNUTLS_KX_SRP);

		(*data) = NULL;

		if (cred==NULL) return 0;

		if (cred->username!=NULL) { /* send username */
			(*data) = strdup( cred->username);
			return strlen( cred->username);
		}
	}
	return 0;
}
