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

#include "gnutls_int.h"
#include "gnutls_auth_int.h"
#include "auth_srp.h"
#include "gnutls_errors.h"
#include "gnutls_algorithms.h"

int _gnutls_srp_recv_params( GNUTLS_STATE state, const opaque* data, int data_size) {
	uint8 len;

	if (_gnutls_kx_priority( state, GNUTLS_KX_SRP) < 0) {
		/* algorithm was not allowed in this state
		 */
		gnutls_assert();
		return 0;
	}
	
	if (state->security_parameters.entity == GNUTLS_SERVER) {
		if (data_size > 0) {
			state->gnutls_key->auth_info = gnutls_calloc(1, sizeof(SRP_SERVER_AUTH_INFO));
			if (state->gnutls_key->auth_info==NULL) return GNUTLS_E_MEMORY_ERROR;
			
			if (sizeof( ((SRP_SERVER_AUTH_INFO)state->gnutls_key->auth_info)->username) > data_size) {
				len = data[0];
				if (len > data_size) {
					gnutls_assert();
					return GNUTLS_E_UNEXPECTED_PACKET_LENGTH;
				}
				memcpy( ((SRP_SERVER_AUTH_INFO)state->gnutls_key->auth_info)->username, &data[1], len);
				((SRP_SERVER_AUTH_INFO)state->gnutls_key->auth_info)->username[len]=0; /* null terminated */
				state->gnutls_key->auth_info_size = sizeof(SRP_SERVER_AUTH_INFO_INT);
			} else {
				state->gnutls_key->auth_info_size = 0;
				gnutls_free(state->gnutls_key->auth_info);
				state->gnutls_key->auth_info = NULL;
				gnutls_assert();
				return GNUTLS_E_MEMORY_ERROR;
			}
		}
	} else { /* client side reading server hello extensions */
		if (state->gnutls_internals.resumed==RESUME_FALSE)
			return proc_srp_server_hello( state, data, data_size);
		else /* we do not need to process this if
		      * we are resuming.
		      */
			return 0;
	}
	return 0;
}

/* returns data_size or a negative number on failure
 * data is allocated localy
 */
int _gnutls_srp_send_params( GNUTLS_STATE state, opaque** data) {
	uint8 len;
	/* this function sends the client extension data (username) */
	if (state->security_parameters.entity == GNUTLS_CLIENT) {
		const SRP_CLIENT_CREDENTIALS cred = _gnutls_get_cred( state->gnutls_key, GNUTLS_SRP, NULL);

		(*data) = NULL;

		if (cred==NULL) return 0;

		if (cred->username!=NULL) { /* send username */
			len = strlen(cred->username);
			(*data) = gnutls_malloc(len+1); /* hold the size also */
			(*data)[0] = len;
			memcpy( &(*data)[1], cred->username, len);
			return len + 1;
		}
	} else { /* SERVER SIDE sending (g,n,s) */
		/* We only send the packet if we are NOT
		 * resuming AND we are using SRP
		 */
		if (state->security_parameters.kx_algorithm!=GNUTLS_KX_SRP)
			return 0; /* no data to send */
		
		if (state->gnutls_internals.resumed==RESUME_FALSE)
			return gen_srp_server_hello( state, data);
		else
			return 0;
	}
	return 0;
}
