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
#include "auth_x509.h"
#include "gnutls_errors.h"

int _gnutls_dnsname_recv_params( GNUTLS_STATE state, const opaque* data, int data_size) {
	uint8 len;
	if (state->security_parameters.entity == GNUTLS_SERVER) {
		if (data_size > 0) {
			state->gnutls_key->auth_info = gnutls_calloc(1, sizeof(X509PKI_AUTH_INFO));
			if (state->gnutls_key->auth_info==NULL) return GNUTLS_E_MEMORY_ERROR;
			
			if (sizeof( ((X509PKI_AUTH_INFO*)state->gnutls_key->auth_info)->dnsname) > data_size) {
				len = data[0];
				if (len > data_size) {
					gnutls_assert();
					return GNUTLS_E_UNEXPECTED_PACKET_LENGTH;
				}
				memcpy( ((X509PKI_AUTH_INFO*)state->gnutls_key->auth_info)->dnsname, &data[1], len);
				((X509PKI_AUTH_INFO*)state->gnutls_key->auth_info)->dnsname[len]=0; /* null terminated */
				state->gnutls_key->auth_info_size = sizeof(X509PKI_AUTH_INFO);
			} else {
				state->gnutls_key->auth_info_size = 0;
				gnutls_free(state->gnutls_key->auth_info);
				state->gnutls_key->auth_info = NULL;
				gnutls_assert();
				return GNUTLS_E_MEMORY_ERROR;
			}
		}
	}
	return 0;
}

/* returns data_size or a negative number on failure
 * data is allocated localy
 */
int _gnutls_dnsname_send_params( GNUTLS_STATE state, opaque** data) {
	uint8 len;
	/* this function sends the client extension data (dnsname) */
	if (state->security_parameters.entity == GNUTLS_CLIENT) {
		const X509PKI_CLIENT_CREDENTIALS* cred = _gnutls_get_cred( state->gnutls_key, GNUTLS_X509PKI, NULL);

		(*data) = NULL;

		if (cred==NULL) return 0;

		if (cred->dnsname!=NULL) { /* send dnsname */
			len = strlen(cred->dnsname);
			(*data) = gnutls_malloc(len+1); /* hold the size also */
			(*data)[0] = len;
			memcpy( &(*data)[1], cred->dnsname, len);
			return len + 1;
		}
	}
	return 0;
}
