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
#include "auth_x509.h"
#include "gnutls_errors.h"
#include "gnutls_num.h"

int _gnutls_dnsname_recv_params( GNUTLS_STATE state, const opaque* data, int data_size) {
	uint16 len;
	if (state->security_parameters.entity == GNUTLS_SERVER) {
		if (data_size > 0) {
			if (sizeof( state->security_parameters.extensions.dnsname) > data_size) {
				len = READuint16( data);
				if (len > data_size || len >= MAX_DNSNAME_SIZE) {
					gnutls_assert();
					return GNUTLS_E_UNEXPECTED_PACKET_LENGTH;
				}
				/* note that dnsname is in UTF-8
				 * format.
				 */
				memcpy( state->security_parameters.extensions.dnsname, &data[2], len);
				state->security_parameters.extensions.dnsname[len]=0; /* null terminated */
			}
		}
	}
	return 0;
}

/* returns data_size or a negative number on failure
 * data is allocated localy
 */
int _gnutls_dnsname_send_params( GNUTLS_STATE state, opaque** data) {
	uint16 len;
	/* this function sends the client extension data (dnsname) */
	if (state->security_parameters.entity == GNUTLS_CLIENT) {

		if ( (len = strlen(state->security_parameters.extensions.dnsname)) > 0) { /* send dnsname */
			(*data) = gnutls_malloc(len+2); /* hold the size also */
			WRITEuint16( len, *data);
			memcpy( &(*data)[2], state->security_parameters.extensions.dnsname, len);
			return len + 2;
		}
	}
	return 0;
}
