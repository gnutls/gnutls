/*
 * Copyright (C) 2001,2002 Nikos Mavroyanopoulos
 *
 * This file is part of GNUTLS.
 *
 * GNUTLS-EXTRA is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * GNUTLS-EXTRA is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA
 */

#include "gnutls_int.h"
#include <ext_srp.h>

#ifdef ENABLE_SRP

#include "gnutls_auth_int.h"
#include "auth_srp.h"
#include "gnutls_errors.h"
#include "gnutls_algorithms.h"

int _gnutls_srp_recv_params( gnutls_session state, const opaque* data, size_t _data_size) {
	uint8 len;
	ssize_t data_size = _data_size;

	if (_gnutls_kx_priority( state, GNUTLS_KX_SRP) < 0 && 
		_gnutls_kx_priority( state, GNUTLS_KX_SRP_DSS) < 0 && 
		_gnutls_kx_priority( state, GNUTLS_KX_SRP_RSA) < 0) {
		/* algorithm was not allowed in this session
		 */
		return 0;
	}
	
	if (state->security_parameters.entity == GNUTLS_SERVER) {
		if (data_size > 0) {
			len = data[0];
			DECR_LEN( data_size, len);

			if ( sizeof( state->security_parameters.extensions.srp_username) <= len) {
				gnutls_assert();
				return GNUTLS_E_ILLEGAL_SRP_USERNAME;
			}
			memcpy( state->security_parameters.extensions.srp_username, &data[1], len);
			state->security_parameters.extensions.srp_username[len]=0; /* null terminated */
		}
	}
	return 0;
}

/* Checks if the given cipher suite is an SRP one
 */
inline static int is_srp( GNUTLS_CipherSuite suite) {
	int kx = _gnutls_cipher_suite_get_kx_algo( suite);
	
	if (kx == GNUTLS_KX_SRP || (kx == GNUTLS_KX_SRP_RSA) ||
	  kx == GNUTLS_KX_SRP_DSS) {
		return 1;
	}
	
	return 0;
}

/* returns data_size or a negative number on failure
 * data is allocated locally
 */
int _gnutls_srp_send_params( gnutls_session state, opaque* data, size_t data_size) {
	uint len;

	if (_gnutls_kx_priority( state, GNUTLS_KX_SRP) < 0 && 
		_gnutls_kx_priority( state, GNUTLS_KX_SRP_DSS) < 0 && 
		_gnutls_kx_priority( state, GNUTLS_KX_SRP_RSA) < 0) {
		/* algorithm was not allowed in this session
		 */
		return 0;
	}

	/* this function sends the client extension data (username) */
	if (state->security_parameters.entity == GNUTLS_CLIENT) {
		const gnutls_srp_client_credentials cred = _gnutls_get_cred( state->key, GNUTLS_CRD_SRP, NULL);

		if (cred==NULL) return 0;

		if (cred->username!=NULL) { /* send username */
			len = strlen(cred->username);
			
			if (len > 255) len = 255;

			if (data_size < len+1) {
				gnutls_assert();
				return GNUTLS_E_INVALID_REQUEST;
			}

			data[0] = (uint8) len;
			memcpy( &data[1], cred->username, len);
			return len + 1;
		}
	}
	return 0;
}

#endif /* ENABLE_SRP */
