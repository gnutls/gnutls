/*
 * Copyright (C) 2001,2002,2003 Nikos Mavroyanopoulos
 * Copyright (C) 2004 Free Software Foundation
 *
 * This file is part of GNUTLS.
 *
 *  The GNUTLS library is free software; you can redistribute it and/or
 *  modify it under the terms of the GNU Lesser General Public   
 *  License as published by the Free Software Foundation; either 
 *  version 2.1 of the License, or (at your option) any later version.
 *
 *  This library is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of 
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 *  Lesser General Public License for more details.
 *
 *  You should have received a copy of the GNU Lesser General Public
 *  License along with this library; if not, write to the Free Software
 *  Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA 02111-1307  USA
 *
 */

#include <gnutls_int.h>
#include <ext_srp.h>

#ifdef ENABLE_SRP

#include "gnutls_auth_int.h"
#include "auth_srp.h"
#include "gnutls_errors.h"
#include "gnutls_algorithms.h"
#include <gnutls_num.h>

int _gnutls_srp_recv_params(gnutls_session_t session, const opaque * data,
			    size_t _data_size)
{
    uint8 len;
    ssize_t data_size = _data_size;

    if (_gnutls_kx_priority(session, GNUTLS_KX_SRP) < 0 &&
	_gnutls_kx_priority(session, GNUTLS_KX_SRP_DSS) < 0 &&
	_gnutls_kx_priority(session, GNUTLS_KX_SRP_RSA) < 0) {
	/* algorithm was not allowed in this session
	 */
	return 0;
    }

    if (session->security_parameters.entity == GNUTLS_SERVER) {
	if (data_size > 0) {
	    len = data[0];
	    DECR_LEN(data_size, len);

	    if (sizeof
		(session->security_parameters.extensions.srp_username) <=
		len) {
		gnutls_assert();
		return GNUTLS_E_ILLEGAL_SRP_USERNAME;
	    }
	    memcpy(session->security_parameters.extensions.srp_username,
		   &data[1], len);
	    session->security_parameters.extensions.srp_username[len] = 0;	/* null terminated */
	}
    }
    return 0;
}

/* Checks if the given cipher suite is an SRP one
 */
inline static int is_srp(cipher_suite_st suite)
{
    int kx = _gnutls_cipher_suite_get_kx_algo(&suite);

    if (IS_SRP_KX(kx))
	return 1;
    return 0;
}

/* returns data_size or a negative number on failure
 * data is allocated locally
 */
int _gnutls_srp_send_params(gnutls_session_t session, opaque * data,
			    size_t data_size)
{
    uint len;

    if (_gnutls_kx_priority(session, GNUTLS_KX_SRP) < 0 &&
	_gnutls_kx_priority(session, GNUTLS_KX_SRP_DSS) < 0 &&
	_gnutls_kx_priority(session, GNUTLS_KX_SRP_RSA) < 0) {
	/* algorithm was not allowed in this session
	 */
	return 0;
    }

    /* this function sends the client extension data (username) */
    if (session->security_parameters.entity == GNUTLS_CLIENT) {
	const gnutls_srp_client_credentials_t cred =
	    _gnutls_get_cred(session->key, GNUTLS_CRD_SRP, NULL);

	if (cred == NULL)
	    return 0;

	if (cred->username != NULL) {	/* send username */
	    len = GMIN(strlen(cred->username), 255);

	    if (data_size < len + 1) {
		gnutls_assert();
		return GNUTLS_E_SHORT_MEMORY_BUFFER;
	    }

	    data[0] = (uint8) len;
	    memcpy(&data[1], cred->username, len);
	    return len + 1;
	} else if (cred->get_function != NULL) {
	    /* Try the callback
	     */
	    char *username = NULL, *password = NULL;

	    if (cred->
		get_function(session,
			     session->internals.handshake_restarted,
			     &username, &password) < 0 || username == NULL
		|| password == NULL) {

		if (session->internals.handshake_restarted) {
		    gnutls_assert();
		    return GNUTLS_E_ILLEGAL_SRP_USERNAME;
		}

		return 0;
	    }

	    len = GMIN(strlen(username), 255);

	    if (data_size < len + 1) {
		gnutls_free(username);
		gnutls_free(password);
		gnutls_assert();
		return GNUTLS_E_SHORT_MEMORY_BUFFER;
	    }

	    session->internals.srp_username = username;
	    session->internals.srp_password = password;

	    data[0] = (uint8) len;
	    memcpy(&data[1], username, len);
	    return len + 1;
	}
    }
    return 0;
}

#endif				/* ENABLE_SRP */
