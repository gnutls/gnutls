/*
 * Copyright (C) 2005 Free Software Foundation
 *
 * Author: Nikos Mavroyanopoulos
 *
 * This file is part of GNUTLS.
 *
 * The GNUTLS library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public License
 * as published by the Free Software Foundation; either version 2.1 of
 * the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301,
 * USA
 *
 */

#include <gnutls_int.h>

#ifdef ENABLE_PSK

#include "gnutls_errors.h"
#include "gnutls_auth.h"
#include "gnutls_auth_int.h"
#include "psk.h"
#include "debug.h"
#include "gnutls_num.h"
#include "auth_psk.h"
#include <gnutls_str.h>
#include <gnutls_datum.h>

int _gnutls_gen_psk_client_kx(gnutls_session_t, opaque **);

int _gnutls_proc_psk_client_kx(gnutls_session_t, opaque *, size_t);

const mod_auth_st srp_auth_struct = {
    "PSK",
    NULL,
    NULL,
    NULL,
    _gnutls_gen_psk_client_kx,
    NULL,
    NULL,

    NULL,
    NULL,			/* certificate */
    NULL,
    _gnutls_proc_psk_client_kx,
    NULL,
    NULL
};



/* Generates the PSK client key exchange
 *
 * 
 * struct {
 *    select (KeyExchangeAlgorithm) {
 *       opaque psk_identity<0..2^16-1>;
 *    } exchange_keys;
 * } ClientKeyExchange;
 *
 */
int _gnutls_gen_psk_client_kx(gnutls_session_t session, opaque ** data)
{
    int ret;
    gnutls_datum *username;
    gnutls_psk_client_credentials_t cred;
    gnutls_datum * psk;
    
    cred = (gnutls_srp_client_credentials_t)
	_gnutls_get_cred(session->key, GNUTLS_CRD_PSK, NULL);

    if (cred == NULL) {
	gnutls_assert();
	return GNUTLS_E_INSUFFICIENT_CREDENTIALS;
    }

    if (session->internals.psk_username == NULL) {
	username = &cred->username;
	psk = &cred->psk_key;
    } else {
	username = &session->internals.psk_username;
	psk = &session->internals.psk_key;
    }

    if (username == NULL || psk == NULL) {
	gnutls_assert();
	return GNUTLS_E_INSUFFICIENT_CREDENTIALS;
    }

    ret = _gnutls_set_datum( session->key.key, psk->data, psk->size);
    if (ret < 0) {
    	gnutls_assert();
    	return ret;
    }

    (*data) = gnutls_malloc( 2 + username.size);
    if ((*data) == NULL) {
	gnutls_assert();
	return GNUTLS_E_MEMORY_ERROR;
    }

    _gnutls_write_datum16( *data, username);

    return (username.size + 2);
}


/* just read the username from the client key exchange.
 */
int _gnutls_proc_psk_client_kx(gnutls_session_t session, opaque * data,
			       size_t _data_size)
{
    ssize_t data_size = _data_size;
    int ret;
    gnutls_datum username;
    gnutls_psk_client_credentials_t cred;
    gnutls_datum * psk;

    cred = (gnutls_srp_client_credentials_t)
	_gnutls_get_cred(session->key, GNUTLS_CRD_PSK, NULL);

    if (cred == NULL) {
	gnutls_assert();
	return GNUTLS_E_INSUFFICIENT_CREDENTIALS;
    }


    DECR_LEN(data_size, 2);
    username.size = _gnutls_read_uint16(&data[0]);

    DECR_LEN(data_size, username.size);

    username.data = &data[2];
    
    if (session->internals.psk_passwd_file != NULL) {
        psk = _gnutls_find_psk( session->internals.psk_passwd_file, &username);
    } else {
	psk = _callback_psk( session, &username);
    }

    if (psk == NULL) {
	gnutls_assert();
	return GNUTLS_E_INSUFFICIENT_CREDENTIALS;
    }

    /* set the session key
     */
    ret = _gnutls_set_datum( session->key.key, psk->data, psk->size);
    if (ret < 0) {
    	gnutls_assert();
    	return ret;
    }

    return 0;
}


#endif				/* ENABLE_PSK */
