/*
 * Copyright (C) 2001 Nikos Mavroyanopoulos
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

#include "gnutls_int.h"

#ifdef ENABLE_ANON

#include "gnutls_errors.h"
#include "auth_anon.h"
#include "gnutls_auth_int.h"
#include "gnutls_dh.h"
#include "gnutls_num.h"
#include "gnutls_mpi.h"

static const int anon_dummy;

/**
  * gnutls_anon_free_server_credentials - Used to free an allocated gnutls_anon_server_credentials_t structure
  * @sc: is an &gnutls_anon_server_credentials_t structure.
  *
  * This structure is complex enough to manipulate directly thus
  * this helper function is provided in order to free (deallocate) it.
  **/
void gnutls_anon_free_server_credentials(gnutls_anon_server_credentials_t sc)
{

    gnutls_free(sc);
}

/*-
  * _gnutls_anon_get_dh_params - Returns the DH parameters pointer
  * @sc: is an &gnutls_certificate_credentials_t structure.
  *
  * This function will return the dh parameters pointer.
  *
  -*/
gnutls_dh_params_t _gnutls_anon_get_dh_params(const
					    gnutls_anon_server_credentials_t
					    sc, gnutls_session_t session)
{
    gnutls_params_st params;
    int ret;

    if (session->internals.params.anon_dh_params)
	return session->internals.params.anon_dh_params;

    if (sc->dh_params) {
	session->internals.params.anon_dh_params = sc->dh_params;
    } else if (sc->params_func) {
	ret = sc->params_func(session, GNUTLS_PARAMS_DH, &params);
	if (ret == 0 && params.type == GNUTLS_PARAMS_DH) {
	    session->internals.params.anon_dh_params = params.params.dh;
	    session->internals.params.free_anon_dh_params = params.deinit;
	}
    }

    return session->internals.params.anon_dh_params;
}

/**
  * gnutls_anon_allocate_server_credentials - Used to allocate an gnutls_anon_server_credentials_t structure
  * @sc: is a pointer to an &gnutls_anon_server_credentials_t structure.
  *
  * This structure is complex enough to manipulate directly thus
  * this helper function is provided in order to allocate it.
  **/
int gnutls_anon_allocate_server_credentials(gnutls_anon_server_credentials_t
					    * sc)
{

    *sc = gnutls_calloc(1, sizeof(anon_server_credentials_st));

    return 0;
}


/**
  * gnutls_anon_free_client_credentials - Used to free an allocated gnutls_anon_client_credentials_t structure
  * @sc: is an &gnutls_anon_client_credentials_t structure.
  *
  * This structure is complex enough to manipulate directly thus
  * this helper function is provided in order to free (deallocate) it.
  **/
void gnutls_anon_free_client_credentials(gnutls_anon_client_credentials_t sc)
{
}

/**
  * gnutls_allocate_anon_client_credentials - Used to allocate a credentials structure
  * @sc: is a pointer to an &gnutls_anon_client_credentials_t structure.
  *
  * This structure is complex enough to manipulate directly thus
  * this helper function is provided in order to allocate it.
  **/
int gnutls_anon_allocate_client_credentials(gnutls_anon_client_credentials_t
					    * sc)
{
    /* anon_dummy is only there for *sc not to be null.
     * it is not used at all;
     */
    *sc = (void *) &anon_dummy;

    return 0;
}

#endif
