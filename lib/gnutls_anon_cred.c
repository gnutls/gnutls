/*
 * Copyright (C) 2001 Nikos Mavroyanopoulos
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
#include "gnutls_errors.h"
#include "auth_anon.h"

#ifdef ENABLE_ANON

#include "gnutls_auth_int.h"
#include "gnutls_dh.h"
#include "gnutls_num.h"
#include "gnutls_mpi.h"

static int anon_tmp;

/**
  * gnutls_anon_free_server_credentials - Used to free an allocated gnutls_anon_server_credentials structure
  * @sc: is an &gnutls_anon_server_credentials structure.
  *
  * This structure is complex enough to manipulate directly thus
  * this helper function is provided in order to free (deallocate)
  * the structure.
  **/
void gnutls_anon_free_server_credentials( gnutls_anon_server_credentials sc) {

	gnutls_free( sc);
}

/**
  * gnutls_anon_allocate_server_credentials - Used to allocate an gnutls_anon_server_credentials structure
  * @sc: is a pointer to an &gnutls_anon_server_credentials structure.
  *
  * This structure is complex enough to manipulate directly thus
  * this helper function is provided in order to allocate
  * the structure.
  **/
int gnutls_anon_allocate_server_credentials( gnutls_anon_server_credentials *sc) {

	*sc = gnutls_calloc( 1, sizeof(ANON_SERVER_CREDENTIALS_INT));
	(*sc)->dh_params = &_gnutls_dh_default_params;

	return 0;
}


/**
  * gnutls_anon_free_client_credentials - Used to free an allocated gnutls_anon_client_credentials structure
  * @sc: is an &gnutls_anon_client_credentials structure.
  *
  * This structure is complex enough to manipulate directly thus
  * this helper function is provided in order to free (deallocate)
  * the structure.
  **/
void gnutls_anon_free_client_credentials( gnutls_anon_client_credentials sc) {
	return;
}

/**
  * gnutls_allocate_anon_client_credentials - Used to allocate an GNUTLS_ANON_CLIENT CREDENTIALS structure
  * @sc: is a pointer to an &gnutls_anon_client_credentials structure.
  *
  * This structure is complex enough to manipulate directly thus
  * this helper function is provided in order to allocate
  * the structure.
  **/
int gnutls_anon_allocate_client_credentials( gnutls_anon_client_credentials *sc) 
{
	/* anon_tmp is only there for *sc not to be null.
	 * it is not used at all;
	 */
	*sc = (void*) &anon_tmp;
	
	return 0;
}

#endif
