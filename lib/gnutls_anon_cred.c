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
#include "gnutls_errors.h"
#include "gnutls_dh.h"
#include "auth_anon.h"
#include "gnutls_num.h"
#include "gnutls_gcry.h"

static int anon_tmp;

/**
  * gnutls_anon_free_server_sc - Used to free an allocated GNUTLS_ANON_SERVER_CREDENTIALS structure
  * @sc: is an &GNUTLS_ANON_SERVER_CREDENTIALS structure.
  *
  * This structure is complex enough to manipulate directly thus
  * this helper function is provided in order to free (deallocate)
  * the structure.
  **/
void gnutls_anon_free_server_sc( GNUTLS_ANON_SERVER_CREDENTIALS sc) {
	return;
}

/**
  * gnutls_anon_allocate_server_sc - Used to allocate an GNUTLS_ANON_SERVER CREDENTIALS structure
  * @sc: is a pointer to an &GNUTLS_ANON_SERVER_CREDENTIALS structure.
  *
  * This structure is complex enough to manipulate directly thus
  * this helper function is provided in order to allocate
  * the structure.
  **/
int gnutls_anon_allocate_server_sc( GNUTLS_ANON_SERVER_CREDENTIALS *sc) {
	*sc = &anon_tmp;
	return 0;
}


/**
  * gnutls_anon_free_client_sc - Used to free an allocated GNUTLS_ANON_CLIENT_CREDENTIALS structure
  * @sc: is an &GNUTLS_ANON_CLIENT_CREDENTIALS structure.
  *
  * This structure is complex enough to manipulate directly thus
  * this helper function is provided in order to free (deallocate)
  * the structure.
  **/
void gnutls_anon_free_client_sc( GNUTLS_ANON_CLIENT_CREDENTIALS sc) {
	return;
}


/**
  * gnutls_allocate_anon_client_sc - Used to allocate an GNUTLS_ANON_CLIENT CREDENTIALS structure
  * @sc: is a pointer to an &GNUTLS_ANON_CLIENT_CREDENTIALS structure.
  *
  * This structure is complex enough to manipulate directly thus
  * this helper function is provided in order to allocate
  * the structure.
  **/
int gnutls_anon_allocate_client_sc( GNUTLS_ANON_CLIENT_CREDENTIALS *sc) {
	/* anon_tmp is only there for *sc not to be null.
	 * it is not used at all;
	 */
	*sc = (void*) &anon_tmp;
	
	return 0;
}
