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

/**
  * gnutls_free_anon_server_sc - Used to free an allocated ANON_SERVER_CREDENTIALS structure
  * @sc: is an &ANON_SERVER_CREDENTIALS structure.
  *
  * This structure is complex enough to manipulate directly thus
  * this helper function is provided in order to free (deallocate)
  * the structure.
  **/
void gnutls_free_anon_server_sc( ANON_SERVER_CREDENTIALS* sc) {
	gnutls_free(sc);
}

/**
  * gnutls_allocate_anon_server_sc - Used to allocate an ANON_SERVER CREDENTIALS structure
  * @sc: is a pointer to an &ANON_SERVER_CREDENTIALS structure.
  *
  * This structure is complex enough to manipulate directly thus
  * this helper function is provided in order to allocate
  * the structure.
  **/
int gnutls_allocate_anon_server_sc( ANON_SERVER_CREDENTIALS **sc) {
	*sc = gnutls_malloc(sizeof( ANON_SERVER_CREDENTIALS));
	
	if (*sc==NULL) return GNUTLS_E_MEMORY_ERROR;
	return 0;
}

/**
  * gnutls_set_anon_server_cred - Used to set the number of bits to use in DH, in a ANON_SERVER_CREDENTIALS structure
  * @res: is an &ANON_SERVER_CREDENTIALS structure.
  * @dh_bits: is the number of bits in DH key exchange
  *
  **/

int gnutls_set_anon_server_cred( ANON_SERVER_CREDENTIALS* res, int dh_bits) {
	res->dh_bits = dh_bits;
	return 0;
}

