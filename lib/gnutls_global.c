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
#include <gnutls_int.h>
#include <gnutls_errors.h>
#include <cert_asn1.h>
#include <signal.h>

static void* old_sig_handler;
ssize_t (*recv_func)( SOCKET, void*, size_t, int);
ssize_t (*send_func)( SOCKET,const void*, size_t, int);

int gnutls_is_secure_memory(const void* mem) {
	return 0;
}

/**
  * gnutls_global_init - This function initializes the global state to defaults.
  *
  * This function initializes the global state to defaults.
  * Every gnutls application has a global state which holds common parameters
  * shared by gnutls state structures.
  * You must call gnutls_global_deinit() when gnutls usage is no longer needed
  * Returns zero on success.
  **/
int gnutls_global_init(char* PKIX, char* PKCS1)
{
	int result;

	/* for gcrypt in order to be able to allocate memory */
	gcry_set_allocation_handler(gnutls_malloc, secure_malloc, gnutls_is_secure_memory, gnutls_realloc, free);

	/* we need this */
	old_sig_handler = signal( SIGPIPE, SIG_IGN);

	/* set default recv/send functions
	 */
	recv_func = recv;
	send_func = send;

	/* initialize parser 
	 * This should not deal with files in the final
	 * version.
	 */
	
	result = parser_asn1(PKIX);

	if (result != ASN_OK) {
		return GNUTLS_E_ASN1_PARSING_ERROR;
	}
	
	result = parser_asn1(PKCS1);

	if (result != ASN_OK) {
		return GNUTLS_E_PARSING_ERROR;
	}
	
	return 0;
}

/**
  * gnutls_global_deinit - This function deinitializes the global state 
  *
  * This function deinitializes the global state.
  **/

void gnutls_global_deinit() {

	/* restore signal handler  */
	signal( SIGPIPE, old_sig_handler);



}
