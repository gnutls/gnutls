/*
 *      Copyright (C) 2001,2002 Nikos Mavroyanopoulos
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

#include <gnutls_int.h>
#include <gnutls_errors.h>
#include <x509_asn1.h>
#include <gnutls_dh.h>


/* created by asn1c */
extern const static_asn gnutls_asn1_tab[];
extern const static_asn pkix_asn1_tab[];


typedef void (*LOG_FUNC)( const char*);
#define GNUTLS_LOG_FUNC LOG_FUNC

LOG_FUNC _gnutls_log_func;

static node_asn *PKIX1_ASN;
static node_asn *GNUTLS_ASN;

node_asn* _gnutls_get_pkix(void) {
	return PKIX1_ASN;
}

node_asn* _gnutls_get_gnutls_asn(void) {
	return GNUTLS_ASN;
}


/**
  * gnutls_global_set_log_func - This function sets the logging function
  * @log_func: it's a log function
  *
  * This is the function were you set the logging function gnutls
  * is going to use. This function only accepts a character array.
  * Normaly you may not use this function since
  * it is only used for debugging reasons.
  * LOG_FUNC is of the form, 
  * void (*LOG_FUNC)( const char*);
  **/
void gnutls_global_set_log_func( GNUTLS_LOG_FUNC log_func) {
	_gnutls_log_func = log_func;
}


/* default logging function */
static void dlog( const char* str) {
#ifdef DEBUG
	fprintf( stderr, "%s", str);
#endif
}

static int _gnutls_init = 0;

/**
  * gnutls_global_init - This function initializes the global state to defaults.
  *
  * This function initializes the global state to defaults.
  * Every gnutls application has a global state which holds common parameters
  * shared by gnutls state structures.
  * You must call gnutls_global_deinit() when gnutls usage is no longer needed
  * Returns zero on success.
  *
  * Note that this function will also initialize libgcrypt, if it has not
  * been initialized before. Thus if you want to manualy initialize libgcrypt
  * you must do it before calling this function. (useful in cases you want
  * to disable internal lockings etc.)
  *
  **/
int gnutls_global_init( void)
{
	int result;

	_gnutls_init++;

	if (_gnutls_init!=1) {
		return 0;
	}
	
	if (gcry_control( GCRYCTL_ANY_INITIALIZATION_P) == 0) {
		/* for gcrypt in order to be able to allocate memory */
		gcry_set_allocation_handler(gnutls_malloc, gnutls_secure_malloc, _gnutls_is_secure_memory, gnutls_realloc, gnutls_free);
		
		/* gcry_control (GCRYCTL_DISABLE_INTERNAL_LOCKING, NULL, 0); */

		gcry_control (GCRYCTL_INITIALIZATION_FINISHED, NULL,0);
	}
	
	/* set default recv/send functions
	 */
	gnutls_global_set_log_func( dlog);

	/* initialize parser 
	 * This should not deal with files in the final
	 * version.
	 */
	
	result=asn1_create_tree( (void*)pkix_asn1_tab, &PKIX1_ASN);
	if (result != ASN_OK) {
		return _gnutls_asn2err(result);
	}

	result=asn1_create_tree( (void*)gnutls_asn1_tab, &GNUTLS_ASN);
	if (result != ASN_OK) {
		asn1_delete_structure( PKIX1_ASN);
		return _gnutls_asn2err(result);
	}

	result = _gnutls_dh_calc_mpis();
	if (result < 0) {
		gnutls_assert();
		return result;
	}
	
	return 0;
}

/**
  * gnutls_global_deinit - This function deinitializes the global state 
  *
  * This function deinitializes the global state.
  *
  **/

void gnutls_global_deinit( void) {

	_gnutls_init--;

	if (_gnutls_init==0) {
		asn1_delete_structure( GNUTLS_ASN);
		asn1_delete_structure( PKIX1_ASN);
	
		_gnutls_dh_clear_mpis();
	}
	
}


/* These functions should be elsewere. Kept here for 
 * historical reasons.
 */

/**
  * gnutls_transport_set_pull_func - This function sets a read like function
  * @pull_func: it's a function like read
  * @state: gnutls state
  *
  * This is the function where you set a function for gnutls 
  * to receive data. Normaly, if you use berkeley style sockets,
  * you may not use this function since the default (recv(2)) will 
  * probably be ok.
  * This function should be called once and after gnutls_global_init().
  * PULL_FUNC is of the form, 
  * ssize_t (*GNUTLS_PULL_FUNC)(GNUTLS_TRANSPORT_PTR, const void*, size_t);
  **/
void gnutls_transport_set_pull_func( GNUTLS_STATE state, GNUTLS_PULL_FUNC pull_func) {
	state->gnutls_internals._gnutls_pull_func = pull_func;
}

/**
  * gnutls_transport_set_push_func - This function sets the function to send data
  * @push_func: it's a function like write
  * @state: gnutls state
  *
  * This is the function where you set a push function for gnutls
  * to use in order to send data. If you are going to use berkeley style
  * sockets, you may not use this function since
  * the default (send(2)) will probably be ok. Otherwise you should
  * specify this function for gnutls to be able to send data.
  *  
  * This function should be called once and after gnutls_global_init().
  * PUSH_FUNC is of the form, 
  * ssize_t (*GNUTLS_PUSH_FUNC)(GNUTLS_TRANSPORT_PTR, const void*, size_t);
  **/
void gnutls_transport_set_push_func( GNUTLS_STATE state, GNUTLS_PUSH_FUNC push_func) {
	state->gnutls_internals._gnutls_push_func = push_func;
}
