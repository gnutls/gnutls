/*
 *      Copyright (C) 2001,2002 Nikos Mavroyanopoulos
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
#include <gnutls_errors.h>
#include <libtasn1.h>
#include <gnutls_dh.h>

typedef void (*LOG_FUNC)( const char*);
#define GNUTLS_LOG_FUNC LOG_FUNC

/* created by asn1c */
extern const ASN1_ARRAY_TYPE gnutls_asn1_tab[];
extern const ASN1_ARRAY_TYPE pkix_asn1_tab[];

LOG_FUNC _gnutls_log_func;

static ASN1_TYPE PKIX1_ASN;
static ASN1_TYPE GNUTLS_ASN;

ASN1_TYPE _gnutls_get_pkix(void) {
	return PKIX1_ASN;
}

ASN1_TYPE _gnutls_get_gnutls_asn(void) {
	return GNUTLS_ASN;
}


/**
  * gnutls_global_set_log_function - This function sets the logging function
  * @log_func: it's a log function
  *
  * This is the function were you set the logging function gnutls
  * is going to use. This function only accepts a character array.
  * Normaly you may not use this function since
  * it is only used for debugging reasons.
  * LOG_FUNC is of the form, 
  * void (*LOG_FUNC)( const char*);
  **/
void gnutls_global_set_log_function( GNUTLS_LOG_FUNC log_func) {
	_gnutls_log_func = log_func;
}


/* default logging function */
static void dlog( const char* str) {
#ifdef DEBUG
	fprintf( stderr, "%s", str);
#endif
}

extern ALLOC_FUNC gnutls_secure_malloc;
extern ALLOC_FUNC gnutls_malloc;
extern FREE_FUNC gnutls_free;
extern int (*_gnutls_is_secure_memory)(const void*);
extern REALLOC_FUNC gnutls_realloc;
extern char* (*gnutls_strdup)(const char*);
extern void* (*gnutls_calloc)(size_t, size_t);

int _gnutls_is_secure_mem_null( const void*);

/**
  * gnutls_global_set_mem_function - This function sets the memory allocation functions
  * @alloc_func: it's the default memory allocation function. Like malloc().
  * @secure_alloc_func: This is the memory allocation function that will be used for sensitive data.
  * @is_secure_func: a function that returns 0 if the memory given is not secure. May be NULL.
  * @realloc_func: A realloc function
  * @free_func: The function that frees allocated data.
  *
  * This is the function were you set the memory allocation functions gnutls
  * is going to use. By default the libc's allocation functions (malloc(), free()),
  * are used by gnutls, to allocate both sensitive and not sensitive data.
  * This function is provided to set the memory allocation functions to
  * something other than the defaults (ie the gcrypt allocation functions). 
  *
  * This function must be called before gnutls_global_init() is called.
  *
  **/
void gnutls_global_set_mem_function( 
	void *(*gnutls_alloc_func)(size_t), void* (*gnutls_secure_alloc_func)(size_t),
	int (*gnutls_is_secure_func)(const void*), void *(*gnutls_realloc_func)(void *, size_t),
	void (*gnutls_free_func)(void*))
{
	gnutls_secure_malloc = gnutls_secure_alloc_func;
	gnutls_malloc = gnutls_alloc_func;
	gnutls_realloc = gnutls_realloc_func;
	gnutls_free = gnutls_free_func;

	if (gnutls_is_secure_func==NULL)
		_gnutls_is_secure_memory = gnutls_is_secure_func;
	else
		_gnutls_is_secure_memory = _gnutls_is_secure_mem_null;

	/* if using the libc's default malloc
	 * then also use the libc's strdup.
	 */
	if ( gnutls_malloc == malloc) {
		gnutls_strdup = strdup;
		gnutls_calloc = calloc;
	} else { /* use the included ones */
		gnutls_strdup = _gnutls_strdup;
		gnutls_calloc = _gnutls_calloc;
	}
	return;
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
		gcry_control (GCRYCTL_SET_VERBOSITY, (int)0);
	}
	
	/* set default recv/send functions
	 */
	gnutls_global_set_log_function( dlog);

	/* initialize parser 
	 * This should not deal with files in the final
	 * version.
	 */
	
	result=asn1_array2tree( pkix_asn1_tab, &PKIX1_ASN, NULL);
	if (result != ASN1_SUCCESS) {
		return _gnutls_asn2err(result);
	}

	result=asn1_array2tree( gnutls_asn1_tab, &GNUTLS_ASN, NULL);
	if (result != ASN1_SUCCESS) {
		asn1_delete_structure(& PKIX1_ASN);
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
		asn1_delete_structure(& GNUTLS_ASN);
		asn1_delete_structure(& PKIX1_ASN);
	
		_gnutls_dh_clear_mpis();
	}
	
}


/* These functions should be elsewere. Kept here for 
 * historical reasons.
 */

/**
  * gnutls_transport_set_pull_function - This function sets a read like function
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
void gnutls_transport_set_pull_function( GNUTLS_STATE state, GNUTLS_PULL_FUNC pull_func) {
	state->gnutls_internals._gnutls_pull_func = pull_func;
}

/**
  * gnutls_transport_set_push_function - This function sets the function to send data
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
void gnutls_transport_set_push_function( GNUTLS_STATE state, GNUTLS_PUSH_FUNC push_func) {
	state->gnutls_internals._gnutls_push_func = push_func;
}
