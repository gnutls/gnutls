/*
 * Copyright (C) 2001,2002 Nikos Mavroyanopoulos
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
	fputs( str, stderr);
#endif
}

extern gnutls_alloc_function gnutls_secure_malloc;
extern gnutls_alloc_function gnutls_malloc;
extern gnutls_free_function gnutls_free;
extern int (*_gnutls_is_secure_memory)(const void*);
extern gnutls_realloc_function gnutls_realloc;
extern char* (*gnutls_strdup)(const char*);
extern void* (*gnutls_calloc)(size_t, size_t);

int _gnutls_is_secure_mem_null( const void*);

/**
  * gnutls_global_set_mem_functions - This function sets the memory allocation functions
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
void gnutls_global_set_mem_functions( 
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

#ifdef DEBUG
static void _gnutls_gcry_log_handler( void* dummy, int level, const char* fmt, 
	va_list list)
{
	_gnutls_log( fmt, list);
}
#endif

static int _gnutls_init = 0;

/**
  * gnutls_global_init - This function initializes the global data to defaults.
  *
  * This function initializes the global data to defaults.
  * Every gnutls application has a global data which holds common parameters
  * shared by gnutls session structures.
  * You must call gnutls_global_deinit() when gnutls usage is no longer needed
  * Returns zero on success.
  *
  * Note that this function will also initialize libgcrypt, if it has not
  * been initialized before. Thus if you want to manualy initialize libgcrypt
  * you must do it before calling this function. This is useful in cases you 
  * want to disable libgcrypt's internal lockings etc.
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

#ifdef DEBUG
		gcry_set_log_handler( _gnutls_gcry_log_handler, NULL);
#else
		gcry_control (GCRYCTL_SET_VERBOSITY, (int)0);
#endif
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
  * gnutls_global_deinit - This function deinitializes the global data 
  *
  * This function deinitializes the global data, that were initialized
  * using gnutls_global_init().
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
  * @session: gnutls session
  *
  * This is the function where you set a function for gnutls 
  * to receive data. Normaly, if you use berkeley style sockets,
  * you may not use this function since the default (recv(2)) will 
  * probably be ok.
  * This function should be called once and after gnutls_global_init().
  * PULL_FUNC is of the form, 
  * ssize_t (*gnutls_pull_func)(gnutls_transport_ptr, const void*, size_t);
  **/
void gnutls_transport_set_pull_function( gnutls_session session, gnutls_pull_func pull_func) {
	session->internals._gnutls_pull_func = pull_func;
}

/**
  * gnutls_transport_set_push_function - This function sets the function to send data
  * @push_func: it's a function like write
  * @session: gnutls session
  *
  * This is the function where you set a push function for gnutls
  * to use in order to send data. If you are going to use berkeley style
  * sockets, you may not use this function since
  * the default (send(2)) will probably be ok. Otherwise you should
  * specify this function for gnutls to be able to send data.
  *  
  * This function should be called once and after gnutls_global_init().
  * PUSH_FUNC is of the form, 
  * ssize_t (*gnutls_push_func)(gnutls_transport_ptr, const void*, size_t);
  **/
void gnutls_transport_set_push_function( gnutls_session session, gnutls_push_func push_func) {
	session->internals._gnutls_push_func = push_func;
}


/* Taken from libgcrypt. Needed to configure scripts.
 */

static const char*
parse_version_number( const char *s, int *number )
{
    int val = 0;

    if( *s == '0' && isdigit(s[1]) )
	return NULL; /* leading zeros are not allowed */
    for ( ; isdigit(*s); s++ ) {
	val *= 10;
	val += *s - '0';
    }
    *number = val;
    return val < 0? NULL : s;
}

/* The parse version functions were copied from libgcrypt.
 */
static const char *
parse_version_string( const char *s, int *major, int *minor, int *micro )
{
    s = parse_version_number( s, major );
    if( !s || *s != '.' )
	return NULL;
    s++;
    s = parse_version_number( s, minor );
    if( !s || *s != '.' )
	return NULL;
    s++;
    s = parse_version_number( s, micro );
    if( !s )
	return NULL;
    return s; /* patchlevel */
}

/**
  * gnutls_check_version - This function checks the library's version
  * @req_version: the version to check
  *
  * Check that the the version of the library is at minimum the requested one
  * and return the version string; return NULL if the condition is not
  * satisfied.  If a NULL is passed to this function, no check is done,
  * but the version string is simply returned.
  *
  **/
const char *
gnutls_check_version( const char *req_version )
{
    const char *ver = GNUTLS_VERSION;
    int my_major, my_minor, my_micro;
    int rq_major, rq_minor, rq_micro;
    const char *my_plvl, *rq_plvl;

    if ( !req_version )
	return ver;

    my_plvl = parse_version_string( ver, &my_major, &my_minor, &my_micro );
    if ( !my_plvl )
	return NULL;  /* very strange our own version is bogus */
    rq_plvl = parse_version_string( req_version, &rq_major, &rq_minor,
								&rq_micro );
    if ( !rq_plvl )
	return NULL;  /* req version string is invalid */

    if ( my_major > rq_major
	|| (my_major == rq_major && my_minor > rq_minor)
	|| (my_major == rq_major && my_minor == rq_minor
				 && my_micro > rq_micro)
	|| (my_major == rq_major && my_minor == rq_minor
				 && my_micro == rq_micro
				 && strcmp( my_plvl, rq_plvl ) >= 0) ) {
	return ver;
    }
    return NULL;
}

/**
  * gnutls_global_get_malloc_function - Returns a malloc() like function
  * @session: is a &gnutls_session structure.
  *
  * This function will return a malloc() compatible function to be
  * used by callbacks. The returned function is the one set by
  * gnutls_global_set_mem_functions().
  *
  **/
gnutls_alloc_function gnutls_global_get_malloc_function(void)
{
	return gnutls_malloc;
}

/**
  * gnutls_global_get_free_function - Returns a free() like function
  * @session: is a &gnutls_session structure.
  *
  * This function will return a free() compatible function to be
  * used by callbacks. The returned function is the one set by
  * gnutls_global_set_mem_functions().
  *
  **/
gnutls_free_function gnutls_global_get_free_function(void)
{
	return gnutls_free;
}

