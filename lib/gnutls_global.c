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

#include <gnutls_int.h>
#include <gnutls_errors.h>
#include <x509_asn1.h>
#ifdef HAVE_SIGNAL_H
# include <signal.h>
#endif

/* created by asn1c */
extern const static_asn pkcs1_asn1_tab[];
extern const static_asn pkix_asn1_tab[];

static void* old_sig_handler;

typedef ssize_t (*RECV_FUNC)(SOCKET, void*, size_t,int);
typedef ssize_t (*SEND_FUNC)(SOCKET, const void*, size_t,int);
typedef void (*LOG_FUNC)( const char*);

RECV_FUNC _gnutls_recv_func;
SEND_FUNC _gnutls_send_func;
LOG_FUNC _gnutls_log_func;

static node_asn *PKIX1_ASN;
static node_asn *PKCS1_ASN;

node_asn* _gnutls_get_pkix() {
	return PKIX1_ASN;
}

node_asn* _gnutls_get_pkcs() {
	return PKCS1_ASN;
}

/**
  * gnutls_global_set_recv_func - This function sets the recv() function
  * @recv_func: it's a recv(2) like function
  *
  * This is the function were you set the recv() function gnutls
  * is going to use. Normaly you may not use this function since
  * the default (recv(2)) will probably be ok, unless you use
  * some external library (like gnu pthreads), which provide
  * a front end to this function. This function should be
  * called once and after gnutls_global_init().
  *
  * RECV_FUNC is of the form:
  * ssize_t (*RECV_FUNC)(SOCKET, void*, size_t,int);
  **/
void gnutls_global_set_recv_func( RECV_FUNC recv_func) {
	_gnutls_recv_func = recv_func;
}

/**
  * gnutls_global_set_send_func - This function sets the send() function
  * @send_func: it's a send(2) like function
  *
  * This is the function were you set the send() function gnutls
  * is going to use. Normaly you may not use this function since
  * the default (send(2)) will probably be ok, unless you use
  * some external library (like gnu pthreads), which provide
  * a front end to this function. This function should be
  * called once and after gnutls_global_init().
  *
  * SEND_FUNC is of the form:
  * ssize_t (*SEND_FUNC)(SOCKET, const void*, size_t,int);
  **/
void gnutls_global_set_send_func( SEND_FUNC send_func) {
	_gnutls_send_func = send_func;
}

/**
  * gnutls_global_set_log_func - This function sets the logging function
  * @log_func: it's a log function
  *
  * This is the function were you set the logging function gnutls
  * is going to use. This function only accepts a character array.
  * Normaly you may not use this function since
  * it is only used for debugging reasons.
  *
  * LOG_FUNC is of the form:
  * void (*LOG_FUNC)( const char*);
  **/
void gnutls_global_set_log_func( LOG_FUNC log_func) {
	_gnutls_log_func = log_func;
}


/* default logging function */
static void dlog( const char* str) {
#ifdef DEBUG
	fprintf( stderr, str);
#endif
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
int gnutls_global_init()
{
	int result;

	/* for gcrypt in order to be able to allocate memory */
	gcry_set_allocation_handler(gnutls_malloc, secure_malloc, _gnutls_is_secure_memory, gnutls_realloc, gnutls_free);

	/* we need this */
#ifdef HAVE_SIGNAL
	old_sig_handler = signal( SIGPIPE, SIG_IGN);
#endif

	/* set default recv/send functions
	 */
	_gnutls_recv_func = recv;
	_gnutls_send_func = send;
	gnutls_global_set_log_func( dlog);

	/* initialize parser 
	 * This should not deal with files in the final
	 * version.
	 */
	
	result=asn1_create_tree( (void*)pkix_asn1_tab, &PKIX1_ASN);
	if (result != ASN_OK) {
		return GNUTLS_E_ASN1_PARSING_ERROR;
	}

	result=asn1_create_tree( (void*)pkcs1_asn1_tab, &PKCS1_ASN);
	if (result != ASN_OK) {
		asn1_delete_structure( PKIX1_ASN);
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
#ifdef HAVE_SIGNAL
	signal( SIGPIPE, old_sig_handler);
#endif
	asn1_delete_structure( PKCS1_ASN);
	asn1_delete_structure( PKIX1_ASN);

}
