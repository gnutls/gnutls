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
#include <gnutls_dh.h>

#ifdef USE_SIGNALS

# ifdef HAVE_SIGNAL_H
#  include <signal.h>
# endif

# ifndef SIGFUNC
#  define SIGFUNC
 typedef void Sigfunc(int);
# endif
static Sigfunc *Signal( int signo, Sigfunc *func);

static Sigfunc *old_sig_handler;

#endif


/* created by asn1c */
extern const static_asn pkcs1_asn1_tab[];
extern const static_asn pkix_asn1_tab[];


typedef void (*LOG_FUNC)( const char*);

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
  *
  * If signals are supported in your system, this function sets SIGPIPE,
  * to SIG_IGN. The old signal handler will be restored when calling
  * gnutls_global_deinit().
  *
  **/
int gnutls_global_init()
{
	int result;

	/* for gcrypt in order to be able to allocate memory */
	gcry_set_allocation_handler(gnutls_malloc, secure_malloc, _gnutls_is_secure_memory, gnutls_realloc, gnutls_free);

	/* we need this */
#ifdef USE_SIGNALS
	old_sig_handler = Signal( SIGPIPE, SIG_IGN);
#endif

	/* set default recv/send functions
	 */
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
  **/

void gnutls_global_deinit() {

	/* restore signal handler  */
#ifdef USE_SIGNALS
	Signal( SIGPIPE, old_sig_handler);
#endif
	asn1_delete_structure( PKCS1_ASN);
	asn1_delete_structure( PKIX1_ASN);
	
	_gnutls_dh_clear_mpis();
	
}

#ifdef USE_SIGNALS

/* This is an emulation of the signal() function, using the
 * POSIX sigaction() (if present).
 */
static Sigfunc *
 Signal(int signo, Sigfunc * func)
{
#ifdef HAVE_SIGACTION

	struct sigaction act, oact;

	act.sa_handler = func;
	sigemptyset(&act.sa_mask);
	act.sa_flags = 0;
	if (signo == SIGALRM) {
#ifdef SA_INTERRUPT
		act.sa_flags |= SA_INTERRUPT;	/* SunOs 4.x */
#endif
	} else {
#ifdef SA_RESTART
		act.sa_flags |= SA_RESTART;	/* SVR4, 4.4BSD */
#endif
	}

	if (sigaction(signo, &act, &oact) < 0)
		return (SIG_ERR);
	return (oact.sa_handler);

#else /* ifdef HAVE_SIGACTION */
#ifdef HAVE_SIGNAL
	return signal(signo, func);
#else
	return (Sigfunc *) 0;	/* Do nothing */
#endif /* HAVE_SIGNAL */
#endif /* HAVE_SIGACTION */
}
#endif /* USE_SIGNALS */


/* These functions should be elsewere. Kept here for 
 * historical reasons.
 */

/**
  * gnutls_set_pull_func - This function sets a read like function
  * @pull_func: it's a function like read
  * @state: gnutls state
  *
  * This is the function where you set a function for gnutls 
  * to receive data. Normaly, if you use berkeley style sockets,
  * you may not use this function since the default (recv(2)) will 
  * probably be ok.
  * This function should be called once and after gnutls_global_init().
  * PULL_FUNC is of the form, 
  * ssize_t (*PULL_FUNC)(SOCKET, const void*, size_t);
  **/
void gnutls_set_pull_func( GNUTLS_STATE state, PULL_FUNC pull_func) {
	state->gnutls_internals._gnutls_pull_func = pull_func;
}

/**
  * gnutls_set_push_func - This function sets the function to send data
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
  * ssize_t (*PUSH_FUNC)(SOCKET, const void*, size_t);
  **/
void gnutls_set_push_func( GNUTLS_STATE state, PUSH_FUNC push_func) {
	state->gnutls_internals._gnutls_push_func = push_func;
}
