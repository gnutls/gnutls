/*
 *      Copyright (C) 2000 Nikos Mavroyanopoulos
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

#include "gnutls_errors.h"
#ifdef STDC_HEADERS
# include <stdarg.h>
#endif

extern void (*_gnutls_log_func)( const char*);


#define GNUTLS_ERROR_ENTRY(name, fatal) \
	{ #name, name, fatal }

struct gnutls_error_entry {
	char *name;
	int  number;
	int  fatal;
};
typedef struct gnutls_error_entry gnutls_error_entry;

static gnutls_error_entry error_algorithms[] = {
	GNUTLS_ERROR_ENTRY( GNUTLS_E_SUCCESS, 0),
	GNUTLS_ERROR_ENTRY( GNUTLS_E_MAC_FAILED, 1),
	GNUTLS_ERROR_ENTRY( GNUTLS_E_UNKNOWN_CIPHER, 1),
	GNUTLS_ERROR_ENTRY( GNUTLS_E_UNKNOWN_CIPHER_SUITE, 1),
	GNUTLS_ERROR_ENTRY( GNUTLS_E_UNKNOWN_COMPRESSION_ALGORITHM, 1),
	GNUTLS_ERROR_ENTRY( GNUTLS_E_UNKNOWN_MAC_ALGORITHM, 1),
	GNUTLS_ERROR_ENTRY( GNUTLS_E_UNKNOWN_ERROR, 1),
	GNUTLS_ERROR_ENTRY( GNUTLS_E_UNKNOWN_CIPHER_TYPE, 1),
	GNUTLS_ERROR_ENTRY( GNUTLS_E_UNWANTED_ALGORITHM, 1),
	GNUTLS_ERROR_ENTRY( GNUTLS_E_LARGE_PACKET, 1),
	GNUTLS_ERROR_ENTRY( GNUTLS_E_UNSUPPORTED_VERSION_PACKET, 1),
	GNUTLS_ERROR_ENTRY( GNUTLS_E_UNEXPECTED_PACKET_LENGTH, 1),
	GNUTLS_ERROR_ENTRY( GNUTLS_E_INVALID_SESSION, 1),
	GNUTLS_ERROR_ENTRY( GNUTLS_E_INTERNAL, 1),
	GNUTLS_ERROR_ENTRY( GNUTLS_E_RECEIVED_ILLEGAL_EXTENSION, 1),
	GNUTLS_ERROR_ENTRY( GNUTLS_E_UNABLE_SEND_DATA, 1),
	GNUTLS_ERROR_ENTRY( GNUTLS_E_FATAL_ALERT_RECEIVED ,1),
	GNUTLS_ERROR_ENTRY( GNUTLS_E_RECEIVED_BAD_MESSAGE, 1),
	GNUTLS_ERROR_ENTRY( GNUTLS_E_RECEIVED_MORE_DATA, 1),
	GNUTLS_ERROR_ENTRY( GNUTLS_E_UNEXPECTED_PACKET, 1),
	GNUTLS_ERROR_ENTRY( GNUTLS_E_WARNING_ALERT_RECEIVED, 0),
	GNUTLS_ERROR_ENTRY( GNUTLS_E_ERROR_IN_FINISHED_PACKET, 1),
	GNUTLS_ERROR_ENTRY( GNUTLS_E_UNEXPECTED_HANDSHAKE_PACKET, 1),
	GNUTLS_ERROR_ENTRY( GNUTLS_E_UNKNOWN_KX_ALGORITHM, 1),
	GNUTLS_ERROR_ENTRY( GNUTLS_E_MPI_SCAN_FAILED, 1),
	GNUTLS_ERROR_ENTRY( GNUTLS_E_MPI_PRINT_FAILED, 1),
	GNUTLS_ERROR_ENTRY( GNUTLS_E_DECRYPTION_FAILED, 1),
	GNUTLS_ERROR_ENTRY( GNUTLS_E_ENCRYPTION_FAILED, 1),
	GNUTLS_ERROR_ENTRY( GNUTLS_E_PK_DECRYPTION_FAILED, 1),
	GNUTLS_ERROR_ENTRY( GNUTLS_E_PK_ENCRYPTION_FAILED, 1),
	GNUTLS_ERROR_ENTRY( GNUTLS_E_PK_SIGNATURE_FAILED, 1),
	GNUTLS_ERROR_ENTRY( GNUTLS_E_DECOMPRESSION_FAILED, 1),
	GNUTLS_ERROR_ENTRY( GNUTLS_E_COMPRESSION_FAILED, 1),
	GNUTLS_ERROR_ENTRY( GNUTLS_E_MEMORY_ERROR, 1),
	GNUTLS_ERROR_ENTRY( GNUTLS_E_UNIMPLEMENTED_FEATURE, 1),
	GNUTLS_ERROR_ENTRY( GNUTLS_E_INSUFICIENT_CRED, 1),
	GNUTLS_ERROR_ENTRY( GNUTLS_E_PWD_ERROR, 1),
	GNUTLS_ERROR_ENTRY( GNUTLS_E_PKCS1_WRONG_PAD, 1),
	GNUTLS_ERROR_ENTRY( GNUTLS_E_EXPIRED, 1),
	GNUTLS_ERROR_ENTRY( GNUTLS_E_HASH_FAILED, 1),
	GNUTLS_ERROR_ENTRY( GNUTLS_E_PARSING_ERROR, 1),
	GNUTLS_ERROR_ENTRY( GNUTLS_E_REQUESTED_DATA_NOT_AVAILABLE, 0),
	GNUTLS_ERROR_ENTRY( GNUTLS_E_PULL_ERROR, 1),
	GNUTLS_ERROR_ENTRY( GNUTLS_E_PUSH_ERROR, 1),
	GNUTLS_ERROR_ENTRY( GNUTLS_E_NO_CERTIFICATE_FOUND, 1),
	GNUTLS_ERROR_ENTRY( GNUTLS_E_RECORD_LIMIT_REACHED, 1),
	GNUTLS_ERROR_ENTRY( GNUTLS_E_ASN1_PARSING_ERROR, 1),
	GNUTLS_ERROR_ENTRY( GNUTLS_E_ASN1_ERROR, 1),
	GNUTLS_ERROR_ENTRY( GNUTLS_E_X509_CERTIFICATE_ERROR, 1),
	GNUTLS_ERROR_ENTRY( GNUTLS_E_X509_UNSUPPORTED_CRITICAL_EXTENSION, 1),
	GNUTLS_ERROR_ENTRY( GNUTLS_E_X509_KEY_USAGE_VIOLATION, 1),
	GNUTLS_ERROR_ENTRY( GNUTLS_E_AGAIN, 0),
	GNUTLS_ERROR_ENTRY( GNUTLS_E_INTERRUPTED, 0),
	GNUTLS_ERROR_ENTRY( GNUTLS_E_REHANDSHAKE, 0),
	GNUTLS_ERROR_ENTRY( GNUTLS_E_GOT_APPLICATION_DATA, 0),
	GNUTLS_ERROR_ENTRY( GNUTLS_E_DB_ERROR, 1),
	GNUTLS_ERROR_ENTRY( GNUTLS_E_INVALID_PARAMETERS, 1),
	GNUTLS_ERROR_ENTRY( GNUTLS_E_INVALID_REQUEST, 1),
	GNUTLS_ERROR_ENTRY( GNUTLS_E_ILLEGAL_PARAMETER, 1),
	{0}
};

#define GNUTLS_ERROR_LOOP(b) \
        gnutls_error_entry *p; \
                for(p = error_algorithms; p->name != NULL; p++) { b ; }

#define GNUTLS_ERROR_ALG_LOOP(a) \
                        GNUTLS_ERROR_LOOP( if(p->number == error) { a; break; } )



/**
  * gnutls_error_is_fatal - Returns non-zero in case of a fatal error
  * @error: is an error returned by a gnutls function. Error should be a negative value.
  *
  * If a function returns a negative value you may feed that value
  * to this function to see if it is fatal. Returns 1 for a fatal 
  * error 0 otherwise. However you may want to check the
  * error code manualy, since some non-fatal errors to the protocol
  * may be fatal for you (your program).
  **/
int gnutls_error_is_fatal(int error)
{
	int ret = 0;

	GNUTLS_ERROR_ALG_LOOP(ret = p->fatal);
	return ret;
}

/**
  * gnutls_perror - prints a string to stderr with a description of an error
  * @error: is an error returned by a gnutls function. Error is always a negative value.
  *
  * This function is like perror(). The only difference is that it accepts an 
  * error returned by a gnutls function. 
  **/
void gnutls_perror(int error)
{
	char *ret = NULL;

	/* avoid prefix */
	GNUTLS_ERROR_ALG_LOOP(ret =
			      gnutls_strdup(p->name + sizeof("GNUTLS_E_") - 1));

	_gnutls_log( "GNUTLS ERROR: %s\n", ret);
	
	gnutls_free( ret);
}


/**
  * gnutls_strerror - Returns a string with a description of an error
  * @error: is an error returned by a gnutls function. Error is always a negative value.
  *
  * This function is similar to strerror(). The only difference is that it 
  * accepts an error (number) returned by a gnutls function. 
  **/
const char* gnutls_strerror(int error)
{
	char *ret = NULL;

	/* avoid prefix */
	GNUTLS_ERROR_ALG_LOOP(ret =
			      p->name + sizeof("GNUTLS_E_") - 1);

	return ret;
}

/* this function will output a message using the
 * caller provided function 
 */
#ifdef DEBUG
void _gnutls_log( const char *fmt, ...) {
 va_list args;
 char str[MAX_LOG_SIZE];
 void (*log_func)(const char*) = _gnutls_log_func;
 
 if (_gnutls_log_func==NULL) return;

 va_start(args,fmt);
 vsprintf( str,fmt,args); /* Flawfinder: ignore */
 va_end(args);   

 log_func( str);

 return;
}
#endif
