/*
 *  Copyright (C) 2002,2003 Nikos Mavroyanopoulos
 *  Copyright (C) 2004 Free Software Foundation
 *
 *  This file is part of GNUTLS.
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

/* This file includes all functions that were in the 0.5.x and 0.8.x
 * gnutls API. They are now implemented over the new certificate parsing
 * API.
 */

#include <gnutls_global.h>
#include <gnutls_errors.h>
#include <string.h> /* memset */
#include <dn.h>
#include <libtasn1.h>
#include <gnutls/x509.h>
#include <gnutls/compat8.h>

/**
  * gnutls_x509_extract_certificate_activation_time - This function returns the peer's certificate activation time
  * @cert: should contain an X.509 DER encoded certificate
  *
  * This function will return the certificate's activation time in UNIX time 
  * (ie seconds since 00:00:00 UTC January 1, 1970).
  * Returns a (time_t) -1 in case of an error.
  *
  **/
time_t gnutls_x509_extract_certificate_activation_time(const
							  gnutls_datum *
							  cert)
{
	gnutls_x509_crt xcert;
	time_t result;

	result = gnutls_x509_crt_init( &xcert);
	if (result < 0) return result;
	
	result = gnutls_x509_crt_import( xcert, cert, GNUTLS_X509_FMT_DER);
	if (result < 0) {
		gnutls_x509_crt_deinit( xcert);
		return result;
	}
	
	result = gnutls_x509_crt_get_activation_time( xcert);
	
	gnutls_x509_crt_deinit( xcert);
	
	return result;
}

/**
  * gnutls_x509_extract_certificate_expiration_time - This function returns the certificate's expiration time
  * @cert: should contain an X.509 DER encoded certificate
  *
  * This function will return the certificate's expiration time in UNIX time 
  * (ie seconds since 00:00:00 UTC January 1, 1970).
  * Returns a (time_t) -1 in case of an error.
  *
  **/
time_t gnutls_x509_extract_certificate_expiration_time(const
							  gnutls_datum *
							  cert)
{
	gnutls_x509_crt xcert;
	time_t result;

	result = gnutls_x509_crt_init( &xcert);
	if (result < 0) return result;
	
	result = gnutls_x509_crt_import( xcert, cert, GNUTLS_X509_FMT_DER);
	if (result < 0) {
		gnutls_x509_crt_deinit( xcert);
		return result;
	}
	
	result = gnutls_x509_crt_get_expiration_time( xcert);
	
	gnutls_x509_crt_deinit( xcert);
	
	return result;
}

