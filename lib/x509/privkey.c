/*
 *  Copyright (C) 2003 Nikos Mavroyanopoulos
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

#include <gnutls_int.h>
#include <gnutls_datum.h>
#include <gnutls_global.h>
#include <gnutls_errors.h>
#include <common.h>
#include <gnutls_x509.h>
#include <x509_b64.h>
#include <x509.h>
#include <dn.h>
#include <extensions.h>
#include <gnutls_privkey.h>

/**
  * gnutls_x509_privkey_init - This function initializes a gnutls_crl structure
  * @key: The structure to be initialized
  *
  * This function will initialize an private key structure. 
  *
  * Returns 0 on success.
  *
  **/
int gnutls_x509_privkey_init(gnutls_x509_privkey * key)
{
	*key = gnutls_calloc( 1, sizeof(gnutls_x509_privkey_int));

	if (*key) {
		return 0;		/* success */
	}
	return GNUTLS_E_MEMORY_ERROR;
}

/**
  * gnutls_x509_privkey_deinit - This function deinitializes memory used by a gnutls_x509_privkey structure
  * @key: The structure to be initialized
  *
  * This function will deinitialize a CRL structure. 
  *
  **/
void gnutls_x509_privkey_deinit(gnutls_x509_privkey key)
{
	_gnutls_free_datum(&key->raw);

	gnutls_free(key);
}

#define PEM_KEY_DSA "DSA PRIVATE"
#define PEM_KEY_RSA "RSA PRIVATE"

/**
  * gnutls_x509_privkey_import - This function will import a DER or PEM encoded Certificate
  * @key: The structure to store the parsed key
  * @data: The DER or PEM encoded certificate.
  * @format: One of DER or PEM
  *
  * This function will convert the given DER or PEM encoded Certificate
  * to the native gnutls_x509_privkey format. The output will be stored in 'key'.
  *
  * If the Certificate is PEM encoded it should have a header of "X509 CERTIFICATE", or
  * "CERTIFICATE" and must be a null terminated string.
  *
  * Returns 0 on success.
  *
  **/
int gnutls_x509_privkey_import(gnutls_x509_privkey key, const gnutls_datum * data,
	gnutls_x509_crt_fmt format)
{
	int result = 0, need_free = 0;
	gnutls_datum _data = { data->data, data->size };

	/* If the Certificate is in PEM format then decode it
	 */
	if (format == GNUTLS_X509_FMT_PEM) {
		opaque *out;
		
		/* Try the first header */
		result = _gnutls_fbase64_decode(PEM_KEY_RSA, data->data, data->size,
			&out);

		if (result <= 0) {
			/* try for the second header */
			result = _gnutls_fbase64_decode(PEM_KEY_DSA, data->data, data->size,
				&out);

			if (result <= 0) {
				if (result==0) result = GNUTLS_E_INTERNAL_ERROR;
				gnutls_assert();
				return result;
			}
		}
		
		_data.data = out;
		_data.size = result;
		
		need_free = 1;
	}

	result =
	    _gnutls_set_datum(&key->raw, _data.data, _data.size);
	if (result < 0) {
		gnutls_assert();
		goto cleanup;
	}
	
	if (need_free) _gnutls_free_datum( &_data);

	return 0;

      cleanup:
	_gnutls_free_datum(&key->raw);
	if (need_free) _gnutls_free_datum( &_data);
	return result;
}



/**
  * gnutls_x509_privkey_get_pk_algorithm - This function returns the key's PublicKey algorithm
  * @cert: should contain a gnutls_x509_privkey structure
  *
  * This function will return the public key algorithm of a private
  * key.
  *
  * Returns a member of the gnutls_pk_algorithm enumeration on success,
  * or a negative value on error.
  *
  **/
int gnutls_x509_privkey_get_pk_algorithm( gnutls_x509_privkey key)
{
int cv, pk;

        pk = GNUTLS_PK_UNKNOWN;

	/* The only way to distinguish the keys
	 * is to count the sequence of integers.
	 */
	cv = _gnutls_der_check_if_rsa_key( &key->raw);
	if (cv==0)
		pk = GNUTLS_PK_RSA;
	else {
		cv = _gnutls_der_check_if_dsa_key( &key->raw);
		if (cv==0)
			pk = GNUTLS_PK_DSA;
	}

	return pk;

}
