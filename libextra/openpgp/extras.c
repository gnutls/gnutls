/*
 *  Copyright (C) 2003 Nikos Mavroyanopoulos
 *
 *  This file is part of GNUTLS-EXTRA.
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

/* Functions on OpenPGP keyring and trustdb parsing
 */

#include <gnutls_int.h>

#ifdef HAVE_LIBOPENCDK

#include <gnutls_datum.h>
#include <gnutls_global.h>
#include <gnutls_errors.h>
#include <opencdk.h>
#include <gnutls_openpgp.h>
#include <openpgp.h>

/* Keyring stuff.
 */

/**
  * gnutls_openpgp_keyring_init - This function initializes a gnutls_openpgp_keyring structure
  * @keyring: The structure to be initialized
  *
  * This function will initialize an OpenPGP keyring structure. 
  *
  * Returns 0 on success.
  *
  **/
int gnutls_openpgp_keyring_init(gnutls_openpgp_keyring * keyring)
{
	*keyring = gnutls_calloc( 1, sizeof(gnutls_openpgp_keyring_int));

	if (*keyring) {
		return 0; /* success */
	}
	return GNUTLS_E_MEMORY_ERROR;
}

/**
  * gnutls_openpgp_keyring_deinit - This function deinitializes memory used by a gnutls_openpgp_keyring structure
  * @keyring: The structure to be initialized
  *
  * This function will deinitialize a CRL structure. 
  *
  **/
void gnutls_openpgp_keyring_deinit(gnutls_openpgp_keyring keyring)
{
	if (!keyring) return;

	if (keyring->hd) {
		cdk_free( keyring->hd);
		keyring->hd = NULL;
	}
	
	gnutls_free(keyring);
}

/**
  * gnutls_openpgp_keyring_import - This function will import a RAW or BASE64 encoded key
  * @keyring: The structure to store the parsed key.
  * @data: The RAW or BASE64 encoded keyring.
  * @format: One of gnutls_openpgp_keyring_fmt elements.
  *
  * This function will convert the given RAW or Base64 encoded keyring
  * to the native gnutls_openpgp_keyring format. The output will be stored in 'keyring'.
  *
  * Returns 0 on success.
  *
  **/
int gnutls_openpgp_keyring_import(gnutls_openpgp_keyring keyring, 
	const gnutls_datum * data,
	gnutls_openpgp_key_fmt format)
{
int rc;
keybox_blob *blob = NULL;


	blob = kbx_read_blob( data, 0);
	if( !blob ) {
		gnutls_assert();
		return GNUTLS_E_INTERNAL_ERROR;
	}
	
	keyring->hd = kbx_to_keydb( blob);
	if( !keyring->hd ) {
		gnutls_assert();
		rc = GNUTLS_E_INTERNAL_ERROR;
		goto leave;
	}
	
	rc = 0;
	
	leave:
		kbx_blob_release( blob );
		return rc;
}


/* TrustDB stuff.
 */

/**
  * gnutls_openpgp_trustdb_init - This function initializes a gnutls_openpgp_trustdb structure
  * @trustdb: The structure to be initialized
  *
  * This function will initialize an OpenPGP trustdb structure. 
  *
  * Returns 0 on success.
  *
  **/
int gnutls_openpgp_trustdb_init(gnutls_openpgp_trustdb * trustdb)
{
	*trustdb = gnutls_calloc( 1, sizeof(gnutls_openpgp_trustdb_int));

	if (*trustdb) {
		return 0; /* success */
	}
	return GNUTLS_E_MEMORY_ERROR;
}

/**
  * gnutls_openpgp_trustdb_deinit - This function deinitializes memory used by a gnutls_openpgp_trustdb structure
  * @trustdb: The structure to be initialized
  *
  * This function will deinitialize a CRL structure. 
  *
  **/
void gnutls_openpgp_trustdb_deinit(gnutls_openpgp_trustdb trustdb)
{
	if (!trustdb) return;

	if (trustdb->st) {
		cdk_stream_close( trustdb->st);
		trustdb->st = NULL;
	}
	
	gnutls_free(trustdb);
}

/**
  * gnutls_openpgp_trustdb_import_file - This function will import a RAW or BASE64 encoded key
  * @trustdb: The structure to store the parsed key.
  * @file: The file that holds the trustdb.
  *
  * This function will convert the given RAW or Base64 encoded trustdb
  * to the native gnutls_openpgp_trustdb format. The output will be stored in 'trustdb'.
  *
  * Returns 0 on success.
  *
  **/
int gnutls_openpgp_trustdb_import_file(gnutls_openpgp_trustdb trustdb, 
	const char * file)
{
int rc;

	
	rc = cdk_stream_open( file, &trustdb->st);
	if( rc ) {
		rc = _gnutls_map_cdk_rc( rc );
		gnutls_assert();
		return rc;
	}

	return 0;
}

#endif
