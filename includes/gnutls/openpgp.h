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

/* This file contains the types and prototypes for the OpenPGP
 * key and private key parsing functions.
 */

#ifndef GNUTLS_OPENPGP_H
# define GNUTLS_OPENPGP_H

#ifdef __cplusplus
extern "C" {
#endif

#include <gnutls/gnutls.h>

struct gnutls_openpgp_key_int; /* object to hold (parsed) openpgp keys */
typedef struct gnutls_openpgp_key_int* gnutls_openpgp_key;

typedef enum gnutls_openpgp_key_fmt { GNUTLS_X509_FMT_RAW,
        GNUTLS_X509_FMT_BASE64 } gnutls_openpgp_key_fmt;

int gnutls_openpgp_key_init( gnutls_openpgp_key* key); /* initializes the memory for gnutls_openpgp_key struct */
void gnutls_openpgp_key_deinit(gnutls_openpgp_key key); /* frees all memory */

int gnutls_openpgp_key_import(gnutls_openpgp_key key,
	const gnutls_datum* data, gnutls_openpgp_key_fmt format);

int gnutls_openpgp_key_get_fingerprint( gnutls_openpgp_key key,
	char* result, size_t* result_size);
	
int gnutls_openpgp_key_get_name( gnutls_openpgp_key key,
	int idx, char *buf, size_t *sizeof_buf);

int gnutls_openpgp_key_get_pk_algorithm(gnutls_openpgp_key key,
                                            int *r_bits);

int gnutls_openpgp_key_get_version( gnutls_openpgp_key key );

time_t gnutls_openpgp_key_get_creation_time( gnutls_openpgp_key key );
time_t gnutls_openpgp_key_get_expiration_time( gnutls_openpgp_key key );

int gnutls_openpgp_key_get_id( gnutls_openpgp_key key, unsigned char keyid[8]);

int gnutls_openpgp_key_check_hostname( gnutls_openpgp_key key, const char *hostname);

int gnutls_openpgp_key_to_xml( gnutls_openpgp_key key, gnutls_datum *xmlkey,
	int ext);

/* Keyring stuff.
 */
struct gnutls_openpgp_keyring_int; /* object to hold (parsed) openpgp keyrings */
typedef struct gnutls_openpgp_keyring_int* gnutls_openpgp_keyring;

int gnutls_openpgp_keyring_init( gnutls_openpgp_keyring* ring);
void gnutls_openpgp_keyring_deinit(gnutls_openpgp_keyring ring);

int gnutls_openpgp_keyring_import(gnutls_openpgp_keyring ring,
	const gnutls_datum* data, gnutls_openpgp_key_fmt format);

/* Trustdb functions.
 */
struct gnutls_openpgp_trustdb_int; /* object to hold (parsed) openpgp trustdbs */
typedef struct gnutls_openpgp_trustdb_int* gnutls_openpgp_trustdb;

int gnutls_openpgp_trustdb_init( gnutls_openpgp_trustdb* db);
void gnutls_openpgp_trustdb_deinit(gnutls_openpgp_trustdb db);

int gnutls_openpgp_trustdb_import(gnutls_openpgp_trustdb db,
	const char* file);


int gnutls_openpgp_key_verify_ring( 
	gnutls_openpgp_key key, 
	gnutls_openpgp_keyring ring,
	unsigned int flags,
	unsigned int * verify /* the output of the verification */);

int gnutls_openpgp_key_verify_trustdb( 
	gnutls_openpgp_key key, 
	gnutls_openpgp_trustdb db,
	unsigned int flags,
	unsigned int * verify /* the output of the verification */);


#ifdef __cplusplus
}
#endif
#endif /* GNUTLS_OPENPGP_H */

