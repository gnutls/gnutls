/*
 *      Copyright (C) 2002 Nikos Mavroyanopoulos
 *
 * GNUTLS-EXTRA is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * GNUTLS-EXTRA is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA
 */

/* Note the libgnutls-extra is not a standalone library. It requires
 * to link also against libgnutls.
 */

#ifndef GNUTLS_EXTRA_H
# define GNUTLS_EXTRA_H

#include <gnutls/gnutls.h>

#define LIBGNUTLS_EXTRA_VERSION LIBGNUTLS_VERSION

/* SRP */

typedef struct DSTRUCT* gnutls_srp_server_credentials;
typedef struct DSTRUCT* gnutls_srp_client_credentials;

void gnutls_srp_free_client_credentials( gnutls_srp_client_credentials sc);
int gnutls_srp_allocate_client_credentials( gnutls_srp_client_credentials *sc);
int gnutls_srp_set_client_credentials( gnutls_srp_client_credentials res, char *username, char* password);

void gnutls_srp_free_server_credentials( gnutls_srp_server_credentials sc);
int gnutls_srp_allocate_server_credentials( gnutls_srp_server_credentials *sc);
int gnutls_srp_set_server_credentials_file( gnutls_srp_server_credentials res, char *password_file, char* password_conf_file);

const char* gnutls_srp_server_get_username( gnutls_session state);

typedef int gnutls_srp_server_select_function(gnutls_session, char **, char**, int);
#define gnutls_srp_server_select_func gnutls_srp_server_select_function

void gnutls_srp_server_set_select_function( gnutls_session, gnutls_srp_server_select_function *);
#define gnutls_srp_server_set_select_func gnutls_srp_server_set_select_function

/* Openpgp certificate stuff */
int gnutls_openpgp_fingerprint( const gnutls_datum* data, char* result, size_t* result_size);

int gnutls_openpgp_key_to_xml( const gnutls_datum *cert, gnutls_datum *xmlkey,
	int ext);

int gnutls_openpgp_extract_key_name( const gnutls_datum *cert,
                                 int idx,
                                 gnutls_openpgp_name *dn );

int gnutls_openpgp_extract_key_pk_algorithm(const gnutls_datum *cert,
                                            int *r_bits);

int gnutls_openpgp_extract_key_version( const gnutls_datum *cert );

time_t gnutls_openpgp_extract_key_creation_time( const gnutls_datum *cert );
time_t gnutls_openpgp_extract_key_expiration_time( const gnutls_datum *cert );

int gnutls_openpgp_extract_key_id( const gnutls_datum *cert, unsigned char keyid[8]);

typedef int (*gnutls_openpgp_recv_key_func)(unsigned char keyid[8], 
	gnutls_datum *key);

void gnutls_openpgp_set_recv_key_function( gnutls_session, gnutls_openpgp_recv_key_func);

int gnutls_openpgp_verify_key( const gnutls_datum* keyring, 
	const gnutls_datum* key_list, 
	int key_list_length);

int gnutls_certificate_set_openpgp_key_file( gnutls_certificate_credentials res, char *CERTFILE, char* KEYFILE);
int gnutls_certificate_set_openpgp_key_mem( gnutls_certificate_credentials res,
	const gnutls_datum* CERT, const gnutls_datum* KEY);

int gnutls_certificate_set_openpgp_keyserver(gnutls_certificate_credentials res,
     char* keyserver, int port);

int gnutls_certificate_set_openpgp_trustdb(gnutls_certificate_credentials res,
     char* trustdb);

int gnutls_certificate_set_openpgp_keyring_mem(
    gnutls_certificate_credentials c,
    const unsigned char *data, size_t dlen );

int gnutls_certificate_set_openpgp_keyring_file( gnutls_certificate_credentials res, const char *name);

int gnutls_global_init_extra(void);

/* returns libgnutls-extra version (call it with a NULL argument) 
 */
const char* gnutls_extra_check_version( const char*);

#endif
