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

/* SRP */

typedef struct DSTRUCT* GNUTLS_SRP_SERVER_CREDENTIALS;
typedef struct DSTRUCT* GNUTLS_SRP_CLIENT_CREDENTIALS;

void gnutls_srp_free_client_sc( GNUTLS_SRP_CLIENT_CREDENTIALS sc);
int gnutls_srp_allocate_client_sc( GNUTLS_SRP_CLIENT_CREDENTIALS *sc);
int gnutls_srp_set_client_cred( GNUTLS_SRP_CLIENT_CREDENTIALS res, char *username, char* password);

void gnutls_srp_free_server_sc( GNUTLS_SRP_SERVER_CREDENTIALS sc);
int gnutls_srp_allocate_server_sc( GNUTLS_SRP_SERVER_CREDENTIALS *sc);
int gnutls_srp_set_server_cred_file( GNUTLS_SRP_SERVER_CREDENTIALS res, char *password_file, char* password_conf_file);

const char* gnutls_srp_server_get_username( GNUTLS_STATE state);

typedef int gnutls_srp_server_select_function(GNUTLS_STATE, char **, char**, int);

void gnutls_srp_server_set_select_function( GNUTLS_STATE, gnutls_srp_server_select_function *);

/* Openpgp certificate stuff */
int gnutls_openpgp_fingerprint( const gnutls_datum* data, char* result, size_t* result_size);

int gnutls_openpgp_get_key_xml( const gnutls_datum *cert, int ext,
    gnutls_datum *xmlkey);

int gnutls_openpgp_extract_key_name( const gnutls_datum *cert,
                                 int idx,
                                 gnutls_openpgp_name *dn );

int gnutls_openpgp_extract_key_pk_algorithm(const gnutls_datum *cert,
                                            int *r_bits);

int gnutls_openpgp_extract_key_version( const gnutls_datum *cert );

time_t gnutls_openpgp_extract_key_creation_time( const gnutls_datum *cert );
time_t gnutls_openpgp_extract_key_expiration_time( const gnutls_datum *cert );

int gnutls_openpgp_verify_key( const gnutls_datum* keyring, 
	const gnutls_datum* key_list, 
	int key_list_length);

int gnutls_certificate_set_openpgp_key_file( GNUTLS_CERTIFICATE_CREDENTIALS res, char *CERTFILE, char* KEYFILE);
int gnutls_certificate_set_openpgp_key_mem( GNUTLS_CERTIFICATE_CREDENTIALS res,
	const gnutls_datum* CERT, const gnutls_datum* KEY);

int gnutls_certificate_set_openpgp_keyserver(GNUTLS_CERTIFICATE_CREDENTIALS res,
     char* keyserver, int port);

int gnutls_certificate_set_openpgp_trustdb(GNUTLS_CERTIFICATE_CREDENTIALS res,
     char* trustdb);

int gnutls_certificate_set_openpgp_keyring_mem(
    GNUTLS_CERTIFICATE_CREDENTIALS c,
    const unsigned char *data, size_t dlen );

int gnutls_certificate_set_openpgp_keyring_file( GNUTLS_CERTIFICATE_CREDENTIALS res, const char *name);

int gnutls_global_init_extra(void);

#endif
