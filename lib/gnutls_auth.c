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

#include "gnutls_int.h"
#include "gnutls_errors.h"
#include "gnutls_auth.h"
#include "gnutls_auth_int.h"
#include "gnutls_algorithms.h"

#include "auth_anon.h"
/* The functions here are used in order for authentication algorithms
 * to be able to retrieve the needed credentials eg public and private
 * key etc.
 */

/* This clears the whole linked list */
int gnutls_clear_creds( GNUTLS_STATE state) {
	AUTH_CRED * ccred, *ncred;
	
	if (state->gnutls_key->cred!=NULL) { /* begining of the list */
		ccred = state->gnutls_key->cred;
		while(ccred!=NULL) {
			ncred = ccred->next;
			if (ccred!=NULL) gnutls_free(ccred);
			ccred = ncred;
		}
		state->gnutls_key->cred = NULL;
	}

	return 0;
}

/* 
 * This creates a linked list of the form:
 * { algorithm, credentials, pointer to next }
 */
/**
  * gnutls_set_cred - Sets the needed credentials for the specified authentication algorithm.
  * @state: is a &GNUTLS_STATE structure.
  * @type: is the type of the credentials
  * @cred: is a pointer to a structure.
  *
  * Sets the needed credentials for the specified type.
  * Eg username, password - or public and private keys etc.  
  * The (void* cred) parameter is a structure that depends on the
  * specified type and on the current state (client or server).
  * [ In order to minimize memory usage, and share credentials between 
  * several threads gnutls keeps a pointer to cred, and not the whole cred
  * structure. Thus you will have to keep the structure allocated until   
  * you call gnutls_deinit(). ]
  *
  * For %GNUTLS_ANON cred should be NULL in case of a client.
  * In case of a server it should be &ANON_SERVER_CREDENTIALS.   
  * 
  * For %GNUTLS_SRP cred should be &SRP_CLIENT_CREDENTIALS
  * in case of a client, and &SRP_SERVER_CREDENTIALS, in case
  * of a server.
  **/
int gnutls_set_cred( GNUTLS_STATE state, CredType type, void* cred) {
	AUTH_CRED * ccred, *pcred;
	int exists=0;	
	
	if (state->gnutls_key->cred==NULL) { /* begining of the list */
		
		state->gnutls_key->cred = gnutls_malloc(sizeof(AUTH_CRED));
		if (state->gnutls_key->cred == NULL) return GNUTLS_E_MEMORY_ERROR;
		
		/* copy credentials localy */
		state->gnutls_key->cred->credentials = cred;
		
		state->gnutls_key->cred->next = NULL;
		state->gnutls_key->cred->algorithm = type;
	} else {
		ccred = state->gnutls_key->cred;
		while(ccred!=NULL) {
			if (ccred->algorithm==type) {
				exists=1;
				break;
			}
			pcred = ccred;
			ccred = ccred->next;
		}
		
		if (exists==0) { /* new entry */
			pcred->next = gnutls_malloc(sizeof(AUTH_CRED));
			if (pcred->next == NULL) return GNUTLS_E_MEMORY_ERROR;
		
			ccred = pcred->next;

			/* copy credentials localy */
			ccred->credentials = cred;

			ccred->next = NULL;
			ccred->algorithm = type;
		} else { /* modify existing entry */
			gnutls_free(ccred->credentials);
			ccred->credentials = cred;
		}
	}

	return 0;
}

/**
  * gnutls_get_auth_info_type - Returns the type of credentials for the current authentication schema.
  * @state: is a &GNUTLS_STATE structure.
  *
  * Returns type of credentials for the current authentication schema.
  * The returned information can be used to distinguish the appropriate structures
  * for the gnutls_get_auth_info() function.
  * Eg. if this function returns GNUTLS_X509PKI then the return type
  *  of gnutls_get_auth_info() will be X509PKI_(SERVER/CLIENT)_AUTH_INFO
  * (depends on the side - client/server)
  **/

CredType gnutls_get_auth_info_type( GNUTLS_STATE state) {
	return _gnutls_map_kx_get_cred(
		state->security_parameters.kx_algorithm);
}

/* 
 * This returns an pointer to the linked list. Don't
 * free that!!!
 */
const void *_gnutls_get_kx_cred( GNUTLS_KEY key, KXAlgorithm algo, int *err) {
	return _gnutls_get_cred( key, _gnutls_map_kx_get_cred(algo), err);
}
const void *_gnutls_get_cred( GNUTLS_KEY key, CredType type, int *err) {
	AUTH_CRED * ccred;
	
	ccred = key->cred;
	while(ccred!=NULL) {
		if (ccred->algorithm==type) {
			break;
		}
		ccred = ccred->next;
	}
	if (ccred==NULL) {
		if (err!=NULL) *err=-1;
		return NULL;
	}
			
	if (err!=NULL) *err=0;
	return ccred->credentials;
}

/**
  * gnutls_get_auth_info - Returns a pointer to authentication information.
  * @state: is a &GNUTLS_STATE structure.
  *
  * This function must be called after a succesful gnutls_handshake().
  * Returns a pointer to authentication information. That information
  * is data obtained by the handshake protocol, the key exchange algorithm,
  * and the TLS extensions messages.
  *
  * In case of %GNUTLS_ANON returns a pointer to &ANON_(SERVER/CLIENT)_AUTH_INFO;
  * In case of %GNUTLS_X509PKI returns a pointer to structure &X509PKI_(SERVER/CLIENT)_AUTH_INFO;
  * In case of %GNUTLS_SRP returns a pointer to structure &SRP_(SERVER/CLIENT)_AUTH_INFO;
  **/
const void* gnutls_get_auth_info( GNUTLS_STATE state) {
	return state->gnutls_key->auth_info;
}
