/*
 *      Copyright (C) 2001,2002 Nikos Mavroyanopoulos
 *
 * This file is part of GNUTLS.
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

#include "gnutls_int.h"
#include "gnutls_errors.h"
#include "gnutls_auth.h"
#include "gnutls_auth_int.h"
#include "gnutls_algorithms.h"
#include "auth_cert.h"
#include <gnutls_datum.h>

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
  * gnutls_cred_set - Sets the needed credentials for the specified authentication algorithm.
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
  * For GNUTLS_CRD_ANON cred should be ANON_CLIENT_CREDENTIALS in case of a client.
  * In case of a server it should be ANON_SERVER_CREDENTIALS.
  * 
  * For GNUTLS_CRD_SRP cred should be SRP_CLIENT_CREDENTIALS
  * in case of a client, and SRP_SERVER_CREDENTIALS, in case
  * of a server.
  *
  * For GNUTLS_CRD_CERTIFICATE cred should be CERTIFICATE_CLIENT_CREDENTIALS
  * in case of a client, and CERTIFICATE_SERVER_CREDENTIALS, in case
  * of a server.
  **/
int gnutls_cred_set( GNUTLS_STATE state, GNUTLS_CredType type, void* cred) {
	AUTH_CRED * ccred=NULL, *pcred=NULL;
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
		/* After this, pcred is not null.
		 */

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
  * gnutls_auth_get_type - Returns the type of credentials for the current authentication schema.
  * @state: is a &GNUTLS_STATE structure.
  *
  * Returns type of credentials for the current authentication schema.
  * The returned information is to be used to distinguish the function used
  * to access authentication data.
  * 
  * Eg. for CERTIFICATE ciphersuites (key exchange algorithms: KX_RSA, KX_DHE_RSA),
  * the same function are to be used to access the authentication data.
  **/
GNUTLS_CredType gnutls_auth_get_type( GNUTLS_STATE state) {

	return _gnutls_map_kx_get_cred(
		 _gnutls_cipher_suite_get_kx_algo
                         (state->security_parameters.current_cipher_suite));
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

	if (key == NULL) return NULL;
	
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

/*-
  * _gnutls_get_auth_info - Returns a pointer to authentication information.
  * @state: is a &GNUTLS_STATE structure.
  *
  * This function must be called after a succesful gnutls_handshake().
  * Returns a pointer to authentication information. That information
  * is data obtained by the handshake protocol, the key exchange algorithm,
  * and the TLS extensions messages.
  *
  * In case of GNUTLS_CRD_ANON returns a pointer to &ANON_(SERVER/CLIENT)_AUTH_INFO;
  * In case of GNUTLS_CRD_CERTIFICATE returns a pointer to structure &CERTIFICATE_(SERVER/CLIENT)_AUTH_INFO;
  * In case of GNUTLS_CRD_SRP returns a pointer to structure &SRP_(SERVER/CLIENT)_AUTH_INFO;
  -*/
void* _gnutls_get_auth_info( GNUTLS_STATE state) {
	return state->gnutls_key->auth_info;
}

/*-
  * _gnutls_free_auth_info - Frees the auth info structure
  * @state: is a &GNUTLS_STATE structure.
  *
  * this function frees the auth info structure and sets it to
  * null. It must be called since some structures contain malloced
  * elements.
  -*/
void _gnutls_free_auth_info( GNUTLS_STATE state) {
	if (state==NULL || state->gnutls_key==NULL) {
		gnutls_assert();
		return;
	}
	
	switch ( state->gnutls_key->auth_info_type) {
	case GNUTLS_CRD_SRP:
	case GNUTLS_CRD_ANON:
		
		break;
	case GNUTLS_CRD_CERTIFICATE: {
		int i;
		CERTIFICATE_AUTH_INFO info =
		            _gnutls_get_auth_info(state);

			if (info==NULL) break;
			for (i=0;i<info->ncerts;i++) {
				gnutls_free_datum( &info->raw_certificate_list[i]);
			}
	
			gnutls_free( info->raw_certificate_list);
			info->raw_certificate_list = NULL;
			info->ncerts = 0;
		}


		break;
	default:
		return;

	}

	gnutls_free( state->gnutls_key->auth_info);
	state->gnutls_key->auth_info = NULL;
	state->gnutls_key->auth_info_size = 0;
	state->gnutls_key->auth_info_type = 0;

}

/* This function will set the auth info structure in the gnutls_key
 * structure.
 * If allow change is !=0 then this will allow changing the auth
 * info structure to a different type.
 */
int _gnutls_auth_info_set( GNUTLS_STATE state, CredType type, int size, int allow_change) {
	if ( state->gnutls_key->auth_info == NULL) {
		state->gnutls_key->auth_info = gnutls_calloc( 1, size);
		if (state->gnutls_key->auth_info == NULL) {
			gnutls_assert();
			return GNUTLS_E_MEMORY_ERROR;
		}
		state->gnutls_key->auth_info_type = type;
		state->gnutls_key->auth_info_size = size;
	} else {
		if (allow_change==0) {
			/* If the credentials for the current authentication scheme,
			 * are not the one we want to set, then it's an error.
			 * This may happen if a rehandshake is performed an the
			 * ciphersuite which is negotiated has different authentication
			 * schema.
			 */
			if ( gnutls_auth_get_type( state) != state->gnutls_key->auth_info_type) {
				gnutls_assert();
				return GNUTLS_E_INVALID_REQUEST;
			}
		} else {
			/* The new behaviour: Here we reallocate the auth info structure
			 * in order to be able to negotiate different authentication
			 * types. Ie. perform an auth_anon and then authenticate again using a
			 * certificate (in order to prevent revealing the certificate's contents,
			 * to passive eavesdropers.
			 */
			if ( gnutls_auth_get_type( state) != state->gnutls_key->auth_info_type) {
				state->gnutls_key->auth_info = gnutls_realloc_fast( 
					state->gnutls_key->auth_info, size);
				if (state->gnutls_key->auth_info == NULL) {
					gnutls_assert();
					return GNUTLS_E_MEMORY_ERROR;
				}
				memset( state->gnutls_key->auth_info, 0, size);
				state->gnutls_key->auth_info_type = type;
				state->gnutls_key->auth_info_size = size;
			}
		}
	}
	return 0;
}

/* this function will copy an GNUTLS_MPI key to 
 * opaque data.
 */
int _gnutls_generate_key(GNUTLS_KEY key) {
        _gnutls_mpi_print( NULL, &key->key.size, key->KEY);
	key->key.data = gnutls_secure_malloc( key->key.size);
	if ( key->key.data==NULL) {
		return GNUTLS_E_MEMORY_ERROR;
	}
	_gnutls_mpi_print( key->key.data, &key->key.size, key->KEY);
	return 0;
}
