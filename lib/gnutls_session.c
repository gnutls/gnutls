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
#include "gnutls_int.h"
#include "gnutls_errors.h"
#include "debug.h"

#define SESSION_SIZE sizeof(SecurityParameters) + sizeof(state->gnutls_key->auth_info_size) + state->gnutls_key->auth_info_size

/**
  * gnutls_get_current_session - Returns all session parameters.
  * @state: is a &GNUTLS_STATE structure.
  * @session: is a pointer to space to hold the session.
  * @session_size: is the session's size, or it will be set by the function.
  *
  * Returns all session parameters - in order to support resuming.
  * The client should call this - and keep the returned session - if he wants to
  * resume that current version later by calling gnutls_set_current_session()
  * This function must be called after a successful handshake.
  *
  * Resuming sessions is really useful and speedups connections after a succesful one.
  **/
int gnutls_get_current_session( GNUTLS_STATE state, opaque* session, int *session_size) {

	if (*session_size < SESSION_SIZE) {
		*session_size = SESSION_SIZE;
		session = NULL; /* return with the new session_size value */
	}

	if (state->gnutls_internals.resumable==RESUME_FALSE) return GNUTLS_E_INVALID_SESSION;
	/* just return the session size */
	if (session==NULL) {
		return 0;
	}
	memcpy( session, &state->security_parameters, sizeof(SecurityParameters));
	memcpy( &session[sizeof(SecurityParameters)], &state->gnutls_key->auth_info_size,  sizeof(state->gnutls_key->auth_info_size));
	memcpy( &session[sizeof(state->gnutls_key->auth_info_size)+sizeof(SecurityParameters)], 
		state->gnutls_key->auth_info,  state->gnutls_key->auth_info_size);

	return 0;
}


/**
  * gnutls_get_current_session_id - Returns session id.
  * @state: is a &GNUTLS_STATE structure.
  * @session: is a pointer to space to hold the session id.
  * @session_size: is the session id's size, or it will be set by the function.
  *
  * Returns the current session id. This can be used if you want to check if
  * the next session you tried to resume was actually resumed.
  * (resumed sessions have the same sessionID with the first session)
  *
  * Session id is some data set by the server, that identify the current session. 
  * In TLS 1.0 session id should not be more than 32 bytes.
  **/
int gnutls_get_current_session_id( GNUTLS_STATE state, void* session, int *session_size) {

	*session_size = state->security_parameters.session_id_size;
	
	/* just return the session size */
	if (session==NULL) {
		return 0;
	}
	memcpy( session, &state->security_parameters.session_id, *session_size);
	
	return 0;
}

/**
  * gnutls_set_current_session - Sets all session parameters
  * @state: is a &GNUTLS_STATE structure.
  * @session: is a pointer to space to hold the session.
  * @session_size: is the session's size
  *
  * Sets all session parameters - in order to support resuming
  * session must be the one returned by gnutls_get_current_session();
  * This function should be called before gnutls_handshake().
  * Keep in mind that session resuming is advisory. The server may
  * choose not to resume the session, thus a full handshake will be
  * performed.
  **/
int gnutls_set_current_session( GNUTLS_STATE state, opaque* session, int session_size) {
	int auth_info_size;
	int timestamp = time(0);
	SecurityParameters sp;

	if ( (session_size - sizeof(SecurityParameters)) 
		>= sizeof(state->gnutls_key->auth_info_size)) { /* have more data */
		auth_info_size = *((int*)&session[sizeof(SecurityParameters)]);	
	} else {
		auth_info_size = 0;
		gnutls_assert();
		return GNUTLS_E_DB_ERROR;
	}
	
	if (session_size < sizeof(SecurityParameters)) {
		gnutls_assert();
		return GNUTLS_E_UNIMPLEMENTED_FEATURE;
	}
	
	memcpy( &sp, session, sizeof(SecurityParameters));
	if ( timestamp - sp.timestamp <= state->gnutls_internals.expire_time 
		&& sp.timestamp <= timestamp) {

		memcpy( &state->gnutls_internals.resumed_security_parameters, &sp, sizeof(SecurityParameters));
		if (auth_info_size > 0) {
			state->gnutls_key->auth_info = gnutls_malloc(auth_info_size);
			if (state->gnutls_key->auth_info==NULL) {
				gnutls_assert();
				return GNUTLS_E_MEMORY_ERROR;
			}
			state->gnutls_key->auth_info_size = auth_info_size;
			memcpy( state->gnutls_key->auth_info, &session[sizeof(SecurityParameters)+sizeof(state->gnutls_key->auth_info_size)], auth_info_size);
		} else { /* set to null */
			state->gnutls_key->auth_info_size = 0;
			state->gnutls_key->auth_info = NULL;
		}
	} else {
		return GNUTLS_E_EXPIRED;
	}
	return 0;
}
