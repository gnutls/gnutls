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
#include <gnutls_session_pack.h>

#define SESSION_SIZE _gnutls_session_size( state)

/**
  * gnutls_session_get_data - Returns all session parameters.
  * @state: is a &GNUTLS_STATE structure.
  * @session: is a pointer to space to hold the session.
  * @session_size: is the session's size, or it will be set by the function.
  *
  * Returns all session parameters - in order to support resuming.
  * The client should call this - and keep the returned session - if he wants to
  * resume that current version later by calling gnutls_session_set_data()
  * This function must be called after a successful handshake.
  *
  * Resuming sessions is really useful and speedups connections after a succesful one.
  **/
int gnutls_session_get_data( GNUTLS_STATE state, opaque* session, int *session_size) {

	gnutls_datum psession;
	int ret;
	
	if (*session_size < SESSION_SIZE || session==NULL) {
		*session_size = SESSION_SIZE;
		session = NULL; /* return with the new session_size value */
	}

	if (state->gnutls_internals.resumable==RESUME_FALSE) return GNUTLS_E_INVALID_SESSION;
	/* just return the session size */
	if (session==NULL) {
		return 0;
	}
	
	psession.data = session;
	
	ret = _gnutls_session_pack( state, &psession);
	if (ret< 0) {
		gnutls_assert();
		return ret;
	}
	*session_size = psession.size;

	return 0;
}


/**
  * gnutls_session_get_id - Returns session id.
  * @state: is a &GNUTLS_STATE structure.
  * @session: is a pointer to space to hold the session id.
  * @session_size: is the session id's size, or it will be set by the function.
  *
  * Returns the current session id. This can be used if you want to check if
  * the next session you tried to resume was actually resumed.
  * This is because resumed sessions have the same sessionID with the 
  * original session.
  *
  * Session id is some data set by the server, that identify the current session. 
  * In TLS 1.0 session id should not be more than 32 bytes.
  **/
int gnutls_session_get_id( GNUTLS_STATE state, void* session, int *session_size) {

	*session_size = state->security_parameters.session_id_size;
	
	/* just return the session size */
	if (session==NULL) {
		return 0;
	}
	memcpy( session, &state->security_parameters.session_id, *session_size);
	
	return 0;
}

/**
  * gnutls_session_set_data - Sets all session parameters
  * @state: is a &GNUTLS_STATE structure.
  * @session: is a pointer to space to hold the session.
  * @session_size: is the session's size
  *
  * Sets all session parameters - in order to support resuming
  * session must be the one returned by gnutls_session_get_data();
  * This function should be called before gnutls_handshake().
  * Keep in mind that session resuming is advisory. The server may
  * choose not to resume the session, thus a full handshake will be
  * performed.
  **/
int gnutls_session_set_data( GNUTLS_STATE state, opaque* session, int session_size) {
	int ret;
	gnutls_datum psession = { session, session_size };

	if (session==NULL || session_size == 0) {
		gnutls_assert();
		return GNUTLS_E_INVALID_REQUEST;
	}
	ret = _gnutls_session_unpack( state, &psession);
	if (ret < 0) {
		gnutls_assert();
		return ret;
	}
	
	return 0;
}
