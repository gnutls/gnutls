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
#include <defines.h>
#include "gnutls_int.h"
#include "gnutls_errors.h"

/* Returns all session parameters - in order to support resuming.
 * The client should call this - and keep the returned session - if he wants to resume his 
 * current version later by calling gnutls_set_current_session().
 * This function must be called after a successful handshake.
 */
int gnutls_get_current_session( GNUTLS_STATE state, void* session, int *session_size) {

	( *session_size = sizeof(SecurityParameters));
	
	if (state->gnutls_internals.resumable==RESUME_FALSE) return GNUTLS_E_INVALID_SESSION;
	/* just return the session size */
	if (session==NULL) {
		return 0;
	}
	memcpy( session, &state->security_parameters, sizeof(SecurityParameters));
	
	return 0;
}

/* Returns session id
 */
int gnutls_get_current_session_id( GNUTLS_STATE state, void* session, int *session_size) {

	( *session_size = state->security_parameters.session_id_size);
	
	/* just return the session size */
	if (session==NULL) {
		return 0;
	}
	memcpy( session, &state->security_parameters.session_id, *session_size);
	
	return 0;
}

/* Sets all session parameters - in order to support resuming 
 * session must be the one returned by get_current_session();
 * This function should be called before gnutls_handshake_begin
 */
int gnutls_set_current_session( GNUTLS_STATE state, void* session, int session_size) {

	if ( session_size != sizeof(SecurityParameters)) {
		return GNUTLS_E_UNIMPLEMENTED_FEATURE;
	}

	memcpy( &state->gnutls_internals.resumed_security_parameters, session, sizeof(SecurityParameters));
	
	return 0;
}
