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
#include "gnutls_session.h"
#ifdef HAVE_LIBGDBM
#include <gdbm.h>
#endif

int gnutls_set_cache_expiration( GNUTLS_STATE state, int seconds) {
	state->gnutls_internals.expire_time = seconds;
	return 0;
}

int gnutls_set_db_name( GNUTLS_STATE state, char* filename) {
#ifdef HAVE_LIBGDBM

	gnutls_free(state->gnutls_internals.db_name);
	state->gnutls_internals.db_name = strdup(filename);

	return 0;
#else
	return GNUTLS_E_UNIMPLEMENTED_FEATURE;
#endif
}

int gnutls_clean_db( GNUTLS_STATE state) {
#ifdef HAVE_LIBGDBM
FILE * tmp;

	tmp = fopen( state->gnutls_internals.db_name, "w");
	if (tmp!=NULL) fclose(tmp);

	return 0;
#else
	return GNUTLS_E_UNIMPLEMENTED_FEATURE;
#endif
}

int _gnutls_server_register_current_session( GNUTLS_STATE state)
{
#ifdef HAVE_LIBGDBM
GDBM_FILE dbf;
datum key = { state->security_parameters.session_id, state->security_parameters.session_id_size };
datum content = { (void*)&state->security_parameters, sizeof(SecurityParameters) };
int ret;

	if (state->gnutls_internals.resumable==RESUME_FALSE) return GNUTLS_E_INVALID_SESSION;

	if (state->gnutls_internals.db_name==NULL) return GNUTLS_E_DB_ERROR;
	if (state->security_parameters.session_id==NULL || state->security_parameters.session_id_size==0) return GNUTLS_E_INVALID_SESSION;

	dbf = gdbm_open(state->gnutls_internals.db_name, 0, GDBM_WRCREAT|GDBM_FAST, 0600, NULL);
	if (dbf==NULL) return GNUTLS_E_AGAIN;
	ret = gdbm_store( dbf, key, content, GDBM_INSERT);

	gdbm_close(dbf);

	return (ret == 0 ? ret : GNUTLS_E_UNKNOWN_ERROR);
#else
	return GNUTLS_E_UNIMPLEMENTED_FEATURE;
#endif
}


int _gnutls_server_restore_session( GNUTLS_STATE state, uint8* session_id, int session_id_size)
{
#ifdef HAVE_LIBGDBM
GDBM_FILE dbf;
datum content;
datum key = { session_id, session_id_size};
int ret;

	if (state->gnutls_internals.db_name==NULL) return GNUTLS_E_DB_ERROR;

	dbf = gdbm_open(state->gnutls_internals.db_name, 0, GDBM_READER|GDBM_FAST, 0600, NULL);
	if (dbf==NULL) return GNUTLS_E_AGAIN;
	content = gdbm_fetch( dbf, key);
	gdbm_close(dbf);

	if (content.dptr==NULL) return GNUTLS_E_INVALID_SESSION;
	if ( ((SecurityParameters*)(content.dptr))->timestamp > time(0) || ((SecurityParameters*)(content.dptr))->timestamp < 0) return GNUTLS_E_INVALID_SESSION;

	/* if not expired */	

	ret = gnutls_set_current_session( state, content.dptr, content.dsize);
	free(content.dptr);

	return ret;
#else
	return GNUTLS_E_UNIMPLEMENTED_FEATURE;
#endif
}

int _gnutls_db_remove_session( GNUTLS_STATE state, uint8* session_id, int session_id_size)
{
#ifdef HAVE_LIBGDBM
GDBM_FILE dbf;
datum key = { session_id, session_id_size};
int ret;

	if (state->gnutls_internals.db_name==NULL) return GNUTLS_E_DB_ERROR;

	dbf = gdbm_open(state->gnutls_internals.db_name, 0, GDBM_READER|GDBM_FAST, 0600, NULL);
	if (dbf==NULL) return GNUTLS_E_AGAIN;
	ret = gdbm_delete( dbf, key);
	gdbm_close(dbf);

	return (ret==0 ? ret : GNUTLS_E_DB_ERROR);
#else
	return GNUTLS_E_UNIMPLEMENTED_FEATURE;
#endif
}

