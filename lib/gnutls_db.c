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

/* This file contains functions that manipulate a database
 * for resumed sessions. 
 */
#include "gnutls_int.h"
#include "gnutls_errors.h"
#include "gnutls_session.h"
#include "debug.h"

#ifdef HAVE_LIBGDBM
# define GNUTLS_DBF state->gnutls_internals.db_reader
# define GNUTLS_DBNAME state->gnutls_internals.db_name
# define GNUTLS_REOPEN_DB() if (GNUTLS_DBF!=NULL) \
	gdbm_close( GNUTLS_DBF); \
	GNUTLS_DBF = gdbm_open(GNUTLS_DBNAME, 0, GDBM_READER, 0600, NULL);
#endif

/**
  * gnutls_set_cache_expiration - Sets the expiration time for resumed sessions.
  * @state: is a &GNUTLS_STATE structure.
  * @seconds: is the number of seconds.
  *
  * Sets the expiration time for resumed sessions. The default is 3600 (one hour)
  * at the time writing this.
  **/
int gnutls_set_cache_expiration( GNUTLS_STATE state, int seconds) {
	state->gnutls_internals.expire_time = seconds;
	return 0;
}

/**
  * gnutls_set_db_name - Sets the name of the database that holds TLS sessions.
  * @state: is a &GNUTLS_STATE structure.
  * @filename: is the filename for the database
  *
  * Sets the name of the (gdbm) database to be used to keep
  * the sessions to be resumed. This function also creates the database
  * - if it does not exist - and opens it for reading.
  **/
int gnutls_set_db_name( GNUTLS_STATE state, char* filename) {
#ifdef HAVE_LIBGDBM
GDBM_FILE dbf;

	if (filename==NULL) return 0;

	/* deallocate previous name */
	if (GNUTLS_DBNAME!=NULL)
		gnutls_free(GNUTLS_DBNAME);

	/* set name */
	GNUTLS_DBNAME = gnutls_strdup(filename);
	if (GNUTLS_DBNAME==NULL) return GNUTLS_E_MEMORY_ERROR;


	/* open for reader */
	GNUTLS_DBF = gdbm_open(GNUTLS_DBNAME, 0, GDBM_READER, 0600, NULL);
	if (GNUTLS_DBF==NULL) {
		/* maybe it does not exist - so try to
		 * create it.
		 */
		dbf = gdbm_open( filename, 0, GDBM_WRCREAT, 0600, NULL);
		if (dbf==NULL) return GNUTLS_E_DB_ERROR;
		gdbm_close(dbf);

		/* try to open again */
		GNUTLS_DBF = gdbm_open(GNUTLS_DBNAME, 0, GDBM_READER, 0600, NULL);
	}
	if (GNUTLS_DBF==NULL)
		return GNUTLS_E_DB_ERROR;

	return 0;
#else
	return GNUTLS_E_UNIMPLEMENTED_FEATURE;
#endif
}


/**
  * gnutls_clean_db - removes expired and invalid sessions from the database
  * @state: is a &GNUTLS_STATE structure.
  *
  * This function Deletes all expired records in the resumed sessions' database. 
  * This database may become huge if this function is not called.
  * (this function is also quite expensive)
  **/
int gnutls_clean_db( GNUTLS_STATE state) {
#ifdef HAVE_LIBGDBM
GDBM_FILE dbf;
int ret;
datum key;
time_t timestamp;

	if (GNUTLS_DBF==NULL) return GNUTLS_E_DB_ERROR;
	if (GNUTLS_DBNAME==NULL) return GNUTLS_E_DB_ERROR;
	
	dbf = gdbm_open(GNUTLS_DBNAME, 0, GDBM_WRITER, 0600, NULL);
	if (dbf==NULL) return GNUTLS_E_AGAIN;
	key = gdbm_firstkey(dbf);

	timestamp = time(0);

	while( key.dptr != NULL) {

		if ( timestamp - ((SecurityParameters*)(key.dptr))->timestamp <= state->gnutls_internals.expire_time || ((SecurityParameters*)(key.dptr))->timestamp > timestamp|| ((SecurityParameters*)(key.dptr))->timestamp == 0) {
		    /* delete expired entry */
		    gdbm_delete( dbf, key);
		}
		
		free(key.dptr);
		key = gdbm_nextkey(dbf, key);
	}
	ret = gdbm_reorganize(dbf);
	
	gdbm_close(dbf);
	GNUTLS_REOPEN_DB();
	
	if (ret!=0) return GNUTLS_E_DB_ERROR;
		
	return 0;
#else
	return GNUTLS_E_UNIMPLEMENTED_FEATURE;
#endif

}

/* The format of storing data is:
 * SECURITY_PARAMETERS + AUTH_INFO_SIZE + AUTH_INFO
 */
int _gnutls_server_register_current_session( GNUTLS_STATE state)
{
#ifdef HAVE_LIBGDBM
GDBM_FILE dbf;
datum key = { state->security_parameters.session_id, state->security_parameters.session_id_size };
datum content;
int ret = 0;

	if (state->gnutls_internals.resumable==RESUME_FALSE) 
		return GNUTLS_E_INVALID_SESSION;

	if (GNUTLS_DBNAME==NULL)
		return GNUTLS_E_DB_ERROR;

	if (state->security_parameters.session_id==NULL || state->security_parameters.session_id_size==0)
		return GNUTLS_E_INVALID_SESSION;

	/* if we can't read why bother writing? */
	if (GNUTLS_DBF==NULL)
		return GNUTLS_E_DB_ERROR;

/* allocate space for data */
	content.dsize = sizeof(SecurityParameters) + state->gnutls_key->auth_info_size
		+ sizeof(state->gnutls_key->auth_info_size);
	content.dptr = gnutls_malloc( content.dsize);
	if (content.dptr==NULL) return GNUTLS_E_MEMORY_ERROR;

/* copy data */
	memcpy( content.dptr, (void*)&state->security_parameters, sizeof(SecurityParameters));
	memcpy( &content.dptr[sizeof(SecurityParameters)], &state->gnutls_key->auth_info_size,  sizeof(state->gnutls_key->auth_info_size));
	memcpy( &content.dptr[sizeof(state->gnutls_key->auth_info_size)+sizeof(SecurityParameters)], 
		state->gnutls_key->auth_info,  state->gnutls_key->auth_info_size);

	dbf = gdbm_open(GNUTLS_DBNAME, 0, GDBM_WRITER, 0600, NULL);
	if (dbf==NULL) {
		gnutls_free(content.dptr);
		/* cannot open db for writing. This may happen if multiple
		 * instances try to write. 
		 */
		return GNUTLS_E_AGAIN;
	}
	ret = gdbm_store( dbf, key, content, GDBM_INSERT);

	gnutls_free( content.dptr);

	gdbm_close(dbf);
	return (ret == 0 ? ret : GNUTLS_E_UNKNOWN_ERROR);
#else
	return GNUTLS_E_UNIMPLEMENTED_FEATURE;
#endif
}

int _gnutls_server_restore_session( GNUTLS_STATE state, uint8* session_id, int session_id_size)
{
#ifdef HAVE_LIBGDBM
datum content;
datum key = { session_id, session_id_size};
int ret;

	if (GNUTLS_DBNAME==NULL) return GNUTLS_E_DB_ERROR;

	if (GNUTLS_DBF==NULL) return GNUTLS_E_DB_ERROR;
	content = gdbm_fetch( GNUTLS_DBF, key);

	if (content.dptr==NULL) {
		return GNUTLS_E_INVALID_SESSION;
	}

	/* expiration check is performed inside */
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

	if (GNUTLS_DBNAME==NULL) return GNUTLS_E_DB_ERROR;

	dbf = gdbm_open(GNUTLS_DBNAME, 0, GDBM_READER, 0600, NULL);
	if (dbf==NULL) return GNUTLS_E_AGAIN;
	ret = gdbm_delete( dbf, key);
	gdbm_close(dbf);

	return (ret==0 ? ret : GNUTLS_E_DB_ERROR);
#else
	return GNUTLS_E_UNIMPLEMENTED_FEATURE;
#endif
}

