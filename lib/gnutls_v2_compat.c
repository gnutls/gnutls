/*
 *      Copyright (C) 2001 Nikos Mavroyanopoulos
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

/* Functions to parse the SSLv2.0 hello message.
 */

#include "gnutls_int.h"
#include "gnutls_errors.h"
#include "gnutls_dh.h"
#include "debug.h"
#include "gnutls_algorithms.h"
#include "gnutls_compress.h"
#include "gnutls_cipher.h"
#include "gnutls_buffers.h"
#include "gnutls_kx.h"
#include "gnutls_handshake.h"
#include "gnutls_num.h"
#include "gnutls_hash_int.h"
#include "gnutls_db.h"
#include "gnutls_extensions.h"
#include "gnutls_random.h"
#include "gnutls_auth_int.h"

/* This selects the best supported ciphersuite from the ones provided */
static int _gnutls_handshake_select_v2_suite(gnutls_session session, char *data, int datalen)
{
	int i, j, ret;
	char* _data;
	int _datalen;
	
	_data = gnutls_malloc( datalen);
	if (_data==NULL) {
		gnutls_assert();
		return GNUTLS_E_MEMORY_ERROR;
	}

	_gnutls_handshake_log( "HSK: Parsing a version 2.0 client hello.\n");

	i = _datalen = 0;
	for (j = 0; j < datalen; j += 3) {
		if (data[j] == 0) {
			memcpy( &_data[i], &data[j+1], 2);
			i+=2;
			_datalen+=2;
		}
	}

	ret = _gnutls_server_select_suite( session, _data, _datalen);
	gnutls_free(_data);

	return ret;

}


/* Read a v2 client hello. Some browsers still use that beast!
 * However they set their version to 3.0 or 3.1.
 */
int _gnutls_read_client_hello_v2(gnutls_session session, opaque * data,
			      int datalen)
{
	uint16 session_id_len = 0;
	int pos = 0;
	int ret = 0;
	uint16 sizeOfSuites;
	gnutls_protocol_version version;
	opaque random[TLS_RANDOM_SIZE];
	int len = datalen;
	int err;
	uint16 challenge;
	opaque session_id[TLS_MAX_SESSION_ID_SIZE];
	gnutls_protocol_version ver;
	
	/* we only want to get here once - only in client hello */
	session->internals.v2_hello = 0;

	DECR_LEN(len, 2);

	_gnutls_handshake_log( "HSK: SSL 2.0 Hello: Client's version: %d.%d\n", data[pos],
		data[pos + 1]);

	set_adv_version( session, data[pos], data[pos+1]);
	
	version = _gnutls_version_get(data[pos], data[pos + 1]);

	/* if we do not support that version  */
	if (_gnutls_version_is_supported(session, version) == 0) {
		ver = _gnutls_version_lowest( session);
	} else {
		ver = version;
	}

	if (ver==GNUTLS_VERSION_UNKNOWN || ver > version) {
		gnutls_assert();
		return GNUTLS_E_UNSUPPORTED_VERSION_PACKET;
	}

	_gnutls_set_current_version(session, ver);

	pos += 2;


	/* Read uint16 cipher_spec_length */
	DECR_LEN(len, 2);
	sizeOfSuites = _gnutls_read_uint16( &data[pos]);
	pos += 2;
	
	/* read session id length */
	DECR_LEN(len, 2);
	session_id_len = _gnutls_read_uint16( &data[pos]);
	pos += 2;

	if (session_id_len > TLS_MAX_SESSION_ID_SIZE) { 
		gnutls_assert();
		return GNUTLS_E_UNEXPECTED_PACKET_LENGTH;
	}

	/* read challenge length */
	DECR_LEN(len, 2);
	challenge = _gnutls_read_uint16( &data[pos]);
	pos += 2;

	if ( challenge < 16 || challenge > TLS_RANDOM_SIZE) {
		gnutls_assert();
		return GNUTLS_E_UNSUPPORTED_VERSION_PACKET;
	}

	/* find an appropriate cipher suite */

	DECR_LEN(len, sizeOfSuites);
	ret = _gnutls_handshake_select_v2_suite(session, &data[pos], sizeOfSuites);

	pos += sizeOfSuites;
	if (ret < 0) {
		gnutls_assert();
		return ret;
	}

	/* check if the credentials (username, public key etc. are ok)
	 */
	if (_gnutls_get_kx_cred( session->key, _gnutls_cipher_suite_get_kx_algo(session->security_parameters.current_cipher_suite), &err) == NULL && err != 0) {
		gnutls_assert();
		return GNUTLS_E_INSUFICIENT_CREDENTIALS;
	}

	/* set the MOD_AUTH_STRUCT to the appropriate struct
	 * according to the KX algorithm. This is needed since all the
	 * handshake functions are read from there;
	 */
	session->internals.auth_struct =
	    _gnutls_kx_auth_struct(_gnutls_cipher_suite_get_kx_algo
				   (session->security_parameters.
				    current_cipher_suite));
	if (session->internals.auth_struct == NULL) {

		_gnutls_handshake_log(
			"HSK: SSL 2.0 Hello: Cannot find the appropriate handler for the KX algorithm\n");

		gnutls_assert();
		return GNUTLS_E_INTERNAL_ERROR;
	}

	

	/* read random new values -skip session id for now */
	DECR_LEN(len, session_id_len); /* skip session id for now */
	memcpy( session_id, &data[pos], session_id_len);
	pos+=session_id_len;
	
	DECR_LEN(len, challenge);
	memset( random, 0, TLS_RANDOM_SIZE);
	
	memcpy( &random[TLS_RANDOM_SIZE-challenge], &data[pos], challenge);

	_gnutls_set_client_random( session, random);

	/* generate server random value */

	_gnutls_create_random( random);
	_gnutls_set_server_random( session, random);
	
	session->security_parameters.timestamp = time(NULL);


	/* RESUME SESSION */

	DECR_LEN(len, session_id_len);
	ret = _gnutls_server_restore_session(session, session_id, session_id_len);

	if (ret == 0) {		/* resumed! */
		/* get the new random values */
		memcpy(session->internals.resumed_security_parameters.server_random,
		       session->security_parameters.server_random, TLS_RANDOM_SIZE);
		memcpy(session->internals.resumed_security_parameters.client_random,
		       session->security_parameters.client_random, TLS_RANDOM_SIZE);

		session->internals.resumed = RESUME_TRUE;
		return 0;
	} else {
		_gnutls_generate_session_id(session->security_parameters.
					    session_id,
					    &session->security_parameters.
					    session_id_size);
		session->internals.resumed = RESUME_FALSE;
	}

	session->internals.compression_method = GNUTLS_COMP_NULL;

	return 0;
}
