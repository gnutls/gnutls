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

int _gnutls_SelectCompMethod(GNUTLS_STATE state, CompressionMethod * ret, opaque * data, int datalen);

/* This selects the best supported ciphersuite from the ones provided */
static int SelectSuite_v2(GNUTLS_STATE state, opaque ret[2], char *data,
			  int datalen)
{
	int x, i, j;
	GNUTLS_CipherSuite *ciphers;

	x = _gnutls_supported_ciphersuites(state, &ciphers);
	x = _gnutls_remove_unwanted_ciphersuites( state, &ciphers, x);

#ifdef HANDSHAKE_DEBUG
	_gnutls_handshake_log( "HSK: Requested cipher suites [v2 hello]: \n");
	for (j = 0; j < datalen; j += 3) {
		if (data[j] == 0) {	/* only print if in v2 compat mode */
			_gnutls_handshake_log( "\t%s\n",
				_gnutls_cipher_suite_get_name(*
							      ((GNUTLS_CipherSuite *) & data[j+1])));
		}
	}
	_gnutls_handshake_log( "HSK: Supported cipher suites: \n");
	for (j = 0; j < x; j++)
		_gnutls_handshake_log( "\t%s\n",
			_gnutls_cipher_suite_get_name(ciphers[j]));
#endif
	memset(ret, '\0', 2);

	for (j = 0; j < datalen; j += 3) {
		for (i = 0; i < x; i++) {
			if (data[j] == 0)
				if ( memcmp(ciphers[i].CipherSuite, &data[j+1],
				     2) == 0) {

					_gnutls_handshake_log(
						"HSK: Selected cipher suite: ");
					_gnutls_handshake_log( "%s\n",
						_gnutls_cipher_suite_get_name
						(*
						 ((GNUTLS_CipherSuite *) &
						  data[j+1])));

					memcpy(ret,
						ciphers[i].CipherSuite,
						2);
					gnutls_free(ciphers);

					return 0;
				}
		}
	}


	gnutls_free(ciphers);
	gnutls_assert();
	return GNUTLS_E_UNKNOWN_CIPHER_SUITE;

}


/* Read a v2 client hello. Some browsers still use that beast!
 * However they set their version to 3.0 or 3.1.
 */
int _gnutls_read_client_hello_v2(GNUTLS_STATE state, opaque * data,
			      int datalen)
{
	uint16 session_id_len = 0;
	int pos = 0;
	int ret = 0;
	uint16 sizeOfSuites;
	GNUTLS_Version version;
	opaque random[TLS_RANDOM_SIZE];
	int len = datalen;
	int err;
	uint16 challenge;
	opaque session_id[TLS_MAX_SESSION_ID_SIZE];
	GNUTLS_Version ver;
	
	/* we only want to get here once - only in client hello */
	state->gnutls_internals.v2_hello = 0;

	DECR_LEN(len, 2);

	_gnutls_handshake_log( "HSK: V2 Hello: Client's version: %d.%d\n", data[pos],
		data[pos + 1]);

	set_adv_version( state, data[pos], data[pos+1]);
	
	version = _gnutls_version_get(data[pos], data[pos + 1]);

	/* if we do not support that version  */
	if (_gnutls_version_is_supported(state, version) == 0) {
		ver = _gnutls_version_lowest( state);
	} else {
		ver = version;
	}

	if (ver==GNUTLS_VERSION_UNKNOWN || ver > version) {
		gnutls_assert();
		return GNUTLS_E_UNSUPPORTED_VERSION_PACKET;
	}

	_gnutls_set_current_version(state, ver);

	pos += 2;


	/* Read uint16 cipher_spec_length */
	DECR_LEN(len, 2);
	sizeOfSuites = READuint16( &data[pos]);
	pos += 2;
	
	/* read session id length */
	DECR_LEN(len, 2);
	session_id_len = READuint16( &data[pos]);
	pos += 2;

	if (session_id_len > TLS_MAX_SESSION_ID_SIZE) { 
		gnutls_assert();
		return GNUTLS_E_UNEXPECTED_PACKET_LENGTH;
	}

	/* read challenge length */
	DECR_LEN(len, 2);
	challenge = READuint16( &data[pos]);
	pos += 2;

	if ( challenge < 16 || challenge > TLS_RANDOM_SIZE) {
		gnutls_assert();
		return GNUTLS_E_UNSUPPORTED_VERSION_PACKET;
	}

	/* find an appropriate cipher suite */

	DECR_LEN(len, sizeOfSuites);
	ret = SelectSuite_v2(state, state->security_parameters.
				  current_cipher_suite.CipherSuite,
				  &data[pos], sizeOfSuites);

	pos += sizeOfSuites;
	if (ret < 0) {
		gnutls_assert();
		return ret;
	}

	/* check if the credentials (username, public key etc. are ok)
	 */
	if (_gnutls_get_kx_cred( state->gnutls_key, _gnutls_cipher_suite_get_kx_algo(state->security_parameters.current_cipher_suite), &err) == NULL && err != 0) {
		gnutls_assert();
		return GNUTLS_E_INSUFICIENT_CRED;
	}

	/* set the MOD_AUTH_STRUCT to the appropriate struct
	 * according to the KX algorithm. This is needed since all the
	 * handshake functions are read from there;
	 */
	state->gnutls_internals.auth_struct =
	    _gnutls_kx_auth_struct(_gnutls_cipher_suite_get_kx_algo
				   (state->security_parameters.
				    current_cipher_suite));
	if (state->gnutls_internals.auth_struct == NULL) {

		_gnutls_handshake_log(
			"HSK: V2 Hello: Cannot find the appropriate handler for the KX algorithm\n");

		gnutls_assert();
		return GNUTLS_E_UNKNOWN_CIPHER_TYPE;
	}

	

	/* read random new values -skip session id for now */
	DECR_LEN(len, session_id_len); /* skip session id for now */
	memcpy( session_id, &data[pos], session_id_len);
	pos+=session_id_len;
	
	DECR_LEN(len, challenge);
	memset( random, 0, TLS_RANDOM_SIZE);
	
	memcpy( &random[TLS_RANDOM_SIZE-challenge], &data[pos], challenge);

	_gnutls_set_client_random( state, random);

	/* generate server random value */

	_gnutls_create_random( random);
	_gnutls_set_server_random( state, random);
	
	state->security_parameters.timestamp = time(NULL);


	/* RESUME SESSION */

	DECR_LEN(len, session_id_len);
	ret = _gnutls_server_restore_session(state, session_id, session_id_len);

	if (ret == 0) {		/* resumed! */
		/* get the new random values */
		memcpy(state->gnutls_internals.resumed_security_parameters.server_random,
		       state->security_parameters.server_random, TLS_RANDOM_SIZE);
		memcpy(state->gnutls_internals.resumed_security_parameters.client_random,
		       state->security_parameters.client_random, TLS_RANDOM_SIZE);

		state->gnutls_internals.resumed = RESUME_TRUE;
		return 0;
	} else {
		_gnutls_generate_session_id(state->security_parameters.
					    session_id,
					    &state->security_parameters.
					    session_id_size);
		state->gnutls_internals.resumed = RESUME_FALSE;
	}

	state->gnutls_internals.compression_method = GNUTLS_COMP_NULL;

	return 0;
}
