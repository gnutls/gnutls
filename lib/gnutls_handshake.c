/*
 *      Copyright (C) 2000,2001,2002 Nikos Mavroyanopoulos
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

/* Functions that relate to the TLS handshake procedure.
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
#include "gnutls_v2_compat.h"
#include "auth_cert.h"
#include "gnutls_cert.h"
#include "gnutls_constate.h"
#include <gnutls_record.h>
#include <gnutls_alert.h>
#include <gnutls_state.h>

#ifdef HANDSHAKE_DEBUG
#define ERR(x, y) _gnutls_handshake_log( "HSK: %s (%d)\n", x,y)
#else
#define ERR(x, y)
#endif

#define TRUE 1
#define FALSE 0

int _gnutls_server_select_comp_method(GNUTLS_STATE state,
				    opaque * data, int datalen);


/* Clears the handshake hash buffers and handles.
 */
inline static
void _gnutls_handshake_hash_buffers_clear( GNUTLS_STATE state) {
	_gnutls_hash_deinit( state->gnutls_internals.handshake_mac_handle_md5, NULL);
	_gnutls_hash_deinit( state->gnutls_internals.handshake_mac_handle_sha, NULL);
	state->gnutls_internals.handshake_mac_handle_md5 = NULL;
	state->gnutls_internals.handshake_mac_handle_sha = NULL;
	_gnutls_handshake_buffer_clear( state);
}

/* this will copy the required values for resuming to 
 * gnutls_internals, and to security_parameters.
 * this will keep as less data to security_parameters.
 */
static void resume_copy_required_values(GNUTLS_STATE state)
{
	/* get the new random values */
	memcpy(state->gnutls_internals.resumed_security_parameters.
	       server_random,
	       state->security_parameters.server_random, TLS_RANDOM_SIZE);
	memcpy(state->gnutls_internals.resumed_security_parameters.
	       client_random,
	       state->security_parameters.client_random, TLS_RANDOM_SIZE);

	/* keep the ciphersuite and compression 
	 * That is because the client must see these in our
	 * hello message.
	 */
	memcpy(state->security_parameters.current_cipher_suite.
	       CipherSuite,
	       state->gnutls_internals.resumed_security_parameters.
	       current_cipher_suite.CipherSuite, 2);

	state->gnutls_internals.compression_method = state->gnutls_internals.resumed_security_parameters.read_compression_algorithm;	/* or write_compression_algorithm
																	 * they are the same
																	 */

	state->security_parameters.entity =
	    state->gnutls_internals.resumed_security_parameters.entity;

	_gnutls_set_current_version( state, state->gnutls_internals.resumed_security_parameters.version);

	state->security_parameters.cert_type =
	    state->gnutls_internals.resumed_security_parameters.cert_type;

	memcpy(state->security_parameters.session_id,
	       state->gnutls_internals.resumed_security_parameters.
	       session_id, sizeof(state->security_parameters.session_id));
	state->security_parameters.session_id_size =
	    state->gnutls_internals.resumed_security_parameters.
	    session_id_size;

	return;
}

void _gnutls_set_server_random(GNUTLS_STATE state, uint8 * random)
{
	memcpy(state->security_parameters.server_random, random,
	       TLS_RANDOM_SIZE);
}

void _gnutls_set_client_random(GNUTLS_STATE state, uint8 * random)
{
	memcpy(state->security_parameters.client_random, random,
	       TLS_RANDOM_SIZE);
}

/* Calculate The SSL3 Finished message 
 */
#define SSL3_CLIENT_MSG "CLNT"
#define SSL3_SERVER_MSG "SRVR"
#define SSL_MSG_LEN 4
static int _gnutls_ssl3_finished(GNUTLS_STATE state, int type, opaque * ret)
{
	const int siz = SSL_MSG_LEN;
	GNUTLS_MAC_HANDLE td_md5;
	GNUTLS_MAC_HANDLE td_sha;
	const opaque *mesg;

	td_md5 = _gnutls_hash_copy( state->gnutls_internals.handshake_mac_handle_md5);
	if (td_md5 == NULL) {
		gnutls_assert();
		return GNUTLS_E_HASH_FAILED;
	}

	td_sha = _gnutls_hash_copy( state->gnutls_internals.handshake_mac_handle_sha);
	if (td_sha == NULL) {
		gnutls_assert();
		_gnutls_hash_deinit( td_md5, NULL);
		return GNUTLS_E_HASH_FAILED;
	}

	if (type == GNUTLS_SERVER) {
		mesg = SSL3_SERVER_MSG;
	} else {
		mesg = SSL3_CLIENT_MSG;
	}

	_gnutls_hash(td_md5, mesg, siz);
	_gnutls_hash(td_sha, mesg, siz);

	_gnutls_mac_deinit_ssl3_handshake(td_md5, ret, state->security_parameters.master_secret, TLS_MASTER_SIZE);
	_gnutls_mac_deinit_ssl3_handshake(td_sha, &ret[16], state->security_parameters.master_secret, TLS_MASTER_SIZE);

	return 0;
}

/* Hash the handshake messages as required by TLS 1.0 
 */
#define SERVER_MSG "server finished"
#define CLIENT_MSG "client finished"
#define TLS_MSG_LEN 15
int _gnutls_finished(GNUTLS_STATE state, int type, void *ret)
{
	const int siz = TLS_MSG_LEN;
	opaque concat[36];
	const opaque *mesg;
	GNUTLS_MAC_HANDLE td_md5;
	GNUTLS_MAC_HANDLE td_sha;


	td_md5 = _gnutls_hash_copy( state->gnutls_internals.handshake_mac_handle_md5);
	if (td_md5 == NULL) {
		gnutls_assert();
		return GNUTLS_E_HASH_FAILED;
	}

	td_sha = _gnutls_hash_copy( state->gnutls_internals.handshake_mac_handle_sha);
	if (td_sha == NULL) {
		gnutls_assert();
		_gnutls_hash_deinit( td_md5, NULL);
		return GNUTLS_E_HASH_FAILED;
	}


	_gnutls_hash_deinit(td_md5, concat);
	_gnutls_hash_deinit(td_sha, &concat[16]);

	if (type == GNUTLS_SERVER) {
		mesg = SERVER_MSG;
	} else {
		mesg = CLIENT_MSG;
	}

	return _gnutls_PRF(state->security_parameters.master_secret,
			  TLS_MASTER_SIZE, mesg, siz, concat, 36,
			  12, ret);
}

/* this function will produce TLS_RANDOM_SIZE bytes of random data
 * and put it to dst.
 */
int _gnutls_create_random(opaque * dst)
{
	uint32 tim;
	opaque rand[TLS_RANDOM_SIZE - 4];

	tim = time(NULL);
	/* generate server random value */
	_gnutls_write_uint32(tim, dst);

	if (_gnutls_get_random
	    (rand, TLS_RANDOM_SIZE - 4, GNUTLS_STRONG_RANDOM) < 0) {
		gnutls_assert();
		return GNUTLS_E_MEMORY_ERROR;
	}
	memcpy(&dst[4], rand, 28);

	return 0;
}


/* Read a client hello packet. 
 * A client hello must be a known version client hello
 * or version 2.0 client hello (only for compatibility
 * since SSL version 2.0 is not supported).
 */
int _gnutls_read_client_hello(GNUTLS_STATE state, opaque * data,
			      int datalen)
{
	uint8 session_id_len = 0, z;
	int pos = 0;
	int ret = 0;
	uint16 sizeOfSuites;
	GNUTLS_Version version;
	int len = datalen;
	opaque random[TLS_RANDOM_SIZE], *suite_ptr;
	GNUTLS_Version ver;

	if (state->gnutls_internals.v2_hello != 0) {	/* version 2.0 */
		return _gnutls_read_client_hello_v2(state, data, datalen);
	}
	DECR_LEN(len, 2);

	_gnutls_handshake_log("HSK: Client's version: %d.%d\n", data[pos], data[pos + 1]);

	version = _gnutls_version_get(data[pos], data[pos + 1]);
	set_adv_version(state, data[pos], data[pos + 1]);
	pos += 2;

	/* if we do not support that version  */
	if (_gnutls_version_is_supported(state, version) == 0) {
		/* If he requested something we do not support
		 * then we send him the lowest we support.
		 */
		ver = _gnutls_version_lowest(state);
	} else {
		ver = version;
	}

	/* he should have send us the highest version
	 * he supports.
	 */
	if (ver == GNUTLS_VERSION_UNKNOWN || ver > version) {
		gnutls_assert();
		return GNUTLS_E_UNSUPPORTED_VERSION_PACKET;
	}
	_gnutls_set_current_version(state, ver);

	/* Read client random value.
	 */
	DECR_LEN(len, TLS_RANDOM_SIZE);
	_gnutls_set_client_random(state, &data[pos]);
	pos += TLS_RANDOM_SIZE;

	_gnutls_create_random(random);
	_gnutls_set_server_random(state, random);

	state->security_parameters.timestamp = time(NULL);

	DECR_LEN(len, 1);
	session_id_len = data[pos++];

	/* RESUME SESSION 
	 */
	if (session_id_len > TLS_MAX_SESSION_ID_SIZE) {
		gnutls_assert();
		return GNUTLS_E_UNEXPECTED_PACKET_LENGTH;
	}
	DECR_LEN(len, session_id_len);
	ret = _gnutls_server_restore_session(state, &data[pos], session_id_len);
	pos += session_id_len;

	if (ret == 0) {		/* resumed! */
		resume_copy_required_values(state);
		state->gnutls_internals.resumed = RESUME_TRUE;
		return 0;
	} else {
		_gnutls_generate_session_id(state->security_parameters.
					    session_id,
					    &state->security_parameters.
					    session_id_size);

		state->gnutls_internals.resumed = RESUME_FALSE;
	}

	/* Select a ciphersuite 
	 */
	DECR_LEN(len, 2);
	sizeOfSuites = _gnutls_read_uint16(&data[pos]);
	pos += 2;

	DECR_LEN(len, sizeOfSuites);
	suite_ptr = &data[pos];
	pos += sizeOfSuites;

	/* Select an appropriate compression method
	 */
	DECR_LEN(len, 1);
	z = data[pos++]; /* z is the number of compression methods */

	DECR_LEN(len, z);
	ret = _gnutls_server_select_comp_method(state, &data[pos], z);
	pos += z;

	if (ret < 0) {
		gnutls_assert();
		return ret;
	}
	
	/* Parse the extensions (if any)
	 */
	if (ver >= GNUTLS_TLS1) {
		ret = _gnutls_parse_extensions(state, &data[pos], len);	/* len is the rest of the parsed length */
		if (ret < 0) {
			gnutls_assert();
			return ret;
		}
	}
	
	/* select an appropriate cipher suite
	 */
	ret = _gnutls_server_select_suite(state, suite_ptr, sizeOfSuites);
	if (ret < 0) {
		gnutls_assert();
		return ret;
	}

	return 0;
}

/* here we hash all pending data. 
 */
inline static int
_gnutls_handshake_hash_pending( GNUTLS_STATE state) {
int siz, ret;
char * data;

	if (state->gnutls_internals.handshake_mac_handle_sha==NULL ||
		state->gnutls_internals.handshake_mac_handle_md5==NULL) {
		gnutls_assert();
		return GNUTLS_E_INTERNAL_ERROR;
	}

	/* We check if there are pending data to hash.
	 */
	if ((ret=_gnutls_handshake_buffer_get_ptr(state, &data, &siz)) < 0) {
		gnutls_assert();
		return ret;
	}

	if (siz > 0) {
		_gnutls_hash( state->gnutls_internals.handshake_mac_handle_sha, data, siz);
		_gnutls_hash( state->gnutls_internals.handshake_mac_handle_md5, data, siz);
	}
	
	_gnutls_handshake_buffer_empty( state);
	
	return 0;
}


/* This is to be called after sending CHANGE CIPHER SPEC packet
 * and initializing encryption. This is the first encrypted message
 * we send.
 */
int _gnutls_send_finished(GNUTLS_STATE state, int again)
{
	uint8 data[36];
	int ret=0;
	int data_size = 0;


	if (again == 0) {

		/* This needed in order to hash all the required
		 * messages.
		 */
		if ((ret=_gnutls_handshake_hash_pending(state)) < 0) {
			gnutls_assert();
			return ret;
		}

		if (gnutls_protocol_get_version( state) == GNUTLS_SSL3) {
			ret =
			    _gnutls_ssl3_finished(state,
						  state->
						  security_parameters.
						  entity, data);
			data_size = 36;
		} else {	/* TLS 1.0 */
			ret =
			    _gnutls_finished(state,
					     state->security_parameters.
					     entity, data);
			data_size = 12;
		}
	}

	if (ret < 0) {
		gnutls_assert();
		return ret;
	}

	ret =
	    _gnutls_send_handshake(state, data, data_size,
				   GNUTLS_FINISHED);

	return ret;
}

/* This is to be called after sending our finished message. If everything
 * went fine we have negotiated a secure connection 
 */
int _gnutls_recv_finished(GNUTLS_STATE state)
{
	uint8 data[36], *vrfy;
	int data_size;
	int ret;
	int vrfysize;

	ret = 0;

	ret =
	    _gnutls_recv_handshake(state, &vrfy, &vrfysize,
				   GNUTLS_FINISHED, MANDATORY_PACKET);
	if (ret < 0) {
		ERR("recv finished int", ret);
		gnutls_assert();
		return ret;
	}


	if ( gnutls_protocol_get_version( state) == GNUTLS_SSL3) {
		data_size = 36;
	} else {
		data_size = 12;
	}

	if (vrfysize != data_size) {
		gnutls_assert();
		return GNUTLS_E_ERROR_IN_FINISHED_PACKET;
	}

	if (gnutls_protocol_get_version( state) == GNUTLS_SSL3) {
		ret =
		    _gnutls_ssl3_finished(state,
					  (state->security_parameters.
					   entity + 1) % 2, data);
	} else {		/* TLS 1.0 */
		ret =
		    _gnutls_finished(state,
				     (state->security_parameters.entity +
				      1) % 2, data);
	}

	if (ret < 0) {
		gnutls_assert();
		return ret;
	}

	if (memcmp(vrfy, data, data_size) != 0) {
		gnutls_assert();
		ret = GNUTLS_E_ERROR_IN_FINISHED_PACKET;
	}
	gnutls_free(vrfy);

	return ret;
}

/* returns PK_RSA if the given cipher suite list only supports,
 * RSA algorithms, PK_DSA if DSS, and -1 if both or none.
 */
int _gnutls_find_pk_algos_in_ciphersuites( opaque* data, int datalen) {
int j;
PKAlgorithm algo=-1, prev_algo = 0;
KXAlgorithm kx;

	for (j = 0; j < datalen; j += 2) {
		kx = _gnutls_cipher_suite_get_kx_algo(*((GNUTLS_CipherSuite *) & data[j]));
		
		if ( _gnutls_map_kx_get_cred( kx) == GNUTLS_CRD_CERTIFICATE) {
			algo = _gnutls_map_pk_get_pk( kx);
	
			if (algo!=prev_algo && prev_algo!=0) return -1;
			prev_algo = algo;
		}
	}

	return algo;
}


/* This selects the best supported ciphersuite from the ones supported. Then
 * it adds the suite into the state and performs some checks. 
 */
int _gnutls_server_select_suite(GNUTLS_STATE state, opaque *data, int datalen)
{
	int x, i, j;
	GNUTLS_CipherSuite *ciphers;
	int retval, err;
	PKAlgorithm pk_algo; /* will hold the pk algorithms
			      * supported by the peer.
			      */

	pk_algo = _gnutls_find_pk_algos_in_ciphersuites( data, datalen);

	x = _gnutls_supported_ciphersuites(state, &ciphers);
	if (x<=0) {
		gnutls_assert();
		if (x<0) return x; 
		else return GNUTLS_E_INVALID_REQUEST;
	}

	/* Here we remove any ciphersuite that does not conform
	 * the certificate requested, or to the
	 * authentication requested (eg SRP).
	 */
	x = _gnutls_remove_unwanted_ciphersuites(state, &ciphers, x, pk_algo);
	if (x<=0) {
		gnutls_assert();
		if (x<0) return x;
		else return GNUTLS_E_INSUFICIENT_CRED;
	}

#ifdef HANDSHAKE_DEBUG
	_gnutls_handshake_log("HSK: Requested cipher suites: \n");
	for (j = 0; j < datalen; j += 2)
		_gnutls_handshake_log("\t%s\n",
			    _gnutls_cipher_suite_get_name(*
							  ((GNUTLS_CipherSuite *) & data[j])));
	_gnutls_handshake_log("HSK: Supported cipher suites: \n");
	for (j = 0; j < x; j++)
		_gnutls_handshake_log("\t%s\n",
			    _gnutls_cipher_suite_get_name(ciphers[j]));
#endif
	memset(state->security_parameters.current_cipher_suite.CipherSuite, '\0', 2);

	retval = GNUTLS_E_UNKNOWN_CIPHER_SUITE;
	
	for (j = 0; j < datalen; j += 2) {
		for (i = 0; i < x; i++) {
			if (memcmp(ciphers[i].CipherSuite, &data[j], 2) ==
			    0) {
				_gnutls_handshake_log("HSK: Selected cipher suite: ");
				_gnutls_handshake_log("%s\n",
					    _gnutls_cipher_suite_get_name(*
									  ((GNUTLS_CipherSuite *) & data[j])));
				memcpy(state->security_parameters.current_cipher_suite.CipherSuite, ciphers[i].CipherSuite, 2);
				retval = 0;
				goto finish;
			}
		}
	}

	finish:
	gnutls_free(ciphers);
	
	if (retval != 0) {
		gnutls_assert();
		return retval;
	}
	
	/* check if the credentials (username, public key etc. are ok)
	 */
	if (_gnutls_get_kx_cred
	    (state->gnutls_key,
	     _gnutls_cipher_suite_get_kx_algo(state->security_parameters.
					      current_cipher_suite),
	     &err) == NULL && err != 0) {
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

		_gnutls_handshake_log
		    ("HSK: Cannot find the appropriate handler for the KX algorithm\n");
		gnutls_assert();
		return GNUTLS_E_UNKNOWN_CIPHER_TYPE;
	}

	return 0;

}


/* This selects the best supported compression method from the ones provided 
 */
int _gnutls_server_select_comp_method(GNUTLS_STATE state, opaque * data,
				    int datalen)
{
	int x, i, j;
	uint8 *ciphers;

	x = _gnutls_supported_compression_methods(state, &ciphers);
	memset( &state->gnutls_internals.compression_method, '\0', sizeof(CompressionMethod));

	for (j = 0; j < datalen; j++) {
		for (i = 0; i < x; i++) {
			if (ciphers[i] == data[j]) {
				state->gnutls_internals.compression_method =
				    _gnutls_compression_get_id(ciphers[i]);
				gnutls_free(ciphers);

				_gnutls_handshake_log("HSK: Selected Compression Method: %s\n",
				    gnutls_compression_get_name(state->gnutls_internals.
							compression_method));


				return 0;
			}
		}
	}

	/* we were not able to find a compatible compression
	 * algorithm
	 */
	gnutls_free(ciphers);
	gnutls_assert();
	return GNUTLS_E_UNKNOWN_COMPRESSION_ALGORITHM;

}

/* This function sends an empty handshake packet. (like hello request).
 * If the previous _gnutls_send_empty_handshake() returned
 * GNUTLS_E_AGAIN or GNUTLS_E_INTERRUPTED, then it must be called again 
 * (until it returns ok), with NULL parameters.
 */
int _gnutls_send_empty_handshake(GNUTLS_STATE state, HandshakeType type,
				 int again)
{
	opaque data = 0;
	opaque *ptr;

	if (again == 0)
		ptr = &data;
	else
		ptr = NULL;

	return _gnutls_send_handshake(state, ptr, 0, type);
}


/* This function will hash the handshake message we sent.
 */
static
int _gnutls_handshake_hash_add_sent( GNUTLS_STATE state, HandshakeType type,
	opaque* dataptr, uint32 datalen) {
int ret;

	if ( (ret=_gnutls_handshake_hash_pending( state)) < 0) {
		gnutls_assert();
		return ret;
	}

	if ( type != GNUTLS_HELLO_REQUEST) {
		_gnutls_hash( state->gnutls_internals.handshake_mac_handle_sha, dataptr, datalen);
		_gnutls_hash( state->gnutls_internals.handshake_mac_handle_md5, dataptr, datalen);
	}

	return 0;
}


/* This function sends a handshake message of type 'type' containing the
 * data specified here. If the previous _gnutls_send_handshake() returned
 * GNUTLS_E_AGAIN or GNUTLS_E_INTERRUPTED, then it must be called again 
 * (until it returns ok), with NULL parameters.
 */
int _gnutls_send_handshake(GNUTLS_STATE state, void *i_data,
			   uint32 i_datasize, HandshakeType type)
{
	int ret;
	uint8 *data;
	uint32 datasize;
	int pos = 0;

	/* to know where the procedure was interrupted.
	 */
	state->gnutls_internals.handshake_direction = 1; /* write */

	if (i_data == NULL && i_datasize == 0) {
		/* we are resuming a previously interrupted
		 * send.
		 */
		ret = _gnutls_handshake_io_write_flush(state);
		return ret;

	}

	if (i_data == NULL && i_datasize > 0) {
		gnutls_assert();
		return GNUTLS_E_INVALID_PARAMETERS;
	}

	/* first run */
	datasize = i_datasize + HANDSHAKE_HEADER_SIZE;
	data = gnutls_alloca(datasize);
	if (data == NULL) {
		gnutls_assert();
		return GNUTLS_E_MEMORY_ERROR;
	}

	data[pos++] = (uint8) type;
	_gnutls_write_uint24(i_datasize, &data[pos]);
	pos += 3;

	if (i_datasize > 0)
		memcpy(&data[pos], i_data, i_datasize);

	_gnutls_handshake_log("HSK: %s was send [%ld bytes]\n",
		    _gnutls_handshake2str(type), datasize);


	/* Here we keep the handshake messages in order to hash them...
	 */
	if ( type != GNUTLS_HELLO_REQUEST)
		if ( (ret= _gnutls_handshake_hash_add_sent( state, type, data, datasize)) < 0) {
				gnutls_assert();
				gnutls_afree(data);
				return ret;
		}

	ret =
	    _gnutls_handshake_io_send_int(state, GNUTLS_HANDSHAKE, type,
				       data, datasize);

	gnutls_afree(data);

	return ret;
}

/* This function will read the handshake header, and return it to the called. If the
 * received handshake packet is not the one expected then it buffers the header, and
 * returns UNEXPECTED_HANDSHAKE_PACKET.
 *
 * FIXME: This function is complex.
 */
#define SSL2_HEADERS 1
static int _gnutls_recv_handshake_header(GNUTLS_STATE state,
					 HandshakeType type,
					 HandshakeType * recv_type)
{
	int ret;
	uint32 length32 = 0;
	uint8 *dataptr = NULL;	/* for realloc */
	int handshake_header_size = HANDSHAKE_HEADER_SIZE;

	/* if we have data into the buffer then return them, do not read the next packet.
	 * In order to return we need a full TLS handshake header, or in case of a version 2
	 * packet, then we return the first byte.
	 */
	if (state->gnutls_internals.handshake_header_buffer.header_size ==
	    handshake_header_size || (state->gnutls_internals.v2_hello != 0
				      && type == GNUTLS_CLIENT_HELLO
				      && state->gnutls_internals.
				      handshake_header_buffer.
				      packet_length > 0)) {

		*recv_type =
		    state->gnutls_internals.handshake_header_buffer.
		    recv_type;

		return state->gnutls_internals.handshake_header_buffer.
		    packet_length;
	}

	/* Note: SSL2_HEADERS == 1 */

	dataptr = state->gnutls_internals.handshake_header_buffer.header;

	/* If we haven't already read the handshake headers.
	 */
	if (state->gnutls_internals.handshake_header_buffer.header_size <
	    SSL2_HEADERS) {
		ret =
		    _gnutls_handshake_io_recv_int(state, GNUTLS_HANDSHAKE,
					       type, dataptr,
					       SSL2_HEADERS);

		if (ret < 0) {
			return (ret <
				0) ? ret :
			    GNUTLS_E_UNEXPECTED_PACKET_LENGTH;
		}

		if (ret != SSL2_HEADERS) {
			gnutls_assert();
			return GNUTLS_E_UNEXPECTED_PACKET_LENGTH;
		}
		state->gnutls_internals.handshake_header_buffer.
		    header_size = SSL2_HEADERS;
	}

	if (state->gnutls_internals.v2_hello == 0
	    || type != GNUTLS_CLIENT_HELLO) {
		ret =
		    _gnutls_handshake_io_recv_int(state, GNUTLS_HANDSHAKE,
					       type,
					       &dataptr[state->
							gnutls_internals.
							handshake_header_buffer.
							header_size],
					       HANDSHAKE_HEADER_SIZE -
					       state->gnutls_internals.
					       handshake_header_buffer.
					       header_size);
		if (ret <= 0) {
			gnutls_assert();
			return (ret <
				0) ? ret :
			    GNUTLS_E_UNEXPECTED_PACKET_LENGTH;
		}
		if (ret !=
		    HANDSHAKE_HEADER_SIZE -
		    state->gnutls_internals.handshake_header_buffer.
		    header_size) {
			gnutls_assert();
			return GNUTLS_E_UNEXPECTED_PACKET_LENGTH;
		}
		*recv_type = dataptr[0];

		/* we do not use DECR_LEN because we know
		 * that the packet has enough data.
		 */
		length32 = _gnutls_read_uint24(&dataptr[1]);
		handshake_header_size = HANDSHAKE_HEADER_SIZE;

		_gnutls_handshake_log("HSK: %s was received [%ld bytes]\n",
			    _gnutls_handshake2str(dataptr[0]),
			    length32 + HANDSHAKE_HEADER_SIZE);

	} else {		/* v2 hello */
		length32 = state->gnutls_internals.v2_hello - SSL2_HEADERS;	/* we've read the first byte */

		handshake_header_size = SSL2_HEADERS;	/* we've already read one byte */

		*recv_type = dataptr[0];

		_gnutls_handshake_log("HSK: %s(v2) was received [%ld bytes]\n",
			    _gnutls_handshake2str(*recv_type),
			    length32 + handshake_header_size);

		if (*recv_type != GNUTLS_CLIENT_HELLO) {	/* it should be one or nothing */
			gnutls_assert();
			return GNUTLS_E_UNEXPECTED_HANDSHAKE_PACKET;
		}
	}

	/* put the packet into the buffer */
	state->gnutls_internals.handshake_header_buffer.header_size =
	    handshake_header_size;
	state->gnutls_internals.handshake_header_buffer.packet_length =
	    length32;
	state->gnutls_internals.handshake_header_buffer.recv_type =
	    *recv_type;

	if (*recv_type != type) {
		gnutls_assert();
		return GNUTLS_E_UNEXPECTED_HANDSHAKE_PACKET;
	}

	return length32;
}

#define _gnutls_handshake_header_buffer_clear( state) state->gnutls_internals.handshake_header_buffer.header_size = 0



/* This function will hash the handshake headers and the
 * handshake data.
 */
static
int _gnutls_handshake_hash_add_recvd( GNUTLS_STATE state, HandshakeType recv_type,
	opaque* header, uint16 header_size, opaque* dataptr, uint32 datalen) {
int ret;

	/* The idea here is to hash the previous message we received,
	 * and add the one we just received into the handshake_hash_buffer.
	 */
	
	if ( (ret=_gnutls_handshake_hash_pending( state)) < 0) {
		gnutls_assert();
		return ret;
	}
	
	/* here we buffer the handshake messages - needed at Finished message */
	if ( recv_type != GNUTLS_HELLO_REQUEST) {

		if ((ret =
		     _gnutls_handshake_buffer_put(state, 
			    header, header_size)) < 0) {
			gnutls_assert();
			return ret;
		}

		if ( datalen > 0) {
			if ((ret =
			     _gnutls_handshake_buffer_put(state, dataptr,
						       datalen)) < 0) {
				gnutls_assert();
				return ret;
			}
		}
	}

	return 0;
}


/* This function will receive handshake messages of the given types,
 * and will pass the message to the right place in order to be processed.
 * Eg. for the SERVER_HELLO message (if it is expected), it will be
 * send to _gnutls_recv_hello().
 */
int _gnutls_recv_handshake(GNUTLS_STATE state, uint8 ** data,
			   int *datalen, HandshakeType type,
			   Optional optional)
{
	int ret;
	uint32 length32 = 0;
	opaque *dataptr = NULL;
	HandshakeType recv_type;

	/* to know where the procedure was interrupted.
	 */
	state->gnutls_internals.handshake_direction = 0; /* read */

	ret = _gnutls_recv_handshake_header(state, type, &recv_type);
	if (ret < 0) {
		if (ret == GNUTLS_E_UNEXPECTED_HANDSHAKE_PACKET
		    && optional == OPTIONAL_PACKET) {
			*datalen = 0;
			*data = NULL;
			return 0;	/* ok just ignore the packet */
		}
		/* gnutls_assert(); */
		return ret;
	}


	length32 = ret;

	if (length32 > 0)
		dataptr = gnutls_malloc(length32);
	else if (recv_type != GNUTLS_SERVER_HELLO_DONE) {
		gnutls_assert();
		return GNUTLS_E_UNEXPECTED_PACKET_LENGTH;
	}

	if (dataptr == NULL && length32 > 0) {
		gnutls_assert();
		return GNUTLS_E_MEMORY_ERROR;
	}

	if (datalen != NULL)
		*datalen = length32;

	if (length32 > 0) {
		ret =
		    _gnutls_handshake_io_recv_int(state, GNUTLS_HANDSHAKE,
					       type, dataptr, length32);
		if (ret <= 0) {
			gnutls_assert();
			gnutls_free(dataptr);
			return (ret ==
				0) ? GNUTLS_E_UNEXPECTED_PACKET_LENGTH :
			    ret;
		}
	}


	ret = GNUTLS_E_UNKNOWN_ERROR;

	if (data != NULL && length32 > 0)
		*data = dataptr;


	if ( (ret=_gnutls_handshake_hash_add_recvd( state, recv_type, 
		state->gnutls_internals.handshake_header_buffer.header,
		state->gnutls_internals.handshake_header_buffer.header_size,
		dataptr, length32)) < 0) {
		gnutls_assert();
		_gnutls_handshake_header_buffer_clear(state);
		return ret;
	}

	/* If we fail before this then we will reuse the handshake header
	 * have have received above. if we get here the we clear the handshake
	 * header we received.
	 */
	_gnutls_handshake_header_buffer_clear(state);

	switch (recv_type) {
	case GNUTLS_CLIENT_HELLO:
	case GNUTLS_SERVER_HELLO:
		ret = _gnutls_recv_hello(state, dataptr, length32);
		/* dataptr is freed because the caller does not
		 * need it */
		gnutls_free(dataptr);
		break;
	case GNUTLS_SERVER_HELLO_DONE:
		if (length32==0) ret = 0;
		else ret = GNUTLS_E_UNEXPECTED_PACKET_LENGTH;
		break;
	case GNUTLS_CERTIFICATE_PKT:
	case GNUTLS_FINISHED:
	case GNUTLS_SERVER_KEY_EXCHANGE:
	case GNUTLS_CLIENT_KEY_EXCHANGE:
	case GNUTLS_CERTIFICATE_REQUEST:
	case GNUTLS_CERTIFICATE_VERIFY:
		ret = length32;
		break;
	default:
		gnutls_assert();
		gnutls_free(dataptr);
		if (data!=NULL) *data = NULL;
		ret = GNUTLS_E_UNEXPECTED_HANDSHAKE_PACKET;
	}

	return ret;
}

/* This function checks if the given cipher suite is supported, and sets it
 * to the state;
 */
static int _gnutls_client_set_ciphersuite(GNUTLS_STATE state,
					  opaque suite[2])
{
	uint8 z;
	GNUTLS_CipherSuite *cipher_suites;
	uint16 x;
	int i, err;

	z = 1;
	x = _gnutls_supported_ciphersuites(state, &cipher_suites);
	for (i = 0; i < x; i++) {
		if (memcmp(&cipher_suites[i], suite, 2) == 0) {
			z = 0;
		}
	}

	gnutls_free(cipher_suites);

	if (z != 0) {
		gnutls_assert();
		return GNUTLS_E_UNKNOWN_CIPHER_TYPE;
	}

	memcpy(state->security_parameters.
	       current_cipher_suite.CipherSuite, suite, 2);

	_gnutls_handshake_log("HSK: Selected cipher suite: ");
	_gnutls_handshake_log("%s\n",
		    _gnutls_cipher_suite_get_name(state->
						  security_parameters.
						  current_cipher_suite));


	/* check if the credentials (username, public key etc. are ok). 
	 * Actually checks if they exist.
	 */
	if (_gnutls_get_kx_cred
	    (state->gnutls_key,
	     _gnutls_cipher_suite_get_kx_algo(state->
					      security_parameters.
					      current_cipher_suite),
	     &err) == NULL && err != 0) {
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

		_gnutls_handshake_log
		    ("HSK: Cannot find the appropriate handler for the KX algorithm\n");
		gnutls_assert();
		return GNUTLS_E_UNKNOWN_CIPHER_TYPE;
	}


	return 0;
}

/* This function sets the given comp method to the state.
 */
static int _gnutls_client_set_comp_method(GNUTLS_STATE state,
					  opaque comp_method)
{
	uint8 z;
	uint8 *compression_methods;
	int i;

	z = _gnutls_supported_compression_methods(state,
						  &compression_methods);
	for (i = 0; i < z; i++) {
		if (compression_methods[i] == comp_method) {
			z = 0;
		}
	}

	gnutls_free(compression_methods);

	if (z != 0) {
		gnutls_assert();
		return GNUTLS_E_UNKNOWN_COMPRESSION_ALGORITHM;
	}

	state->gnutls_internals.compression_method =
	    _gnutls_compression_get_id(comp_method);


	return 0;
}

/* This function returns 0 if we are resuming a session or -1 otherwise.
 * This also sets the variables in the state. Used only while reading a server
 * hello.
 */
static int _gnutls_client_check_if_resuming(GNUTLS_STATE state,
					    opaque * session_id,
					    int session_id_len)
{

	_gnutls_handshake_log("HSK: SessionID length: %d\n", session_id_len);
	_gnutls_handshake_log("HSK: SessionID: %s\n",
		    _gnutls_bin2hex(session_id, session_id_len));

	if ((state->gnutls_internals.resumed_security_parameters.
	     session_id_size > 0)
	    && memcmp(session_id,
		      state->gnutls_internals.
		      resumed_security_parameters.session_id,
		      session_id_len) == 0) {
		/* resume session */
		memcpy(state->gnutls_internals.
		       resumed_security_parameters.server_random,
		       state->security_parameters.server_random,
		       TLS_RANDOM_SIZE);
		memcpy(state->gnutls_internals.
		       resumed_security_parameters.client_random,
		       state->security_parameters.client_random,
		       TLS_RANDOM_SIZE);
		state->gnutls_internals.resumed = RESUME_TRUE;	/* we are resuming */

		return 0;
	} else {
		/* keep the new session id */
		state->gnutls_internals.resumed = RESUME_FALSE;	/* we are not resuming */
		state->security_parameters.session_id_size =
		    session_id_len;
		memcpy(state->security_parameters.session_id,
		       session_id, session_id_len);

		return -1;
	}
}


/* This function read and parse the server hello handshake message.
 * This function also restores resumed parameters if we are resuming a
 * session.
 */
static int _gnutls_read_server_hello(GNUTLS_STATE state, char *data,
				     int datalen)
{
	uint8 session_id_len = 0;
	int pos = 0;
	int ret = 0;
	GNUTLS_Version version;
	int len = datalen;

	if (datalen < 38) {
		gnutls_assert();
		return GNUTLS_E_UNEXPECTED_PACKET_LENGTH;
	}

	_gnutls_handshake_log("HSK: Server's version: %d.%d\n", data[pos], data[pos + 1]);

	DECR_LEN(len, 2);
	version = _gnutls_version_get(data[pos], data[pos + 1]);
	if (_gnutls_version_is_supported(state, version) == 0) {
		gnutls_assert();
		return GNUTLS_E_UNSUPPORTED_VERSION_PACKET;
	} else {
		_gnutls_set_current_version(state, version);
	}

	pos += 2;

	DECR_LEN(len, TLS_RANDOM_SIZE);
	_gnutls_set_server_random(state, &data[pos]);
	pos += TLS_RANDOM_SIZE;


	/* Read session ID
	 */
	DECR_LEN(len, 1);
	session_id_len = data[pos++];

	if (len < session_id_len) {
		gnutls_assert();
		return GNUTLS_E_UNSUPPORTED_VERSION_PACKET;
	}
	DECR_LEN(len, session_id_len);


	/* check if we are resuming and set the appropriate
	 * values;
	 */
	if (_gnutls_client_check_if_resuming
	    (state, &data[pos], session_id_len) == 0)
		return 0;
	pos += session_id_len;


	/* Check if the given cipher suite is supported and copy
	 * it to the state.
	 */

	DECR_LEN(len, 2);
	ret = _gnutls_client_set_ciphersuite(state, &data[pos]);
	if (ret < 0) {
		gnutls_assert();
		return ret;
	}
	pos += 2;



	/* move to compression 
	 */
	DECR_LEN(len, 1);

	ret = _gnutls_client_set_comp_method(state, data[pos++]);
	if (ret < 0) {
		gnutls_assert();
		return GNUTLS_E_UNKNOWN_COMPRESSION_ALGORITHM;
	}

	/* Parse extensions.
	 */
	if (version >= GNUTLS_TLS1) {
		ret = _gnutls_parse_extensions(state, &data[pos], len);	/* len is the rest of the parsed length */
		if (ret < 0) {
			gnutls_assert();
			return ret;
		}
	}
	return ret;
}


/* This function copies the appropriate ciphersuites, to a localy allocated buffer 
 * Needed in client hello messages. Returns the new data length.
 */
static int _gnutls_copy_ciphersuites(GNUTLS_STATE state,
				     opaque ** ret_data)
{
	int ret, i;
	GNUTLS_CipherSuite *cipher_suites;
	uint16 cipher_num;
	int datalen, pos;

	ret = _gnutls_supported_ciphersuites_sorted(state, &cipher_suites);
	if (ret <= 0) {
		gnutls_assert();
		if (ret==0) return GNUTLS_E_INVALID_REQUEST;
		else return ret;
	}

	/* Here we remove any ciphersuite that does not conform
	 * the certificate requested, or to the
	 * authentication requested (eg SRP).
	 */
	ret =
	    _gnutls_remove_unwanted_ciphersuites(state, &cipher_suites,
						 ret, -1);
	if (ret < 0) {
		gnutls_assert();
		return ret;
	}

	/* If no cipher suites were enabled.
	 */
	if (ret == 0) {
		gnutls_assert();
		return GNUTLS_E_INSUFICIENT_CRED;
	}

	cipher_num = ret;
	
	cipher_num *= sizeof(uint16);	/* in order to get bytes */
 
	datalen = pos = 0;

	datalen += sizeof(uint16) + cipher_num;

	*ret_data = gnutls_malloc(datalen);
	if (*ret_data == NULL) {
		gnutls_assert();
		return GNUTLS_E_MEMORY_ERROR;
	}

	_gnutls_write_uint16(cipher_num, *ret_data);
	pos += 2;

	for (i = 0; i < (cipher_num / 2); i++) {
		memcpy( &(*ret_data)[pos], cipher_suites[i].CipherSuite, 2);
		pos += 2;
	}

	gnutls_free(cipher_suites);

	return datalen;
}


/* This function copies the appropriate compression methods, to a localy allocated buffer 
 * Needed in hello messages. Returns the new data length.
 */
static int _gnutls_copy_comp_methods(GNUTLS_STATE state,
				     opaque ** ret_data)
{
	int ret, i;
	uint8 *compression_methods, comp_num;
	int datalen, pos;

	ret =
	    _gnutls_supported_compression_methods(state,
						  &compression_methods);
	if (ret < 0) {
		gnutls_assert();
		return ret;
	}

	comp_num = ret;

	datalen = pos = 0;
	datalen += comp_num + 1;

	*ret_data = gnutls_malloc(datalen);
	if (*ret_data == NULL) {
		gnutls_assert();
		return GNUTLS_E_MEMORY_ERROR;
	}

	(*ret_data)[pos++] = comp_num; /* put the number of compression methods */

	for (i = 0; i < comp_num; i++) {
		(*ret_data)[pos++] = compression_methods[i];
	}

	gnutls_free(compression_methods);

	return datalen;
}

/* This function sends the client hello handshake message.
 */
static int _gnutls_send_client_hello(GNUTLS_STATE state, int again)
{
	opaque *data = NULL;
	opaque *extdata;
	int extdatalen;
	int pos = 0;
	int datalen, ret = 0;
	opaque random[TLS_RANDOM_SIZE];
	GNUTLS_Version hver;

	opaque *SessionID =
	    state->gnutls_internals.resumed_security_parameters.session_id;
	uint8 session_id_len =
	    state->gnutls_internals.resumed_security_parameters.
	    session_id_size;

	if (SessionID == NULL || session_id_len == 0) {
		session_id_len = 0;
		SessionID = NULL;
	}

	data = NULL;
	datalen = 0;
	if (again == 0) {

		datalen = 2 + (session_id_len + 1) + TLS_RANDOM_SIZE;
		/* 2 for version, (4 for unix time + 28 for random bytes==TLS_RANDOM_SIZE) 
		 */
		 
		data = gnutls_malloc(datalen);
		if (data == NULL) {
			gnutls_assert();
			return GNUTLS_E_MEMORY_ERROR;
		}

		/* if we are resuming a session then we set the
		 * version number to the previously established.
		 */
		if (SessionID == NULL)
			hver = _gnutls_version_max(state);
		else {		/* we are resuming a session */
			hver =
			    state->gnutls_internals.
			    resumed_security_parameters.version;
		}

		if (hver <= 0) {
			if (hver == 0)
				hver = GNUTLS_E_UNKNOWN_ERROR;
			gnutls_assert();
			return hver;
		}

		data[pos++] = _gnutls_version_get_major(hver);
		data[pos++] = _gnutls_version_get_minor(hver);

		/* Set the version we advertized as maximum 
		 * (RSA uses it).
		 */
		_gnutls_set_adv_version( state, hver);

		/* Some implementations do not interoperate if we send a
		 * different version in the record layer.
		 * It seems they prefer to read the record's version
		 * as the one we actually requested.
		 *  The proper behaviour is to use the one in the client hello 
		 * handshake packet and ignore the one in the packet's record 
		 * header.
		 */
		if (state->gnutls_internals.default_record_version==0)
			_gnutls_set_current_version(state, hver);
		else _gnutls_set_current_version(state,
			state->gnutls_internals.default_record_version);

		/* In order to know when this session was initiated.
		 */
		state->security_parameters.timestamp = time(NULL);

		/* Generate random data 
		 */
		_gnutls_create_random(random);
		_gnutls_set_client_random(state, random);

		memcpy(&data[pos], random, TLS_RANDOM_SIZE);
		pos += TLS_RANDOM_SIZE;

		/* Copy the Session ID 
		 */
		data[pos++] = session_id_len;

		if (session_id_len > 0) {
			memcpy(&data[pos], SessionID, session_id_len);
		}
		pos += session_id_len;


		/* Copy the ciphersuites.
		 */
		extdatalen = _gnutls_copy_ciphersuites(state, &extdata);
		if (extdatalen > 0) {
			datalen += extdatalen;
			data = gnutls_realloc(data, datalen);
			if (data == NULL) {
				gnutls_assert();
				gnutls_free(extdata);
				return GNUTLS_E_MEMORY_ERROR;
			}

			memcpy(&data[pos], extdata, extdatalen);
			gnutls_free(extdata);
			pos += extdatalen;

		} else {
			if (extdatalen == 0)
				extdatalen = GNUTLS_E_UNKNOWN_ERROR;
			gnutls_free(data);
			gnutls_assert();
			return extdatalen;
		}


		/* Copy the compression methods.
		 */
		extdatalen = _gnutls_copy_comp_methods(state, &extdata);
		if (extdatalen > 0) {
			datalen += extdatalen;
			data = gnutls_realloc(data, datalen);
			if (data == NULL) {
				gnutls_assert();
				gnutls_free(extdata);
				return GNUTLS_E_MEMORY_ERROR;
			}

			memcpy(&data[pos], extdata, extdatalen);
			gnutls_free(extdata);
			pos += extdatalen;

		} else {
			if (extdatalen == 0)
				extdatalen = GNUTLS_E_UNKNOWN_ERROR;
			gnutls_free(data);
			gnutls_assert();
			return extdatalen;
		}

		/* Generate and copy TLS extensions.
		 */
		if (hver >= GNUTLS_TLS1) {
			extdatalen = _gnutls_gen_extensions(state, &extdata);
			if (extdatalen > 0) {
				datalen += extdatalen;
				data = gnutls_realloc(data, datalen);
				if (data == NULL) {
					gnutls_assert();
					gnutls_free(extdata);
					return GNUTLS_E_MEMORY_ERROR;
				}

				memcpy(&data[pos], extdata, extdatalen);
				gnutls_free(extdata);
			}
		}
	}

	ret =
	    _gnutls_send_handshake(state, data, datalen,
				   GNUTLS_CLIENT_HELLO);
	gnutls_free(data);

	return ret;
}

static int _gnutls_send_server_hello(GNUTLS_STATE state, int again)
{
	opaque *data;
	opaque *extdata;
	int extdatalen;
	int pos = 0;
	int datalen, ret = 0;
	uint8 comp;
	opaque *SessionID = state->security_parameters.session_id;
	uint8 session_id_len = state->security_parameters.session_id_size;

	if (SessionID == NULL)
		session_id_len = 0;

	data = NULL;
	datalen = 0;

	if (again == 0) {
		datalen = 2 + session_id_len + 1 + TLS_RANDOM_SIZE + 3;
		extdatalen = _gnutls_gen_extensions(state, &extdata);

		data = gnutls_alloca(datalen + extdatalen);
		if (data == NULL) {
			gnutls_assert();
			gnutls_free(extdata);
			return GNUTLS_E_MEMORY_ERROR;
		}

		data[pos++] =
		    _gnutls_version_get_major(state->security_parameters.
					      version);
		data[pos++] =
		    _gnutls_version_get_minor(state->security_parameters.
					      version);

		memcpy(&data[pos],
		       state->security_parameters.server_random,
		       TLS_RANDOM_SIZE);
		pos += TLS_RANDOM_SIZE;

		data[pos++] = session_id_len;
		if (session_id_len > 0) {
			memcpy(&data[pos], SessionID, session_id_len);
		}
		pos += session_id_len;

		_gnutls_handshake_log("HSK: SessionID: %s\n",
			    _gnutls_bin2hex(SessionID, session_id_len));

		memcpy(&data[pos],
		       state->security_parameters.
		       current_cipher_suite.CipherSuite, 2);
		pos += 2;

		comp =
		    (uint8) _gnutls_compression_get_num(state->
							gnutls_internals.
							compression_method);
		data[pos++] = comp;


		if (extdatalen > 0) {
			datalen += extdatalen;

			memcpy(&data[pos], extdata, extdatalen);
			gnutls_free(extdata);
		}
	}

	ret =
	    _gnutls_send_handshake(state, data, datalen,
				   GNUTLS_SERVER_HELLO);
	gnutls_afree(data);

	return ret;
}

int _gnutls_send_hello(GNUTLS_STATE state, int again)
{
	int ret;

	if (state->security_parameters.entity == GNUTLS_CLIENT) {
		ret = _gnutls_send_client_hello(state, again);

	} else {		/* SERVER */
		ret = _gnutls_send_server_hello(state, again);
	}

	return ret;
}

/* RECEIVE A HELLO MESSAGE. This should be called from gnutls_recv_handshake_int only if a
 * hello message is expected. It uses the security_parameters.current_cipher_suite
 * and gnutls_internals.compression_method.
 */
int _gnutls_recv_hello(GNUTLS_STATE state, char *data, int datalen)
{
	int ret;

	if (state->security_parameters.entity == GNUTLS_CLIENT) {
		ret = _gnutls_read_server_hello(state, data, datalen);
		if (ret < 0) {
			gnutls_assert();
			return ret;
		}
	} else {		/* Server side reading a client hello */

		ret = _gnutls_read_client_hello(state, data, datalen);
		if (ret < 0) {
			gnutls_assert();
			return ret;
		}
	}

	return ret;
}

/* The packets in gnutls_handshake (it's more broad than original TLS handshake)
 *
 *     Client                                               Server
 *
 *     ClientHello                  -------->
 *                                  <--------         ServerHello
 *
 *                                                    Certificate*
 *                                              ServerKeyExchange*
 *     Client Key Exchange0         -------->
 *                                  <--------   CertificateRequest*
 *
 *                                  <--------   Server Key Exchange2
 *                                  <--------      ServerHelloDone
 *     Certificate*
 *     ClientKeyExchange
 *     CertificateVerify*
 *     [ChangeCipherSpec]
 *     Finished                     -------->
 *                                              [ChangeCipherSpec]
 *                                  <--------             Finished
 *
 * (*): means optional packet.
 */

/**
  * gnutls_rehandshake - This function will renegotiate security parameters
  * @state: is a a &GNUTLS_STATE structure.
  *
  * This function will renegotiate security parameters with the
  * client. This should only be called in case of a server.
  *
  * This message informs the peer that we want to renegotiate
  * parameters (perform a handshake).
  *
  * If this function succeeds (returns 0), you must call
  * the gnutls_handshake() function in order to negotiate
  * the new parameters.
  *
  * If the client does not wish to renegotiate parameters he
  * will reply with an alert message, thus the return code will be
  * GNUTLS_E_WARNING_ALERT_RECEIVED and the alert will be
  * GNUTLS_A_NO_RENEGOTIATION.
  **/
int gnutls_rehandshake(GNUTLS_STATE state)
{
	int ret;

	/* only server sends that handshake packet */
	if (state->security_parameters.entity == GNUTLS_CLIENT)
		return GNUTLS_E_INVALID_REQUEST;

	ret =
	    _gnutls_send_empty_handshake(state, GNUTLS_HELLO_REQUEST,
					 AGAIN(STATE50));
	STATE = STATE50;

	if (ret < 0) {
		gnutls_assert();
		return ret;
	}
	STATE = STATE0;

	return 0;
}

/**
  * gnutls_handshake_get_direction - This function will return the state of the handshake protocol
  * @state: is a a &GNUTLS_STATE structure.
  *
  * This function provides information about the handshake procedure, and
  * is only useful if the gnutls_handshake() call was interrupted for some
  * reason.
  *
  * Returns 0 if the function was interrupted while receiving data, and 
  * 1 otherwise. 
  *
  **/
int gnutls_handshake_get_direction(GNUTLS_STATE state) {
	return state->gnutls_internals.handshake_direction;
}

static int _gnutls_abort_handshake( GNUTLS_STATE state, int ret) {
	if ( ((ret==GNUTLS_E_WARNING_ALERT_RECEIVED) && 
		( gnutls_alert_get(state) == GNUTLS_A_NO_RENEGOTIATION))
		|| ret==GNUTLS_E_GOT_APPLICATION_DATA)
			return 0;

	/* this doesn't matter */
	return GNUTLS_E_UNKNOWN_ERROR;
}


/* This function initialized the handshake hash state.
 * required for finished messages.
 */
inline
static int _gnutls_handshake_hash_init( GNUTLS_STATE state) {

	if ( state->gnutls_internals.handshake_mac_handle_md5==NULL) {
		state->gnutls_internals.handshake_mac_handle_md5 = _gnutls_hash_init( GNUTLS_MAC_MD5);

		if (state->gnutls_internals.handshake_mac_handle_md5==GNUTLS_HASH_FAILED) {
			gnutls_assert();
			return GNUTLS_E_MEMORY_ERROR;
		}
	}

	if ( state->gnutls_internals.handshake_mac_handle_sha==NULL) {
		state->gnutls_internals.handshake_mac_handle_sha = _gnutls_hash_init( GNUTLS_MAC_SHA);
		if (state->gnutls_internals.handshake_mac_handle_sha==GNUTLS_HASH_FAILED) {
			gnutls_assert();
			return GNUTLS_E_MEMORY_ERROR;
		}
	}

	return 0;
}		

/**
  * gnutls_handshake - This the main function in the handshake protocol.
  * @state: is a a &GNUTLS_STATE structure.
  *
  * This function does the handshake of the TLS/SSL protocol,
  * and initializes the TLS connection. 
  *
  * This function will fail if any problem is encountered,
  * and will return a negative error code. In case of a client,
  * if it has been asked to resume a session, but the server didn't, then
  * a full handshake will be performed.
  *
  * This function may also return the non-fatal errors GNUTLS_E_AGAIN, or 
  * GNUTLS_E_INTERRUPTED. In that case you may resume the handshake
  * (call this function again, until it returns ok)
  *
  * If this function is called by a server after a rehandshake request then
  * GNUTLS_E_GOT_APPLICATION_DATA or GNUTLS_E_WARNING_ALERT_RECEIVED 
  * may be returned. Note that these are non fatal errors, only in the
  * case of a rehandshake. In that case they mean that the client
  * rejected the rehandshake request.
  *
  **/
int gnutls_handshake(GNUTLS_STATE state)
{
	int ret;

	if ( (ret=_gnutls_handshake_hash_init( state)) < 0) {
		gnutls_assert();
		return ret;
	}

	if (state->security_parameters.entity == GNUTLS_CLIENT) {
		ret = gnutls_handshake_client(state);
	} else {
		ret = gnutls_handshake_server(state);
	}
	if (ret < 0) {
		/* In the case of a rehandshake abort
		 * we should reset the handshake's state
		 */
		if (_gnutls_abort_handshake( state, ret) == 0)
			STATE = STATE0;
		return ret;
	}
	
	ret = gnutls_handshake_common(state);

	if (ret < 0) {
		if (_gnutls_abort_handshake( state, ret) == 0)
			STATE = STATE0;
		return ret;
	}
	
	STATE = STATE0;

	_gnutls_handshake_io_buffer_clear(state);
	_gnutls_handshake_internal_state_clear(state);

	return 0;
}

#define IMED_RET( str, ret) \
	if (ret < 0) { \
		if (gnutls_error_is_fatal(ret)==0) return ret; \
		gnutls_assert(); \
		ERR( str, ret); \
		_gnutls_handshake_hash_buffers_clear(state); \
		return ret; \
	}



/*
 * gnutls_handshake_client 
 * This function performs the client side of the handshake of the TLS/SSL protocol.
 */
int gnutls_handshake_client(GNUTLS_STATE state)
{
	int ret = 0;

#ifdef HANDSHAKE_DEBUG
	if (state->gnutls_internals.resumed_security_parameters.
	    session_id_size > 0)
		_gnutls_handshake_log("HSK: Ask to resume: %s\n",
			    _gnutls_bin2hex(state->gnutls_internals.
					    resumed_security_parameters.
					    session_id,
					    state->gnutls_internals.
					    resumed_security_parameters.
					    session_id_size));
#endif

	switch (STATE) {
	case STATE0:
	case STATE1:
		ret = _gnutls_send_hello(state, AGAIN(STATE1));
		STATE = STATE1;
		IMED_RET("send hello", ret);

	case STATE2:
		/* receive the server hello */
		ret =
		    _gnutls_recv_handshake(state, NULL, NULL,
					   GNUTLS_SERVER_HELLO,
					   MANDATORY_PACKET);
		STATE = STATE2;
		IMED_RET("recv hello", ret);

	case STATE3:
		/* RECV CERTIFICATE */
		if (state->gnutls_internals.resumed == RESUME_FALSE)	/* if we are not resuming */
			ret = _gnutls_recv_server_certificate(state);
		STATE = STATE3;
		IMED_RET("recv server certificate", ret);

	case STATE4:
		/* receive the server key exchange */
		if (state->gnutls_internals.resumed == RESUME_FALSE)	/* if we are not resuming */
			ret = _gnutls_recv_server_kx_message(state);
		STATE = STATE4;
		IMED_RET("recv server kx message", ret);

	case STATE5:
		/* Added for SRP, 
		 * send the client key exchange for SRP 
		 */
		if (state->gnutls_internals.resumed == RESUME_FALSE)	/* if we are not resuming */
			ret =
			    _gnutls_send_client_kx_message0(state,
							    AGAIN(STATE5));
		STATE = STATE5;
		IMED_RET("send client kx0", ret);

	case STATE6:
		/* receive the server certificate request - if any 
		 */

		if (state->gnutls_internals.resumed == RESUME_FALSE)	/* if we are not resuming */
			ret =
			    _gnutls_recv_server_certificate_request(state);
		STATE = STATE6;
		IMED_RET("recv server certificate request message", ret);

	case STATE7:
		/* receive the server key exchange (B) (SRP only) 
		 */

		if (state->gnutls_internals.resumed == RESUME_FALSE)	/* if we are not resuming */
			ret = _gnutls_recv_server_kx_message2(state);
		STATE = STATE7;
		IMED_RET("recv server kx message2", ret);

	case STATE8:
		/* receive the server hello done */
		if (state->gnutls_internals.resumed == RESUME_FALSE)	/* if we are not resuming */
			ret =
			    _gnutls_recv_handshake(state, NULL, NULL,
						   GNUTLS_SERVER_HELLO_DONE,
						   MANDATORY_PACKET);
		STATE = STATE8;
		IMED_RET("recv server hello done", ret);

	case STATE9:
		/* send our certificate - if any and if requested
		 */
		if (state->gnutls_internals.resumed == RESUME_FALSE)	/* if we are not resuming */
			ret =
			    _gnutls_send_client_certificate(state,
							    AGAIN(STATE9));
		STATE = STATE9;
		IMED_RET("send client certificate", ret);

	case STATE10:
		if (state->gnutls_internals.resumed == RESUME_FALSE)	/* if we are not resuming */
			ret =
			    _gnutls_send_client_kx_message(state,
							   AGAIN(STATE10));
		STATE = STATE10;
		IMED_RET("send client kx", ret);

	case STATE11:
		/* send client certificate verify */
		if (state->gnutls_internals.resumed == RESUME_FALSE)	/* if we are not resuming */
			ret =
			    _gnutls_send_client_certificate_verify(state,
								   AGAIN
								   (STATE11));
		STATE = STATE11;
		IMED_RET("send client certificate verify", ret);

		STATE = STATE0;
	default:
	}


	return 0;
}

/* This function sends the final handshake packets and initializes connection 
 */
static int _gnutls_send_handshake_final(GNUTLS_STATE state, int init)
{
	int ret = 0;

	/* to know where the procedure was interrupted.
	 */
	state->gnutls_internals.handshake_direction = 1; /* write */

	/* Send the CHANGE CIPHER SPEC PACKET */

	switch (STATE) {
	case STATE0:
	case STATE20:
		ret =
		    _gnutls_send_change_cipher_spec(state, AGAIN(STATE20));
		STATE = STATE20;
		if (ret < 0) {
			ERR("send ChangeCipherSpec", ret);
			gnutls_assert();
			return ret;
		}

		/* Initialize the connection state (start encryption) - in case of client 
		 */
		if (init == TRUE) {
			ret = _gnutls_connection_state_init(state);
			if (ret < 0) {
				gnutls_assert();
				return ret;
			}
		}

		ret = _gnutls_write_connection_state_init(state);
		if (ret < 0) {
			gnutls_assert();
			return ret;
		}

	case STATE21:
		/* send the finished message */
		ret = _gnutls_send_finished(state, AGAIN(STATE21));
		STATE = STATE21;
		if (ret < 0) {
			ERR("send Finished", ret);
			gnutls_assert();
			return ret;
		}

		STATE = STATE0;
	default:
	}

	return 0;
}

/* This function receives the final handshake packets 
 * And executes the appropriate function to initialize the
 * read state.
 */
static int _gnutls_recv_handshake_final(GNUTLS_STATE state, int init)
{
	int ret = 0;
	uint8 ch;

	/* to know where the procedure was interrupted.
	 */
	state->gnutls_internals.handshake_direction = 0; /* recv */

	switch (STATE) {
	case STATE0:
	case STATE30:
		ret =
		    gnutls_recv_int(state, GNUTLS_CHANGE_CIPHER_SPEC, -1,
				    &ch, 1);
		STATE = STATE30;
		if (ret <= 0) {
			ERR("recv ChangeCipherSpec", ret);
			gnutls_assert();
			return (ret <
				0) ? ret :
			    GNUTLS_E_UNEXPECTED_PACKET_LENGTH;
		}

		/* Initialize the connection state (start encryption) - in case of server */
		if (init == TRUE) {
			ret = _gnutls_connection_state_init(state);
			if (ret < 0) {
				gnutls_assert();
				return ret;
			}
		}

		ret = _gnutls_read_connection_state_init(state);
		if (ret < 0) {
			gnutls_assert();
			return ret;
		}

	case STATE31:
		ret = _gnutls_recv_finished(state);
		STATE = STATE31;
		if (ret < 0) {
			ERR("recv finished", ret);
			gnutls_assert();
			return ret;
		}
		STATE = STATE0;
	default:
	}


	return 0;
}

 /*
  * gnutls_handshake_server 
  * This function does the server stuff of the handshake protocol.
  */

int gnutls_handshake_server(GNUTLS_STATE state)
{
	int ret = 0;

	switch (STATE) {
	case STATE0:
	case STATE1:
		ret =
		    _gnutls_recv_handshake(state, NULL, NULL,
					   GNUTLS_CLIENT_HELLO,
					   MANDATORY_PACKET);
		STATE = STATE1;
		IMED_RET("recv hello", ret);

	case STATE2:
		ret = _gnutls_send_hello(state, AGAIN(STATE2));
		STATE = STATE2;
		IMED_RET("send hello", ret);

		/* SEND CERTIFICATE + KEYEXCHANGE + CERTIFICATE_REQUEST */
	case STATE3:
		/* NOTE: these should not be send if we are resuming */

		if (state->gnutls_internals.resumed == RESUME_FALSE)
			ret =
			    _gnutls_send_server_certificate(state,
							    AGAIN(STATE3));
		STATE = STATE3;
		IMED_RET("send server certificate", ret);

	case STATE4:
		/* send server key exchange (A) */
		if (state->gnutls_internals.resumed == RESUME_FALSE)
			ret =
			    _gnutls_send_server_kx_message(state,
							   AGAIN(STATE4));
		STATE = STATE4;
		IMED_RET("send server kx", ret);

	case STATE5:
		/* Send certificate request - if requested to */
		if (state->gnutls_internals.resumed == RESUME_FALSE)
			ret =
			    _gnutls_send_server_certificate_request(state,
								    AGAIN
								    (STATE5));
		STATE = STATE5;
		IMED_RET("send server cert request", ret);

	case STATE6:
		/* Added for SRP which uses a different handshake */
		/* receive the client key exchange message */

		if (state->gnutls_internals.resumed == RESUME_FALSE)	/* if we are not resuming */
			ret = _gnutls_recv_client_kx_message0(state);
		STATE = STATE6;
		IMED_RET("recv client kx0", ret);

	case STATE7:
		/* send server key exchange (B) */
		if (state->gnutls_internals.resumed == RESUME_FALSE)
			ret =
			    _gnutls_send_server_kx_message2(state,
							    AGAIN(STATE7));
		STATE = STATE7;
		IMED_RET("send server kx2", ret);

	case STATE8:
		/* send the server hello done */
		if (state->gnutls_internals.resumed == RESUME_FALSE)	/* if we are not resuming */
			ret =
			    _gnutls_send_empty_handshake(state,
							 GNUTLS_SERVER_HELLO_DONE,
							 AGAIN(STATE8));
		STATE = STATE8;
		IMED_RET("send server hello done", ret);


		/* RECV CERTIFICATE + KEYEXCHANGE + CERTIFICATE_VERIFY */
	case STATE9:
		/* receive the client certificate message */
		if (state->gnutls_internals.resumed == RESUME_FALSE)	/* if we are not resuming */
			ret = _gnutls_recv_client_certificate(state);
		STATE = STATE9;
		IMED_RET("recv client certificate", ret);

	case STATE10:
		/* receive the client key exchange message */
		if (state->gnutls_internals.resumed == RESUME_FALSE)	/* if we are not resuming */
			ret = _gnutls_recv_client_kx_message(state);
		STATE = STATE10;
		IMED_RET("recv client kx", ret);

	case STATE11:
		/* receive the client certificate verify message */
		if (state->gnutls_internals.resumed == RESUME_FALSE)	/* if we are not resuming */
			ret =
			    _gnutls_recv_client_certificate_verify_message
			    (state);
		STATE = STATE11;
		IMED_RET("recv client certificate verify", ret);

		STATE = STATE0;	/* finished thus clear state */
	default:
	}

	return 0;
}

int gnutls_handshake_common(GNUTLS_STATE state)
{
	int ret = 0;


	/* send and recv the change cipher spec and finished messages */
	if ((state->gnutls_internals.resumed == RESUME_TRUE
	     && state->security_parameters.entity == GNUTLS_CLIENT)
	    || (state->gnutls_internals.resumed == RESUME_FALSE
		&& state->security_parameters.entity == GNUTLS_SERVER)) {
		/* if we are a client resuming - or we are a server not resuming */

		ret = _gnutls_recv_handshake_final(state, TRUE);
		IMED_RET("recv handshake final", ret);

		ret = _gnutls_send_handshake_final(state, FALSE);
		IMED_RET("send handshake final", ret);
	} else {		/* if we are a client not resuming - or we are a server resuming */

		ret = _gnutls_send_handshake_final(state, TRUE);
		IMED_RET("send handshake final 2", ret);

		ret = _gnutls_recv_handshake_final(state, FALSE);
		IMED_RET("recv handshake final 2", ret);
	}

	if (state->security_parameters.entity == GNUTLS_SERVER) {
		/* in order to support session resuming */
		_gnutls_server_register_current_session(state);
	}

	/* clear handshake buffer */
	_gnutls_handshake_hash_buffers_clear(state);
	return ret;

}

int _gnutls_generate_session_id(char *session_id, uint8 * len)
{
	opaque rand[TLS_RANDOM_SIZE];
	if (_gnutls_get_random(rand, TLS_RANDOM_SIZE, GNUTLS_WEAK_RANDOM) <
	    0) {
		gnutls_assert();
		return GNUTLS_E_MEMORY_ERROR;
	}
	memcpy(session_id, rand, TLS_RANDOM_SIZE);
	*len = TLS_RANDOM_SIZE;

	_gnutls_handshake_log("HSK: Generated SessionID: %s\n",
		    _gnutls_bin2hex(session_id, TLS_RANDOM_SIZE));

	return 0;
}

int _gnutls_recv_hello_request(GNUTLS_STATE state, void *data,
			       uint32 data_size)
{
	uint8 type;

	if (state->security_parameters.entity == GNUTLS_SERVER) {
		gnutls_assert();
		return GNUTLS_E_UNEXPECTED_PACKET;
	}
	if (data_size < 1) {
		gnutls_assert();
		return GNUTLS_E_UNEXPECTED_PACKET_LENGTH;
	}
	type = ((uint8 *) data)[0];
	if (type == GNUTLS_HELLO_REQUEST)
		return GNUTLS_E_REHANDSHAKE;
	else {
		gnutls_assert();
		return GNUTLS_E_UNEXPECTED_PACKET;
	}
}

/* This function will remove algorithms that are not supported by
 * the requested authentication method. We remove algorithm if
 * we have a certificate with keyUsage bits set.
 *
 * This does a more high level check than  gnutls_supported_ciphersuites(),
 * by checking certificates etc.
 */
int _gnutls_remove_unwanted_ciphersuites(GNUTLS_STATE state,
					 GNUTLS_CipherSuite **
					 cipherSuites, int numCipherSuites, 
					 PKAlgorithm requested_pk_algo)
{

	int ret = 0;
	GNUTLS_CipherSuite *newSuite;
	int newSuiteSize = 0, i, j, keep;
	const GNUTLS_CERTIFICATE_CREDENTIALS x509_cred;
	const gnutls_cert *cert = NULL;
	KXAlgorithm *alg;
	int alg_size;
	KXAlgorithm kx;


	/* if we should use a specific certificate, 
	 * we should remove all algorithms that are not supported
	 * by that certificate and are on the same authentication
	 * method (CERTIFICATE).
	 */

	x509_cred =
	    _gnutls_get_cred(state->gnutls_key, GNUTLS_CRD_CERTIFICATE, NULL);

	/* if x509_cred==NULL we should remove all X509 ciphersuites
	 */

	cert = NULL;
	if (state->security_parameters.entity == GNUTLS_SERVER)
		cert = _gnutls_server_find_cert(state, requested_pk_algo);

	if (cert == NULL) {
		/* No certificate was found 
		 */
		gnutls_assert();
		alg_size = 0;
		alg = NULL;
	} else {
		/* get all the key exchange algorithms that are 
		 * supported by the X509 certificate parameters.
		 */
		if ((ret =
		     _gnutls_cert_supported_kx(cert, &alg,
					       &alg_size)) < 0) {
			gnutls_assert();
			return ret;
		}
	}

	newSuite =
	    gnutls_malloc(numCipherSuites * sizeof(GNUTLS_CipherSuite));
	if (newSuite == NULL) {
		gnutls_assert();
		gnutls_free(alg);
		return GNUTLS_E_MEMORY_ERROR;
	}

	/* now removes ciphersuites based on the KX algorithm
	 */
	for (i = 0; i < numCipherSuites; i++) {
		/* finds the key exchange algorithm in
		 * the ciphersuite
		 */
		kx = _gnutls_cipher_suite_get_kx_algo((*cipherSuites)[i]);

		keep = 0;

		/* if it is defined but had no credentials 
		 */
		if (_gnutls_get_kx_cred
		    (state->gnutls_key, kx, NULL) == NULL) {
			keep = 1;
		} else
		/* If there was no credentials to use with the specified
		 * key exchange method, then just remove it.
		 */
		if (_gnutls_map_kx_get_cred(kx) == GNUTLS_CRD_CERTIFICATE) {
			keep = 1;	/* do not keep */
			if (x509_cred != NULL) {
				if (state->security_parameters.entity ==
				    GNUTLS_SERVER) {
					/* here we check if the KX algorithm 
					 * is compatible with the certificate.
					 */
					for (j = 0; j < alg_size; j++) {
						if (alg[j] == kx) {
							keep = 0;
							break;
						}
					}
				} else	/* CLIENT */
					keep = 0;
			}
		}

		if (keep == 0) {

			_gnutls_handshake_log("HSK: Keeping ciphersuite: ");
			_gnutls_handshake_log("%s\n",
				    _gnutls_cipher_suite_get_name(*
								  ((GNUTLS_CipherSuite *) & (*cipherSuites)[i].CipherSuite)));

			memcpy(newSuite[newSuiteSize].CipherSuite,
			       (*cipherSuites)[i].CipherSuite, 2);
			newSuiteSize++;
		} else {
			_gnutls_handshake_log("HSK: Removing ciphersuite: ");
			_gnutls_handshake_log("%s\n",
				    _gnutls_cipher_suite_get_name(*
								  ((GNUTLS_CipherSuite *) & (*cipherSuites)[i].CipherSuite)));

		}
	}

	gnutls_free(alg);
	gnutls_free(*cipherSuites);
	*cipherSuites = newSuite;

	ret = newSuiteSize;

	return ret;

}

/**
  * gnutls_handshake_set_max_packet_length - This function will set the maximum length of a handshake message
  * @state: is a a &GNUTLS_STATE structure.
  * @max: is the maximum number.
  *
  * This function will set the maximum size of a handshake message.
  * Handshake messages over this size are rejected.
  * The default value is 16kb which is large enough. Set this to 0 if you do not want
  * to set an upper limit.
  *
  **/
void gnutls_handshake_set_max_packet_length(GNUTLS_STATE state, int max)
{
	state->gnutls_internals.max_handshake_data_buffer_size = max;
}

void _gnutls_set_adv_version( GNUTLS_STATE state, GNUTLS_Version ver) {
	set_adv_version( state, _gnutls_version_get_major(ver), _gnutls_version_get_minor(ver));
}

GNUTLS_Version _gnutls_get_adv_version( GNUTLS_STATE state) {
	return _gnutls_version_get( _gnutls_get_adv_version_major( state), 
		_gnutls_get_adv_version_minor( state));
}

