/*
 *      Copyright (C) 2000,2001 Nikos Mavroyanopoulos
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
#include "gnutls_dh.h"
#include "debug.h"
#include "gnutls_algorithms.h"
#include "gnutls_compress.h"
#include "gnutls_plaintext.h"
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

#ifdef DEBUG
#define ERR(x, y) fprintf(stderr, "GNUTLS Error: %s (%d)\n", x,y)
#else
#define ERR(x, y)
#endif

#define TRUE 1
#define FALSE 0

static int SelectSuite(GNUTLS_STATE state, opaque ret[2], char *data, int datalen);
static int SelectCompMethod(GNUTLS_STATE state, CompressionMethod * ret, opaque * data, int datalen);

/* Calculate The SSL3 Finished message */
#define SSL3_CLIENT_MSG "CLNT"
#define SSL3_SERVER_MSG "SRVR"
void *_gnutls_ssl3_finished(GNUTLS_STATE state, int type, int skip)
{
	int siz;
	GNUTLS_MAC_HANDLE td;
	GNUTLS_MAC_HANDLE td2;
	char *data;
	char *concat = gnutls_malloc(36);
	char *mesg;

	td = gnutls_mac_init_ssl3_handshake(GNUTLS_MAC_MD5,
					    state->security_parameters.
					    master_secret, 48);
	td2 =
	    gnutls_mac_init_ssl3_handshake(GNUTLS_MAC_SHA,
					   state->security_parameters.
					   master_secret, 48);

	siz = gnutls_getHashDataBufferSize(state) - skip;
	data = gnutls_malloc(siz);

	gnutls_readHashDataFromBuffer(state, data, siz);

	gnutls_mac_ssl3(td, data, siz);
	gnutls_mac_ssl3(td2, data, siz);
	gnutls_free(data);

	if (type == GNUTLS_SERVER) {
		mesg = SSL3_SERVER_MSG;
	} else {
		mesg = SSL3_CLIENT_MSG;
	}
	siz = strlen(mesg);
	gnutls_mac_ssl3(td, mesg, siz);
	gnutls_mac_ssl3(td2, mesg, siz);

	data = gnutls_mac_deinit_ssl3_handshake(td);
	memcpy(concat, data, 16);
	gnutls_free(data);

	data = gnutls_mac_deinit_ssl3_handshake(td2);

	memcpy(&concat[16], data, 20);
	gnutls_free(data);
	return concat;
}

/* Hash the handshake messages as required by TLS 1.0 */
#define SERVER_MSG "server finished"
#define CLIENT_MSG "client finished"
void *_gnutls_finished(GNUTLS_STATE state, int type, int skip)
{
	int siz;
	GNUTLS_MAC_HANDLE td;
	GNUTLS_MAC_HANDLE td2;
	char *data;
	char concat[36];
	char *mesg;

	td = gnutls_hash_init(GNUTLS_MAC_MD5);
	td2 = gnutls_hash_init(GNUTLS_MAC_SHA);

	siz = gnutls_getHashDataBufferSize(state) - skip;
	data = gnutls_malloc(siz);

	gnutls_readHashDataFromBuffer(state, data, siz);

	gnutls_hash(td, data, siz);
	gnutls_hash(td2, data, siz);

	gnutls_free(data);

	data = gnutls_hash_deinit(td);
	memcpy(concat, data, 16);
	gnutls_free(data);

	data = gnutls_hash_deinit(td2);

	memcpy(&concat[16], data, 20);
	gnutls_free(data);

	if (type == GNUTLS_SERVER) {
		mesg = SERVER_MSG;
	} else {
		mesg = CLIENT_MSG;
	}
	data =
	    gnutls_PRF(state->security_parameters.master_secret,
		       48, mesg, strlen(mesg), concat, 36, 12);
	return data;
}


/* Read a client hello 
 * client hello must be a known version client hello
 * or version 2.0 client hello (only for compatibility)
 * version 2.0 is not supported.
 */

#define DECR_LEN(len, x) len-=x; if (len<0) {gnutls_assert(); return GNUTLS_E_UNEXPECTED_PACKET_LENGTH;}

int _gnutls_read_client_hello(GNUTLS_STATE state, opaque * data,
			      int datalen)
{
	uint8 session_id_len = 0, z;
	int pos = 0;
	int ret = 0;
	uint16 sizeOfSuites;
	GNUTLS_Version version;
	char *rand;
	int len = datalen;
	int err;

	if (state->gnutls_internals.v2_hello!=0) {	/* version 2.0 */
		return _gnutls_read_client_hello_v2(state, data, datalen);
	}

	DECR_LEN(len, 2);

#ifdef DEBUG
	fprintf(stderr, "Client's version: %d.%d\n", data[pos],
		data[pos + 1]);
#endif

	version = _gnutls_version_get(data[pos], data[pos + 1]);

	/* if we do not support that version  */
	if (_gnutls_version_is_supported(state, version) == 0) {
		gnutls_assert();
		return GNUTLS_E_UNSUPPORTED_VERSION_PACKET;
	} else {
		gnutls_set_current_version(state, version);
	}

	pos += 2;

	DECR_LEN(len, 32);
	memcpy(state->security_parameters.client_random, &data[pos], 32);
	pos += 32;

	/* generate server random value */
	WRITEuint32( time(NULL), state->security_parameters.server_random);

	rand = _gnutls_get_random(28, GNUTLS_STRONG_RANDOM);
	memcpy(&state->security_parameters.server_random[4], rand, 28);
	_gnutls_free_rand(rand);
	state->security_parameters.timestamp = time(NULL);

	DECR_LEN(len, 1);
	memcpy(&session_id_len, &data[pos++], 1);

	/* RESUME SESSION */
	if (session_id_len > 32)
		return GNUTLS_E_UNEXPECTED_PACKET_LENGTH;

	DECR_LEN(len, session_id_len);
	ret =
	    _gnutls_server_restore_session(state, &data[pos],
					   session_id_len);
	pos += session_id_len;

	if (ret == 0) {		/* resumed! */
		/* get the new random values */
		memcpy(state->gnutls_internals.resumed_security_parameters.
		       server_random,
		       state->security_parameters.server_random, 32);
		memcpy(state->gnutls_internals.resumed_security_parameters.
		       client_random,
		       state->security_parameters.client_random, 32);

		state->gnutls_internals.resumed = RESUME_TRUE;
		return 0;
	} else {
		_gnutls_generate_session_id(state->security_parameters.
					    session_id,
					    &state->security_parameters.
					    session_id_size);
		state->gnutls_internals.resumed = RESUME_FALSE;
	}

	/* Select a ciphersuite */
	DECR_LEN(len, 2);
	sizeOfSuites = READuint16( &data[pos]);
	pos += 2;

	DECR_LEN(len, sizeOfSuites);
	ret = SelectSuite(state, state->gnutls_internals.
			  current_cipher_suite.CipherSuite, &data[pos],
			  sizeOfSuites);

	pos += sizeOfSuites;
	if (ret < 0)
		return ret;


	/* check if the credentials (username, public key etc. are ok)
	 */
	if (_gnutls_get_kx_cred
	    (state->gnutls_key,
	     _gnutls_cipher_suite_get_kx_algo(state->gnutls_internals.
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
				   (state->gnutls_internals.
				    current_cipher_suite));
	if (state->gnutls_internals.auth_struct == NULL) {
#ifdef DEBUG
		fprintf(stderr,
			"Cannot find the appropriate handler for the KX algorithm\n");
#endif
		gnutls_assert();
		return GNUTLS_E_UNKNOWN_CIPHER_TYPE;
	}

	DECR_LEN(len, 1);
	memcpy(&z, &data[pos++], 1);	/* z is the number of compression methods */

	DECR_LEN(len, z);
	ret = SelectCompMethod(state, &state->
			       gnutls_internals.compression_method,
			       &data[pos], z);
	pos += z;

	if (ret < 0) {
		gnutls_assert();
		return ret;
	}

	ret = _gnutls_parse_extensions(state, &data[pos], len);	/* len is the rest of the parsed length */
	if (ret < 0) {
		gnutls_assert();
		return ret;
	}

	return ret;
}


/* This is to be called after sending CHANGE CIPHER SPEC packet
 * and initializing encryption. This is the first encrypted message
 * we send.
 */
int _gnutls_send_finished(int cd, GNUTLS_STATE state)
{
	uint8 *data;
	int ret;
	int data_size;

	if (_gnutls_version_ssl3(state->connection_state.version) == 0) {
		data =
		    _gnutls_ssl3_finished(state,
					  state->security_parameters.
					  entity, 0);
		data_size = 36;
	} else {		/* TLS 1.0 */
		data =
		    _gnutls_finished(state,
				     state->security_parameters.entity, 0);
		data_size = 12;
	}

	ret =
	    _gnutls_send_handshake(cd, state, data, data_size,
				   GNUTLS_FINISHED);
	gnutls_free(data);

	return ret;
}

/* This is to be called after sending our finished message. If everything
 * went fine we have negotiated a secure connection 
 */
#define HANDSHAKE_HEADERS_SIZE 4
int _gnutls_recv_finished(int cd, GNUTLS_STATE state)
{
	uint8 *data, *vrfy;
	int data_size;
	int ret;
	int vrfysize;

	ret = 0;

	ret =
	    _gnutls_recv_handshake(cd, state, &vrfy, &vrfysize,
				   GNUTLS_FINISHED);
	if (ret < 0) {
		ERR("recv finished int", ret);
		return ret;
	}

	if (_gnutls_version_ssl3(state->connection_state.version) == 0) {
		data_size = 36;
	} else {
		data_size = 12;
	}

	if (vrfysize != data_size) {
		gnutls_assert();
		return GNUTLS_E_ERROR_IN_FINISHED_PACKET;
	}

	if (_gnutls_version_ssl3(state->connection_state.version) == 0) {
		/* skip the bytes from the last message */
		data =
		    _gnutls_ssl3_finished(state,
					  (state->security_parameters.
					   entity + 1) % 2,
					  vrfysize +
					  HANDSHAKE_HEADERS_SIZE);
	} else {		/* TLS 1.0 */
		data =
		    _gnutls_finished(state,
				     (state->security_parameters.entity +
				      1) % 2,
				     vrfysize + HANDSHAKE_HEADERS_SIZE);
	}

	if (memcmp(vrfy, data, data_size) != 0) {
		gnutls_assert();
		ret = GNUTLS_E_ERROR_IN_FINISHED_PACKET;
	}

	gnutls_free(data);
	gnutls_free(vrfy);

	return ret;
}



/* This selects the best supported ciphersuite from the ones provided */
static int SelectSuite(GNUTLS_STATE state, opaque ret[2], char *data,
		       int datalen)
{
	int x, i, j;
	GNUTLS_CipherSuite *ciphers;

	x = _gnutls_supported_ciphersuites(state, &ciphers);
#ifdef HARD_DEBUG
	fprintf(stderr, "Requested cipher suites: \n");
	for (j = 0; j < datalen; j += 2)
		fprintf(stderr, "\t%s\n",
			_gnutls_cipher_suite_get_name(*
						      ((GNUTLS_CipherSuite
							*) & data[j])));
	fprintf(stderr, "Supported cipher suites: \n");
	for (j = 0; j < x; j++)
		fprintf(stderr, "\t%s\n",
			_gnutls_cipher_suite_get_name(ciphers[j]));
#endif
	memset(ret, '\0', sizeof(GNUTLS_CipherSuite));

	for (j = 0; j < datalen; j += 2) {
		for (i = 0; i < x; i++) {
			if (memcmp(&ciphers[i].CipherSuite, &data[j], 2) ==
			    0) {
#ifdef HARD_DEBUG
				fprintf(stderr, "Selected cipher suite: ");
				fprintf(stderr, "%s\n",
					_gnutls_cipher_suite_get_name(*
								      ((GNUTLS_CipherSuite *) & data[j])));
#endif
				memcpy(ret, &ciphers[i].CipherSuite, 2);
				gnutls_free(ciphers);

				return 0;
			}
		}
	}


	gnutls_free(ciphers);
	gnutls_assert();
	return GNUTLS_E_UNKNOWN_CIPHER_SUITE;

}


/* This selects the best supported compression method from the ones provided */
static int SelectCompMethod(GNUTLS_STATE state, CompressionMethod * ret,
			    opaque * data, int datalen)
{
	int x, i, j;
	uint8 *ciphers;

	x = _gnutls_supported_compression_methods(state, &ciphers);
	memset(ret, '\0', sizeof(CompressionMethod));

	for (j = 0; j < datalen; j++) {
		for (i = 0; i < x; i++) {
			if (ciphers[i] == data[j]) {
				*ret = _gnutls_compression_get_id(ciphers[i]);
				gnutls_free(ciphers);
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

int _gnutls_send_handshake(int cd, GNUTLS_STATE state, void *i_data,
			   uint32 i_datasize, HandshakeType type)
{
	int ret;
	uint8 *data;
	uint32 datasize;
	int pos = 0;

	datasize = i_datasize;

	i_datasize += HANDSHAKE_HEADERS_SIZE;
	data = gnutls_malloc(i_datasize);

	memcpy(&data[pos++], &type, 1);
	WRITEuint24( datasize, &data[pos]);
	pos+=3;

	if (i_datasize > 4)
		memcpy(&data[pos], i_data, i_datasize - 4);

#ifdef HANDSHAKE_DEBUG
	fprintf(stderr, "Handshake: %s was send [%ld bytes]\n",
		_gnutls_handshake2str(type), i_datasize);
#endif

	/* Here we keep the handshake messages in order to hash them later!
	 */
	if (type != GNUTLS_HELLO_REQUEST)
		gnutls_insertHashDataBuffer(state, data, i_datasize);

	ret =
	    _gnutls_Send_int(cd, state, GNUTLS_HANDSHAKE, data,
			     i_datasize);

	gnutls_free(data);
	return ret;
}


/* This function will receive handshake messages of the given types,
 * and will pass the message to the right place in order to be processed.
 * Eg. for the SERVER_HELLO message (if it is expected), it will be
 * send to _gnutls_recv_hello().
 */
#define SSL2_HEADERS 1
int _gnutls_recv_handshake(int cd, GNUTLS_STATE state, uint8 ** data,
			   int *datalen, HandshakeType type)
{
	int ret;
	uint32 length32 = 0, sum = 0;
	uint8 *dataptr=NULL; /* for realloc */
	int handshake_headers = HANDSHAKE_HEADERS_SIZE;
	HandshakeType recv_type;

	if (type == GNUTLS_CERTIFICATE) {
		/* If the ciphersuite does not support certificate just quit */
		if (state->security_parameters.entity == GNUTLS_CLIENT) {
			if (_gnutls_kx_server_certificate( _gnutls_cipher_suite_get_kx_algo( state->gnutls_internals.current_cipher_suite) ) == 0)
				return 0;
		} else {	/* server */
			if (_gnutls_kx_client_certificate( _gnutls_cipher_suite_get_kx_algo( state->gnutls_internals.current_cipher_suite) ) == 0)
				return 0;
		}
	}

	dataptr = gnutls_malloc(HANDSHAKE_HEADERS_SIZE);
	
	ret =
	    _gnutls_Recv_int(cd, state, GNUTLS_HANDSHAKE, dataptr, SSL2_HEADERS);
	if (ret < 0) {
		gnutls_assert();
		gnutls_free(dataptr);
		return ret;
	}
	if (ret!=SSL2_HEADERS) {
		gnutls_assert();
		gnutls_free(dataptr);
		return GNUTLS_E_UNEXPECTED_PACKET_LENGTH;
	}

	if ( state->gnutls_internals.v2_hello == 0 || type != GNUTLS_CLIENT_HELLO) {

		ret =
		    _gnutls_Recv_int(cd, state, GNUTLS_HANDSHAKE, &dataptr[SSL2_HEADERS],
			     HANDSHAKE_HEADERS_SIZE-SSL2_HEADERS);
		if (ret < 0) {
			gnutls_assert();
			gnutls_free(dataptr);
			return ret;
		}
		if (ret != HANDSHAKE_HEADERS_SIZE - SSL2_HEADERS) {
			gnutls_assert();
			gnutls_free(dataptr);
			return GNUTLS_E_UNEXPECTED_PACKET_LENGTH;
		}

		recv_type = dataptr[0];
		
		if (recv_type != type) {
			gnutls_assert();
			gnutls_free(dataptr);
			return GNUTLS_E_UNEXPECTED_HANDSHAKE_PACKET;
		}
	
		length32 = READuint24( &dataptr[1]);

#ifdef HANDSHAKE_DEBUG
		fprintf(stderr, "Handshake: %s was received [%ld bytes]\n",
			_gnutls_handshake2str(dataptr[0]),
			length32 + HANDSHAKE_HEADERS_SIZE);
#endif


	} else { /* v2 hello */
		length32 = state->gnutls_internals.v2_hello - 1; /* we've read the first byte */
		
		handshake_headers = 0; /* no headers in v2 */

#ifdef HANDSHAKE_DEBUG
		fprintf(stderr, "Handshake: %s(v2) was received [%ld bytes]\n",
			_gnutls_handshake2str(dataptr[0]),
			length32 + handshake_headers);
#endif
		recv_type = dataptr[0];
		if (dataptr[0] != GNUTLS_CLIENT_HELLO) /* it should be one or nothing */
			return GNUTLS_E_UNEXPECTED_HANDSHAKE_PACKET;
	}

	dataptr =
	    gnutls_realloc(dataptr, length32 + handshake_headers);
	if (length32 > 0 && data != NULL)
		*data = gnutls_malloc(length32);

	if (datalen != NULL)
		*datalen = length32;		

	sum = handshake_headers;
	do {
		ret =
		    _gnutls_Recv_int(cd, state, GNUTLS_HANDSHAKE,
				     &dataptr[sum], length32);
		sum += ret;
	} while (((sum - handshake_headers) < length32) && (ret > 0));
	
	if (ret < 0) {
		gnutls_assert();
		gnutls_free(dataptr);
		return ret;
	}
	ret = GNUTLS_E_UNKNOWN_ERROR;

	if (length32 > 0 && data != NULL)
		memcpy(*data, &dataptr[handshake_headers], length32);

	/* here we buffer the handshake messages - needed at Finished message */
	
	if (recv_type!=GNUTLS_HELLO_REQUEST)
		gnutls_insertHashDataBuffer(state, dataptr, length32 + handshake_headers);

	switch (recv_type) {
	case GNUTLS_CLIENT_HELLO:
	case GNUTLS_SERVER_HELLO:
		ret =
		    _gnutls_recv_hello(cd, state,
				       &dataptr[handshake_headers],
				       length32);
		break;
	case GNUTLS_CERTIFICATE:
		ret =
		    _gnutls_recv_certificate(cd, state,
					     &dataptr
					     [HANDSHAKE_HEADERS_SIZE],
					     length32);
		break;
	case GNUTLS_SERVER_HELLO_DONE:
		ret = 0;
		break;
	case GNUTLS_FINISHED:
		ret = length32;
		break;
	case GNUTLS_SERVER_KEY_EXCHANGE:
		ret = length32;
		break;
	case GNUTLS_CLIENT_KEY_EXCHANGE:
		ret = length32;
		break;
	case GNUTLS_CERTIFICATE_REQUEST:
#ifdef HARD_DEBUG
		fprintf(stderr, "Requested Client Certificate!\n");
#endif
		/* FIXME: just ignore that message for the time being 
		 * we have to parse it and the store the needed information
		 */
		state->gnutls_internals.certificate_requested = 1;
		ret = length32;
		break;
	default:
		gnutls_assert();
		ret = GNUTLS_E_UNEXPECTED_HANDSHAKE_PACKET;
	}
	gnutls_free(dataptr);
	return ret;
}

/**
  * gnutls_send_hello_request - This function will renegotiate security parameters
  * @cd: is a connection descriptor, as returned by socket().
  * @state: is a a &GNUTLS_STATE structure.
  *
  * This function will renegotiate security parameters with the
  * client. This should only be called in case of a server.
  * If the client does not wish to renegotiate parameters he
  * will reply with an alert message, thus the return code will be
  * GNUTLS_E_WARNING_ALERT_RECEIVED and the alert will be
  * GNUTLS_NO_RENEGOTIATION.
  **/
int gnutls_send_hello_request(int cd, GNUTLS_STATE state)
{
int 	ret;

	/* only server sends that handshake packet */
	if (state->security_parameters.entity == GNUTLS_CLIENT)
		return GNUTLS_E_UNIMPLEMENTED_FEATURE;

	ret = _gnutls_send_handshake(cd, state, NULL, 0,
				      GNUTLS_HELLO_REQUEST);

	if (ret < 0) {
		gnutls_assert();
		return ret;
	}

	/* begin handshake procedure again */
	ret = gnutls_handshake(cd, state);

	return ret;
}

int _gnutls_send_client_certificate(int cd, GNUTLS_STATE state)
{
	char data[1];
	int ret;

	if (state->gnutls_internals.certificate_requested == 0)
		return 0;

	/* we do not have that functionality yet */
	state->gnutls_internals.certificate_verify_needed = 0;
#ifdef HARD_DEBUG
	fprintf(stderr, "Sending Client Certificate\n");
#endif

/* Here since we do not support certificates yet we
 * do not have that functionality.
 */
	data[0] = 0;
	ret = _gnutls_send_handshake(cd, state, &data, 1,
				     GNUTLS_CERTIFICATE);

	return ret;
}

static int _gnutls_read_server_hello( GNUTLS_STATE state, char *data, int datalen)
{
	uint8 session_id_len = 0, z;
	int pos = 0;
	GNUTLS_CipherSuite cipher_suite, *cipher_suites;
	uint8 compression_method, *compression_methods;
	int i, ret = 0;
	uint16 x;
	GNUTLS_Version version;
	int len = datalen;
	int err;

	if (datalen < 38) {
		gnutls_assert();
		return GNUTLS_E_UNEXPECTED_PACKET_LENGTH;
	}
#ifdef DEBUG
	fprintf(stderr, "Server's version: %d.%d\n", data[pos],
		data[pos + 1]);
#endif
	DECR_LEN(len, 2);
	version = _gnutls_version_get(data[pos], data[pos + 1]);
	if (_gnutls_version_is_supported(state, version) == 0) {
		gnutls_assert();
		return GNUTLS_E_UNSUPPORTED_VERSION_PACKET;
	} else {
		gnutls_set_current_version(state, version);
	}
	pos += 2;

	DECR_LEN(len, 32);
	memcpy(state->security_parameters.server_random,
		&data[pos], 32);
	pos += 32;

	DECR_LEN(len, 1);
	memcpy(&session_id_len, &data[pos++], 1);

	if (len < session_id_len) {
		gnutls_assert();
		return GNUTLS_E_UNSUPPORTED_VERSION_PACKET;
	}

	DECR_LEN(len, session_id_len);

#ifdef HARD_DEBUG
	fprintf(stderr, "SessionID length: %d\n", session_id_len);
	fprintf(stderr, "SessionID: %s\n",
		_gnutls_bin2hex(&data[pos], session_id_len));
#endif
	if ((state->gnutls_internals.resumed_security_parameters.
	     session_id_size > 0)
	    && memcmp(&data[pos],
		      state->gnutls_internals.
		      resumed_security_parameters.session_id,
		      session_id_len) == 0) {
		/* resume session */
		memcpy(state->gnutls_internals.
		       resumed_security_parameters.server_random,
		       state->security_parameters.server_random,
		       32);
		memcpy(state->gnutls_internals.
		       resumed_security_parameters.client_random,
		       state->security_parameters.client_random,
		       32);
		state->gnutls_internals.resumed = RESUME_TRUE;	/* we are resuming */

		return 0;
	} else {
		/* keep the new session id */
		state->gnutls_internals.resumed = RESUME_FALSE;	/* we are not resuming */
		state->security_parameters.session_id_size =
		    session_id_len;
		memcpy(state->security_parameters.session_id,
		       &data[pos], session_id_len);
		}
		pos += session_id_len;
		DECR_LEN(len, 2);
	memcpy(&cipher_suite.CipherSuite, &data[pos], 2);
	pos += 2;

	z = 1;
	x = _gnutls_supported_ciphersuites(state, &cipher_suites);
	for (i = 0; i < x; i++) {
		if (memcmp
		    (&cipher_suites[i], cipher_suite.CipherSuite,
		     2) == 0) {
			z = 0;
		}
	}
	if (z != 0) {
		gnutls_assert();
		return GNUTLS_E_UNKNOWN_CIPHER_TYPE;
	}

	memcpy(state->gnutls_internals.
		current_cipher_suite.CipherSuite,
		cipher_suite.CipherSuite, 2);

#ifdef HARD_DEBUG
	fprintf(stderr, "Selected cipher suite: ");
	fprintf(stderr, "%s\n",
		_gnutls_cipher_suite_get_name(state->
			      gnutls_internals.
			      current_cipher_suite));
#endif

	/* check if the credentials (username, public key etc. are ok - actually check if they exist)
	 */
	if (_gnutls_get_kx_cred
	    (state->gnutls_key,
	     _gnutls_cipher_suite_get_kx_algo(state->
					      gnutls_internals.
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
				   (cipher_suite));
	if (state->gnutls_internals.auth_struct == NULL) {
#ifdef DEBUG
	fprintf(stderr,
		"Cannot find the appropriate handler for the KX algorithm\n");
#endif
		gnutls_assert();
		return GNUTLS_E_UNKNOWN_CIPHER_TYPE;
	}


	/* move to compression */
	z = 1;
	DECR_LEN(len, 1);
	memcpy(&compression_method, &data[pos++], 1);

	z = _gnutls_supported_compression_methods
	    (state, &compression_methods);
	for (i = 0; i < z; i++) {
		if (memcmp
		    (&compression_methods[i], &compression_method,
		     1) == 0) {
			z = 0;
		}
	}

	if (z != 0) {
		gnutls_assert();
		return GNUTLS_E_UNKNOWN_COMPRESSION_ALGORITHM;
	}
	state->gnutls_internals.compression_method =
		_gnutls_compression_get_id( compression_method);

	gnutls_free(cipher_suites);
	gnutls_free(compression_methods);

	ret = _gnutls_parse_extensions(state, &data[pos], len);	/* len is the rest of the parsed length */
	if (ret < 0) {
		gnutls_assert();
		return ret;
	}
	
	return ret;
}

int _gnutls_send_hello(int cd, GNUTLS_STATE state)
{
	char *rand;
	char *data = NULL;
	opaque *extdata;
	int extdatalen;
	uint8 z;
	int pos = 0;
	GNUTLS_CipherSuite *cipher_suites;
	uint8 *compression_methods;
	int i, datalen, ret = 0;
	uint16 x;

	if (state->security_parameters.entity == GNUTLS_CLIENT) {
		opaque * SessionID = state->gnutls_internals.resumed_security_parameters.session_id;
		uint8 session_id_len = state->gnutls_internals.resumed_security_parameters.session_id_size;

		if (SessionID==NULL) session_id_len = 0;
		
		datalen = 2 + 4 + (session_id_len + 1) + 28 + 3;
		/* 2 for version, 4 for unix time, 28 for random bytes 2 for cipher suite's
		 * size and 1 for compression method's size 
		 */
		data = gnutls_malloc(datalen);

		data[pos++] =
		    _gnutls_version_get_major(state->connection_state.
					      version);
		data[pos++] =
		    _gnutls_version_get_minor(state->connection_state.
					      version);

		WRITEuint32( time(NULL), state->security_parameters.client_random);

		rand = _gnutls_get_random(28, GNUTLS_STRONG_RANDOM);
		memcpy(&state->security_parameters.client_random[4], rand,
			28);
		_gnutls_free_rand(rand);

		state->security_parameters.timestamp = time(0);

		memcpy(&data[pos],
			state->security_parameters.client_random, 32);
		pos += 32;

		memcpy(&data[pos++], &session_id_len, 1);

		if (session_id_len > 0) {
			memcpy(&data[pos], SessionID, session_id_len);
		}
		pos += session_id_len;

		x = _gnutls_supported_ciphersuites_sorted(state,
							  &cipher_suites);
		x *= sizeof(uint16);	/* in order to get bytes */

		WRITEuint16( x, &data[pos]);
		pos += sizeof(uint16);

		datalen += x;
		data = gnutls_realloc(data, datalen);

		for (i = 0; i < x / 2; i++) {
			memcpy(&data[pos], &cipher_suites[i].CipherSuite,
				2);
			pos += 2;
		}
		gnutls_free(cipher_suites);

		z = _gnutls_supported_compression_methods
		    (state, &compression_methods);

		memcpy(&data[pos++], &z, 1);	/* put the number of compression methods */

		datalen += z;
		data = gnutls_realloc(data, datalen);

		for (i = 0; i < z; i++) {
			memcpy(&data[pos++], &compression_methods[i], 1);
		}

		gnutls_free(compression_methods);

		extdatalen = _gnutls_gen_extensions(state, &extdata);
		if (extdatalen > 0) {
			datalen += extdatalen;
			data = gnutls_realloc(data, datalen);
			memcpy(&data[pos], extdata, extdatalen);
			gnutls_free(extdata);
		}

		ret =
		    _gnutls_send_handshake(cd, state, data, datalen,
					   GNUTLS_CLIENT_HELLO);
		gnutls_free(data);


	} else {		/* SERVER */
		uint8 comp;
		opaque * SessionID = state->security_parameters.session_id;
		uint8 session_id_len = state->security_parameters.session_id_size;
		
		if (SessionID==NULL) session_id_len = 0;
		
		datalen = 2 + session_id_len + 1 + 32;
		data = gnutls_malloc(datalen);

		data[pos++] =
		    _gnutls_version_get_major(state->connection_state.
					      version);
		data[pos++] =
		    _gnutls_version_get_minor(state->connection_state.
					      version);

		memcpy(&data[pos],
			state->security_parameters.server_random, 32);
		pos += 32;

		memcpy(&data[pos++], &session_id_len, sizeof(uint8));
		if (session_id_len > 0) {
			memcpy(&data[pos], SessionID, session_id_len);
		}
		pos += session_id_len;

		datalen += 2;
		data = gnutls_realloc(data, datalen);
		memcpy(&data[pos],
			&state->gnutls_internals.
			current_cipher_suite.CipherSuite, 2);
		pos += 2;

		datalen += 1;
		data = gnutls_realloc(data, datalen);
		
		comp = (uint8) _gnutls_compression_get_num(state->gnutls_internals.compression_method);
		memcpy(&data[pos++], &comp, 1);

		extdatalen = _gnutls_gen_extensions(state, &extdata);
		if (extdatalen > 0) {
			datalen += extdatalen;
			data = gnutls_realloc(data, datalen);
			memcpy(&data[pos], extdata, extdatalen);
			gnutls_free(extdata);
		}

		ret =
		    _gnutls_send_handshake(cd, state, data, datalen,
					   GNUTLS_SERVER_HELLO);
		gnutls_free(data);

	}

	return ret;
}

/* RECEIVE A HELLO MESSAGE. This should be called from gnutls_recv_handshake_int only if a
 * hello message is expected. It uses the gnutls_internals.current_cipher_suite
 * and gnutls_internals.compression_method.
 */
int _gnutls_recv_hello(int cd, GNUTLS_STATE state, char *data, int datalen)
{
int ret;

	if (state->security_parameters.entity == GNUTLS_CLIENT) {
		ret = _gnutls_read_server_hello(state, data, datalen);
		if (ret < 0) {
			_gnutls_send_alert( cd, state, GNUTLS_FATAL, GNUTLS_HANDSHAKE_FAILURE); /* send handshake failure */
			gnutls_assert();
			return ret;
		}
	} else {		/* Server side reading a client hello */

		ret = _gnutls_read_client_hello(state, data, datalen);
		if (ret < 0) {
			_gnutls_send_alert( cd, state, GNUTLS_FATAL, GNUTLS_HANDSHAKE_FAILURE); /* send handshake failure */
			gnutls_assert();
			return ret;
		}
	}

	return ret;
}

int _gnutls_recv_certificate(int cd, GNUTLS_STATE state, char *data,
			     int datalen)
{
	int pos = 0;
	char *certificate_list;
	int ret = 0;
	uint32 sizeOfCert;

	if (state->security_parameters.entity == GNUTLS_CLIENT) {
		if (datalen < 2) {
			gnutls_assert();
			return GNUTLS_E_UNEXPECTED_PACKET_LENGTH;
		}

		sizeOfCert = READuint24( &data[pos]);
		pos += 3;

		if (sizeOfCert > MAX24) {
			gnutls_assert();
			return GNUTLS_E_UNEXPECTED_PACKET_LENGTH;
		}
		certificate_list = gnutls_malloc(sizeOfCert);

		memcpy(certificate_list, &data[pos], sizeOfCert);

		/* Verify certificates !!! */

		gnutls_free(certificate_list);	/* oooops! */

	} else {		/* Server side reading a client certificate */
		/* actually this is not complete */
		if (datalen < 1) {
			gnutls_assert();
			return GNUTLS_E_UNEXPECTED_PACKET_LENGTH;
		}

		ret = 0;
	}

	return ret;
}


/**
  * gnutls_handshake - This the main function in the handshake protocol.
  * @cd: is a connection descriptor, as returned by socket().
  * @state: is a a &GNUTLS_STATE structure.
  *
  * This function does the handshake of the TLS/SSL protocol,
  * and initializes the TLS connection. Here the identity of the peer
  * is checked automatically.
  * This function will fail if any problem is encountered,
  * and the connection should be terminated.
  **/
int gnutls_handshake(int cd, GNUTLS_STATE state)
{
	int ret;

	ret = gnutls_handshake_begin(cd, state);
	/* FIXME: check certificate */

	if (ret == 0)
		ret = gnutls_handshake_finish(cd, state);

	return ret;
}

/**
  * gnutls_handshake_begin - This function does a partial handshake of the TLS/SSL protocol.
  * @cd: is a connection descriptor, as returned by socket().
  * @state: is a a &GNUTLS_STATE structure.
  *
  * This function initiates the handshake of the TLS/SSL protocol.
  * Here we will receive - if requested and supported by the ciphersuite -
  * the peer's certificate. 
  *
  * This function will fail if any problem in the handshake is encountered.   
  * However this failure will not be fatal. However you may choose to
  * continue the handshake - eg. even if the certificate cannot
  * be verified- by calling gnutls_handshake_finish().
  **/
int gnutls_handshake_begin(int cd, GNUTLS_STATE state)
{
	int ret;

	if (state->security_parameters.entity == GNUTLS_CLIENT) {
#ifdef HARD_DEBUG
		if (state->gnutls_internals.resumed_security_parameters.
		    session_id_size > 0)
			fprintf(stderr, "Ask to resume: %s\n",
				_gnutls_bin2hex(state->gnutls_internals.
						resumed_security_parameters.
						session_id,
						state->gnutls_internals.
						resumed_security_parameters.
						session_id_size));
#endif
		ret =
		    _gnutls_send_hello(cd, state);
		if (ret < 0) {
			ERR("send hello", ret);
			gnutls_clearHashDataBuffer(state);
			return ret;
		}

		/* receive the server hello */
		ret =
		    _gnutls_recv_handshake(cd, state, NULL, NULL,
					   GNUTLS_SERVER_HELLO);
		if (ret < 0) {
			ERR("recv hello", ret);
			gnutls_clearHashDataBuffer(state);
			return ret;
		}

		/* RECV CERTIFICATE */
		if (state->gnutls_internals.resumed == RESUME_FALSE)	/* if we are not resuming */
			ret =
			    _gnutls_recv_handshake(cd, state, NULL, NULL,
						   GNUTLS_CERTIFICATE);
		if (ret < 0) {
			ERR("recv server certificate", ret);
			gnutls_clearHashDataBuffer(state);
			return ret;
		}
		return 0;
	} else {		/* SERVER SIDE */

		ret =
		    _gnutls_recv_handshake(cd, state, NULL, NULL,
					   GNUTLS_CLIENT_HELLO);
		if (ret < 0) {
			ERR("recv hello", ret);
			gnutls_assert();
			gnutls_clearHashDataBuffer(state);
			return ret;
		}

		ret =
		    _gnutls_send_hello(cd, state);
		if (ret < 0) {
			ERR("send hello", ret);
			gnutls_assert();
			gnutls_clearHashDataBuffer(state);
			return ret;
		}

		/* FIXME: send our certificate - if required */
		/* NOTE: these should not be send if we are resuming */

		/* SEND CERTIFICATE + KEYEXCHANGE + CERTIFICATE_REQUEST */

		/* send server key exchange (A) */
		if (state->gnutls_internals.resumed == RESUME_FALSE)
			ret = _gnutls_send_server_kx_message(cd, state);
		if (ret < 0) {
			ERR("send server kx", ret);
			gnutls_assert();
			gnutls_clearHashDataBuffer(state);
			return ret;
		}

/* Added for SRP which uses a different handshake */
		/* receive the client key exchange message */
		if (state->gnutls_internals.resumed == RESUME_FALSE)	/* if we are not resuming */
			ret = _gnutls_recv_client_kx_message0(cd, state);
		if (ret < 0) {
			ERR("recv client kx0", ret);
			gnutls_clearHashDataBuffer(state);
			return ret;
		}

		/* send server key exchange (B) */
		if (state->gnutls_internals.resumed == RESUME_FALSE)
			ret = _gnutls_send_server_kx_message2(cd, state);
		if (ret < 0) {
			ERR("send server kx2", ret);
			gnutls_clearHashDataBuffer(state);
			return ret;
		}

		/* FIXME: request - and get - a client certificate */
		return 0;
	}
}

/* This function sends the final handshake packets and initializes connection */
static int _gnutls_send_handshake_final(int cd, GNUTLS_STATE state,
					int init)
{
	int ret = 0;

	/* Send the CHANGE CIPHER SPEC PACKET */
	ret = _gnutls_send_change_cipher_spec(cd, state);
	if (ret < 0) {
		ERR("send ChangeCipherSpec", ret);
		gnutls_clearHashDataBuffer(state);
		return ret;
	}

	/* Initialize the connection state (start encryption) - in case of client */
	if (init == TRUE) {
		ret = _gnutls_connection_state_init(state);
		if (ret < 0) {
			gnutls_assert();
			gnutls_clearHashDataBuffer(state);
			return ret;
		}
	}
	/* send the finished message */

	ret = _gnutls_send_finished(cd, state);
	if (ret < 0) {
		ERR("send Finished", ret);
		gnutls_clearHashDataBuffer(state);
		return ret;
	}
	return ret;
}

/* This function receives the final handshake packets */
static int _gnutls_recv_handshake_final(int cd, GNUTLS_STATE state,
					int init)
{
	int ret = 0;

	ret =
	    gnutls_recv_int(cd, state, GNUTLS_CHANGE_CIPHER_SPEC,
			    NULL, 0, 0);
	if (ret < 0) {
		ERR("recv ChangeCipherSpec", ret);
		gnutls_clearHashDataBuffer(state);
		return ret;
	}

	/* Initialize the connection state (start encryption) - in case of server */
	if (init == TRUE) {
		ret = _gnutls_connection_state_init(state);
		if (ret < 0) {
			gnutls_assert();
			gnutls_clearHashDataBuffer(state);
			return ret;
		}
	}

	ret = _gnutls_recv_finished(cd, state);
	if (ret < 0) {
		ERR("recv finished", ret);
		gnutls_clearHashDataBuffer(state);
		return ret;
	}
	return ret;
}

/**
  * gnutls_handshake_finish - This function finished a partial handshake of the TLS/SSL protocol.
  * @cd: is a connection descriptor, as returned by socket().
  * @state: is a a &GNUTLS_STATE structure.
  *
  * This function does the final stuff of the handshake protocol.
  * You should call it only if you used gnutls_handshake_begin() and
  * you have somehow verified the identity of the peer.
  * This function will fail if any problem is encountered.
  **/
int gnutls_handshake_finish(int cd, GNUTLS_STATE state)
{
	int ret = 0;

	if (state->security_parameters.entity == GNUTLS_CLIENT) {

		/* receive the server key exchange */
		if (state->gnutls_internals.resumed == RESUME_FALSE)	/* if we are not resuming */
			ret = _gnutls_recv_server_kx_message(cd, state);
		if (ret < 0) {
			gnutls_assert();
			ERR("recv server kx message", ret);
			gnutls_clearHashDataBuffer(state);
			return ret;
		}


		/* Added for SRP */

		/* send the client key exchange for SRP */
		if (state->gnutls_internals.resumed == RESUME_FALSE)	/* if we are not resuming */
			ret = _gnutls_send_client_kx_message0(cd, state);
		if (ret < 0) {
			gnutls_assert();
			ERR("send client kx0", ret);
			gnutls_clearHashDataBuffer(state);
			return ret;
		}

		/* receive the server key exchange (B) (SRP only) */
		if (state->gnutls_internals.resumed == RESUME_FALSE)	/* if we are not resuming */
			ret = _gnutls_recv_server_kx_message2(cd, state);
		if (ret < 0) {
			gnutls_assert();
			ERR("recv server kx message2", ret);
			gnutls_clearHashDataBuffer(state);
			return ret;
		}


		/* FIXME: receive certificate request */

		/* receive the server hello done */
		if (state->gnutls_internals.resumed == RESUME_FALSE)	/* if we are not resuming */
			ret =
			    _gnutls_recv_handshake(cd, state, NULL, NULL,
						   GNUTLS_SERVER_HELLO_DONE);
		if (ret < 0) {
			gnutls_assert();
			ERR("recv server hello done", ret);
			gnutls_clearHashDataBuffer(state);
			return ret;
		}

		/* send our certificate - if any */
		if (state->gnutls_internals.resumed == RESUME_FALSE)	/* if we are not resuming */
			ret = _gnutls_send_client_certificate(cd, state);
		if (ret < 0) {
			gnutls_assert();
			ERR("send client certificate", ret);
			gnutls_clearHashDataBuffer(state);
			return ret;
		}

		if (state->gnutls_internals.resumed == RESUME_FALSE)	/* if we are not resuming */
			ret = _gnutls_send_client_kx_message(cd, state);
		if (ret < 0) {
			gnutls_assert();
			ERR("send client kx", ret);
			gnutls_clearHashDataBuffer(state);
			return ret;
		}

		/* send client certificate verify */
		if (state->gnutls_internals.resumed == RESUME_FALSE)	/* if we are not resuming */
			ret =
			    _gnutls_send_client_certificate_verify(cd,
								   state);
		if (ret < 0) {
			gnutls_assert();
			ERR("send client certificate verify", ret);
			gnutls_clearHashDataBuffer(state);
			return ret;
		}

	} else {		/* SERVER SIDE */

		/* send the server hello done */
		if (state->gnutls_internals.resumed == RESUME_FALSE)	/* if we are not resuming */
			ret =
			    _gnutls_send_handshake(cd, state, NULL, 0,
						   GNUTLS_SERVER_HELLO_DONE);
		if (ret < 0) {
			gnutls_assert();
			ERR("send server hello done", ret);
			gnutls_clearHashDataBuffer(state);
			return ret;
		}

		/* RECV CERTIFICATE + KEYEXCHANGE + CERTIFICATE_VERIFY */

		/* receive the client key exchange message */
		if (state->gnutls_internals.resumed == RESUME_FALSE)	/* if we are not resuming */
			ret = _gnutls_recv_client_kx_message(cd, state);
		if (ret < 0) {
			gnutls_assert();
			ERR("recv client kx", ret);
			gnutls_clearHashDataBuffer(state);
			return ret;
		}


	}

	/* send and recv the change cipher spec and finished messages */
	if ((state->gnutls_internals.resumed == RESUME_TRUE
	     && state->security_parameters.entity == GNUTLS_CLIENT)
	    || (state->gnutls_internals.resumed == RESUME_FALSE
		&& state->security_parameters.entity == GNUTLS_SERVER)) {
		/* if we are a client resuming - or we are a server not resuming */

		ret = _gnutls_recv_handshake_final(cd, state, TRUE);
		if (ret < 0) {
			gnutls_assert();
			gnutls_clearHashDataBuffer(state);
			/* for srp */
			if (state->security_parameters.kx_algorithm==GNUTLS_KX_SRP) return GNUTLS_E_AUTH_FAILED;
			return ret;
		}

		ret = _gnutls_send_handshake_final(cd, state, FALSE);
		if (ret < 0) {
			gnutls_assert();
			gnutls_clearHashDataBuffer(state);
			return ret;
		}
	} else {		/* if we are a client not resuming - or we are a server resuming */

		ret = _gnutls_send_handshake_final(cd, state, TRUE);
		if (ret < 0) {
			gnutls_assert();
			gnutls_clearHashDataBuffer(state);
			return ret;
		}

		ret = _gnutls_recv_handshake_final(cd, state, FALSE);
		if (ret < 0) {
			gnutls_assert();
			gnutls_clearHashDataBuffer(state);
			/* in srp failure here - means authentication error */
			if (state->security_parameters.kx_algorithm==GNUTLS_KX_SRP) return GNUTLS_E_AUTH_FAILED;
			return ret;
		}
	}

	if (state->security_parameters.entity == GNUTLS_SERVER) {
		/* in order to support session resuming */
		_gnutls_server_register_current_session(state);
	}

	/* clear handshake buffer */
	gnutls_clearHashDataBuffer(state);
	return ret;

}

int _gnutls_generate_session_id(char *session_id, uint8 * len)
{
	char *rand;
	rand = _gnutls_get_random(32, GNUTLS_WEAK_RANDOM);

	memcpy(session_id, rand, 32);
	_gnutls_free_rand(rand);
	*len = 32;

#ifdef HARD_DEBUG
	fprintf(stderr, "SessionID: %s\n",
		_gnutls_bin2hex(session_id, 32));
#endif
	return 0;
}

int _gnutls_recv_hello_request(int cd, GNUTLS_STATE state, void* data, uint32 data_size) {
int ret;

	/* only client should receive that */
	if (state->security_parameters.entity == GNUTLS_SERVER)
		return GNUTLS_E_UNEXPECTED_PACKET;

	/* just return an alert that we don't like that */
	ret = _gnutls_send_alert( cd, state, GNUTLS_WARNING, GNUTLS_NO_RENEGOTIATION);
	if (ret < 0) {
		gnutls_assert();
		return ret;
	}
	return 0;

#if 0 /* this does not work - yet */
uint8 type;

	if (state->security_parameters.entity == GNUTLS_SERVER) {
		gnutls_assert();
		return GNUTLS_E_UNEXPECTED_PACKET;
	}
	
	if (data_size < 1) {
		gnutls_assert();
		return GNUTLS_E_UNEXPECTED_PACKET_LENGTH;
	}
	
	type = ((uint8*)data)[0];
	if (type==GNUTLS_HELLO_REQUEST)
		return gnutls_handshake( cd, state);
	else {
		gnutls_assert();
		return GNUTLS_E_UNEXPECTED_PACKET;
	}
#endif
}
