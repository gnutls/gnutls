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

#ifdef DEBUG
#define ERR(x, y) fprintf(stderr, "GNUTLS Error: %s (%d)\n", x,y)
#else
#define ERR(x, y)
#endif

#define HASH_TRUE 1
#define HASH_FALSE 0

/* This is to be called after sending CHANGE CIPHER SPEC packet
 * and initializing encryption. This is the first encrypted message
 * we send.
 */
#define SERVER_MSG "server finished"
#define CLIENT_MSG "client finished"
int _gnutls_send_finished(int cd, GNUTLS_STATE state)
{
	uint8 *data;
	uint8 concat[36];	/* md5+sha1 */
	int ret;


	memset(concat, 0, 36);

	if (state->security_parameters.entity == GNUTLS_CLIENT) { /* we are a CLIENT */
		memmove(concat, state->gnutls_internals.client_md_md5, 16);
		memmove(&concat[16],
			state->gnutls_internals.client_md_sha1, 20);

		if (_gnutls_version_ssl3(state->connection_state.version) == 0) {
			data = concat;
		} else {
			data =
			    gnutls_PRF( state->security_parameters.master_secret,
				       48, CLIENT_MSG, strlen(CLIENT_MSG), concat,
				       36, 12);
		}
	} else {		/* server */
		memmove(concat, state->gnutls_internals.server_md_md5, 16);
		memmove(&concat[16],
			state->gnutls_internals.server_md_sha1, 20);

		if (_gnutls_version_ssl3(state->connection_state.version) == 0) {
			data = concat;
		} else {
			data =
			    gnutls_PRF( state->security_parameters.master_secret,
				       48, SERVER_MSG, strlen(SERVER_MSG), concat,
				       36, 12);
		}
	}

	ret = _gnutls_send_handshake(cd, state, data, 12, GNUTLS_FINISHED);
	if (_gnutls_version_ssl3(state->connection_state.version) != 0) {
		gnutls_free(data);
	}

	return ret;
}

/* This is to be called after sending our finished message. If everything
 * went fine we have negotiated a secure connection 
 */
int _gnutls_recv_finished(int cd, GNUTLS_STATE state)
{
	uint8 *data, *vrfy;
	uint8 concat[36];	/* md5+sha1 */
	int ret;
	int vrfysize;

	ret = 0;

	ret = _gnutls_recv_handshake(cd, state, &vrfy, &vrfysize, GNUTLS_FINISHED);
	if (ret < 0) {
		ERR("recv finished int", ret);
		return ret;
	}
	if (vrfysize != 12) {
		gnutls_assert();
		return GNUTLS_E_ERROR_IN_FINISHED_PACKET;
	}

	if (state->security_parameters.entity == GNUTLS_CLIENT) {
		memmove(concat, state->gnutls_internals.server_md_md5, 16);
		memmove(&concat[16],
			state->gnutls_internals.server_md_sha1, 20);

		if (_gnutls_version_ssl3(state->connection_state.version) == 0) {
			data = concat;
		} else {
			data =
			    gnutls_PRF( state->security_parameters.master_secret,
				       48, SERVER_MSG, strlen(SERVER_MSG), concat,
				       36, 12);
		}
	} else {		/* server */
		memmove(concat, state->gnutls_internals.client_md_md5, 16);
		memmove(&concat[16],
			state->gnutls_internals.client_md_sha1, 20);

		if (_gnutls_version_ssl3(state->connection_state.version) == 0) {
			data = concat;
		} else {
			data =
			    gnutls_PRF( state->security_parameters.master_secret,
				       48, CLIENT_MSG, strlen(CLIENT_MSG), concat,
				       36, 12);
		}
	}

	if (memcmp(vrfy, data, 12) != 0) {
		gnutls_assert();
		ret = GNUTLS_E_ERROR_IN_FINISHED_PACKET;
	}

	gnutls_free(data);
	gnutls_free(vrfy);
	
	return ret;
}


/* This selects the best supported ciphersuite from the ones provided */
int SelectSuite(GNUTLS_STATE state, opaque ret[2], char *data, int datalen)
{
	int x, i, j;
	GNUTLS_CipherSuite *ciphers;

	x = _gnutls_supported_ciphersuites(state, &ciphers);
#ifdef HARD_DEBUG
	fprintf(stderr, "Requested cipher suites: \n");
	for (j=0;j<datalen;j+=2) fprintf(stderr, "\t%s\n", _gnutls_cipher_suite_get_name( *((GNUTLS_CipherSuite*)&data[j]) ));
	fprintf(stderr, "Supported cipher suites: \n");
	for (j=0;j<x;j++) fprintf(stderr, "\t%s\n", _gnutls_cipher_suite_get_name(ciphers[j]));
#endif
	memset(ret, '\0', sizeof(GNUTLS_CipherSuite));

	for (j = 0; j < datalen; j += 2) {
		for (i = 0; i < x; i++) {
			if (memcmp(&ciphers[i].CipherSuite, &data[j], 2) == 0) {
#ifdef HARD_DEBUG
				fprintf(stderr, "Selected cipher suite: ");
				fprintf(stderr, "%s\n", _gnutls_cipher_suite_get_name( *((GNUTLS_CipherSuite*)&data[j]) ));
#endif
				memmove(ret, &ciphers[i].CipherSuite, 2);
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
int SelectCompMethod(GNUTLS_STATE state, CompressionMethod * ret, char *data, int datalen)
{
	int x, i, j;
	CompressionMethod *ciphers;

	x = _gnutls_supported_compression_methods(state, &ciphers);
	memset(ret, '\0', sizeof(CompressionMethod));
fprintf(stderr, "datalen: %d\n",datalen);
	for (j = 0; j < datalen; j++) {
		for (i = 0; i < x; i++) {
			fprintf(stderr, "cipher[%d] = %u\n", i, ciphers[i]);
			fprintf(stderr, "data[%d] = %u\n", j, data[j]);
			if (memcmp(&ciphers[i], &data[j], 1) == 0) {
				memmove(ret, &ciphers[i], 1);
				gnutls_free(ciphers);
				return 0;
			}
		}
	}


	gnutls_free(ciphers);
	gnutls_assert();
	return GNUTLS_E_UNKNOWN_COMPRESSION_ALGORITHM;

}

int _gnutls_send_handshake(int cd, GNUTLS_STATE state, void *i_data,
			   uint32 i_datasize, HandshakeType type)
{
	int ret;
	uint8 *data;
	uint24 length;
	uint32 datasize;
	int pos = 0;


#ifdef WORDS_BIGENDIAN
	datasize = i_datasize;
#else
	datasize = byteswap32(i_datasize);
#endif

	length = uint32touint24(datasize);

	i_datasize += 4;
	data = gnutls_malloc(i_datasize);

	memmove(&data[pos++], &type, 1);
	memmove(&data[pos++], &length.pint[0], 1);
	memmove(&data[pos++], &length.pint[1], 1);
	memmove(&data[pos++], &length.pint[2], 1);

	if (i_datasize > 4)
		memmove(&data[pos], i_data, i_datasize - 4);

	if (state->gnutls_internals.client_hash == HASH_TRUE) {
		gnutls_hash(state->gnutls_internals.client_td_md5, data,
		      i_datasize);
		gnutls_hash(state->gnutls_internals.client_td_sha1, data,
		      i_datasize);
	}
	if (state->gnutls_internals.server_hash == HASH_TRUE) {
		gnutls_hash(state->gnutls_internals.server_td_md5, data,
		      i_datasize);
		gnutls_hash(state->gnutls_internals.server_td_sha1, data,
		      i_datasize);
	}

#ifdef HARD_DEBUG
	fprintf(stderr, "Send HANDSHAKE[%d]\n", type);
#endif
	ret =
		_gnutls_Send_int(cd, state, GNUTLS_HANDSHAKE, data, i_datasize);

	gnutls_free(data);
	return ret;
}


/* This function will receive handshake messages of the given types,
 * and will pass the message to the right place in order to be processed.
 * Eg. for the SERVER_HELLO message (if it is expected), it will be
 * send to _gnutls_recv_hello().
 */
int _gnutls_recv_handshake(int cd, GNUTLS_STATE state, uint8 **data,
				int* datalen, HandshakeType type)
{
	int ret;
	uint32 length32 = 0, sum=0;
	uint8 *dataptr;
	uint24 num;


	if (type==GNUTLS_CERTIFICATE) {
	/* If the ciphersuite does not support certificate just quit */
		if (state->security_parameters.entity == GNUTLS_CLIENT) {
			if ( _gnutls_kx_server_certificate( 
				_gnutls_cipher_suite_get_kx_algo(state->gnutls_internals.current_cipher_suite)) ==0 )
			return 0;
		} else { /* server */
			if (_gnutls_kx_client_certificate( _gnutls_cipher_suite_get_kx_algo(state->gnutls_internals.current_cipher_suite)==0))
			return 0;
		}
	}

	dataptr = gnutls_malloc(4);
	
	ret = _gnutls_Recv_int(cd, state, GNUTLS_HANDSHAKE, dataptr, 4);
	if (ret < 0) {
		gnutls_free(dataptr);
		return ret;
	}
	if (ret!=4) {
		gnutls_assert();
		gnutls_free(dataptr);
		return GNUTLS_E_UNEXPECTED_PACKET_LENGTH;
	}

#ifdef HARD_DEBUG
	fprintf(stderr, "Received HANDSHAKE[%d]\n", dataptr[0]);
#endif

	if (dataptr[0]!=type) {
		gnutls_assert();
		gnutls_free(dataptr);
		return GNUTLS_E_UNEXPECTED_HANDSHAKE_PACKET;
	}
	
	num.pint[0] = dataptr[1];
	num.pint[1] = dataptr[2];
	num.pint[2] = dataptr[3];
	length32 = uint24touint32(num);

#ifndef WORDS_BIGENDIAN
	length32 = byteswap32(length32);
#endif

	dataptr = gnutls_realloc( dataptr, length32+4);
	if (length32>0 && data!=NULL)
		*data = gnutls_malloc( length32);

	if (datalen!=NULL) *datalen = length32;

	sum=4;
	do {
		ret = _gnutls_Recv_int(cd, state, GNUTLS_HANDSHAKE, &dataptr[sum], length32);
		sum += ret;
	} while( ( (sum-4) < length32) && (ret > 0) );

	if (ret < 0) {
		gnutls_assert();
		gnutls_free(dataptr);
		return ret;
	}
	ret = GNUTLS_E_UNKNOWN_ERROR;

	if (length32 > 0 && data!=NULL)
		memmove( *data, &dataptr[4], length32);

	/* here we do the hashing work needed at finished messages */
	if (state->gnutls_internals.client_hash == HASH_TRUE) {
		gnutls_hash(state->gnutls_internals.client_td_md5, dataptr,
		      length32 + 4);
		gnutls_hash(state->gnutls_internals.client_td_sha1, dataptr,
		      length32 + 4);
	}

	if (state->gnutls_internals.server_hash == HASH_TRUE) {
		gnutls_hash(state->gnutls_internals.server_td_md5, dataptr,
		      length32 + 4);
		gnutls_hash(state->gnutls_internals.server_td_sha1, dataptr,
		      length32 + 4);
	}

	
	switch (dataptr[0]) {
	case GNUTLS_CLIENT_HELLO:
	case GNUTLS_SERVER_HELLO:
		ret = _gnutls_recv_hello(cd, state, &dataptr[4],
					       length32, NULL, 0);
		break;
	case GNUTLS_CERTIFICATE:
		ret = _gnutls_recv_certificate(cd, state, &dataptr[4],
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

int _gnutls_send_hello_request(int cd, GNUTLS_STATE state)
{
	return _gnutls_send_handshake(cd, state, NULL, 0,
				      GNUTLS_HELLO_REQUEST);
}

int _gnutls_send_client_certificate(int cd, GNUTLS_STATE state)
{
	char data[1];
	int ret;
	
	if (state->gnutls_internals.certificate_requested==0) return 0;

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


int _gnutls_send_hello(int cd, GNUTLS_STATE state, opaque * SessionID,
		       uint8 SessionIDLen)
{
	char *rand;
	char *data = NULL;
	uint8 session_id_len, z;
	uint32 cur_time;
	int pos = 0;
	GNUTLS_CipherSuite *cipher_suites;
	CompressionMethod *compression_methods;
	int i, datalen, ret = 0;
	uint16 x;

	session_id_len = SessionIDLen;
	if (SessionID == NULL)
		session_id_len = 0;

	rand = gcry_random_bytes(28, GCRY_STRONG_RANDOM);

	if (state->security_parameters.entity == GNUTLS_CLIENT) {

		datalen = 2 + 4 + (session_id_len + 1) + 28 + 3;
		/* 2 for version, 4 for unix time, 28 for random bytes 2 for cipher suite's
		 * size and 1 for compression method's size 
		 */
		data = gnutls_malloc(datalen);

		data[pos++] = state->connection_state.version.major;
		data[pos++] = state->connection_state.version.minor;
#ifdef WORDS_BIGENDIAN
		cur_time = time(NULL);
#else
		cur_time = byteswap32(time(NULL));
#endif
		memmove(state->security_parameters.client_random,
			&cur_time, 4);
		memmove(&state->security_parameters.client_random[4], rand,
			28);

		memmove(&data[pos], &cur_time, 4);
		pos += 4;
		memmove(&data[pos], rand, 28);
		pos += 28;

		memmove(&data[pos++], &session_id_len, 1);

		if (session_id_len > 0) {
			memmove(&data[pos], SessionID, session_id_len);
		}
		pos += session_id_len;

		x = _gnutls_supported_ciphersuites(state, &cipher_suites);
		x *= sizeof(uint16); /* in order to get bytes */
#ifdef WORDS_BIGENDIAN
		memmove(&data[pos], &x, sizeof(uint16));
#else
		x = byteswap16(x);
		memmove(&data[pos], &x, sizeof(uint16));
		x = byteswap16(x);
#endif
		pos += sizeof(uint16);

		datalen += x;
		data = gnutls_realloc(data, datalen);

		for (i = 0; i < x/2; i++) {
			memmove(&data[pos], &cipher_suites[i].CipherSuite,
				2);
			pos += 2;
		}

		z = _gnutls_supported_compression_methods
		    (state, &compression_methods);
		memmove(&data[pos++], &z, 1); /* put the number of compression methods */

		datalen += z; 
		data = gnutls_realloc(data, datalen);
		
		for (i = 0; i < z; i++) {
			memmove(&data[pos++], &compression_methods[i], 1);
		}

		gcry_free(rand);
		gnutls_free(cipher_suites);
		gnutls_free(compression_methods);

		ret =
		    _gnutls_send_handshake(cd, state, data, datalen,
					   GNUTLS_CLIENT_HELLO);
		gnutls_free(data);


	} else {		/* SERVER */
		datalen = 2 + sizeof(uint32) + session_id_len + 1 + 28;
		data = gnutls_malloc(datalen);

		data[pos++] = state->connection_state.version.major;
		data[pos++] = state->connection_state.version.minor;
#ifdef WORDS_BIGENDIAN
		cur_time = time(NULL);
#else
		cur_time = byteswap32(time(NULL));
#endif
		memmove(state->security_parameters.server_random,
			&cur_time, 4);
		memmove(&state->security_parameters.server_random[4], rand,
			28);

		memmove(&data[pos], &cur_time, sizeof(uint32));
		pos += sizeof(uint32);
		memmove(&data[pos], rand, 28);
		pos += 28;

		memmove(&data[pos++], &session_id_len, sizeof(uint8));
		if (session_id_len > 0) {
			memmove(&data[pos], SessionID, session_id_len);
		}
		pos += session_id_len;

		datalen += 2;
		data = gnutls_realloc(data, datalen);
		memmove(&data[pos],
			&state->gnutls_internals.
			current_cipher_suite.CipherSuite, 2);
		pos += 2;

		datalen += 1;
		data = gnutls_realloc(data, datalen);
		memmove(&data[pos++],
			&state->gnutls_internals.compression_method, 1);

		gcry_free(rand);
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
int _gnutls_recv_hello(int cd, GNUTLS_STATE state, char *data, int datalen,
		       opaque ** SessionID, int SessionIDnum)
{
	uint8 session_id_len = 0, z;
	int pos = 0;
	GNUTLS_CipherSuite cipher_suite, *cipher_suites;
	CompressionMethod compression_method, *compression_methods;
	int i, ret=0;
	uint16 x, sizeOfSuites;
	GNUTLS_Version version;

	if (state->security_parameters.entity == GNUTLS_CLIENT) {
		if (datalen < 38) {
			gnutls_assert();
			return GNUTLS_E_UNEXPECTED_PACKET_LENGTH;
		}

#ifdef DEBUG
		fprintf(stderr, "Server's version: %d.%d\n", data[pos], data[pos+1]);
#endif
		version.local = 0; /* TLS 1.0 / SSL 3.0 */
		version.major = data[pos];
		version.minor = data[pos+1];
		if ( _gnutls_version_is_supported( state, version) == 0) {
			gnutls_assert();
			return GNUTLS_E_UNSUPPORTED_VERSION_PACKET;
		} else {
			gnutls_set_current_version(state, version);
		}
		pos+=2;
		
		memmove(state->security_parameters.server_random,
			&data[pos], 32);
		pos += 32;

		memmove(&session_id_len, &data[pos++], 1);

		if (datalen < 38 + session_id_len) {
			gnutls_assert();
			return GNUTLS_E_UNSUPPORTED_VERSION_PACKET;
		}
#ifdef HARD_DEBUG
		fprintf(stderr, "SessionID length: %d\n", session_id_len);
		fprintf(stderr, "SessionID: %s\n",
			_gnutls_bin2hex(&data[pos], session_id_len));
#endif
		pos += session_id_len;

		/* We should resume an old connection here. This is not
		 * implemented yet.
		 */

		memmove(&cipher_suite.CipherSuite, &data[pos], 2);
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
		if (z != 0)
			return GNUTLS_E_UNKNOWN_CIPHER_TYPE;
		memmove(state->gnutls_internals.
			current_cipher_suite.CipherSuite,
			cipher_suite.CipherSuite, 2);
#ifdef HARD_DEBUG
				fprintf(stderr, "Selected cipher suite: ");
				fprintf(stderr, "%s\n", _gnutls_cipher_suite_get_name(state->gnutls_internals.current_cipher_suite ) );
#endif
		z = 1;
		memmove(&compression_method, &data[pos++], 1);
		z =
		    _gnutls_supported_compression_methods
		    (state, &compression_methods);
		for (i = 0; i < z; i++) {
			if (memcmp
			    (&compression_methods[i], &compression_method,
			     1) == 0) {
				z = 0;

			}
		}
		if (z != 0)
			return GNUTLS_E_UNKNOWN_COMPRESSION_ALGORITHM;
		memmove(&state->gnutls_internals.compression_method,
			&compression_method, 1);


		gnutls_free(cipher_suites);
		gnutls_free(compression_methods);

	} else {		/* Server side reading a client hello */
		if (datalen < 35) {
			gnutls_assert();
			return GNUTLS_E_UNEXPECTED_PACKET_LENGTH;
		}

#ifdef DEBUG
		fprintf(stderr, "Client's version: %d.%d\n", data[pos], data[pos+1]);
#endif
		version.local = 0; /* TLS 1.0 / SSL 3.0 */
		version.major = data[pos];
		version.minor = data[pos+1];
		if ( _gnutls_version_is_supported( state, version) == 0) {
			gnutls_assert();
			return GNUTLS_E_UNSUPPORTED_VERSION_PACKET;
		} else {
			gnutls_set_current_version(state, version);
		}
		pos+=2;
		
		memmove(state->security_parameters.client_random,
			&data[pos], 32);
		pos += 32;

		memmove(&session_id_len, &data[pos++], 1);
		pos += session_id_len;

		/* We should resume an old connection here. This is not
		 * implemented yet.
		 */


		/* Select a ciphersuite */
		memmove(&sizeOfSuites, &data[pos], 2);
		pos += 2;
#ifndef WORDS_BIGENDIAN
		sizeOfSuites = byteswap16(sizeOfSuites);
#endif
		ret = SelectSuite(state, state->gnutls_internals.
			    current_cipher_suite.CipherSuite, &data[pos],
			    sizeOfSuites); 

		if (ret<0) return ret;
		
		pos += sizeOfSuites;

		memmove(&z, &data[pos++], 1); /* z is the number of compression methods */
		ret = SelectCompMethod(state, &state->
				 gnutls_internals.compression_method,
				 &data[pos], z);
		pos+=z;
		
		if (ret<0) return ret;
	}

	return ret;
}

int _gnutls_recv_certificate(int cd, GNUTLS_STATE state, char *data, int datalen)
{
	uint8 session_id_len = 0, z;
	int pos = 0;
	char* certificate_list;
	int i, ret=0;
	uint16 x;
	uint32 sizeOfCert;
	uint24 num;
	
	if (state->security_parameters.entity == GNUTLS_CLIENT) {
		if (datalen < 2) {
			gnutls_assert();
			return GNUTLS_E_UNEXPECTED_PACKET_LENGTH;
		}

	        num.pint[0] = data[pos];
	       	num.pint[1] = data[pos+1];
		num.pint[2] = data[pos+2];
		sizeOfCert = uint24touint32(num);
		
		pos+=3;
#ifndef WORDS_BIGENDIAN
		sizeOfCert=byteswap32(sizeOfCert);
#endif
		if (sizeOfCert > MAX24) {
			gnutls_assert();
			return GNUTLS_E_UNEXPECTED_PACKET_LENGTH;
		}
		certificate_list = gnutls_malloc(sizeOfCert);
		
		memmove( certificate_list, &data[pos], sizeOfCert);
		
		/* Verify certificates !!! */
		
		gnutls_free(certificate_list); /* oooops! */

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


/* This is the main function in the handshake protocol. This does actually
 * everything. (exchange hello messages etc).
 */

#define HASH(x) state->gnutls_internals.x=HASH_TRUE
#define NOT_HASH(x) state->gnutls_internals.x=HASH_FALSE
int gnutls_handshake(int cd, GNUTLS_STATE state)
{
	int ret;
	char *session_id;
	uint8 session_id_size;

	/* These are in order to hash the messages transmitted and received.
	 * (needed by the protocol)
	 */
	if (_gnutls_version_ssl3(state->connection_state.version) == 0) {
/* FIXME!!! we need to keep the messages and hash them - later! */
//		state->gnutls_internals.client_td_md5 = gnutls_hash_init_ssl3(GNUTLS_MAC_MD5);
//		state->gnutls_internals.client_td_sha1 = gnutls_hash_init_ssl3(GNUTLS_MAC_SHA);
//		state->gnutls_internals.server_td_md5 = gnutls_hash_init_ssl3(GNUTLS_MAC_MD5);
//		state->gnutls_internals.server_td_sha1 = gnutls_hash_init_ssl3(GNUTLS_MAC_SHA);
	} else {
		state->gnutls_internals.client_td_md5 = gnutls_hash_init(GNUTLS_MAC_MD5);
		state->gnutls_internals.client_td_sha1 = gnutls_hash_init(GNUTLS_MAC_SHA);
		state->gnutls_internals.server_td_md5 = gnutls_hash_init(GNUTLS_MAC_MD5);
		state->gnutls_internals.server_td_sha1 = gnutls_hash_init(GNUTLS_MAC_SHA);
	}
	if (state->security_parameters.entity == GNUTLS_CLIENT) {
		HASH(client_hash);
		HASH(server_hash);
		ret = _gnutls_send_hello(cd, state, NULL, 0);
		NOT_HASH(client_hash);
		NOT_HASH(server_hash);
		if (ret < 0) {
			ERR("send hello", ret);
			return ret;
		}

		/* receive the server hello */
		HASH(client_hash);
		HASH(server_hash);
		ret =
		    _gnutls_recv_handshake(cd, state, NULL, NULL, GNUTLS_SERVER_HELLO);
		NOT_HASH(client_hash);
		NOT_HASH(server_hash);
		if (ret < 0) {
			ERR("recv hello", ret);
			return ret;
		}

		/* RECV CERTIFICATE + KEYEXCHANGE + CERTIFICATE_REQUEST */
		HASH(client_hash);
		HASH(server_hash);
		ret =
		    _gnutls_recv_handshake(cd, state, NULL, NULL, GNUTLS_CERTIFICATE);
		NOT_HASH(client_hash);
		NOT_HASH(server_hash);
		if (ret < 0) {
			ERR("recv server certificate", ret);
			return ret;
		}
		

		/* receive the server key exchange */
		HASH(client_hash);
		HASH(server_hash);
		ret = _gnutls_recv_server_kx_message(cd, state);
		NOT_HASH(client_hash);
		NOT_HASH(server_hash);
		if (ret < 0) {
			ERR("recv server kx message", ret);
			return ret;
		}


		/* receive the server hello done */
		HASH(client_hash);
		HASH(server_hash);
		ret =
		    _gnutls_recv_handshake(cd, state, NULL, NULL,
					   GNUTLS_SERVER_HELLO_DONE);
		NOT_HASH(client_hash);
		NOT_HASH(server_hash);
		if (ret < 0) {
			ERR("recv server hello done", ret);
			return ret;
		}

		/* SEND CERTIFICATE + KEYEXCHANGE + CERTIFICATE_VERIFY */
		HASH(client_hash);
		HASH(server_hash);
		ret = _gnutls_send_client_certificate(cd, state);
		NOT_HASH(client_hash);
		NOT_HASH(server_hash);
		if (ret < 0) {
			ERR("send client certificate", ret);
			return ret;
		}


		HASH(client_hash);
		HASH(server_hash);
		ret = _gnutls_send_client_kx_message(cd, state);
		NOT_HASH(client_hash);
		NOT_HASH(server_hash);
		if (ret < 0) {
			ERR("send client kx", ret);
			return ret;
		}

		HASH(client_hash);
		HASH(server_hash);
		ret = _gnutls_send_client_certificate_verify( cd, state);
		NOT_HASH(client_hash);
		NOT_HASH(server_hash);
		if (ret < 0) {
			ERR("send client certificate verify", ret);
			return ret;
		}

		/* Send the CHANGE CIPHER SPEC PACKET */
		ret = _gnutls_send_change_cipher_spec(cd, state);
		if (ret < 0) {
			ERR("send ChangeCipherSpec", ret);
			return ret;
		}
	if (_gnutls_version_ssl3(state->connection_state.version) == 0) {
		state->gnutls_internals.client_md_md5 =
		    gnutls_hash_deinit_ssl3(state->gnutls_internals.client_td_md5);
		state->gnutls_internals.client_md_sha1 =
		    gnutls_hash_deinit_ssl3(state->gnutls_internals.client_td_sha1);
	} else {
		state->gnutls_internals.client_md_md5 =
		    gnutls_hash_deinit(state->gnutls_internals.client_td_md5);
		state->gnutls_internals.client_md_sha1 =
		    gnutls_hash_deinit(state->gnutls_internals.client_td_sha1);
	}

		/* Initialize the connection state (start encryption) */
		ret = _gnutls_connection_state_init(state);
		if (ret<0) return ret;

		/* send the finished message */

		NOT_HASH(client_hash);
		HASH(server_hash);
		ret = _gnutls_send_finished(cd, state);
		NOT_HASH(client_hash);
		NOT_HASH(server_hash);
		if (ret < 0) {
			ERR("send Finished", ret);
			return ret;
		}


		ret =
		    gnutls_recv_int(cd, state, GNUTLS_CHANGE_CIPHER_SPEC,
				    NULL, 0);
		if (ret < 0) {
			ERR("recv ChangeCipherSpec", ret);
			return ret;
		}

		if (_gnutls_version_ssl3(state->connection_state.version) == 0) {
			state->gnutls_internals.server_md_md5 =
			    gnutls_hash_deinit_ssl3(state->gnutls_internals.server_td_md5);
			state->gnutls_internals.server_md_sha1 =
		    	    gnutls_hash_deinit_ssl3(state->gnutls_internals.server_td_sha1);
		} else {
			state->gnutls_internals.server_md_md5 =
			    gnutls_hash_deinit(state->gnutls_internals.server_td_md5);
			state->gnutls_internals.server_md_sha1 =
		    	    gnutls_hash_deinit(state->gnutls_internals.server_td_sha1);
		}
		NOT_HASH(client_hash);
		NOT_HASH(server_hash);
		ret = _gnutls_recv_finished(cd, state);
		if (ret < 0) {
			ERR("recv finished", ret);
			return ret;
		}

		gnutls_free(state->gnutls_internals.client_md_md5);
		gnutls_free(state->gnutls_internals.client_md_sha1);
		gnutls_free(state->gnutls_internals.server_md_md5);
		gnutls_free(state->gnutls_internals.server_md_sha1);

	} else {		/* SERVER */

		HASH(client_hash);
		HASH(server_hash);
		ret =
		    _gnutls_recv_handshake(cd, state, NULL, NULL,
					   GNUTLS_CLIENT_HELLO);
		NOT_HASH(client_hash);
		NOT_HASH(server_hash);
		if (ret < 0) {
			ERR("recv hello", ret);
			return ret;
		}

		_gnutls_generate_session_id(&session_id, &session_id_size);
		HASH(client_hash);
		HASH(server_hash);
		ret =
		    _gnutls_send_hello(cd, state, session_id,
				       session_id_size);
		NOT_HASH(client_hash);
		NOT_HASH(server_hash);
		if (ret < 0) {
			ERR("send hello", ret);
			return ret;
		}
		gnutls_free(session_id);

		/* SEND CERTIFICATE + KEYEXCHANGE + CERTIFICATE_REQUEST */
		HASH(client_hash);
		HASH(server_hash);
		ret = _gnutls_send_server_kx_message(cd, state);
		NOT_HASH(client_hash);
		NOT_HASH(server_hash);
		if (ret < 0) {
			ERR("send server kx", ret);
			return ret;
		}

		/* send the server hello done */
		HASH(client_hash);
		HASH(server_hash);
		ret =
		    _gnutls_send_handshake(cd, state, NULL, 0,
					   GNUTLS_SERVER_HELLO_DONE);
		NOT_HASH(client_hash);
		NOT_HASH(server_hash);
		if (ret < 0) {
			ERR("send server hello done", ret);
			return ret;
		}

		/* RECV CERTIFICATE + KEYEXCHANGE + CERTIFICATE_VERIFY */
		
		HASH(client_hash);
		HASH(server_hash);
		ret = _gnutls_recv_client_kx_message(cd, state);
		NOT_HASH(client_hash);
		NOT_HASH(server_hash);
		if (ret < 0) {
			ERR("recv client kx", ret);
			return ret;
		}

		ret =
		    gnutls_recv_int(cd, state, GNUTLS_CHANGE_CIPHER_SPEC,
				    NULL, 0);
		if (ret < 0) {
			ERR("recv ChangeCipherSpec", ret);
			return ret;
		}

		/* Initialize the connection state (start encryption) */
		ret = _gnutls_connection_state_init(state);
		if (ret<0) return ret;

		if (_gnutls_version_ssl3(state->connection_state.version) == 0) {
			state->gnutls_internals.client_md_md5 =
			    gnutls_hash_deinit_ssl3(state->gnutls_internals.client_td_md5);
			state->gnutls_internals.client_md_sha1 =
			    gnutls_hash_deinit_ssl3(state->gnutls_internals.client_td_sha1);
		} else {
			state->gnutls_internals.client_md_md5 =
			    gnutls_hash_deinit(state->gnutls_internals.client_td_md5);
			state->gnutls_internals.client_md_sha1 =
			    gnutls_hash_deinit(state->gnutls_internals.client_td_sha1);		
		}
		NOT_HASH(client_hash);
		HASH(server_hash);
		ret = _gnutls_recv_finished(cd, state);
		NOT_HASH(client_hash);
		NOT_HASH(server_hash);
		if (ret < 0) {
			ERR("recv finished", ret);
			return ret;
		}

		ret = _gnutls_send_change_cipher_spec(cd, state);
		if (ret < 0) {
			ERR("send ChangeCipherSpec", ret);
			return ret;
		}

		if (_gnutls_version_ssl3(state->connection_state.version) == 0) {
			state->gnutls_internals.server_md_md5 =
			    gnutls_hash_deinit_ssl3(state->gnutls_internals.server_td_md5);
			state->gnutls_internals.server_md_sha1 =
			    gnutls_hash_deinit_ssl3(state->gnutls_internals.server_td_sha1);
		} else {
			state->gnutls_internals.server_md_md5 =
			    gnutls_hash_deinit(state->gnutls_internals.server_td_md5);
			state->gnutls_internals.server_md_sha1 =
			    gnutls_hash_deinit(state->gnutls_internals.server_td_sha1);		
		}
		NOT_HASH(client_hash);
		NOT_HASH(server_hash);
		ret = _gnutls_send_finished(cd, state);
		if (ret < 0) {
			ERR("send finished", ret);
			return ret;
		}

		gnutls_free(state->gnutls_internals.server_md_md5);
		gnutls_free(state->gnutls_internals.server_md_sha1);
		gnutls_free(state->gnutls_internals.client_md_md5);
		gnutls_free(state->gnutls_internals.client_md_sha1);

	}

	return ret;

}

int _gnutls_generate_session_id(char **session_id, uint8 * len)
{
	char *rand;
	*session_id = gnutls_malloc(32);
	rand = gcry_random_bytes(32, GCRY_WEAK_RANDOM);

	memmove(*session_id, rand, 32);
	gcry_free(rand);
	*len = 32;

#ifdef HARD_DEBUG
	fprintf(stderr, "SessionID: %s\n", _gnutls_bin2hex(*session_id, 32));
#endif
	return 0;
}
