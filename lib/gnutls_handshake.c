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

#ifdef DEBUG
#define ERR(x, y) fprintf(stderr, "GNUTLS Error: %s (%d)\n", x,y)
#else
#define ERR(x, y)
#endif

#define HASH_TRUE 1
#define HASH_FALSE 0

#define SERVER_MSG "server finished"
#define CLIENT_MSG "client finished"
int _gnutls_send_finished(int cd, GNUTLS_STATE state)
{
	uint8 *data;
	uint8 concat[36];	/* md5+sha1 */
	int ret;


	memset(concat, 0, 36);

	if (state->security_parameters.entity == GNUTLS_CLIENT) {
		memmove(concat, state->gnutls_internals.client_md_md5, 16);
		memmove(&concat[16],
			state->gnutls_internals.client_md_sha1, 20);

		data =
		    gnutls_PRF(state->security_parameters.master_secret,
			       48, CLIENT_MSG, strlen(CLIENT_MSG), concat,
			       36, 12);
	} else {		/* server */
		memmove(concat, state->gnutls_internals.server_md_md5, 16);
		memmove(&concat[16],
			state->gnutls_internals.server_md_sha1, 20);

		data =
		    gnutls_PRF(state->security_parameters.master_secret,
			       48, SERVER_MSG, strlen(SERVER_MSG), concat,
			       36, 12);
	}

	ret = _gnutls_send_handshake(cd, state, data, 12, GNUTLS_FINISHED);
	gnutls_free(data);

	return ret;
}

int _gnutls_recv_handshake(int cd, GNUTLS_STATE state, void *data,
			   uint32 datalen, HandshakeType type)
{
	int ret;
	state->gnutls_internals.next_handshake_type = type;
	ret = gnutls_recv_int(cd, state, GNUTLS_HANDSHAKE, data, datalen);
	state->gnutls_internals.next_handshake_type = GNUTLS_NONE;

	return ret;
}

_gnutls_recv_finished(int cd, GNUTLS_STATE state)
{
	uint8 *data, vrfy[12];
	uint8 concat[36];	/* md5+sha1 */
	int ret = 0;

	memset(concat, 0, 36);
	memset(vrfy, 0, 12);

	ret = _gnutls_recv_handshake(cd, state, vrfy, 12, GNUTLS_FINISHED);
	if (ret < 0) {
		ERR("recv finished int", ret);
		return ret;
	}
	if (ret != 12)
		return GNUTLS_E_ERROR_IN_FINISHED_PACKET;

	if (state->security_parameters.entity == GNUTLS_CLIENT) {
		memmove(concat, state->gnutls_internals.server_md_md5, 16);
		memmove(&concat[16],
			state->gnutls_internals.server_md_sha1, 20);

		data =
		    gnutls_PRF(state->security_parameters.master_secret,
			       48, SERVER_MSG, strlen(SERVER_MSG), concat,
			       36, 12);
	} else {		/* server */
		memmove(concat, state->gnutls_internals.client_md_md5, 16);
		memmove(&concat[16],
			state->gnutls_internals.client_md_sha1, 20);

		data =
		    gnutls_PRF(state->security_parameters.master_secret,
			       48, CLIENT_MSG, strlen(CLIENT_MSG), concat,
			       36, 12);
	}

	if (memcmp(vrfy, data, 12) != 0)
		ret = GNUTLS_E_ERROR_IN_FINISHED_PACKET;

	gnutls_free(data);

	return ret;
}



int SelectSuite(opaque ret[2], char *data, int datalen)
{
	int x, pos = 0, i, j;
	GNUTLS_CipherSuite *ciphers;

	x = _gnutls_supported_ciphersuites(&ciphers);
	memset(ret, '\0', sizeof(GNUTLS_CipherSuite));

	for (j = 0; j < datalen; j += 2) {
		for (i = 0; i < x; i++) {
			if (memcmp(&ciphers[i].CipherSuite, &data[j], 2) ==
			    0) {
				memmove(ret, &ciphers[i].CipherSuite, 2);
				gnutls_free(ciphers);
				return 0;
			}
		}
	}


	gnutls_free(ciphers);
	return GNUTLS_E_UNKNOWN_CIPHER;

}

int SelectCompMethod(CompressionMethod * ret, char *data, int datalen)
{
	int x, pos = 0, i, j;
	CompressionMethod *ciphers;

	x = _gnutls_supported_compression_methods(&ciphers);
	memset(ret, '\0', sizeof(CompressionMethod));

	for (j = 0; j < datalen; j++) {
		for (i = 0; i < x; i++) {
			if (memcmp(&ciphers[i], &data[j], 1) == 0) {
				memmove(ret, &ciphers[i], 1);
				gnutls_free(ciphers);
				return 0;
			}
		}
	}


	gnutls_free(ciphers);
	return GNUTLS_E_UNKNOWN_COMPRESSION_ALGORITHM;

}


int _gnutls_supported_ciphersuites(GNUTLS_CipherSuite ** ciphers)
{

	int i;
	int count = _gnutls_cipher_suite_count();
	*ciphers = gnutls_malloc(count * sizeof(GNUTLS_CipherSuite));


	for (i = 0; i < count; i++) {

		(*ciphers)[i].CipherSuite[0] =
		    cipher_suite_algorithms[i].suite.CipherSuite[0];
		(*ciphers)[i].CipherSuite[1] =
		    cipher_suite_algorithms[i].suite.CipherSuite[1];
	}

	return count;
}


#define SUPPORTED_COMPRESSION_METHODS 1
int _gnutls_supported_compression_methods(CompressionMethod ** comp)
{

	int i;

	*comp =
	    gnutls_malloc(SUPPORTED_COMPRESSION_METHODS *
			  sizeof(CompressionMethod));

/* NULL Compression */
	(*comp)[0] = COMPRESSION_NULL;

	return SUPPORTED_COMPRESSION_METHODS;
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

	if (i_datasize > 0)
		memmove(&data[pos], i_data, i_datasize - 4);

	if (state->gnutls_internals.client_hash == HASH_TRUE) {
		mhash(state->gnutls_internals.client_td_md5, data,
		      i_datasize);
		mhash(state->gnutls_internals.client_td_sha1, data,
		      i_datasize);
	}
	if (state->gnutls_internals.server_hash == HASH_TRUE) {
		mhash(state->gnutls_internals.server_td_md5, data,
		      i_datasize);
		mhash(state->gnutls_internals.server_td_sha1, data,
		      i_datasize);
	}

	ret =
	    gnutls_send_int(cd, state, GNUTLS_HANDSHAKE, data, i_datasize);

	return ret;
}

int _gnutls_recv_handshake_int(int cd, GNUTLS_STATE state, void *data,
			       uint32 datasize, void *output_data,
			       uint32 output_datasize)
{
	int ret;
	uint32 length32 = 0;
	int pos = 0;
	uint8 *dataptr = data;
	uint24 num;


	num.pint[0] = dataptr[1];
	num.pint[1] = dataptr[2];
	num.pint[2] = dataptr[3];
	length32 = uint24touint32(num);


#ifndef WORDS_BIGENDIAN
	length32 = byteswap32(length32);
#endif

	if (state->gnutls_internals.client_hash == HASH_TRUE) {
		mhash(state->gnutls_internals.client_td_md5, dataptr,
		      length32 + 4);
		mhash(state->gnutls_internals.client_td_sha1, dataptr,
		      length32 + 4);
	}

	if (state->gnutls_internals.server_hash == HASH_TRUE) {
		mhash(state->gnutls_internals.server_td_md5, dataptr,
		      length32 + 4);
		mhash(state->gnutls_internals.server_td_sha1, dataptr,
		      length32 + 4);
	}

	ret = GNUTLS_E_UNEXPECTED_HANDSHAKE_PACKET;

	switch (dataptr[0]) {
	case GNUTLS_CLIENT_HELLO:
	case GNUTLS_SERVER_HELLO:
		if (state->gnutls_internals.next_handshake_type ==
		    dataptr[0]) ret =
			    _gnutls_recv_hello(cd, state, &dataptr[4],
					       length32, NULL, 0);
		break;
	case GNUTLS_SERVER_HELLO_DONE:
		ret = 0;
		break;
	case GNUTLS_FINISHED:
		if (output_datasize > length32)
			output_datasize = length32;
		memmove(output_data, &dataptr[4], length32);
		ret = length32;
		break;
	case GNUTLS_SERVER_KEY_EXCHANGE:
		if (output_datasize > length32)
			output_datasize = length32;
		memmove(output_data, &dataptr[4], length32);
		ret = length32;
		break;
	case GNUTLS_CLIENT_KEY_EXCHANGE:
		if (output_datasize > length32)
			output_datasize = length32;
		memmove(output_data, &dataptr[4], length32);
		ret = length32;
		break;
	}

	return ret;
}

int _gnutls_send_hello_request(int cd, GNUTLS_STATE state)
{
	return _gnutls_send_handshake(cd, state, NULL, 0,
				      GNUTLS_HELLO_REQUEST);
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
		data = gnutls_malloc(datalen);

		data[pos++] = GNUTLS_VERSION_MAJOR;
		data[pos++] = GNUTLS_VERSION_MINOR;
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

		x = _gnutls_supported_ciphersuites(&cipher_suites);

#ifdef WORDS_BIGENDIAN
		memmove(&data[pos], &x, sizeof(uint16));
#else
		x = byteswap16(x);
		memmove(&data[pos], &x, sizeof(uint16));
		x = byteswap16(x);
#endif
		pos += 2;

		datalen += 2 * x;
		data = gnutls_realloc(data, datalen);

		for (i = 0; i < x; i++) {
			memmove(&data[pos], &cipher_suites[i].CipherSuite,
				2);
			pos += 2;
		}

		z =
		    _gnutls_supported_compression_methods
		    (&compression_methods);
		memmove(&data[pos++], &z, sizeof(uint8));
		datalen += z;
		data = gnutls_realloc(data, datalen);

		for (i = 0; i < z; i++) {
			memmove(&data[pos], &compression_methods[i], 1);
			pos++;
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

		data[pos++] = GNUTLS_VERSION_MAJOR;
		data[pos++] = GNUTLS_VERSION_MINOR;
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
	uint32 cur_time;
	int pos = 0;
	GNUTLS_CipherSuite cipher_suite, *cipher_suites;
	CompressionMethod compression_method, *compression_methods;
	int i, ret;
	uint16 x, sizeOfSuites;

	if (state->security_parameters.entity == GNUTLS_CLIENT) {
		if (datalen < 38)
			return GNUTLS_E_UNEXPECTED_PACKET_LENGTH;

#ifdef DEBUG
		fprintf(stderr, "Server's major version: %d\n", data[pos]);
#endif
		if (data[pos++] != GNUTLS_VERSION_MAJOR)
			return GNUTLS_E_UNSUPPORTED_VERSION_PACKET;

#ifdef DEBUG
		fprintf(stderr, "Server's minor version: %d\n", data[pos]);
#endif
		if (data[pos++] != GNUTLS_VERSION_MINOR)
			return GNUTLS_E_UNSUPPORTED_VERSION_PACKET;

		memmove(state->security_parameters.server_random,
			&data[pos], 32);
		pos += 32;

		memmove(&session_id_len, &data[pos++], 1);

		if (datalen < 38 + session_id_len)
			return GNUTLS_E_UNSUPPORTED_VERSION_PACKET;
#ifdef DEBUG
		fprintf(stderr, "SessionID length: %d\n", session_id_len);
		fprintf(stderr, "SessionID: %s\n",
			bin2hex(&data[pos], session_id_len));
#endif
		pos += session_id_len;

		/* We should resume an old connection here. This is not
		 * implemented yet.
		 */

		memmove(&cipher_suite.CipherSuite, &data[pos], 2);
		pos += 2;

		z = 1;
		x = _gnutls_supported_ciphersuites(&cipher_suites);
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

		z = 1;
		memmove(&compression_method, &data[pos++], 1);
		z =
		    _gnutls_supported_compression_methods
		    (&compression_methods);
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
		if (datalen < 35)
			return GNUTLS_E_UNEXPECTED_PACKET_LENGTH;

#ifdef DEBUG
		fprintf(stderr, "Client's major version: %d\n", data[pos]);
#endif

		if (data[pos++] != GNUTLS_VERSION_MAJOR)
			return GNUTLS_E_UNSUPPORTED_VERSION_PACKET;


#ifdef DEBUG
		fprintf(stderr, "Client's minor version: %d\n", data[pos]);
#endif

		if (data[pos++] != GNUTLS_VERSION_MINOR)
			return GNUTLS_E_UNSUPPORTED_VERSION_PACKET;

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
		SelectSuite(state->gnutls_internals.
			    current_cipher_suite.CipherSuite, &data[pos],
			    sizeOfSuites);
		pos += sizeOfSuites;

		memmove(&z, &data[pos++], 1);
		SelectCompMethod(&state->
				 gnutls_internals.compression_method,
				 &data[pos], z);

	}

	return ret;
}

#define HASH(x) state->gnutls_internals.x=HASH_TRUE
#define NOT_HASH(x) state->gnutls_internals.x=HASH_FALSE

int gnutls_handshake(int cd, GNUTLS_STATE state)
{
	int ret;
	char *session_id;
	uint8 session_id_size;

	state->gnutls_internals.client_td_md5 = mhash_init(MHASH_MD5);
	state->gnutls_internals.client_td_sha1 = mhash_init(MHASH_SHA1);
	state->gnutls_internals.server_td_md5 = mhash_init(MHASH_MD5);
	state->gnutls_internals.server_td_sha1 = mhash_init(MHASH_SHA1);

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
		    _gnutls_recv_handshake(cd, state, NULL, 0,
					   GNUTLS_SERVER_HELLO);
		NOT_HASH(client_hash);
		NOT_HASH(server_hash);
		if (ret < 0) {
			ERR("recv hello", ret);
			return ret;
		}

		/* RECV CERTIFICATE + KEYEXCHANGE + CERTIFICATE_REQUEST */

		/* receive the server key exchange */
		HASH(client_hash);
		HASH(server_hash);
		ret = _gnutls_recv_server_kx_message(cd, state);
		NOT_HASH(client_hash);
		NOT_HASH(server_hash);
		if (ret < 0) {
			ERR("recv server hello done", ret);
			return ret;
		}


		/* receive the server hello done */
		HASH(client_hash);
		HASH(server_hash);
		ret =
		    _gnutls_recv_handshake(cd, state, NULL, 0,
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
		ret = _gnutls_send_client_kx_message(cd, state);
		NOT_HASH(client_hash);
		NOT_HASH(server_hash);
		if (ret < 0) {
			ERR("send client kx", ret);
			return ret;
		}


		/* Send the CHANGE CIPHER SPEC PACKET */
		ret = _gnutls_send_change_cipher_spec(cd, state);
		if (ret < 0) {
			ERR("send ChangeCipherSpec", ret);
			return ret;
		}


		state->gnutls_internals.client_md_md5 =
		    mhash_end(state->gnutls_internals.client_td_md5);
		state->gnutls_internals.client_md_sha1 =
		    mhash_end(state->gnutls_internals.client_td_sha1);

		/* Initialize the connection state (start encryption) */
		_gnutls_connection_state_init(state);

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

		state->gnutls_internals.server_md_md5 =
		    mhash_end(state->gnutls_internals.server_td_md5);
		state->gnutls_internals.server_md_sha1 =
		    mhash_end(state->gnutls_internals.server_td_sha1);

		NOT_HASH(client_hash);
		NOT_HASH(server_hash);
		ret = _gnutls_recv_finished(cd, state);
		if (ret < 0) {
			ERR("recv finished", ret);
			return ret;
		}

		mhash_free(state->gnutls_internals.client_md_md5);
		mhash_free(state->gnutls_internals.client_md_sha1);
		mhash_free(state->gnutls_internals.server_md_md5);
		mhash_free(state->gnutls_internals.server_md_sha1);

	} else {		/* SERVER */

		HASH(client_hash);
		HASH(server_hash);
		ret =
		    _gnutls_recv_handshake(cd, state, NULL, 0,
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



		/* Initialize the connection state (start encryption) */



		ret =
		    gnutls_recv_int(cd, state, GNUTLS_CHANGE_CIPHER_SPEC,
				    NULL, 0);
		if (ret < 0) {
			ERR("recv ChangeCipherSpec", ret);
			return ret;
		}

		_gnutls_connection_state_init(state);

		state->gnutls_internals.client_md_md5 =
		    mhash_end(state->gnutls_internals.client_td_md5);
		state->gnutls_internals.client_md_sha1 =
		    mhash_end(state->gnutls_internals.client_td_sha1);

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

		state->gnutls_internals.server_md_md5 =
		    mhash_end(state->gnutls_internals.server_td_md5);
		state->gnutls_internals.server_md_sha1 =
		    mhash_end(state->gnutls_internals.server_td_sha1);

		NOT_HASH(client_hash);
		NOT_HASH(server_hash);
		ret = _gnutls_send_finished(cd, state);
		if (ret < 0) {
			ERR("recv finished", ret);
			return ret;
		}

		mhash_free(state->gnutls_internals.server_md_md5);
		mhash_free(state->gnutls_internals.server_md_sha1);
		mhash_free(state->gnutls_internals.client_md_md5);
		mhash_free(state->gnutls_internals.client_md_sha1);

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

#ifdef DEBUG
	fprintf(stderr, "SessionID: %s\n", bin2hex(*session_id, 32));
#endif
	return 0;
}
