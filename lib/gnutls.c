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
#include "debug.h"
#include "gnutls_compress.h"
#include "gnutls_plaintext.h"
#include "gnutls_cipher.h"
#include "gnutls_buffers.h"
#include "gnutls_handshake.h"
#include "gnutls_hash_int.h"
#include "gnutls_cipher_int.h"
#include "gnutls_priority.h"
#include "gnutls_algorithms.h"
#include "gnutls_db.h"
#include "gnutls_auth_int.h"
#include "gnutls_num.h"
#ifdef HAVE_ERRNO_H
#include <errno.h>
#endif

#ifndef EAGAIN
# define EAGAIN EWOULDBLOCK
#endif

GNUTLS_Version gnutls_get_current_version(GNUTLS_STATE state) {
GNUTLS_Version ver;
	ver = state->connection_state.version;
	return ver;
}

void gnutls_set_current_version(GNUTLS_STATE state, GNUTLS_Version version) {
	state->connection_state.version = version;
	state->gnutls_key->version.major = _gnutls_version_get_major(version);
	state->gnutls_key->version.minor = _gnutls_version_get_minor(version);
}

int gnutls_is_secure_memory(const void* mem) {
	return 0;
}

/**
  * gnutls_set_lowat - Used to set the lowat value in order for select to check for pending data.
  * @state: is a &GNUTLS_STATE structure.
  * @num: is the low water value.
  *
  * Used to set the lowat value in order for select to check
  * if there are pending data to socket buffer. Used only   
  * if you have changed the default low water value (default is 1).
  * Normally you will not need that function.
  **/
int gnutls_set_lowat(GNUTLS_STATE state, int num) {
	state->gnutls_internals.lowat = num;
	return 0;
}

/**
  * gnutls_init - This function initializes the state to null (null encryption etc...).
  * @con_end: is used to indicate if this state is to be used for server or 
  * client. Can be one of GNUTLS_CLIENT and GNUTLS_SERVER. 
  * @state: is a pointer to a &GNUTLS_STATE structure.
  *
  * This function initializes the current state to null. Every state
  * must be initialized before use, so internal structures can be allocated.
  * This function allocates structures which can only be free'd
  * by calling gnutls_deinit(). Returns zero on success.
  **/
int gnutls_init(GNUTLS_STATE * state, ConnectionEnd con_end)
{
	/* for gcrypt in order to be able to allocate memory */
	gcry_set_allocation_handler(gnutls_malloc, secure_malloc, gnutls_is_secure_memory, gnutls_realloc, free);

	*state = gnutls_calloc(1, sizeof(GNUTLS_STATE_INT));
	
	(*state)->security_parameters.entity = con_end;

/* Set the defaults for initial handshake */
	(*state)->security_parameters.bulk_cipher_algorithm = GNUTLS_NULL_CIPHER;
	(*state)->security_parameters.mac_algorithm = GNUTLS_NULL_MAC;
	(*state)->security_parameters.compression_algorithm = GNUTLS_NULL_COMPRESSION;

	(*state)->gnutls_internals.resumable = RESUME_TRUE;

	gnutls_set_current_version ( (*state), GNUTLS_TLS1); /* default */

	(*state)->gnutls_key = gnutls_calloc(1, sizeof(GNUTLS_KEY_A));

	(*state)->gnutls_internals.resumed = RESUME_FALSE;

	(*state)->gnutls_internals.expire_time = DEFAULT_EXPIRE_TIME; /* one hour default */

	gnutls_set_lowat((*state), DEFAULT_LOWAT); /* the default for tcp */

	/* everything else not initialized here is initialized
	 * as NULL or 0. This is why calloc is used.
	 */
	
	return 0;
}

#define GNUTLS_FREE(x) if(x!=NULL) gnutls_free(x)
/**
  * gnutls_init - This function clears all buffers associated with the &state
  * @state: is a &GNUTLS_STATE structure.
  *
  * This function clears all buffers associated with the &state.
  **/
int gnutls_deinit(GNUTLS_STATE state)
{
	/* if the session has failed abnormally it has to be removed from the db */
	if ( state->gnutls_internals.resumable==RESUME_FALSE) {
		_gnutls_db_remove_session( state, state->security_parameters.session_id, state->security_parameters.session_id_size);
	}

	/* remove auth info firstly */
	GNUTLS_FREE(state->gnutls_key->auth_info);

#ifdef HAVE_LIBGDBM
	/* close the database - resuming sessions */
	if ( state->gnutls_internals.db_reader != NULL)
		gdbm_close(state->gnutls_internals.db_reader);
#endif

	GNUTLS_FREE(state->connection_state.read_compression_state);
	GNUTLS_FREE(state->connection_state.read_mac_secret);
	GNUTLS_FREE(state->connection_state.write_compression_state);
	GNUTLS_FREE(state->connection_state.write_mac_secret);

	GNUTLS_FREE(state->gnutls_internals.buffer.data);
	GNUTLS_FREE(state->gnutls_internals.buffer_handshake.data);
	GNUTLS_FREE(state->gnutls_internals.hash_buffer.data);

	gnutls_clear_creds( state);

	if (state->connection_state.read_cipher_state != NULL)
		gnutls_cipher_deinit(state->connection_state.read_cipher_state);
	if (state->connection_state.write_cipher_state != NULL)
		gnutls_cipher_deinit(state->connection_state.write_cipher_state);

	secure_free(state->cipher_specs.server_write_mac_secret);
	secure_free(state->cipher_specs.client_write_mac_secret);
	secure_free(state->cipher_specs.server_write_IV);
	secure_free(state->cipher_specs.client_write_IV);
	secure_free(state->cipher_specs.server_write_key);
	secure_free(state->cipher_specs.client_write_key);

	mpi_release(state->gnutls_key->KEY);
	mpi_release(state->gnutls_key->client_Y);
	mpi_release(state->gnutls_key->client_p);
	mpi_release(state->gnutls_key->client_g);

	mpi_release(state->gnutls_key->u);
	mpi_release(state->gnutls_key->a);
	mpi_release(state->gnutls_key->x);
	mpi_release(state->gnutls_key->A);
	mpi_release(state->gnutls_key->B);
	mpi_release(state->gnutls_key->b);

	mpi_release(state->gnutls_key->dh_secret);
	GNUTLS_FREE(state->gnutls_key);


	/* free priorities */
	GNUTLS_FREE(state->gnutls_internals.MACAlgorithmPriority.algorithm_priority);
	GNUTLS_FREE(state->gnutls_internals.KXAlgorithmPriority.algorithm_priority);
	GNUTLS_FREE(state->gnutls_internals.BulkCipherAlgorithmPriority.algorithm_priority);
	GNUTLS_FREE(state->gnutls_internals.CompressionMethodPriority.algorithm_priority);

	GNUTLS_FREE(state->gnutls_internals.db_name);

	GNUTLS_FREE(state);
	return 0;
}

inline
static void *_gnutls_cal_PRF_A( MACAlgorithm algorithm, void *secret, int secret_size, void *seed, int seed_size)
{
	GNUTLS_MAC_HANDLE td1;

	td1 = gnutls_hmac_init(algorithm, secret, secret_size);
	gnutls_hmac(td1, seed, seed_size);
	return gnutls_hmac_deinit(td1);
}


/* Produces "total_bytes" bytes using the hash algorithm specified.
 * (used in the PRF function)
 */
static svoid *gnutls_P_hash( MACAlgorithm algorithm, opaque * secret, int secret_size, opaque * seed, int seed_size, int total_bytes)
{

	GNUTLS_MAC_HANDLE td2;
	opaque *ret;
	void *A, *Atmp;
	int i = 0, times, how, blocksize, A_size;
	void *final;

	ret = secure_calloc(1, total_bytes);

	blocksize = gnutls_hmac_get_algo_len(algorithm);
	do {
		i += blocksize;
	} while (i < total_bytes);

	/* calculate A(0) */
	A = gnutls_malloc(seed_size);
	if (A==NULL) {
		gnutls_assert();
		return NULL;
	}
	
	
	memmove( A, seed, seed_size);
	A_size = seed_size;

	times = i / blocksize;
	for (i = 0; i < times; i++) {
		td2 = gnutls_hmac_init(algorithm, secret, secret_size);

		/* here we calculate A(i+1) */
		Atmp = _gnutls_cal_PRF_A( algorithm, secret, secret_size, A, A_size);
		if (Atmp==NULL) {
			gnutls_assert();
			return NULL;
		}
		A_size = blocksize;
		gnutls_free(A);
		A = Atmp;

		gnutls_hmac(td2, A, A_size);
		gnutls_hmac(td2, seed, seed_size);
		final = gnutls_hmac_deinit(td2);
		if (final==NULL) {
			gnutls_assert();
			return NULL;
		}

		if ( (1+i) * blocksize < total_bytes) {
			how = blocksize;
		} else {
			how = total_bytes - (i) * blocksize;
		}

		if (how > 0) {
			memmove(&ret[i * blocksize], final, how);
		}
		gnutls_free(final);
	}
	gnutls_free(A);
	return ret;
}

/* Function that xor's buffers using the maximum word size supported
 * by the system. It should be faster.
 */
inline static
void _gnutls_xor(void* _o1, void* _o2, int _length) {
unsigned long int* o1 = _o1;
unsigned long int* o2 = _o2;
int i, length = _length/sizeof(unsigned long int);
int modlen = _length%sizeof(unsigned long int);

	for (i = 0; i < length; i++) {
		o1[i] ^= o2[i];
	}
	i*=sizeof(unsigned long int);
	for (;i<modlen;i++) {
		((char*)_o1)[i] ^= ((char*)_o2)[i];
	}
	return ;
}

/* The PRF function expands a given secret 
 * needed by the TLS specification
 */
svoid *gnutls_PRF( opaque * secret, int secret_size, uint8 * label, int label_size, opaque * seed, int seed_size, int total_bytes)
{
	int l_s, s_seed_size;
	char *o1, *o2;
	char *s1, *s2;
	char *s_seed;

	/* label+seed = s_seed */
	s_seed_size = seed_size + label_size;
	s_seed = gnutls_malloc(s_seed_size);
	if (s_seed==NULL) {
		gnutls_assert();
		return NULL;
	}

	memmove(s_seed, label, label_size);
	memmove(&s_seed[label_size], seed, seed_size);

	l_s = secret_size / 2;
	s1 = &secret[0];
	s2 = &secret[l_s];

	if (secret_size % 2 != 0) {
		l_s++;
	}

	o1 = gnutls_P_hash( GNUTLS_MAC_MD5, s1, l_s, s_seed, s_seed_size, total_bytes);
	if (o1==NULL) {
		gnutls_assert();
		return NULL;
	}

	o2 = gnutls_P_hash( GNUTLS_MAC_SHA, s2, l_s, s_seed, s_seed_size, total_bytes);
	if (o2==NULL) {
		gnutls_assert();
		return NULL;
	}


	gnutls_free(s_seed);

	_gnutls_xor(o1, o2, total_bytes);

	secure_free(o2);

	return o1;

}

/* This function is to be called after handshake, when master_secret,
 *  client_random and server_random have been initialized. 
 * This function creates the keys and stores them into pending state.
 * (state->cipher_specs)
 */
int _gnutls_set_keys(GNUTLS_STATE state)
{
	char *key_block;
	char keyexp[] = "key expansion";
	char random[64];
	int hash_size;
	int IV_size;
	int key_size;

	hash_size = state->security_parameters.hash_size;
	IV_size = state->security_parameters.IV_size;
	key_size = state->security_parameters.key_material_length;

	memmove(random, state->security_parameters.server_random, 32);
	memmove(&random[32], state->security_parameters.client_random, 32);

	if (_gnutls_version_ssl3(state->connection_state.version) == 0) { /* SSL 3 */
		key_block = gnutls_ssl3_generate_random( state->security_parameters.master_secret, 48, random, 64,
			2 * hash_size + 2 * key_size + 2 * IV_size);
	} else { /* TLS 1.0 */
		key_block =
		    gnutls_PRF( state->security_parameters.master_secret, 48,
			       keyexp, strlen(keyexp), random, 64, 2 * hash_size + 2 * key_size + 2 * IV_size);
	}

	state->cipher_specs.client_write_mac_secret = secure_malloc(hash_size);
	memmove(state->cipher_specs.client_write_mac_secret, &key_block[0], hash_size);

	state->cipher_specs.server_write_mac_secret = secure_malloc(hash_size);
	memmove(state->cipher_specs.server_write_mac_secret, &key_block[hash_size], hash_size);

	state->cipher_specs.client_write_key = secure_malloc(key_size);
	memmove(state->cipher_specs.client_write_key, &key_block[2 * hash_size], key_size);

	state->cipher_specs.server_write_key = secure_malloc(key_size);
	memmove(state->cipher_specs.server_write_key, &key_block[2 * hash_size + key_size], key_size);

	state->cipher_specs.client_write_IV = secure_malloc(IV_size);
	memmove(state->cipher_specs.client_write_IV, &key_block[2 * key_size + 2 * hash_size], IV_size);

	state->cipher_specs.server_write_IV = secure_malloc(IV_size);
	memmove(state->cipher_specs.server_write_IV, &key_block[2 * hash_size + 2 * key_size + IV_size], IV_size);

	secure_free(key_block);
	return 0;
}

int _gnutls_send_alert(int cd, GNUTLS_STATE state, AlertLevel level, AlertDescription desc)
{
	uint8 data[2];

	memmove(&data[0], &level, 1);
	memmove(&data[1], &desc, 1);

	return gnutls_send_int(cd, state, GNUTLS_ALERT, data, 2, 0);
}

/**
  * gnutls_bye - This function terminates the current TLS/SSL connection.
  * @cd: is a connection descriptor.
  * @state: is a &GNUTLS_STATE structure.
  *
  * Terminates the current TLS/SSL connection. If the return value is 0
  * you may continue using the TCP connection. The connection should
  * have been initiated using gnutls_handshake() or similar function.
  **/
int gnutls_bye(int cd, GNUTLS_STATE state)
{
	int ret;

	ret = _gnutls_send_alert(cd, state, GNUTLS_WARNING, GNUTLS_CLOSE_NOTIFY);

	/* receive the closure alert */
	gnutls_recv_int(cd, state, GNUTLS_ALERT, NULL, 0, 0); 

	state->gnutls_internals.valid_connection = VALID_FALSE;

	return ret;
}

int gnutls_close_nowait(int cd, GNUTLS_STATE state)
{
	int ret;

	ret = _gnutls_send_alert(cd, state, GNUTLS_WARNING, GNUTLS_CLOSE_NOTIFY);

	state->gnutls_internals.valid_connection = VALID_FALSE;

	return ret;
}

/* This function behave exactly like write(). The only difference is 
 * that it accepts, the gnutls_state and the ContentType of data to
 * send (if called by the user the Content is specific)
 * It is intended to transfer data, under the current state.    
 */
ssize_t gnutls_send_int(int cd, GNUTLS_STATE state, ContentType type, const void *_data, size_t sizeofdata, int flags)
{
	uint8 *cipher;
	int i, cipher_size;
	int ret = 0;
	int iterations;
	int Size;
	uint8 headers[5];
	const uint8 *data=_data;

	if (sizeofdata == 0)
		return 0;
	if (state->gnutls_internals.valid_connection == VALID_FALSE) {
		return GNUTLS_E_INVALID_SESSION;
	}

	if (sizeofdata < MAX_ENC_LEN) {
		iterations = 1;
		Size = sizeofdata;
	} else {
		iterations = sizeofdata / MAX_ENC_LEN;
		Size = MAX_ENC_LEN;
	}

	headers[0]=type;
	headers[1]=_gnutls_version_get_major(state->connection_state.version);
	headers[2]=_gnutls_version_get_minor(state->connection_state.version);

#ifdef HARD_DEBUG
	fprintf(stderr, "Record: Sending Packet[%d] %s(%d) with length: %d\n",
		(int) uint64touint32(&state->connection_state.write_sequence_number), _gnutls_packet2str(type), type, sizeofdata);
#endif

	for (i = 0; i < iterations; i++) {
		cipher_size = _gnutls_encrypt( state, &data[i*Size], Size, &cipher, type);
		if (cipher_size <= 0) return cipher_size; /* error */

		WRITEuint16( cipher_size, &headers[3]);
		
		/* cipher does not have headers 
		 * and DOES have size for them
		 */
		memmove( cipher, headers, HEADER_SIZE);

		cipher_size += HEADER_SIZE;
		if (_gnutls_Write(cd, cipher, cipher_size) != cipher_size) {
			state->gnutls_internals.valid_connection = VALID_FALSE;
			state->gnutls_internals.resumable = RESUME_FALSE;
			gnutls_assert();
			return GNUTLS_E_UNABLE_SEND_DATA;
		}
#ifdef HARD_DEBUG
		fprintf(stderr, "Record: Sended Packet[%d] %s(%d) with length: %d\n",
		(int) uint64touint32(&state->connection_state.write_sequence_number), _gnutls_packet2str(type), type, cipher_size);
#endif

		/* increase sequence number
		 */
		if (uint64pp( &state->connection_state.write_sequence_number) !=0) {
			state->gnutls_internals.valid_connection = VALID_FALSE;
			gnutls_assert();
			return GNUTLS_E_RECORD_LIMIT_REACHED;
		}
	}

	/* rest of data 
	 */
	if (iterations > 1) {
		Size = sizeofdata % MAX_ENC_LEN;
		cipher_size = _gnutls_encrypt( state, &data[i*Size], Size, &cipher, type);
		if (cipher_size<=0) return cipher_size;

		WRITEuint16( cipher_size, &headers[3]);

		memmove( cipher, headers, HEADER_SIZE);

		cipher_size += HEADER_SIZE;
		if (_gnutls_Write(cd, cipher, cipher_size) != cipher_size) {
			state->gnutls_internals.valid_connection = VALID_FALSE;
			state->gnutls_internals.resumable = RESUME_FALSE;
			gnutls_assert();
			return GNUTLS_E_UNABLE_SEND_DATA;
		}

		/* increase sequence number
		 */
		if (uint64pp( &state->connection_state.write_sequence_number)!=0) {
			state->gnutls_internals.valid_connection = VALID_FALSE;
			gnutls_assert();
			return GNUTLS_E_RECORD_LIMIT_REACHED;
		}
	}

	ret += sizeofdata;

	gnutls_free(cipher);

	return ret;
}

/* This function is to be called if the handshake was successfully 
 * completed. This sends a Change Cipher Spec packet to the peer.
 */
ssize_t _gnutls_send_change_cipher_spec(int cd, GNUTLS_STATE state)
{
	int ret = 0;
	uint8 type=GNUTLS_CHANGE_CIPHER_SPEC;
	char data[1] = { GNUTLS_TYPE_CHANGE_CIPHER_SPEC };
	uint8 headers[5];

	if (state->gnutls_internals.valid_connection == VALID_FALSE) {
		return GNUTLS_E_INVALID_SESSION;
	}

	headers[0] = type;
	headers[1] = _gnutls_version_get_major(state->connection_state.version);
	headers[2] = _gnutls_version_get_minor(state->connection_state.version);

#ifdef HANDSHAKE_DEBUG
	fprintf(stderr, "ChangeCipherSpec was sent\n");
#endif

	WRITEuint16( 1, &headers[3]);
	
	if (_gnutls_Write(cd, headers, 5) != 5) {
		state->gnutls_internals.valid_connection = VALID_FALSE;
		state->gnutls_internals.resumable = RESUME_FALSE;
		gnutls_assert();
		return GNUTLS_E_UNABLE_SEND_DATA;
	}

	if (_gnutls_Write(cd, &data, 1) != 1) {
		state->gnutls_internals.valid_connection = VALID_FALSE;
		state->gnutls_internals.resumable = RESUME_FALSE;
		gnutls_assert();
		return GNUTLS_E_UNABLE_SEND_DATA;
	}
	ret += 1;

	return ret;
}

#define RCVLOWAT state->gnutls_internals.lowat /* this is the default for TCP - just don't change that! */

static int _gnutls_clear_peeked_data( int cd, GNUTLS_STATE state) {
char peekdata;

	/* this was already read by using MSG_PEEK - so it shouldn't fail */
	_gnutls_Read( cd, &peekdata, RCVLOWAT, 0); 

	return 0;
}

/* This function behave exactly like read(). The only difference is 
 * that it accepts, the gnutls_state and the ContentType of data to
 * send (if called by the user the Content is Userdata only)
 * It is intended to receive data, under the current state.
 * flags is the sockets flags to use. Currently only MSG_DONTWAIT is
 * supported.
 */
#define SSL2_HSIZE
ssize_t gnutls_recv_int(int cd, GNUTLS_STATE state, ContentType type, char *data, size_t sizeofdata, int flags)
{
	uint8 *tmpdata;
	int tmplen;
	GNUTLS_Version version;
	uint8 headers[HEADER_SIZE];
	ContentType recv_type;
	uint16 length;
	uint8 *ciphertext;
	int ret = 0;
	int header_size = HEADER_SIZE;
	/* If we have enough data in the cache do not bother receiving
	 * a new packet. (in order to flush the cache)
	 */
	if ( (type == GNUTLS_APPLICATION_DATA || type == GNUTLS_HANDSHAKE) && gnutls_getDataBufferSize(type, state) > 0) {
		ret = gnutls_getDataFromBuffer(type, state, data, sizeofdata);

		if (type==GNUTLS_APPLICATION_DATA) {
			/* if the buffer just got empty */
			if (gnutls_getDataBufferSize(type, state)==0) {
				_gnutls_clear_peeked_data( cd, state);
			}
		}
		return ret;
	}

	if (state->gnutls_internals.valid_connection == VALID_FALSE) {
		return GNUTLS_E_INVALID_SESSION;
	}

	/* in order for GNUTLS_E_AGAIN to be returned the socket
	 * must be set to non blocking mode
	 */
	if ( _gnutls_Read(cd, headers, HEADER_SIZE, MSG_PEEK|flags) != HEADER_SIZE) {
		if (errno==EAGAIN) return GNUTLS_E_AGAIN;
		state->gnutls_internals.valid_connection = VALID_FALSE;
		if (type==GNUTLS_ALERT) return 0; /* we were expecting close notify */
		state->gnutls_internals.resumable = RESUME_FALSE;
		gnutls_assert();
		return GNUTLS_E_UNEXPECTED_PACKET_LENGTH;
	}

	/* Read the first two bytes to determine if this is a 
	 * version 2 message 
	 */
	if ( headers[0] > 127 && type==GNUTLS_HANDSHAKE) { 

	/* if msb set and expecting handshake message
	 * it should be SSL 2 hello 
	 */
		version = GNUTLS_SSL3; /* assume ssl 3.0 */
		length = (((headers[0] & 0x7f) << 8)) | headers[1];
		header_size = 2;
		recv_type = GNUTLS_HANDSHAKE; /* only v2 client hello we accept */
		state->gnutls_internals.v2_hello = length;
#ifdef DEBUG
		fprintf(stderr, "Record: V2 packet received. Length: %d\n", length);
#endif

	} else {
		/* version 3.x 
		 */
		recv_type = headers[0];
		version = _gnutls_version_get( headers[1], headers[2]);

		length = READuint16( &headers[3]);
	}
	
	if ( gnutls_get_current_version(state) != version) {
#ifdef DEBUG
		fprintf(stderr, "Record: INVALID VERSION PACKET: (%d) %d.%d\n", headers[0], headers[1], headers[2]);
#endif
		_gnutls_send_alert(cd, state, GNUTLS_FATAL, GNUTLS_PROTOCOL_VERSION);
		state->gnutls_internals.resumable = RESUME_FALSE;
		gnutls_assert();
		return GNUTLS_E_UNSUPPORTED_VERSION_PACKET;
	}


#ifdef HARD_DEBUG
	fprintf(stderr, "Record: Expected Packet[%d] %s(%d) with length: %d\n",
		(int) uint64touint32(&state->connection_state.read_sequence_number), _gnutls_packet2str(type), type, sizeofdata);
	fprintf(stderr, "Record: Received Packet[%d] %s(%d) with length: %d\n",
		(int) uint64touint32(&state->connection_state.read_sequence_number), _gnutls_packet2str(recv_type), recv_type, length);
#endif

	if (length > MAX_RECV_SIZE) {
#ifdef DEBUG
		fprintf(stderr, "Record: FATAL ERROR: Received packet with length: %d\n", length);
#endif
		_gnutls_send_alert(cd, state, GNUTLS_FATAL, GNUTLS_RECORD_OVERFLOW);
		state->gnutls_internals.valid_connection = VALID_FALSE;
		state->gnutls_internals.resumable = RESUME_FALSE;
		gnutls_assert();
		return GNUTLS_E_UNEXPECTED_PACKET_LENGTH;
	}

	ciphertext = gnutls_malloc(length+header_size);

/* check if we have that data into buffer. This seems to be
 * expensive - but this is the only way to handle Non Blocking IO.
 */
	if ( _gnutls_Read(cd, ciphertext, header_size+length, MSG_PEEK|flags) != length+header_size) {
		gnutls_free(ciphertext);
		
		if (errno==EAGAIN) return GNUTLS_E_AGAIN;
		state->gnutls_internals.valid_connection = VALID_FALSE;
		state->gnutls_internals.resumable = RESUME_FALSE;
		gnutls_assert();
		return GNUTLS_E_UNEXPECTED_PACKET_LENGTH;		
	}
	
/* ok now we are sure that we can read all the data - so
 * move on !
 */
	if (_gnutls_Read(cd, headers, header_size, 0)!=header_size) {  /* read and clear the headers - again! */
		gnutls_free(ciphertext);
		state->gnutls_internals.valid_connection = VALID_FALSE;
		state->gnutls_internals.resumable = RESUME_FALSE;
		gnutls_assert();
		return GNUTLS_E_UNKNOWN_ERROR;
	}

/* Read the whole packet - again? 
 * Here we keep RCVLOWAT bytes in the TCP buffers, only for
 * APPLICATION_DATA data.
 */	
	if ( type==GNUTLS_APPLICATION_DATA && type==recv_type) {
		/* get the data - but do not free the buffer in the kernel */
		ret = _gnutls_Read(cd, ciphertext, length-RCVLOWAT, 0);
		if (ret>=0)
			ret += _gnutls_Read(cd, &ciphertext[length-RCVLOWAT], RCVLOWAT, MSG_PEEK);

	} else { /* our - internal data */
		ret = _gnutls_Read(cd, ciphertext, length, 0);
	}

	/* Oooops... very rare case since we know that the system HAD 
	 * received that data.
	 */
	if (ret != length) {
#ifdef DEBUG
		fprintf(stderr, "Record: Received packet with length: %d\nExpected %d\n", ret, length);
#endif
		gnutls_free(ciphertext);
		state->gnutls_internals.valid_connection = VALID_FALSE;
		state->gnutls_internals.resumable = RESUME_FALSE;
		gnutls_assert();
		return GNUTLS_E_UNEXPECTED_PACKET_LENGTH;
	}
	
	if (type == GNUTLS_CHANGE_CIPHER_SPEC && recv_type == GNUTLS_CHANGE_CIPHER_SPEC) {
#ifdef HARD_DEBUG
		fprintf(stderr, "Record: ChangeCipherSpec Packet was received\n");
#endif
		gnutls_free(ciphertext);
		if (length!=1) {
			gnutls_assert();
			return GNUTLS_E_UNEXPECTED_PACKET_LENGTH;
		}
		return 0;
	}

	tmplen = _gnutls_decrypt( state, ciphertext, length, &tmpdata, recv_type);
	if (tmplen < 0) {
		switch (tmplen) {
			case GNUTLS_E_MAC_FAILED:
				_gnutls_send_alert(cd, state, GNUTLS_FATAL, GNUTLS_BAD_RECORD_MAC);
				break;
			case GNUTLS_E_DECRYPTION_FAILED:
				_gnutls_send_alert(cd, state, GNUTLS_FATAL, GNUTLS_DECRYPTION_FAILED);
				break;
			case GNUTLS_E_DECOMPRESSION_FAILED:
				_gnutls_send_alert(cd, state, GNUTLS_FATAL, GNUTLS_DECOMPRESSION_FAILURE);
				break;
		}
		state->gnutls_internals.valid_connection = VALID_FALSE;
		state->gnutls_internals.resumable = RESUME_FALSE;
		gnutls_assert();
		gnutls_free(ciphertext);
		return tmplen;
	}

#ifdef HARD_DEBUG
	fprintf(stderr, "Record: Decrypted Packet[%d] %s(%d) with length: %d\n",
		(int) uint64touint32(&state->connection_state.read_sequence_number), _gnutls_packet2str(recv_type), recv_type, tmplen);
#endif

	/* increase sequence number */
	if (uint64pp( &state->connection_state.read_sequence_number)!=0) {
		state->gnutls_internals.valid_connection = VALID_FALSE;
		gnutls_free(tmpdata);
		gnutls_assert();
		return GNUTLS_E_RECORD_LIMIT_REACHED;
	}

	gnutls_free(ciphertext);

	if ( (recv_type == type) && (type == GNUTLS_APPLICATION_DATA || type == GNUTLS_HANDSHAKE)) {
		gnutls_insertDataBuffer(type, state, (void *) tmpdata, tmplen);
	} else {
		switch (recv_type) {
		case GNUTLS_ALERT:
#ifdef DEBUG
			fprintf(stderr, "Record: Alert[%d|%d] - %s - was received\n", tmpdata[0], tmpdata[1], _gnutls_alert2str((int)tmpdata[1]));
#endif
			state->gnutls_internals.last_alert = tmpdata[1];

			/* if close notify is received and
			 * the alert is not fatal
			 */
			if (tmpdata[1] == GNUTLS_CLOSE_NOTIFY && tmpdata[0] != GNUTLS_FATAL) {

				/* If we have been expecting for an alert do 
				 * not call close().
				 */
				if (type != GNUTLS_ALERT)
					gnutls_close_nowait(cd, state);
				
				gnutls_free(tmpdata);
				
				return GNUTLS_E_CLOSURE_ALERT_RECEIVED;
			} else {
			
				/* if the alert is FATAL or WARNING
				 * return the apropriate message
				 */
			
				ret = GNUTLS_E_WARNING_ALERT_RECEIVED;
				if (tmpdata[0] == GNUTLS_FATAL) {
					state->gnutls_internals.valid_connection = VALID_FALSE;
					state->gnutls_internals.resumable = RESUME_FALSE;
					
					ret = GNUTLS_E_FATAL_ALERT_RECEIVED;
				}

				gnutls_free(tmpdata);

				return ret;
			}
			break;

		case GNUTLS_CHANGE_CIPHER_SPEC:
			/* this packet is now handled above */
			gnutls_assert();
	
			gnutls_free(tmpdata);
			
			return GNUTLS_E_UNEXPECTED_PACKET;
		case GNUTLS_APPLICATION_DATA:
			/* even if data is unexpected put it into the buffer */
			gnutls_insertDataBuffer(recv_type, state, (void *) tmpdata, tmplen);
			/* no peeked data to clear since this packet was unexpected */

			break;
		case GNUTLS_HANDSHAKE:
			/* This is only legal if HELLO_REQUEST is received */

			break;
		default:
#ifdef DEBUG
			fprintf(stderr, "Record: Received Unknown packet %d expecting %d\n", recv_type, type);
#endif
			gnutls_assert();
			return GNUTLS_E_UNKNOWN_ERROR;
		}
	}


	/* Get Application data from buffer */
	if ((type == GNUTLS_APPLICATION_DATA || type == GNUTLS_HANDSHAKE) && (recv_type == type)) {
		ret = gnutls_getDataFromBuffer(type, state, data, sizeofdata);
		if (type==GNUTLS_APPLICATION_DATA) {
			/* if the buffer just got empty */
			if (gnutls_getDataBufferSize(type, state)==0) {
				_gnutls_clear_peeked_data( cd, state);
			}

		}
		gnutls_free(tmpdata);
	} else {
		if (recv_type == GNUTLS_HANDSHAKE) {
			/* we may get a hello request */
			ret = _gnutls_recv_hello_request( cd, state, tmpdata, tmplen);
			if (ret < 0) {
				gnutls_assert();
			} else /* inform the caller */
				ret = GNUTLS_E_GOT_HELLO_REQUEST;
		} else {
			gnutls_assert();
			ret = GNUTLS_E_UNEXPECTED_PACKET; 
				/* we didn't get what we wanted to 
				 */
			if (recv_type == GNUTLS_APPLICATION_DATA)
				ret = GNUTLS_E_GOT_APPLICATION_DATA;
		}
		gnutls_free(tmpdata);
	}

	return ret;
}

/**
  * gnutls_get_current_cipher - Returns the currently used cipher.
  * @state: is a &GNUTLS_STATE structure.
  *
  * Returns the currently used cipher.
  **/
BulkCipherAlgorithm gnutls_get_current_cipher( GNUTLS_STATE state) {
	return state->security_parameters.bulk_cipher_algorithm;
}

/**
  * gnutls_get_current_kx - Returns the key exchange algorithm.
  * @state: is a &GNUTLS_STATE structure.
  *
  * Returns the key exchange algorithm used in the last handshake.
  **/
KXAlgorithm gnutls_get_current_kx( GNUTLS_STATE state) {
	return state->security_parameters.kx_algorithm;
}

/**
  * gnutls_get_current_mac_algorithm - Returns the currently used mac algorithm.
  * @state: is a &GNUTLS_STATE structure.
  *
  * Returns the currently used mac algorithm.
  **/
MACAlgorithm gnutls_get_current_mac_algorithm( GNUTLS_STATE state) {
	return state->security_parameters.mac_algorithm;
}

/**
  * gnutls_get_current_compression_method - Returns the currently used compression algorithm.
  * @state: is a &GNUTLS_STATE structure.
  *
  * Returns the currently used compression method.
  **/
CompressionMethod gnutls_get_current_compression_method( GNUTLS_STATE state) {
	return state->security_parameters.compression_algorithm;
}

/* Taken from libgcrypt */

static const char*
parse_version_number( const char *s, int *number )
{
    int val = 0;

    if( *s == '0' && isdigit(s[1]) )
	return NULL; /* leading zeros are not allowed */
    for ( ; isdigit(*s); s++ ) {
	val *= 10;
	val += *s - '0';
    }
    *number = val;
    return val < 0? NULL : s;
}


static const char *
parse_version_string( const char *s, int *major, int *minor, int *micro )
{
    s = parse_version_number( s, major );
    if( !s || *s != '.' )
	return NULL;
    s++;
    s = parse_version_number( s, minor );
    if( !s || *s != '.' )
	return NULL;
    s++;
    s = parse_version_number( s, micro );
    if( !s )
	return NULL;
    return s; /* patchlevel */
}

/****************
 * Check that the the version of the library is at minimum the requested one
 * and return the version string; return NULL if the condition is not
 * satisfied.  If a NULL is passed to this function, no check is done,
 * but the version string is simply returned.
 */
const char *
gnutls_check_version( const char *req_version )
{
    const char *ver = GNUTLS_VERSION;
    int my_major, my_minor, my_micro;
    int rq_major, rq_minor, rq_micro;
    const char *my_plvl, *rq_plvl;

    if ( !req_version )
	return ver;

    my_plvl = parse_version_string( ver, &my_major, &my_minor, &my_micro );
    if ( !my_plvl )
	return NULL;  /* very strange our own version is bogus */
    rq_plvl = parse_version_string( req_version, &rq_major, &rq_minor,
								&rq_micro );
    if ( !rq_plvl )
	return NULL;  /* req version string is invalid */

    if ( my_major > rq_major
	|| (my_major == rq_major && my_minor > rq_minor)
	|| (my_major == rq_major && my_minor == rq_minor
				 && my_micro > rq_micro)
	|| (my_major == rq_major && my_minor == rq_minor
				 && my_micro == rq_micro
				 && strcmp( my_plvl, rq_plvl ) >= 0) ) {
	return ver;
    }
    return NULL;
}

/**
  * gnutls_get_last_alert - Returns the last alert number received.
  * @state: is a &GNUTLS_STATE structure.
  *
  * Returns the last alert number received. This function
  * should be called if %GNUTLS_E_WARNING_ALERT_RECEIVED or
  * %GNUTLS_E_FATAL_ALERT_RECEIVED has been returned by a gnutls function.
  * The peer may send alerts if he thinks some things were not 
  * right. Check gnutls.h for the available alert descriptions.
  **/
AlertDescription gnutls_get_last_alert( GNUTLS_STATE state) {
	return state->gnutls_internals.last_alert;
}

/**
  * gnutls_send - sends to the peer the specified data
  * @cd: is a connection descriptor
  * @state: is a &GNUTLS_STATE structure.
  * @data: contains the data to send
  * @sizeofdata: is the length of the data
  * @flags: contains the flags to pass to send() function.
  *
  * This function has the same semantics as send() has. The only
  * difference is that is accepts a GNUTLS state. Currently flags cannot
  * be anything except 0.
  **/
ssize_t gnutls_send(int cd, GNUTLS_STATE state, const void *data, size_t sizeofdata, int flags) {
	return gnutls_send_int( cd, state, GNUTLS_APPLICATION_DATA, data, sizeofdata, flags);
}

/**
  * gnutls_recv - receives data from the TLS connection
  * @cd: is a connection descriptor
  * @state: is a &GNUTLS_STATE structure.
  * @data: contains the data to send
  * @sizeofdata: is the length of the data
  * @flags: contains the flags to pass to recv() function.
  *
  * This function has the same semantics as recv() has. The only
  * difference is that is accepts a GNUTLS state. Flags are the flags
  * passed to recv() and should be used with care in gnutls.  
  * The only acceptable flag is currently MSG_DONTWAIT. In that case,
  * if the socket is set to non blocking IO it will return GNUTLS_E_AGAIN,
  * if there are no data in the socket. 
  **/
ssize_t gnutls_recv(int cd, GNUTLS_STATE state, void *data, size_t sizeofdata, int flags) {
	return gnutls_recv_int( cd, state, GNUTLS_APPLICATION_DATA, data, sizeofdata, flags);
}

/**
  * gnutls_write - sends to the peer the specified data
  * @cd: is a connection descriptor
  * @state: is a &GNUTLS_STATE structure.
  * @data: contains the data to send
  * @sizeofdata: is the length of the data
  *
  * This function has the same semantics as write() has. The only
  * difference is that is accepts a GNUTLS state.
  **/
ssize_t gnutls_write(int cd, GNUTLS_STATE state, const void *data, size_t sizeofdata) {
	return gnutls_send_int( cd, state, GNUTLS_APPLICATION_DATA, data, sizeofdata, 0);
}

/**
  * gnutls_read - reads data from the TLS connection
  * @cd: is a connection descriptor
  * @state: is a &GNUTLS_STATE structure.
  * @data: contains the data to send
  * @sizeofdata: is the length of the data
  *
  * This function has the same semantics as read() has. The only
  * difference is that is accepts a GNUTLS state. 
  **/
ssize_t gnutls_read(int cd, GNUTLS_STATE state, void *data, size_t sizeofdata) {
	return gnutls_recv_int( cd, state, GNUTLS_APPLICATION_DATA, data, sizeofdata, 0);
}
