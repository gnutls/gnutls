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
}

int gnutls_is_secure_memory(const void* mem) {
	return 0;
}

int gnutls_set_lowat(GNUTLS_STATE state, int num) {
	state->gnutls_internals.lowat = num;
	return 0;
}

/* This function initializes the state to null (null encryption etc...) */
int gnutls_init(GNUTLS_STATE * state, ConnectionEnd con_end)
{
	/* for gcrypt in order to be able to allocate memory */
	gcry_set_allocation_handler(gnutls_malloc, secure_malloc,  gnutls_is_secure_memory, gnutls_realloc, free);

	*state = gnutls_calloc(1, sizeof(GNUTLS_STATE_INT));
	memset(*state, 0, sizeof(GNUTLS_STATE));
	(*state)->security_parameters.entity = con_end;

/* Set the defaults (only to remind me that they should be allocated ) */
	(*state)->security_parameters.bulk_cipher_algorithm = GNUTLS_NULL_CIPHER;
	(*state)->security_parameters.mac_algorithm = GNUTLS_NULL_MAC;
	(*state)->security_parameters.compression_algorithm = GNUTLS_NULL_COMPRESSION;

	(*state)->connection_state.read_compression_state = NULL;
	(*state)->connection_state.read_mac_secret = NULL;
	(*state)->connection_state.write_compression_state = NULL;
	(*state)->connection_state.write_mac_secret = NULL;

	(*state)->cipher_specs.server_write_mac_secret = NULL;
	(*state)->cipher_specs.client_write_mac_secret = NULL;
	(*state)->cipher_specs.server_write_IV = NULL;
	(*state)->cipher_specs.client_write_IV = NULL;
	(*state)->cipher_specs.server_write_key = NULL;
	(*state)->cipher_specs.client_write_key = NULL;

	(*state)->gnutls_internals.v2_hello = 0;
	
	(*state)->gnutls_internals.buffer = NULL;
	/* SSL3 stuff */
	(*state)->gnutls_internals.hash_buffer = NULL;
	
	(*state)->gnutls_internals.buffer_handshake = NULL;
	(*state)->gnutls_internals.resumable = RESUME_TRUE;

	gnutls_set_current_version ( (*state), GNUTLS_TLS1); /* default */

	(*state)->gnutls_key = gnutls_malloc(sizeof(GNUTLS_KEY_A));

	(*state)->gnutls_key->auth_info = NULL; /* no default auth_info */
	(*state)->gnutls_key->auth_info_size = 0; /* no default auth_info */
	(*state)->gnutls_key->cred = NULL; /* no credentials by default */
	
	(*state)->gnutls_key->KEY = NULL;
	(*state)->gnutls_key->client_Y = NULL;
	(*state)->gnutls_key->client_p = NULL;
	(*state)->gnutls_key->client_g = NULL;
	(*state)->gnutls_key->dh_secret = NULL;

	(*state)->gnutls_key->A = NULL;
	(*state)->gnutls_key->a = NULL;	
	(*state)->gnutls_key->x = NULL;
	(*state)->gnutls_key->u = NULL;
	(*state)->gnutls_key->B = NULL;
	(*state)->gnutls_key->b = NULL;	

	(*state)->gnutls_internals.certificate_requested = 0;
	(*state)->gnutls_internals.certificate_verify_needed = 0;

	(*state)->gnutls_internals.MACAlgorithmPriority.algorithm_priority=NULL;
	(*state)->gnutls_internals.MACAlgorithmPriority.algorithms=0;

	(*state)->gnutls_internals.KXAlgorithmPriority.algorithm_priority=NULL;
	(*state)->gnutls_internals.KXAlgorithmPriority.algorithms=0;

	(*state)->gnutls_internals.BulkCipherAlgorithmPriority.algorithm_priority=NULL;
	(*state)->gnutls_internals.BulkCipherAlgorithmPriority.algorithms=0;

	(*state)->gnutls_internals.CompressionMethodPriority.algorithm_priority=NULL;
	(*state)->gnutls_internals.CompressionMethodPriority.algorithms=0;

	/* Set default priorities */
	gnutls_set_cipher_priority( (*state), 2, GNUTLS_RIJNDAEL, GNUTLS_3DES);
	gnutls_set_compression_priority( (*state), 1, GNUTLS_NULL_COMPRESSION);
	gnutls_set_kx_priority( (*state), 1, GNUTLS_KX_ANON_DH);
	gnutls_set_mac_priority( (*state), 2, GNUTLS_MAC_SHA, GNUTLS_MAC_MD5);

	(*state)->security_parameters.session_id_size = 0;
	(*state)->gnutls_internals.resumed_security_parameters.session_id_size = 0;
	(*state)->gnutls_internals.resumed = RESUME_FALSE;
	
	(*state)->gnutls_internals.expire_time = 3600; /* one hour default */

	(*state)->security_parameters.timestamp = 0;

	/* gdbm db */
	(*state)->gnutls_internals.db_name = NULL;

	gnutls_set_lowat((*state), 1); /* the default for tcp */
	
	return 0;
}

#define GNUTLS_FREE(x) if(x!=NULL) gnutls_free(x)
/* This function clears all buffers associated with the state. */
int gnutls_deinit(GNUTLS_STATE * state)
{
	/* if the session has failed abnormally it has to be removed from the db */
	if ( (*state)->gnutls_internals.resumable==RESUME_FALSE) {
		_gnutls_db_remove_session( (*state), (*state)->security_parameters.session_id, (*state)->security_parameters.session_id_size);
	}

	/* remove auth info firstly */
	GNUTLS_FREE((*state)->gnutls_key->auth_info);
	
	GNUTLS_FREE((*state)->connection_state.read_compression_state);
	GNUTLS_FREE((*state)->connection_state.read_mac_secret);
	GNUTLS_FREE((*state)->connection_state.write_compression_state);
	GNUTLS_FREE((*state)->connection_state.write_mac_secret);

	GNUTLS_FREE((*state)->gnutls_internals.buffer);
	GNUTLS_FREE((*state)->gnutls_internals.buffer_handshake);

	gnutls_clear_creds( *state);

	if ((*state)->connection_state.read_cipher_state != NULL)
		gnutls_cipher_deinit((*state)->connection_state.read_cipher_state);
	if ((*state)->connection_state.write_cipher_state != NULL)
		gnutls_cipher_deinit((*state)->connection_state.write_cipher_state);

	secure_free((*state)->cipher_specs.server_write_mac_secret);
	secure_free((*state)->cipher_specs.client_write_mac_secret);
	secure_free((*state)->cipher_specs.server_write_IV);
	secure_free((*state)->cipher_specs.client_write_IV);
	secure_free((*state)->cipher_specs.server_write_key);
	secure_free((*state)->cipher_specs.client_write_key);

	mpi_release((*state)->gnutls_key->KEY);
	mpi_release((*state)->gnutls_key->client_Y);
	mpi_release((*state)->gnutls_key->client_p);
	mpi_release((*state)->gnutls_key->client_g);

	mpi_release((*state)->gnutls_key->u);
	mpi_release((*state)->gnutls_key->a);
	mpi_release((*state)->gnutls_key->x);
	mpi_release((*state)->gnutls_key->A);
	mpi_release((*state)->gnutls_key->B);
	mpi_release((*state)->gnutls_key->b);

	mpi_release((*state)->gnutls_key->dh_secret);
	GNUTLS_FREE((*state)->gnutls_key);


	/* free priorities */
	GNUTLS_FREE((*state)->gnutls_internals.MACAlgorithmPriority.algorithm_priority);
	GNUTLS_FREE((*state)->gnutls_internals.KXAlgorithmPriority.algorithm_priority);
	GNUTLS_FREE((*state)->gnutls_internals.BulkCipherAlgorithmPriority.algorithm_priority);
	GNUTLS_FREE((*state)->gnutls_internals.CompressionMethodPriority.algorithm_priority);

	GNUTLS_FREE((*state)->gnutls_internals.db_name);

	GNUTLS_FREE(*state);
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

int gnutls_close(int cd, GNUTLS_STATE state)
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
ssize_t gnutls_send_int(int cd, GNUTLS_STATE state, ContentType type, void *_data, size_t sizeofdata, int flags)
{
	uint8 *cipher;
	int i, cipher_size;
	int ret = 0;
	int iterations;
	uint16 length;
	int Size;
	uint8 headers[5];
	uint8 *data=_data;

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
	
	for (i = 0; i < iterations; i++) {
		cipher_size = _gnutls_encrypt( state, &data[i*Size], Size, &cipher, type);
		if (cipher_size <= 0) return cipher_size; /* error */
		
#ifdef WORDS_BIGENDIAN
		length = cipher_size;
#else
		length = byteswap16(cipher_size);
#endif
		memmove( &headers[3], &length, sizeof(uint16));
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
		state->connection_state.write_sequence_number++;
	}
		/* rest data */
	if (iterations > 1) {
		Size = sizeofdata % MAX_ENC_LEN;
		cipher_size = _gnutls_encrypt( state, &data[i*Size], Size, &cipher, type);
		if (cipher_size<=0) return cipher_size;
#ifdef WORDS_BIGENDIAN
		length = cipher_size;
#else
		length = byteswap16(cipher_size);
#endif
		memmove( &headers[3], &length, sizeof(uint16));
		memmove( cipher, headers, HEADER_SIZE);

		cipher_size += HEADER_SIZE;
		if (_gnutls_Write(cd, cipher, cipher_size) != cipher_size) {
			state->gnutls_internals.valid_connection = VALID_FALSE;
			state->gnutls_internals.resumable = RESUME_FALSE;
			gnutls_assert();
			return GNUTLS_E_UNABLE_SEND_DATA;
		}
		state->connection_state.write_sequence_number++;
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
	uint16 length;
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

#ifdef WORDS_BIGENDIAN
	length = (uint16)1;
#else
	length = byteswap16((uint16)1);
#endif
	memmove( &headers[3], &length, sizeof(uint16));
	
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
	uint8 recv_type;
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
		memcpy( &recv_type, &headers[0], 1);
		version = _gnutls_version_get( headers[1], headers[2]);

		memcpy( &length, &headers[3], 2);
#ifndef WORDS_BIGENDIAN
		length = byteswap16(length);
#endif
	}
	

	if (type != GNUTLS_HANDSHAKE && gnutls_get_current_version(state) != version) {
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
		(int) state->connection_state.read_sequence_number, _gnutls_packet2str(type), type, sizeofdata);
	fprintf(stderr, "Record: Received Packet[%d] %s(%d) with length: %d\n",
		(int) state->connection_state.read_sequence_number, _gnutls_packet2str(recv_type), recv_type, length);
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
/* Read the whole packet - again? */	
	if ( type==GNUTLS_APPLICATION_DATA) {
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

			if (tmpdata[1] == GNUTLS_CLOSE_NOTIFY && tmpdata[0] != GNUTLS_FATAL) {

				/* If we have been expecting for an alert do 
				 * not call close().
				 */
				if (type != GNUTLS_ALERT)
					gnutls_close_nowait(cd, state);

				return GNUTLS_E_CLOSURE_ALERT_RECEIVED;
			} else {
				if (tmpdata[0] == GNUTLS_FATAL) {
					state->gnutls_internals.valid_connection = VALID_FALSE;
					state->gnutls_internals.resumable = RESUME_FALSE;
					
					return GNUTLS_E_FATAL_ALERT_RECEIVED;
				}
				return GNUTLS_E_WARNING_ALERT_RECEIVED;
			}
			break;

		case GNUTLS_CHANGE_CIPHER_SPEC:
			/* this packet is now handled above */
			gnutls_assert();
			return GNUTLS_E_UNEXPECTED_PACKET;
		case GNUTLS_APPLICATION_DATA:
			/* even if data is unexpected put it into the buffer */
			gnutls_insertDataBuffer(recv_type, state, (void *) tmpdata, tmplen);
			break;
		default:
#ifdef DEBUG
			fprintf(stderr, "Record: Received Unknown packet %d expecting %d\n", recv_type, type);
#endif
			gnutls_assert();
			return GNUTLS_E_UNKNOWN_ERROR;
		}
	}



	/* Increase sequence number */
	state->connection_state.read_sequence_number++;


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
		if (recv_type != GNUTLS_APPLICATION_DATA) {
			gnutls_assert();
			return GNUTLS_E_RECEIVED_BAD_MESSAGE;
		} else {
			ret = 0; /* ok */
		}
	}

	return ret;
}

BulkCipherAlgorithm gnutls_get_current_cipher( GNUTLS_STATE state) {
	return state->security_parameters.bulk_cipher_algorithm;
}
KXAlgorithm gnutls_get_current_kx( GNUTLS_STATE state) {
	return state->security_parameters.kx_algorithm;
}
MACAlgorithm gnutls_get_current_mac_algorithm( GNUTLS_STATE state) {
	return state->security_parameters.mac_algorithm;
}
CompressionMethod gnutls_get_current_compression_method( GNUTLS_STATE state) {
	return state->security_parameters.compression_algorithm;
}
