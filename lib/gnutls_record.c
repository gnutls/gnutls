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

#include "gnutls_int.h"
#include "gnutls_errors.h"
#include "debug.h"
#include "gnutls_compress.h"
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
#include "gnutls_record.h"
#include "gnutls_datum.h"
#include "ext_max_record.h"

/**
  * gnutls_protocol_get_version - Returns the version of the currently used protocol
  * @state: is a &GNUTLS_STATE structure.
  *
  * Returns the version of the currently used protocol. 
  *
  **/
GNUTLS_Version gnutls_protocol_get_version(GNUTLS_STATE state) {
GNUTLS_Version ver;
	ver = state->security_parameters.version;
	return ver;
}

void _gnutls_set_current_version(GNUTLS_STATE state, GNUTLS_Version version) {
	state->security_parameters.version = version;
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
  * This function is only usefull if using berkeley style sockets.
  * Otherwise it must be called and set lowat to zero.
  *
  **/
void gnutls_set_lowat(GNUTLS_STATE state, int num) {
	state->gnutls_internals.lowat = num;
}

/**
  * gnutls_transport_set_ptr - Used to set first argument of the transport functions
  * @state: is a &GNUTLS_STATE structure.
  * @ptr: is the value.
  *
  * Used to set the first argument of the transport function (like PUSH and
  * PULL). In berkeley style sockets this function will set the connection
  * handle.
  *
  **/
void gnutls_transport_set_ptr(GNUTLS_STATE state, GNUTLS_SOCKET_PTR ptr) {
	state->gnutls_internals.transport_ptr = ptr;
}

#define _gnutls_free(x) if(x!=NULL) gnutls_free(x)
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
int default_protocol_list[] = { GNUTLS_TLS1, 0 };

	*state = gnutls_calloc(1, sizeof(struct GNUTLS_STATE_INT));
	if (*state==NULL) return GNUTLS_E_MEMORY_ERROR;
	
	(*state)->security_parameters.entity = con_end;

/* Set the defaults for initial handshake */
	(*state)->security_parameters.read_bulk_cipher_algorithm = 
	(*state)->security_parameters.write_bulk_cipher_algorithm = GNUTLS_CIPHER_NULL;

	(*state)->security_parameters.read_mac_algorithm = 
	(*state)->security_parameters.write_mac_algorithm = GNUTLS_MAC_NULL;

	(*state)->security_parameters.read_compression_algorithm = GNUTLS_COMP_NULL;
	(*state)->security_parameters.write_compression_algorithm = GNUTLS_COMP_NULL;

	(*state)->gnutls_internals.resumable = RESUME_TRUE;

	gnutls_protocol_set_priority( *state, default_protocol_list); /* default */
	
	(*state)->gnutls_key = gnutls_calloc(1, sizeof(struct GNUTLS_KEY_INT));
	if ( (*state)->gnutls_key == NULL) {
		gnutls_free( *state);
		return GNUTLS_E_MEMORY_ERROR;
	}

	(*state)->gnutls_internals.resumed = RESUME_FALSE;

	(*state)->gnutls_internals.expire_time = DEFAULT_EXPIRE_TIME; /* one hour default */

	gnutls_set_lowat((*state), DEFAULT_LOWAT); /* the default for tcp */

	gnutls_set_max_handshake_data_buffer_size( (*state), MAX_HANDSHAKE_DATA_BUFFER_SIZE);

	/* Allocate a minimum size for recv_data 
	 * This is allocated in order to avoid small messages, makeing
	 * the receive procedure slow.
	 */
	(*state)->gnutls_internals.recv_buffer.data = gnutls_malloc(INITIAL_RECV_BUFFER_SIZE);
	
	/* set the default maximum record size for TLS
	 */
	(*state)->security_parameters.max_record_size = DEFAULT_MAX_RECORD_SIZE;
	(*state)->gnutls_internals.proposed_record_size = DEFAULT_MAX_RECORD_SIZE;

	/* everything else not initialized here is initialized
	 * as NULL or 0. This is why calloc is used.
	 */

	return 0;
}

/**
  * gnutls_deinit - This function clears all buffers associated with the &state
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
	_gnutls_free_auth_info(state );

#ifdef HAVE_LIBGDBM
	/* close the database - resuming sessions */
	if ( state->gnutls_internals.db_reader != NULL)
		gdbm_close(state->gnutls_internals.db_reader);
#endif

	_gnutls_clear_handshake_buffers( state);

	gnutls_sfree_datum(&state->connection_state.read_mac_secret);
	gnutls_sfree_datum(&state->connection_state.write_mac_secret);

	_gnutls_free(state->gnutls_internals.recv_buffer.data);
	_gnutls_free(state->gnutls_internals.buffer.data);
	_gnutls_free(state->gnutls_internals.buffer_handshake.data);
	_gnutls_free(state->gnutls_internals.hash_buffer.data);
	_gnutls_free(state->gnutls_internals.send_buffer.data);

	gnutls_clear_creds( state);

	if (state->connection_state.read_cipher_state != NULL)
		gnutls_cipher_deinit(state->connection_state.read_cipher_state);
	if (state->connection_state.write_cipher_state != NULL)
		gnutls_cipher_deinit(state->connection_state.write_cipher_state);

	gnutls_sfree_datum( &state->cipher_specs.server_write_mac_secret);
	gnutls_sfree_datum( &state->cipher_specs.client_write_mac_secret);
	gnutls_sfree_datum( &state->cipher_specs.server_write_IV);
	gnutls_sfree_datum( &state->cipher_specs.client_write_IV);
	gnutls_sfree_datum( &state->cipher_specs.server_write_key);
	gnutls_sfree_datum( &state->cipher_specs.client_write_key);

	if (state->gnutls_key != NULL) {
		_gnutls_mpi_release(&state->gnutls_key->KEY);
		_gnutls_mpi_release(&state->gnutls_key->client_Y);
		_gnutls_mpi_release(&state->gnutls_key->client_p);
		_gnutls_mpi_release(&state->gnutls_key->client_g);

		_gnutls_mpi_release(&state->gnutls_key->u);
		_gnutls_mpi_release(&state->gnutls_key->a);
		_gnutls_mpi_release(&state->gnutls_key->x);
		_gnutls_mpi_release(&state->gnutls_key->A);
		_gnutls_mpi_release(&state->gnutls_key->B);
		_gnutls_mpi_release(&state->gnutls_key->b);

		_gnutls_mpi_release(&state->gnutls_key->dh_secret);
		_gnutls_free(state->gnutls_key);

		state->gnutls_key = NULL;
	}

	/* free priorities */
	_gnutls_free(state->gnutls_internals.MACAlgorithmPriority.algorithm_priority);
	_gnutls_free(state->gnutls_internals.ProtocolPriority.algorithm_priority);
	_gnutls_free(state->gnutls_internals.KXAlgorithmPriority.algorithm_priority);
	_gnutls_free(state->gnutls_internals.BulkCipherAlgorithmPriority.algorithm_priority);
	_gnutls_free(state->gnutls_internals.CompressionMethodPriority.algorithm_priority);

	_gnutls_free(state->gnutls_internals.db_name);

	memset( state, 0, sizeof(struct GNUTLS_STATE_INT));
	gnutls_free(state);
	return 0;
}

inline
static void _gnutls_cal_PRF_A( MACAlgorithm algorithm, void *secret, int secret_size, void *seed, int seed_size, void* result)
{
	GNUTLS_MAC_HANDLE td1;

	td1 = gnutls_hmac_init(algorithm, secret, secret_size);
	gnutls_hmac(td1, seed, seed_size);
	gnutls_hmac_deinit(td1, result);
	
	return;
}

#define MAX_SEED_SIZE 140

/* Produces "total_bytes" bytes using the hash algorithm specified.
 * (used in the PRF function)
 */
static svoid *gnutls_P_hash( MACAlgorithm algorithm, opaque * secret, int secret_size, opaque * seed, int seed_size, int total_bytes)
{

	GNUTLS_MAC_HANDLE td2;
	opaque *ret;
	int i = 0, times, how, blocksize, A_size;
	opaque final[20], Atmp[MAX_SEED_SIZE];

	if (seed_size > MAX_SEED_SIZE || total_bytes<=0) {
		gnutls_assert();
		return NULL;
	}
	
	ret = secure_calloc(1, total_bytes);
	if (ret==NULL) {
		gnutls_assert();
		return ret;
	}

	blocksize = gnutls_hmac_get_algo_len(algorithm);
	do {
		i += blocksize;
	} while (i < total_bytes);

	/* calculate A(0) */

	memcpy( Atmp, seed, seed_size);
	A_size = seed_size;

	times = i / blocksize;
	for (i = 0; i < times; i++) {
		td2 = gnutls_hmac_init(algorithm, secret, secret_size);

		/* here we calculate A(i+1) */
		_gnutls_cal_PRF_A( algorithm, secret, secret_size, Atmp, A_size, Atmp);

		A_size = blocksize;

		gnutls_hmac(td2, Atmp, A_size);
		gnutls_hmac(td2, seed, seed_size);
		gnutls_hmac_deinit(td2, final);

		if ( (1+i) * blocksize < total_bytes) {
			how = blocksize;
		} else {
			how = total_bytes - (i) * blocksize;
		}

		if (how > 0) {
			memcpy(&ret[i * blocksize], final, how);
		}
	}
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

	memcpy(s_seed, label, label_size);
	memcpy(&s_seed[label_size], seed, seed_size);

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

/**
  * gnutls_send_alert - This function sends an alert message to the peer
  * @state: is a &GNUTLS_STATE structure.
  * @level: is the level of the alert
  * @desc: is the alert description
  *
  * This function will send an alert to the peer in order to inform
  * him of something important (eg. his Certificate could not be verified).
  * If the alert level is Fatal then the peer is expected to close the
  * connection, otherwise he may ignore the alert and continue.
  * Returns 0 on success.
  *
  **/
int gnutls_send_alert( GNUTLS_STATE state, AlertLevel level, AlertDescription desc)
{
	uint8 data[2];
	int ret;
	
	memcpy(&data[0], &level, 1);
	memcpy(&data[1], &desc, 1);

#ifdef RECORD_DEBUG
	_gnutls_log( "Record: Sending Alert[%d|%d] - %s\n", data[0], data[1], _gnutls_alert2str((int)data[1]));
#endif

	if ( (ret = gnutls_send_int( state, GNUTLS_ALERT, -1, data, 2)) >= 0)
		return 0;
	else
		return ret;
}

/* Sends the appropriate alert, depending
 * on the error message.
 */
/**
  * gnutls_send_appropriate_alert - This function sends an alert to the peer depending on the error code
  * @state: is a &GNUTLS_STATE structure.
  * @err: is an integer
  *
  * Sends an alert to the peer depending on the error code returned by a gnutls
  * function. All alerts sent by this function are fatal, so connection should
  * be considered terminated after calling this function. The only exception
  * is when err == GNUTLS_E_REHANDSHAKE, then a warning alert is sent to
  * the peer indicating the no renegotiation will be performed.
  *
  * This function may also return GNUTLS_E_AGAIN, or GNUTLS_E_INTERRUPTED.
  *
  * If the return value is GNUTLS_E_UNIMPLEMENTED_FEATURE, then no alert has
  * been sent to the peer.
  *
  **/
int gnutls_send_appropriate_alert( GNUTLS_STATE state, int err) {
int ret = GNUTLS_E_UNIMPLEMENTED_FEATURE;
	switch (err) { /* send appropriate alert */
		case GNUTLS_E_MAC_FAILED:
			ret = gnutls_send_alert( state, GNUTLS_AL_FATAL, GNUTLS_A_BAD_RECORD_MAC);
			break;
		case GNUTLS_E_DECRYPTION_FAILED:
			ret = gnutls_send_alert( state, GNUTLS_AL_FATAL, GNUTLS_A_DECRYPTION_FAILED);
			break;
		case GNUTLS_E_DECOMPRESSION_FAILED:
			ret = gnutls_send_alert( state, GNUTLS_AL_FATAL, GNUTLS_A_DECOMPRESSION_FAILURE);
			break;
		case GNUTLS_E_ILLEGAL_PARAMETER:
                        ret = gnutls_send_alert( state, GNUTLS_AL_FATAL, GNUTLS_A_ILLEGAL_PARAMETER);
                        break;
		case GNUTLS_E_ASN1_PARSING_ERROR:
		case GNUTLS_E_NO_CERTIFICATE_FOUND:
                        ret = gnutls_send_alert( state, GNUTLS_AL_FATAL, GNUTLS_A_BAD_CERTIFICATE);
                        break;
		case GNUTLS_E_UNKNOWN_CIPHER_SUITE:
                        ret = gnutls_send_alert( state, GNUTLS_AL_FATAL, GNUTLS_A_HANDSHAKE_FAILURE);
                        break;
		case GNUTLS_E_UNEXPECTED_PACKET:
                        ret = gnutls_send_alert( state, GNUTLS_AL_FATAL, GNUTLS_A_UNEXPECTED_MESSAGE);
                        break;
		case GNUTLS_E_REHANDSHAKE:
                        ret = gnutls_send_alert( state, GNUTLS_AL_WARNING, GNUTLS_A_NO_RENEGOTIATION);
                        break;
		case GNUTLS_E_UNSUPPORTED_VERSION_PACKET:
                        ret = gnutls_send_alert( state, GNUTLS_AL_WARNING, GNUTLS_A_PROTOCOL_VERSION);
			break;
		case GNUTLS_E_UNEXPECTED_PACKET_LENGTH:
			ret = gnutls_send_alert( state, GNUTLS_AL_FATAL, GNUTLS_A_RECORD_OVERFLOW);
			break;
	}
	return ret;
}

/**
  * gnutls_bye - This function terminates the current TLS/SSL connection.
  * @state: is a &GNUTLS_STATE structure.
  * @how: is an integer
  *
  * Terminates the current TLS/SSL connection. The connection should
  * have been initiated using gnutls_handshake().
  * 'how' should be one of GNUTLS_SHUT_RDWR, GNUTLS_SHUT_WR.
  *
  * In case of GNUTLS_SHUT_RDWR then the TLS connection gets terminated and
  * further receives and sends will be disallowed. If the return
  * value is zero you may continue using the connection.
  * (GNUTLS_SHUT_RDWR actually sends an alert containing a close request
  * and waits for the peer to reply with the same message)
  *
  * In case of GNUTLS_SHUT_WR then the TLS connection gets terminated and
  * further sends will be disallowed. In order to reuse the connection
  * you should wait for an EOF from the peer.
  * (GNUTLS_SHUT_WR sends an alert containing a close request)
  *
  * This function may also return GNUTLS_E_AGAIN, or GNUTLS_E_INTERRUPTED.
  *
  **/
int gnutls_bye( GNUTLS_STATE state, CloseRequest how)
{
	int ret = 0, ret2 = 0;

	switch (STATE) {
		case STATE0:
		case STATE60:
			if (STATE==STATE60) {
				ret = _gnutls_write_flush( state);
			} else {
				ret = gnutls_send_alert( state, GNUTLS_AL_WARNING, GNUTLS_A_CLOSE_NOTIFY);
				STATE = STATE60;
			}

			if (ret < 0)
				return ret;
		case STATE61:
			if ( how == GNUTLS_SHUT_RDWR && ret >= 0) {
				ret2 = gnutls_recv_int( state, GNUTLS_ALERT, -1, NULL, 0); 
				if (ret2 >= 0) state->gnutls_internals.may_read = 1;
			}
			STATE = STATE61;

			if (ret2 < 0)
				return ret2;

	}

	STATE = STATE0;
	
	state->gnutls_internals.may_write = 1;
	return 0;
}

/* This function behave exactly like write(). The only difference is 
 * that it accepts, the gnutls_state and the ContentType of data to
 * send (if called by the user the Content is specific)
 * It is intended to transfer data, under the current state.    
 *
 * Oct 30 2001: Removed capability to send data more than MAX_RECORD_SIZE.
 * This makes the function much easier to read, and more error resistant
 * (there were cases were the old function could mess everything up).
 * --nmav
 *
 */
ssize_t gnutls_send_int( GNUTLS_STATE state, ContentType type, HandshakeType htype, const void *_data, size_t sizeofdata)
{
	uint8 *cipher;
	int cipher_size;
	int retval, ret;
	int data2send;
	uint8 headers[5];
	const uint8 *data=_data;
	GNUTLS_Version lver;

	if (sizeofdata == 0 || _data==NULL) {
		gnutls_assert();
		return GNUTLS_E_INVALID_PARAMETERS;
	}

	if (state->gnutls_internals.valid_connection == VALID_FALSE || state->gnutls_internals.may_write != 0) {
		gnutls_assert();
		return GNUTLS_E_INVALID_SESSION;
	}

	headers[0]=type;
	
	if (htype==GNUTLS_CLIENT_HELLO) { /* then send the lowest 
			  		   * protocol we support 
					   */
		lver = _gnutls_version_lowest(state);
		if (lver==GNUTLS_VERSION_UNKNOWN) {
			gnutls_assert();
		}
	} else { /* send the current */
		lver = gnutls_protocol_get_version( state);
	}

	headers[1]=_gnutls_version_get_major( lver);
	headers[2]=_gnutls_version_get_minor( lver);

	
#ifdef RECORD_DEBUG
	_gnutls_log( "Record: Sending Packet[%d] %s(%d) with length: %d\n",
		(int) uint64touint32(&state->connection_state.write_sequence_number), _gnutls_packet2str(type), type, sizeofdata);
#endif

	if ( sizeofdata > MAX_RECORD_SIZE)
		data2send = MAX_RECORD_SIZE;
	else 
		data2send = sizeofdata;

	/* Only encrypt if we don't have data to send 
	 * from the previous run. - probably interrupted.
	 */
	if (state->gnutls_internals.send_buffer.size > 0) {
		ret = _gnutls_write_flush( state);
		if (ret > 0) cipher_size = ret;
		else cipher_size = 0;
		
		cipher = NULL;

		retval = state->gnutls_internals.send_buffer_user_size;
	} else {
		cipher_size = _gnutls_encrypt( state, headers, RECORD_HEADER_SIZE, data, data2send, &cipher, type);
		if (cipher_size <= 0) {
			gnutls_assert();
			if (cipher_size==0) cipher_size = GNUTLS_E_ENCRYPTION_FAILED;
			return cipher_size; /* error */
		}

		retval = data2send;
		state->gnutls_internals.send_buffer_user_size =	data2send;

		/* increase sequence number
		 */
		if (uint64pp( &state->connection_state.write_sequence_number) != 0) {
			state->gnutls_internals.valid_connection = VALID_FALSE;
			gnutls_assert();
			/* FIXME: Somebody has to do rehandshake before that.
			 */
			return GNUTLS_E_RECORD_LIMIT_REACHED;
		}

		ret = _gnutls_write_buffered( state, cipher, cipher_size);
	}

	if ( ret != cipher_size) {
		gnutls_free( cipher);
		if ( ret < 0 && gnutls_is_fatal_error(ret)==0) {
			/* If we have sent any data then return
			 * that value.
			 */
			gnutls_assert();
			return ret;
		}
		
		if (ret > 0) {
			gnutls_assert();
			ret = GNUTLS_E_UNKNOWN_ERROR;
		}

		state->gnutls_internals.valid_connection = VALID_FALSE;
		state->gnutls_internals.resumable = RESUME_FALSE;
		gnutls_assert();
		return ret;
	}

	state->gnutls_internals.send_buffer_user_size = 0;

	gnutls_free(cipher);

#ifdef RECORD_DEBUG
	_gnutls_log( "Record: Sent Packet[%d] %s(%d) with length: %d\n",
	(int) uint64touint32(&state->connection_state.write_sequence_number), _gnutls_packet2str(type), type, cipher_size);
#endif


	return retval;
}

/* This function is to be called if the handshake was successfully 
 * completed. This sends a Change Cipher Spec packet to the peer.
 */
ssize_t _gnutls_send_change_cipher_spec( GNUTLS_STATE state, int again)
{
	opaque data[1] = { GNUTLS_TYPE_CHANGE_CIPHER_SPEC };

#ifdef HANDSHAKE_DEBUG
	_gnutls_log( "Record: Sent ChangeCipherSpec\n");
#endif
	if (again==0)
		return gnutls_send_int( state, GNUTLS_CHANGE_CIPHER_SPEC, -1, data, 1);
	else {
		return _gnutls_write_flush( state);
	}
}

static int _gnutls_check_recv_type( ContentType recv_type) {
	switch( recv_type) {
	case GNUTLS_CHANGE_CIPHER_SPEC:
	case GNUTLS_ALERT:
	case GNUTLS_HANDSHAKE:
	case GNUTLS_APPLICATION_DATA:
		return 0;
	default:
		gnutls_assert();
		return GNUTLS_E_UNSUPPORTED_VERSION_PACKET;
	}

}

#define CHECK_RECORD_VERSION

/* This function behave exactly like read(). The only difference is 
 * that it accepts, the gnutls_state and the ContentType of data to
 * send (if called by the user the Content is Userdata only)
 * It is intended to receive data, under the current state.
 */
ssize_t gnutls_recv_int( GNUTLS_STATE state, ContentType type, HandshakeType htype, char *data, size_t sizeofdata)
{
	uint8 *tmpdata;
	int tmplen;
	GNUTLS_Version version;
	uint8 *headers;
	ContentType recv_type;
	uint16 length;
	uint8 *ciphertext;
	uint8 *recv_data;
	int ret, ret2;
	int header_size;

	begin:

	header_size = RECORD_HEADER_SIZE;
	ret = 0;

	if (sizeofdata == 0 || data == NULL) {
		gnutls_assert();
		return GNUTLS_E_INVALID_PARAMETERS;
	}

	if (state->gnutls_internals.valid_connection == VALID_FALSE || state->gnutls_internals.may_read!=0) {
		gnutls_assert();
		return GNUTLS_E_INVALID_SESSION;
	}
	
	/* If we have enough data in the cache do not bother receiving
	 * a new packet. (in order to flush the cache)
	 */
	if ( (type == GNUTLS_APPLICATION_DATA || type == GNUTLS_HANDSHAKE) && gnutls_get_data_buffer_size(type, state) > 0) {
		ret = gnutls_get_data_buffer(type, state, data, sizeofdata);
		if (ret < 0) {
			gnutls_assert();
			return ret;
		}
		
		/* if the buffer just got empty */
		if (gnutls_get_data_buffer_size(type, state)==0) {
			if ( (ret2=_gnutls_clear_peeked_data( state)) < 0) {
				gnutls_assert();
				return ret2;
			}
		}

		return ret;
	}
	
	/* in order for GNUTLS_E_AGAIN to be returned the socket
	 * must be set to non blocking mode
	 */
	if ( (ret = _gnutls_read_buffered( state, &headers, header_size, -1)) != header_size) {
		if (ret < 0 && gnutls_is_fatal_error(ret)==0) return ret;

		state->gnutls_internals.valid_connection = VALID_FALSE;
		if (type==GNUTLS_ALERT) {
			gnutls_assert();
			return 0; /* we were expecting close notify */
		}
		state->gnutls_internals.resumable = RESUME_FALSE;
		gnutls_assert();
		return GNUTLS_E_UNEXPECTED_PACKET_LENGTH;
	}

	/* Read the first two bytes to determine if this is a 
	 * version 2 message 
	 */
	if ( htype == GNUTLS_CLIENT_HELLO && type==GNUTLS_HANDSHAKE && headers[0] > 127) { 

	/* if msb set and expecting handshake message
	 * it should be SSL 2 hello 
	 */
		version = GNUTLS_VERSION_UNKNOWN; /* assume unknown version */
		length = (((headers[0] & 0x7f) << 8)) | headers[1];

		header_size = 2;
		recv_type = GNUTLS_HANDSHAKE; /* we accept only v2 client hello
					       */
		state->gnutls_internals.v2_hello = length;
#ifdef RECORD_DEBUG
		_gnutls_log( "Record: V2 packet received. Length: %d\n", length);
#endif

	} else {
		/* version 3.x 
		 */
		recv_type = headers[0];
#ifdef CHECK_RECORD_VERSION
		version = _gnutls_version_get( headers[1], headers[2]);
#endif

		length = READuint16( &headers[3]);
	}

	/* Here we check if the Type of the received packet is
	 * ok. 
	 */
	if ( (ret = _gnutls_check_recv_type( recv_type)) < 0) {
		gnutls_assert();
		return ret;
	}

	/* Here we check if the advertized version is the one we
	 * negotiated in the handshake.
	 */
#ifdef CHECK_RECORD_VERSION
	if ( (htype!=GNUTLS_CLIENT_HELLO && htype!=GNUTLS_SERVER_HELLO) && gnutls_protocol_get_version(state) != version) {
		gnutls_assert();
# ifdef RECORD_DEBUG
		_gnutls_log( "Record: INVALID VERSION PACKET: (%d/%d) %d.%d\n", headers[0], htype, headers[1], headers[2]);
# endif
		state->gnutls_internals.resumable = RESUME_FALSE;
		return GNUTLS_E_UNSUPPORTED_VERSION_PACKET;
	}
#endif

#ifdef RECORD_DEBUG
	_gnutls_log( "Record: Expected Packet[%d] %s(%d) with length: %d\n",
		(int) uint64touint32(&state->connection_state.read_sequence_number), _gnutls_packet2str(type), type, sizeofdata);
	_gnutls_log( "Record: Received Packet[%d] %s(%d) with length: %d\n",
		(int) uint64touint32(&state->connection_state.read_sequence_number), _gnutls_packet2str(recv_type), recv_type, length);
#endif

	if (length > MAX_RECV_SIZE) {
#ifdef RECORD_DEBUG
		_gnutls_log( "Record: FATAL ERROR: Received packet with length: %d\n", length);
#endif
		state->gnutls_internals.valid_connection = VALID_FALSE;
		state->gnutls_internals.resumable = RESUME_FALSE;
		gnutls_assert();
		return GNUTLS_E_UNEXPECTED_PACKET_LENGTH;
	}

	/* check if we have that data into buffer. 
 	 */
	if ( (ret = _gnutls_read_buffered( state, &recv_data, header_size+length, recv_type)) != length+header_size) {
		if (ret<0 && gnutls_is_fatal_error(ret)==0) return ret;

		state->gnutls_internals.valid_connection = VALID_FALSE;
		state->gnutls_internals.resumable = RESUME_FALSE;
		gnutls_assert();
		return GNUTLS_E_UNEXPECTED_PACKET_LENGTH;		
	}
	
/* ok now we are sure that we can read all the data - so
 * move on !
 */
	_gnutls_clear_read_buffer( state);
	ciphertext = &recv_data[header_size];
	
	/* decrypt the data we got
	 */
	tmplen = _gnutls_decrypt( state, ciphertext, length, &tmpdata, recv_type);
	if (tmplen < 0) {
		state->gnutls_internals.valid_connection = VALID_FALSE;
		state->gnutls_internals.resumable = RESUME_FALSE;
		gnutls_assert();
		return tmplen;
	}

	/* Check if this is a CHANGE_CIPHER_SPEC
	 */
	if (type == GNUTLS_CHANGE_CIPHER_SPEC && recv_type == GNUTLS_CHANGE_CIPHER_SPEC) {
#ifdef RECORD_DEBUG
		_gnutls_log( "Record: ChangeCipherSpec Packet was received\n");
#endif

		if (tmplen!=sizeofdata) { /* sizeofdata should be 1 */
			gnutls_assert();
			gnutls_free(tmpdata);
			return GNUTLS_E_UNEXPECTED_PACKET_LENGTH;
		}
		memcpy( data, tmpdata, sizeofdata);
		gnutls_free(tmpdata);

		return tmplen;
	}

#ifdef RECORD_DEBUG
	_gnutls_log( "Record: Decrypted Packet[%d] %s(%d) with length: %d\n",
		(int) uint64touint32(&state->connection_state.read_sequence_number), _gnutls_packet2str(recv_type), recv_type, tmplen);
#endif

	/* increase sequence number */
	if (uint64pp( &state->connection_state.read_sequence_number)!=0) {
		state->gnutls_internals.valid_connection = VALID_FALSE;
		gnutls_free(tmpdata);
		gnutls_assert();
		return GNUTLS_E_RECORD_LIMIT_REACHED;
	}

	if ( (recv_type == type) && (type == GNUTLS_APPLICATION_DATA || type == GNUTLS_HANDSHAKE)) {
		gnutls_insert_to_data_buffer(type, state, (void *) tmpdata, tmplen);
	} else {
		switch (recv_type) {
		case GNUTLS_ALERT:
#ifdef RECORD_DEBUG
			_gnutls_log( "Record: Alert[%d|%d] - %s - was received\n", tmpdata[0], tmpdata[1], _gnutls_alert2str((int)tmpdata[1]));
#endif
			state->gnutls_internals.last_alert = tmpdata[1];

			/* if close notify is received and
			 * the alert is not fatal
			 */
			if (tmpdata[1] == GNUTLS_A_CLOSE_NOTIFY && tmpdata[0] != GNUTLS_AL_FATAL) {
				/* If we have been expecting for an alert do 
				 * not call close().
				 */
				if (type != GNUTLS_ALERT) 
					do ret=gnutls_bye( state, GNUTLS_SHUT_WR);
					while(ret==GNUTLS_E_INTERRUPTED || ret==GNUTLS_E_AGAIN);
				gnutls_free(tmpdata);

				return 0; /* EOF */
			} else {
			
				/* if the alert is FATAL or WARNING
				 * return the apropriate message
				 */
			
				ret = GNUTLS_E_WARNING_ALERT_RECEIVED;
				if (tmpdata[0] == GNUTLS_AL_FATAL) {
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
			if ( (ret=gnutls_insert_to_data_buffer(recv_type, state, (void *) tmpdata, tmplen)) < 0) {
				gnutls_assert();
				return ret;
			}

			gnutls_assert();
			gnutls_free(tmpdata);
			
			goto begin; /* ok we received the packet, 
			             * and now we should get the one
			             * we expected.
			             */
			
			break;
		case GNUTLS_HANDSHAKE:
			/* This is only legal if HELLO_REQUEST is received - and we are a client 
			 */
			if (htype!=GNUTLS_HELLO_REQUEST && state->security_parameters.entity==GNUTLS_SERVER) {
				gnutls_assert();
				gnutls_free( tmpdata);
				return GNUTLS_E_UNEXPECTED_PACKET;
			}

			break;
		default:
#ifdef RECORD_DEBUG
			_gnutls_log( "Record: Received Unknown packet %d expecting %d\n", recv_type, type);
#endif
			gnutls_assert();
			return GNUTLS_E_UNKNOWN_ERROR;
		}
	}


	/* Get Application data from buffer */
	if ((type == GNUTLS_APPLICATION_DATA || type == GNUTLS_HANDSHAKE) && (recv_type == type)) {
		ret = gnutls_get_data_buffer(type, state, data, sizeofdata);
		if (ret < 0) {
			gnutls_assert();
			return ret;
		}

		/* if the buffer just got empty */
		if (gnutls_get_data_buffer_size(type, state)==0) {
			if ( (ret2 = _gnutls_clear_peeked_data( state)) < 0) {
				gnutls_assert();
				return ret2;
			}
		}

		gnutls_free(tmpdata);
	} else {
		if (recv_type == GNUTLS_HANDSHAKE) {
			/* we may get a hello request */
			ret = _gnutls_recv_hello_request( state, tmpdata, tmplen);
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
  * gnutls_cipher_get_algo - Returns the currently used cipher.
  * @state: is a &GNUTLS_STATE structure.
  *
  * Returns the currently used cipher.
  **/
BulkCipherAlgorithm gnutls_cipher_get_algo( GNUTLS_STATE state) {
	return state->security_parameters.read_bulk_cipher_algorithm;
}

/**
  * gnutls_kx_get_algo - Returns the key exchange algorithm.
  * @state: is a &GNUTLS_STATE structure.
  *
  * Returns the key exchange algorithm used in the last handshake.
  **/
KXAlgorithm gnutls_kx_get_algo( GNUTLS_STATE state) {
	return state->security_parameters.kx_algorithm;
}

/**
  * gnutls_mac_get_algo - Returns the currently used mac algorithm.
  * @state: is a &GNUTLS_STATE structure.
  *
  * Returns the currently used mac algorithm.
  **/
MACAlgorithm gnutls_mac_get_algo( GNUTLS_STATE state) {
	return state->security_parameters.read_mac_algorithm;
}

/**
  * gnutls_compression_get_algo - Returns the currently used compression algorithm.
  * @state: is a &GNUTLS_STATE structure.
  *
  * Returns the currently used compression method.
  **/
CompressionMethod gnutls_compression_get_algo( GNUTLS_STATE state) {
	return state->security_parameters.read_compression_algorithm;
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
  * should be called if GNUTLS_E_WARNING_ALERT_RECEIVED or
  * GNUTLS_E_FATAL_ALERT_RECEIVED has been returned by a gnutls function.
  * The peer may send alerts if he thinks some things were not 
  * right. Check gnutls.h for the available alert descriptions.
  **/
AlertDescription gnutls_get_last_alert( GNUTLS_STATE state) {
	return state->gnutls_internals.last_alert;
}

/**
  * gnutls_write - sends to the peer the specified data
  * @state: is a &GNUTLS_STATE structure.
  * @data: contains the data to send
  * @sizeofdata: is the length of the data
  *
  * This function has the similar semantics to write(). The only
  * difference is that is accepts a GNUTLS state, and uses different
  * error codes.
  *
  * If the EINTR is returned by the internal push function (write())
  * then GNUTLS_E_INTERRUPTED, will be returned. If GNUTLS_E_INTERRUPTED or
  * GNUTLS_E_AGAIN is returned you must call this function again, with the 
  * same parameters. Otherwise the write operation will be 
  * corrupted and the connection will be terminated.
  *
  * Returns the number of bytes sent, or a negative error code.
  *
  **/
ssize_t gnutls_write( GNUTLS_STATE state, const void *data, size_t sizeofdata) {
	return gnutls_send_int( state, GNUTLS_APPLICATION_DATA, -1, data, sizeofdata);
}

/**
  * gnutls_read - reads data from the TLS connection
  * @state: is a &GNUTLS_STATE structure.
  * @data: contains the data to send
  * @sizeofdata: is the length of the data
  *
  * This function has the similar semantics to read(). The only
  * difference is that is accepts a GNUTLS state.
  * Also returns the number of bytes received, zero on EOF, but
  * a negative error code in case of an error.
  *
  * If this function returns GNUTLS_E_REHANDSHAKE, then you must
  * either send an alert containing NO_RENEGOTIATION, or perform a
  * handshake. (only a client may receive this message)
  *
  **/
ssize_t gnutls_read( GNUTLS_STATE state, void *data, size_t sizeofdata) {
	return gnutls_recv_int( state, GNUTLS_APPLICATION_DATA, -1, data, sizeofdata);
}

/**
  * gnutls_get_max_record_size - returns the maximum record size
  * @state: is a &GNUTLS_STATE structure.
  *
  * This function returns the maximum record size in this connection.
  * The maximum record size is negotiated by the client after the
  * first handshake message.
  *
  **/
size_t gnutls_get_max_record_size( GNUTLS_STATE state) {
	return state->security_parameters.max_record_size;
}


/**
  * gnutls_set_max_record_size - sets the maximum record size
  * @state: is a &GNUTLS_STATE structure.
  * @size: is the new size
  *
  * This function sets the maximum record size in this connection.
  * This property can only be set to clients. The server may
  * choose not to accept the requested size.
  *
  * Acceptable values are 2^9, 2^10, 2^11 and 2^12.
  * Returns 0 on success. The requested record size does not
  * get in effect immediately. It will be used after a successful
  * handshake.
  *
  * This function uses a TLS extension called 'max record size'.
  * Not all TLS implementations use or even understand this extension.
  *
  **/
size_t gnutls_set_max_record_size( GNUTLS_STATE state, size_t size) {
size_t new_size;

	if (state->security_parameters.entity==GNUTLS_SERVER)
		return GNUTLS_E_INVALID_REQUEST;

	new_size = _gnutls_mre_record2num( size);

	if (new_size < 0) {
		gnutls_assert();
		return new_size;
	}
	
	state->gnutls_internals.proposed_record_size = size;

	return 0;
}
