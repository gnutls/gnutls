/*
 *      Copyright (C) 2000,2001,2002 Nikos Mavroyanopoulos
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
#include <gnutls_alert.h>
#include <gnutls_dh.h>

/**
  * gnutls_protocol_get_version - Returns the version of the currently used protocol
  * @state: is a &GNUTLS_STATE structure.
  *
  * Returns the version of the currently used protocol. 
  *
  **/
GNUTLS_Version gnutls_protocol_get_version(GNUTLS_STATE state) {
	return state->security_parameters.version;
}

void _gnutls_set_current_version(GNUTLS_STATE state, GNUTLS_Version version) {
	state->security_parameters.version = version;
}

/**
  * gnutls_transport_set_lowat - Used to set the lowat value in order for select to check for pending data.
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
void gnutls_transport_set_lowat(GNUTLS_STATE state, int num) {
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
void gnutls_transport_set_ptr(GNUTLS_STATE state, GNUTLS_TRANSPORT_PTR ptr) {
	state->gnutls_internals.transport_ptr = ptr;
}

/**
  * gnutls_transport_get_ptr - Used to return the first argument of the transport functions
  * @state: is a &GNUTLS_STATE structure.
  *
  * Used to get the first argument of the transport function (like PUSH and
  * PULL). This must have been set using gnutls_transport_set_ptr().
  *
  **/
GNUTLS_TRANSPORT_PTR gnutls_transport_get_ptr(GNUTLS_STATE state) {
	return state->gnutls_internals.transport_ptr;
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

#define MAX_SEED_SIZE 200

/* Produces "total_bytes" bytes using the hash algorithm specified.
 * (used in the PRF function)
 */
static int gnutls_P_hash( MACAlgorithm algorithm, opaque * secret, int secret_size, opaque * seed, int seed_size, int total_bytes, opaque* ret)
{

	GNUTLS_MAC_HANDLE td2;
	int i = 0, times, how, blocksize, A_size;
	opaque final[20], Atmp[MAX_SEED_SIZE];

	if (seed_size > MAX_SEED_SIZE || total_bytes<=0) {
		gnutls_assert();
		return GNUTLS_E_INTERNAL;
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
	
	return 0;
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

#define MAX_PRF_BYTES 200

/* The PRF function expands a given secret 
 * needed by the TLS specification. ret must have a least total_bytes
 * available.
 */
int gnutls_PRF( opaque * secret, int secret_size, uint8 * label, int label_size, opaque * seed, int seed_size, int total_bytes, void* ret)
{
	int l_s, s_seed_size;
	char *s1, *s2;
	opaque s_seed[MAX_SEED_SIZE];
	opaque o1[MAX_PRF_BYTES], o2[MAX_PRF_BYTES];
	int result;

	if (total_bytes > MAX_PRF_BYTES) {
		gnutls_assert();
		return GNUTLS_E_INTERNAL;
	}
	/* label+seed = s_seed */
	s_seed_size = seed_size + label_size;

	if (s_seed_size > MAX_SEED_SIZE) {
		gnutls_assert();
		return GNUTLS_E_INTERNAL;
	}

	memcpy(s_seed, label, label_size);
	memcpy(&s_seed[label_size], seed, seed_size);

	l_s = secret_size / 2;
	s1 = &secret[0];
	s2 = &secret[l_s];

	if (secret_size % 2 != 0) {
		l_s++;
	}

	result = gnutls_P_hash( GNUTLS_MAC_MD5, s1, l_s, s_seed, s_seed_size, total_bytes, o1);
	if (result<0) {
		gnutls_assert();
		return result;
	}

	result = gnutls_P_hash( GNUTLS_MAC_SHA, s2, l_s, s_seed, s_seed_size, total_bytes, o2);
	if (result<0) {
		gnutls_assert();
		return result;
	}

	_gnutls_xor(o1, o2, total_bytes);

	memcpy( ret, o1, total_bytes);

	return 0; /* ok */

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
  * GNUTLS_SHUT_RDWR actually sends an alert containing a close request
  * and waits for the peer to reply with the same message.
  *
  * In case of GNUTLS_SHUT_WR then the TLS connection gets terminated and
  * further sends will be disallowed. In order to reuse the connection
  * you should wait for an EOF from the peer.
  * GNUTLS_SHUT_WR sends an alert containing a close request.
  *
  * This function may also return GNUTLS_E_AGAIN, or GNUTLS_E_INTERRUPTED.
  *
  **/
int gnutls_bye( GNUTLS_STATE state, GNUTLS_CloseRequest how)
{
	int ret = 0, ret2 = 0;

	switch (STATE) {
		case STATE0:
		case STATE60:
			if (STATE==STATE60) {
				ret = _gnutls_io_write_flush( state);
			} else {
				ret = gnutls_alert_send( state, GNUTLS_AL_WARNING, GNUTLS_A_CLOSE_NOTIFY);
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

inline
static void _gnutls_session_invalidate( GNUTLS_STATE state) {
	state->gnutls_internals.valid_connection = VALID_FALSE;
}


inline
static void _gnutls_session_unresumable( GNUTLS_STATE state) {
	state->gnutls_internals.resumable = RESUME_FALSE;
}

/* returns 0 if session is valid
 */
inline
static int _gnutls_session_is_valid( GNUTLS_STATE state) {
	if (state->gnutls_internals.valid_connection==VALID_FALSE)
		return GNUTLS_E_INVALID_SESSION;
	
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

	if (type!=GNUTLS_ALERT) /* alert messages are sent anyway */
		if ( _gnutls_session_is_valid( state) || state->gnutls_internals.may_write != 0) {
			return GNUTLS_E_INVALID_SESSION;
		}

	headers[0]=type;
	
	lver = gnutls_protocol_get_version(state);
	if (lver==GNUTLS_VERSION_UNKNOWN) {
		gnutls_assert();
		return GNUTLS_E_INTERNAL;
	}

	headers[1]=_gnutls_version_get_major( lver);
	headers[2]=_gnutls_version_get_minor( lver);

	_gnutls_record_log( "REC: Sending Packet[%d] %s(%d) with length: %d\n",
		(int) uint64touint32(&state->connection_state.write_sequence_number), _gnutls_packet2str(type), type, sizeofdata);

	if ( sizeofdata > MAX_RECORD_SIZE)
		data2send = MAX_RECORD_SIZE;
	else 
		data2send = sizeofdata;

	/* Only encrypt if we don't have data to send 
	 * from the previous run. - probably interrupted.
	 */
	if (state->gnutls_internals.record_send_buffer.size > 0) {
		ret = _gnutls_io_write_flush( state);
		if (ret > 0) cipher_size = ret;
		else cipher_size = 0;
		
		cipher = NULL;

		retval = state->gnutls_internals.record_send_buffer_user_size;
	} else {
		cipher_size = _gnutls_encrypt( state, headers, RECORD_HEADER_SIZE, data, data2send, &cipher, type);
		if (cipher_size <= 0) {
			gnutls_assert();
			if (cipher_size==0) cipher_size = GNUTLS_E_ENCRYPTION_FAILED;
			return cipher_size; /* error */
		}

		retval = data2send;
		state->gnutls_internals.record_send_buffer_user_size =	data2send;

		/* increase sequence number
		 */
		if (uint64pp( &state->connection_state.write_sequence_number) != 0) {
			_gnutls_session_invalidate( state);
			gnutls_assert();
			/* FIXME: Somebody has to do rehandshake before that.
			 */
			return GNUTLS_E_RECORD_LIMIT_REACHED;
		}

		ret = _gnutls_io_write_buffered( state, cipher, cipher_size);
	}

	if ( ret != cipher_size) {
		gnutls_free( cipher);
		if ( ret < 0 && gnutls_error_is_fatal(ret)==0) {
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

		_gnutls_session_unresumable( state);
		_gnutls_session_invalidate( state);
		gnutls_assert();
		return ret;
	}

	state->gnutls_internals.record_send_buffer_user_size = 0;

	gnutls_free(cipher);

	_gnutls_record_log( "REC: Sent Packet[%d] %s(%d) with length: %d\n",
	(int) uint64touint32(&state->connection_state.write_sequence_number), _gnutls_packet2str(type), type, cipher_size);

	return retval;
}

/* This function is to be called if the handshake was successfully 
 * completed. This sends a Change Cipher Spec packet to the peer.
 */
ssize_t _gnutls_send_change_cipher_spec( GNUTLS_STATE state, int again)
{
	opaque data[1] = { GNUTLS_TYPE_CHANGE_CIPHER_SPEC };

	_gnutls_handshake_log( "REC: Sent ChangeCipherSpec\n");

	if (again==0)
		return gnutls_send_int( state, GNUTLS_CHANGE_CIPHER_SPEC, -1, data, 1);
	else {
		return _gnutls_io_write_flush( state);
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


/* Checks if there are pending data into the record buffers. If there are
 * then it copies the data.
 */
static int _gnutls_check_buffers( GNUTLS_STATE state, ContentType type, opaque* data, int sizeofdata) {
	int ret = 0, ret2=0;
	if ( (type == GNUTLS_APPLICATION_DATA || type == GNUTLS_HANDSHAKE) && _gnutls_record_buffer_get_size(type, state) > 0) {
		ret = _gnutls_record_buffer_get(type, state, data, sizeofdata);
		if (ret < 0) {
			gnutls_assert();
			return ret;
		}
		
		/* if the buffer just got empty */
		if (_gnutls_record_buffer_get_size(type, state)==0) {
			if ( (ret2=_gnutls_io_clear_peeked_data( state)) < 0) {
				gnutls_assert();
				return ret2;
			}
		}

		return ret;
	}
	
	return 0;
}


#define CHECK_RECORD_VERSION

/* Checks the record headers and returns the length, version and
 * content type.
 */
static int _gnutls_check_record_headers( GNUTLS_STATE state, uint8 headers[RECORD_HEADER_SIZE], ContentType type, 
	HandshakeType htype, /*output*/ ContentType *recv_type, GNUTLS_Version *version, uint16 *length, uint16* header_size) {

	/* Read the first two bytes to determine if this is a 
	 * version 2 message 
	 */

	if ( htype == GNUTLS_CLIENT_HELLO && type==GNUTLS_HANDSHAKE && headers[0] > 127) { 

		/* if msb set and expecting handshake message
		 * it should be SSL 2 hello 
		 */
		*version = GNUTLS_VERSION_UNKNOWN; /* assume unknown version */
		*length = (((headers[0] & 0x7f) << 8)) | headers[1];

		/* SSL 2.0 headers */
		*header_size = 2;
		*recv_type = GNUTLS_HANDSHAKE; /* we accept only v2 client hello
					       */
		
		/* in order to assist the handshake protocol.
		 * V2 compatibility is a mess.
		 */
		state->gnutls_internals.v2_hello = *length;

		_gnutls_record_log( "REC: V2 packet received. Length: %d\n", *length);

	} else {
		/* version 3.x 
		 */
		*recv_type = headers[0];
#ifdef CHECK_RECORD_VERSION
		*version = _gnutls_version_get( headers[1], headers[2]);
#endif

		*length = READuint16( &headers[3]);
	}

	return 0;
}

/* Here we check if the advertized version is the one we
 * negotiated in the handshake.
 */
inline
static int _gnutls_check_record_version( GNUTLS_STATE state, HandshakeType htype, GNUTLS_Version version) 
{
#ifdef CHECK_RECORD_VERSION
	if ( (htype!=GNUTLS_CLIENT_HELLO && htype!=GNUTLS_SERVER_HELLO) && gnutls_protocol_get_version(state) != version) {
		gnutls_assert();

		_gnutls_record_log( "REC: INVALID VERSION PACKET: (%d) %d.%d\n", htype, _gnutls_version_get_major(version), _gnutls_version_get_minor(version));

		return GNUTLS_E_UNSUPPORTED_VERSION_PACKET;
	}
#endif

	return 0;
}

static int _gnutls_record_check_type( GNUTLS_STATE state, ContentType recv_type,
	ContentType type, HandshakeType htype, opaque* data, int data_size) {
	
	int ret;

	if ( (recv_type == type) && (type == GNUTLS_APPLICATION_DATA || type == GNUTLS_HANDSHAKE)) {
		_gnutls_record_buffer_put(type, state, (void *) data, data_size);
	} else {
		switch (recv_type) {
		case GNUTLS_ALERT:

			_gnutls_record_log( "REC: Alert[%d|%d] - %s - was received\n", data[0], data[1], _gnutls_alert2str((int)data[1]));

			state->gnutls_internals.last_alert = data[1];

			/* if close notify is received and
			 * the alert is not fatal
			 */
			if (data[1] == GNUTLS_A_CLOSE_NOTIFY && data[0] != GNUTLS_AL_FATAL) {
				/* If we have been expecting for an alert do 
				 */

				return GNUTLS_E_INT_RET_0; /* EOF */
			} else {
			
				/* if the alert is FATAL or WARNING
				 * return the apropriate message
				 */
				
				gnutls_assert();		
				ret = GNUTLS_E_WARNING_ALERT_RECEIVED;
				if (data[0] == GNUTLS_AL_FATAL) {
					_gnutls_session_unresumable( state);
					_gnutls_session_invalidate( state);

					ret = GNUTLS_E_FATAL_ALERT_RECEIVED;
				}

				return ret;
			}
			break;

		case GNUTLS_CHANGE_CIPHER_SPEC:
			/* this packet is now handled above */
			gnutls_assert();
	
			return GNUTLS_E_UNEXPECTED_PACKET;

		case GNUTLS_APPLICATION_DATA:
			/* even if data is unexpected put it into the buffer */
			if ( (ret=_gnutls_record_buffer_put(recv_type, state, (void *) data, data_size)) < 0) {
				gnutls_assert();
				return ret;
			}

			gnutls_assert();
			
			/* the got_application data is only returned
			 * if expecting client hello (for rehandshake
			 * reasons). Otherwise it is an unexpected packet
			 */
			if (htype == GNUTLS_CLIENT_HELLO && type==GNUTLS_HANDSHAKE)
				return GNUTLS_E_GOT_APPLICATION_DATA;
			else return GNUTLS_E_UNEXPECTED_PACKET;
			
			break;
		case GNUTLS_HANDSHAKE:
			/* This is only legal if HELLO_REQUEST is received - and we are a client 
			 */
			if ( state->security_parameters.entity==GNUTLS_SERVER) {
				gnutls_assert();
				return GNUTLS_E_UNEXPECTED_PACKET;
			}
			gnutls_assert();
			
			return _gnutls_recv_hello_request( state, data, data_size);

			break;
		default:

			_gnutls_record_log( "REC: Received Unknown packet %d expecting %d\n", recv_type, type);

			gnutls_assert();
			return GNUTLS_E_UNKNOWN_ERROR;
		}
	}
	
	return 0;

}

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
	uint16 header_size;

	/* default headers for TLS 1.0
	 */
	header_size = RECORD_HEADER_SIZE;
	ret = 0;

	if (sizeofdata == 0 || data == NULL) {
		return GNUTLS_E_INVALID_PARAMETERS;
	}

	if ( _gnutls_session_is_valid(state)!=0 || state->gnutls_internals.may_read!=0) {
		gnutls_assert();
		return GNUTLS_E_INVALID_SESSION;
	}
	
	/* If we have enough data in the cache do not bother receiving
	 * a new packet. (in order to flush the cache)
	 */
	ret = _gnutls_check_buffers( state, type, data, sizeofdata);
	if (ret != 0)
		return ret;


	if ( (ret = _gnutls_io_read_buffered( state, &headers, header_size, -1)) != header_size) {
		if (ret < 0 && gnutls_error_is_fatal(ret)==0) return ret;

		_gnutls_session_invalidate( state);
		if (type==GNUTLS_ALERT) {
			gnutls_assert();
			return 0; /* we were expecting close notify */
		}
		_gnutls_session_unresumable( state);
		gnutls_assert();
		return GNUTLS_E_UNEXPECTED_PACKET_LENGTH;
	}

	if ( (ret=_gnutls_check_record_headers( state, headers, type, htype, &recv_type, &version, &length, &header_size)) < 0) {
		gnutls_assert();
		return ret;
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
	if ( (ret=_gnutls_check_record_version( state, htype, version)) < 0) {
		gnutls_assert();
		_gnutls_session_invalidate( state);
		return ret;
	}

	_gnutls_record_log( "REC: Expected Packet[%d] %s(%d) with length: %d\n",
		(int) uint64touint32(&state->connection_state.read_sequence_number), _gnutls_packet2str(type), type, sizeofdata);
	_gnutls_record_log( "REC: Received Packet[%d] %s(%d) with length: %d\n",
		(int) uint64touint32(&state->connection_state.read_sequence_number), _gnutls_packet2str(recv_type), recv_type, length);

	if (length > MAX_RECV_SIZE) {

		_gnutls_record_log( "REC: FATAL ERROR: Received packet with length: %d\n", length);

		_gnutls_session_unresumable( state);
		_gnutls_session_invalidate( state);
		gnutls_assert();
		return GNUTLS_E_UNEXPECTED_PACKET_LENGTH;
	}

	/* check if we have that data into buffer. 
 	 */
	if ( (ret = _gnutls_io_read_buffered( state, &recv_data, header_size+length, recv_type)) != length+header_size) {
		if (ret<0 && gnutls_error_is_fatal(ret)==0) return ret;

		_gnutls_session_unresumable( state);
		_gnutls_session_invalidate( state);
		gnutls_assert();
		return GNUTLS_E_UNEXPECTED_PACKET_LENGTH;		
	}
	
/* ok now we are sure that we can read all the data - so
 * move on !
 */
	_gnutls_io_clear_read_buffer( state);
	ciphertext = &recv_data[header_size];
	
	/* decrypt the data we got
	 */
	tmplen = _gnutls_decrypt( state, ciphertext, length, &tmpdata, recv_type);
	if (tmplen < 0) {
		_gnutls_session_unresumable( state);
		_gnutls_session_invalidate( state);
		gnutls_assert();
		return tmplen;
	}

	/* Check if this is a CHANGE_CIPHER_SPEC
	 */
	if (type == GNUTLS_CHANGE_CIPHER_SPEC && recv_type == GNUTLS_CHANGE_CIPHER_SPEC) {

		_gnutls_record_log( "REC: ChangeCipherSpec Packet was received\n");

		if (tmplen!=sizeofdata) { /* sizeofdata should be 1 */
			gnutls_assert();
			gnutls_free(tmpdata);
			return GNUTLS_E_UNEXPECTED_PACKET_LENGTH;
		}
		memcpy( data, tmpdata, sizeofdata);
		gnutls_free(tmpdata);

		return tmplen;
	}

	_gnutls_record_log( "REC: Decrypted Packet[%d] %s(%d) with length: %d\n",
		(int) uint64touint32(&state->connection_state.read_sequence_number), _gnutls_packet2str(recv_type), recv_type, tmplen);

	/* increase sequence number */
	if (uint64pp( &state->connection_state.read_sequence_number)!=0) {
		_gnutls_session_invalidate( state);
		gnutls_free(tmpdata);
		gnutls_assert();
		return GNUTLS_E_RECORD_LIMIT_REACHED;
	}

	if ( (ret=_gnutls_record_check_type( state, recv_type, type, htype, tmpdata, tmplen)) < 0) {
		gnutls_free( tmpdata);

		if (ret==GNUTLS_E_INT_RET_0) return 0;

		gnutls_assert();
		return ret;
	}
	gnutls_free( tmpdata);

	/* Get Application data from buffer */
	if ((type == GNUTLS_APPLICATION_DATA || type == GNUTLS_HANDSHAKE) && (recv_type == type)) {

		ret = _gnutls_record_buffer_get(type, state, data, sizeofdata);
		if (ret < 0) {
			gnutls_assert();
			return ret;
		}

		/* if the buffer just got empty */
		if (_gnutls_record_buffer_get_size(type, state)==0) {
			if ( (ret2 = _gnutls_io_clear_peeked_data( state)) < 0) {
				gnutls_assert();
				return ret2;
			}
		}

	} else {
		gnutls_assert();
		ret = GNUTLS_E_UNEXPECTED_PACKET; 
		/* we didn't get what we wanted to 
		 */
	}

	return ret;
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
  * If this function returns GNUTLS_E_REHANDSHAKE, then you may
  * ignore this message, send an alert containing NO_RENEGOTIATION, 
  * or perform a handshake again. (only a client may receive this message)
  *
  **/
ssize_t gnutls_read( GNUTLS_STATE state, void *data, size_t sizeofdata) {
	return gnutls_recv_int( state, GNUTLS_APPLICATION_DATA, -1, data, sizeofdata);
}

/**
  * gnutls_record_get_max_size - returns the maximum record size
  * @state: is a &GNUTLS_STATE structure.
  *
  * This function returns the maximum record size in this connection.
  * The maximum record size is negotiated by the client after the
  * first handshake message.
  *
  **/
size_t gnutls_record_get_max_size( GNUTLS_STATE state) {
	return state->security_parameters.max_record_size;
}


/**
  * gnutls_record_set_max_size - sets the maximum record size
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
size_t gnutls_record_set_max_size( GNUTLS_STATE state, size_t size) {
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
