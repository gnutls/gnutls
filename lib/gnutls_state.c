/*
 *      Copyright (C) 2002 Nikos Mavroyanopoulos
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

#include <gnutls_int.h>
#include <gnutls_errors.h>
#include <gnutls_auth_int.h>
#include <gnutls_priority.h>
#include <gnutls_num.h>
#include "gnutls_datum.h"
#include "gnutls_db.h"
#include <gnutls_record.h>
#include <gnutls_handshake.h>
#include <gnutls_dh.h>
#include <gnutls_buffers.h>
#include <gnutls_state.h>
#include <auth_cert.h>
#include <auth_anon.h>

#define CHECK_AUTH(auth, ret) if (gnutls_auth_get_type(state) != auth) { \
	gnutls_assert(); \
	return ret; \
	}

void _gnutls_state_cert_type_set( GNUTLS_STATE state, CertificateType ct) {
	state->security_parameters.cert_type = ct;
}

/**
  * gnutls_cipher_get - Returns the currently used cipher.
  * @state: is a &GNUTLS_STATE structure.
  *
  * Returns the currently used cipher.
  **/
GNUTLS_BulkCipherAlgorithm gnutls_cipher_get( GNUTLS_STATE state) {
	return state->security_parameters.read_bulk_cipher_algorithm;
}

/**
  * gnutls_cert_type_get - Returns the currently used certificate type.
  * @state: is a &GNUTLS_STATE structure.
  *
  * Returns the currently used certificate type. The certificate type
  * is by default X.509, unless it is negotiated as a TLS extension.
  *
  **/
GNUTLS_CertificateType gnutls_cert_type_get( GNUTLS_STATE state) {
	return state->security_parameters.cert_type;
}

/**
  * gnutls_kx_get - Returns the key exchange algorithm.
  * @state: is a &GNUTLS_STATE structure.
  *
  * Returns the key exchange algorithm used in the last handshake.
  **/
GNUTLS_KXAlgorithm gnutls_kx_get( GNUTLS_STATE state) {
	return state->security_parameters.kx_algorithm;
}

/**
  * gnutls_mac_get - Returns the currently used mac algorithm.
  * @state: is a &GNUTLS_STATE structure.
  *
  * Returns the currently used mac algorithm.
  **/
GNUTLS_MACAlgorithm gnutls_mac_get( GNUTLS_STATE state) {
	return state->security_parameters.read_mac_algorithm;
}

/**
  * gnutls_compression_get - Returns the currently used compression algorithm.
  * @state: is a &GNUTLS_STATE structure.
  *
  * Returns the currently used compression method.
  **/
GNUTLS_CompressionMethod gnutls_compression_get( GNUTLS_STATE state) {
	return state->security_parameters.read_compression_algorithm;
}

int _gnutls_state_cert_type_supported( GNUTLS_STATE state, CertificateType cert_type) {
int i;

	if (state->gnutls_internals.cert_type_priority.algorithms==0 && cert_type ==
		DEFAULT_CERT_TYPE) return 0;

	for (i=0;i<state->gnutls_internals.cert_type_priority.algorithms;i++) {
		if (state->gnutls_internals.cert_type_priority.algorithm_priority[i]
			== cert_type) {
				return 0; /* ok */	
		}
	}

	return GNUTLS_E_UNSUPPORTED_CERTIFICATE_TYPE;
}

/* This function will clear all the variables in gnutls_internals
 * structure within the state, which depend on the current handshake.
 * This is used to allow further handshakes.
 */
void _gnutls_handshake_internal_state_clear( GNUTLS_STATE state) {
	state->gnutls_internals.extensions_sent_size = 0;

	/* by default no selected certificate */
	state->gnutls_internals.selected_cert_index = -1;
	state->gnutls_internals.proposed_record_size = DEFAULT_MAX_RECORD_SIZE;
	state->gnutls_internals.adv_version_major = 0;
	state->gnutls_internals.adv_version_minor = 0;
	state->gnutls_internals.v2_hello = 0;
	memset( &state->gnutls_internals.handshake_header_buffer, 0, 
		sizeof(HANDSHAKE_HEADER_BUFFER));
	state->gnutls_internals.adv_version_minor = 0;
	state->gnutls_internals.adv_version_minor = 0;

	state->gnutls_internals.resumable = RESUME_TRUE;

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
int gnutls_init(GNUTLS_STATE * state, GNUTLS_ConnectionEnd con_end)
{
int default_protocol_list[] = { GNUTLS_TLS1, 0 };

	*state = gnutls_calloc(1, sizeof(struct GNUTLS_STATE_INT));
	if (*state==NULL) return GNUTLS_E_MEMORY_ERROR;
	
	(*state)->security_parameters.entity = con_end;

	/* the default certificate type for TLS */
	(*state)->security_parameters.cert_type = DEFAULT_CERT_TYPE;

/* Set the defaults for initial handshake */
	(*state)->security_parameters.read_bulk_cipher_algorithm = 
	(*state)->security_parameters.write_bulk_cipher_algorithm = GNUTLS_CIPHER_NULL;

	(*state)->security_parameters.read_mac_algorithm = 
	(*state)->security_parameters.write_mac_algorithm = GNUTLS_MAC_NULL;

	(*state)->security_parameters.read_compression_algorithm = GNUTLS_COMP_NULL;
	(*state)->security_parameters.write_compression_algorithm = GNUTLS_COMP_NULL;

	(*state)->gnutls_internals.enable_private = 0;

	gnutls_protocol_set_priority( *state, default_protocol_list); /* default */
	
	(*state)->gnutls_key = gnutls_calloc(1, sizeof(struct GNUTLS_KEY_INT));
	if ( (*state)->gnutls_key == NULL) {
		gnutls_free( *state);
		return GNUTLS_E_MEMORY_ERROR;
	}

	(*state)->gnutls_internals.expire_time = DEFAULT_EXPIRE_TIME; /* one hour default */

	gnutls_dh_set_prime_bits( (*state), MIN_BITS);

	gnutls_transport_set_lowat((*state), DEFAULT_LOWAT); /* the default for tcp */

	gnutls_handshake_set_max_packet_length( (*state), MAX_HANDSHAKE_PACKET_SIZE);

	/* Allocate a minimum size for recv_data 
	 * This is allocated in order to avoid small messages, makeing
	 * the receive procedure slow.
	 */
	(*state)->gnutls_internals.record_recv_buffer.data = gnutls_malloc(INITIAL_RECV_BUFFER_SIZE);
	
	/* set the default maximum record size for TLS
	 */
	(*state)->security_parameters.max_record_size = DEFAULT_MAX_RECORD_SIZE;

	
	/* everything else not initialized here is initialized
	 * as NULL or 0. This is why calloc is used.
	 */

	_gnutls_handshake_internal_state_clear( *state);

	return 0;
}

/**
  * gnutls_deinit - This function clears all buffers associated with the &state
  * @state: is a &GNUTLS_STATE structure.
  *
  * This function clears all buffers associated with the &state.
  **/
void gnutls_deinit(GNUTLS_STATE state)
{

	if (state==NULL) return;

	/* remove auth info firstly */
	_gnutls_free_auth_info(state );

	_gnutls_handshake_io_buffer_clear( state);

	gnutls_sfree_datum(&state->connection_state.read_mac_secret);
	gnutls_sfree_datum(&state->connection_state.write_mac_secret);

	_gnutls_free(state->gnutls_internals.application_data_buffer.data);
	_gnutls_free(state->gnutls_internals.handshake_data_buffer.data);
	_gnutls_free(state->gnutls_internals.handshake_hash_buffer.data);
	_gnutls_free(state->gnutls_internals.record_recv_buffer.data);
	_gnutls_free(state->gnutls_internals.record_send_buffer.data);

	gnutls_clear_creds( state);

	if (state->connection_state.read_cipher_state != NULL)
		_gnutls_cipher_deinit(state->connection_state.read_cipher_state);
	if (state->connection_state.write_cipher_state != NULL)
		_gnutls_cipher_deinit(state->connection_state.write_cipher_state);

	if (state->connection_state.read_compression_state != NULL)
		_gnutls_comp_deinit(state->connection_state.read_compression_state, 1);
	if (state->connection_state.write_compression_state != NULL)
		_gnutls_comp_deinit(state->connection_state.write_compression_state, 0);

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

	_gnutls_free(state->gnutls_internals.db_name);

	memset( state, 0, sizeof(struct GNUTLS_STATE_INT));
	gnutls_free(state);

	return;
}

int _gnutls_dh_get_prime_bits( GNUTLS_STATE state) {
	return state->gnutls_internals.dh_prime_bits;
}

int _gnutls_dh_set_peer_public_bits( GNUTLS_STATE state, int bits) {
	switch( gnutls_auth_get_type( state)) {
		case GNUTLS_CRD_ANON: {
			ANON_SERVER_AUTH_INFO info;
			info = _gnutls_get_auth_info(state);
			if (info == NULL)
				return GNUTLS_E_UNKNOWN_ERROR;
			info->dh_peer_public_bits = bits;
			break;
		}
		case GNUTLS_CRD_CERTIFICATE: {
			CERTIFICATE_AUTH_INFO info;

			info = _gnutls_get_auth_info(state);
			if (info == NULL)
				return GNUTLS_E_UNKNOWN_ERROR;

			info->dh_peer_public_bits = bits;
			break;
		}
		default:
			gnutls_assert();
			return GNUTLS_E_UNKNOWN_ERROR;
	}

	return 0;
}

int _gnutls_dh_set_secret_bits( GNUTLS_STATE state, int bits) {
	switch( gnutls_auth_get_type( state)) {
		case GNUTLS_CRD_ANON: {
			ANON_SERVER_AUTH_INFO info;
			info = _gnutls_get_auth_info(state);
			if (info == NULL)
				return GNUTLS_E_UNKNOWN_ERROR;
			info->dh_secret_bits = bits;
			break;
		}
		case GNUTLS_CRD_CERTIFICATE: {
			CERTIFICATE_AUTH_INFO info;

			info = _gnutls_get_auth_info(state);
			if (info == NULL)
				return GNUTLS_E_UNKNOWN_ERROR;

			info->dh_secret_bits = bits;
			break;
		default:
			gnutls_assert();
			return GNUTLS_E_UNKNOWN_ERROR;
		}
	}

	return 0;
}

int _gnutls_dh_set_prime_bits( GNUTLS_STATE state, int bits) {
	switch( gnutls_auth_get_type( state)) {
		case GNUTLS_CRD_ANON: {
			ANON_SERVER_AUTH_INFO info;
			info = _gnutls_get_auth_info(state);
			if (info == NULL)
				return GNUTLS_E_UNKNOWN_ERROR;
			info->dh_prime_bits = bits;
			break;
		}
		case GNUTLS_CRD_CERTIFICATE: {
			CERTIFICATE_AUTH_INFO info;

			info = _gnutls_get_auth_info(state);
			if (info == NULL)
				return GNUTLS_E_UNKNOWN_ERROR;

			info->dh_prime_bits = bits;
			break;
		}
		default:
			gnutls_assert();
			return GNUTLS_E_UNKNOWN_ERROR;
	}

	
	return 0;
}

/**
  * gnutls_openpgp_send_key - This function will order gnutls to send the openpgp fingerprint instead of the key
  * @state: is a pointer to a &GNUTLS_STATE structure.
  * @status: is one of OPENPGP_KEY, or OPENPGP_KEY_FINGERPRINT
  *
  * This function will order gnutls to send the key fingerprint instead
  * of the key in the initial handshake procedure. This should be used
  * with care and only when there is indication or knowledge that the 
  * server can obtain the client's key.
  *
  **/
void gnutls_openpgp_send_key(GNUTLS_STATE state, GNUTLS_OpenPGPKeyStatus status) {
	state->gnutls_internals.pgp_fingerprint = status;
}

int _gnutls_openpgp_send_fingerprint(GNUTLS_STATE state) {
	return state->gnutls_internals.pgp_fingerprint;
}

/*-
  * _gnutls_record_set_default_version - Used to set the default version for the first record packet
  * @state: is a &GNUTLS_STATE structure.
  * @version: is a tls version
  *
  * This function sets the default version that we will use in the first
  * record packet (client hello). This function is only useful to people
  * that know TLS internals and want to debug other implementations.
  *
  -*/
void _gnutls_record_set_default_version(GNUTLS_STATE state, GNUTLS_Version version)
{
	state->gnutls_internals.default_record_version = version;
}

/**
  * gnutls_record_set_cbc_protection - Used to disable the CBC protection
  * @state: is a &GNUTLS_STATE structure.
  * @prot: is an integer (0 or 1)
  *
  * A newly discovered attack against the record protocol requires some
  * counter-measures to be taken. GnuTLS will not enable them by default
  * thus, sends an empty record packet, before each actual record packet,
  * in order to assure that the IV is not known to potential attackers.
  *
  * This function will enable or disable the chosen plaintext protection
  * in the TLS record protocol (used with ciphers in CBC mode).
  * if prot == 0 then protection is disabled (default), otherwise it
  * is enabled.
  *
  * The protection used will slightly decrease performance, and add 
  * 20 or more bytes per record packet.
  *
  **/
void gnutls_record_set_cbc_protection(GNUTLS_STATE state, int prot)
{
	state->gnutls_internals.cbc_protection_hack = prot;
}

/**
  * gnutls_handshake_set_private_extensions - Used to enable the private cipher suites
  * @state: is a &GNUTLS_STATE structure.
  * @allow: is an integer (0 or 1)
  *
  * This function will enable or disable the use of private
  * cipher suites (the ones that start with 0xFF). By default 
  * or if 'allow' is 0 then these cipher suites will not be
  * advertized nor used.
  *
  * Unless this function is called with the option to allow (1), then
  * no compression algorithms, like ZLIB, and encryption algorithms,
  * like TWOFISH, will be available. This is because these algorithms
  * are not yet defined in any RFC or even internet draft.
  *
  **/
void gnutls_handshake_set_private_extensions(GNUTLS_STATE state, int allow)
{
	state->gnutls_internals.enable_private = allow;
}

/**
  * gnutls_handshake_set_rsa_pms_check - Used to disable the RSA PMS check
  * @state: is a &GNUTLS_STATE structure.
  * @prot: is an integer (0 or 1)
  *
  * The TLS 1.0 handshake protocol includes a check in the in the RSA
  * encrypted data (only in the case of RSA key exchange), which allows
  * to detect version roll back attacks. 
  *
  * However it seems that some broken TLS clients exist which do not
  * use this check properly. The only solution is to disable this
  * check completely.
  *
  * if check == 0 then the check is enabled (default), otherwise it
  * is disabled.
  *
  * The protection used will slightly decrease performance, and add 
  * 20 or more bytes per record packet.
  *
  **/
void gnutls_handshake_set_rsa_pms_check(GNUTLS_STATE state, int check)
{
	state->gnutls_internals.rsa_pms_check = check;
}

inline
static void _gnutls_cal_PRF_A( MACAlgorithm algorithm, const void *secret, int secret_size, const void *seed, int seed_size, void* result)
{
	GNUTLS_MAC_HANDLE td1;

	td1 = _gnutls_hmac_init(algorithm, secret, secret_size);
	_gnutls_hmac(td1, seed, seed_size);
	_gnutls_hmac_deinit(td1, result);
	
	return;
}

#define MAX_SEED_SIZE 200

/* Produces "total_bytes" bytes using the hash algorithm specified.
 * (used in the PRF function)
 */
static int _gnutls_P_hash( MACAlgorithm algorithm, const opaque * secret, int secret_size, const opaque * seed, int seed_size, int total_bytes, opaque* ret)
{

	GNUTLS_MAC_HANDLE td2;
	int i = 0, times, how, blocksize, A_size;
	opaque final[20], Atmp[MAX_SEED_SIZE];

	if (seed_size > MAX_SEED_SIZE || total_bytes<=0) {
		gnutls_assert();
		return GNUTLS_E_INTERNAL_ERROR;
	}
	
	blocksize = _gnutls_hmac_get_algo_len(algorithm);
	do {
		i += blocksize;
	} while (i < total_bytes);

	/* calculate A(0) */

	memcpy( Atmp, seed, seed_size);
	A_size = seed_size;

	times = i / blocksize;
	for (i = 0; i < times; i++) {
		td2 = _gnutls_hmac_init(algorithm, secret, secret_size);

		/* here we calculate A(i+1) */
		_gnutls_cal_PRF_A( algorithm, secret, secret_size, Atmp, A_size, Atmp);

		A_size = blocksize;

		_gnutls_hmac(td2, Atmp, A_size);
		_gnutls_hmac(td2, seed, seed_size);
		_gnutls_hmac_deinit(td2, final);

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
 * by the system. It should be faster. - only if one / and % are much faster
 * than the whole xor operation.
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
		((unsigned char*)_o1)[i] ^= ((unsigned char*)_o2)[i];
	}
	return ;
}



#define MAX_PRF_BYTES 200

/* The PRF function expands a given secret 
 * needed by the TLS specification. ret must have a least total_bytes
 * available.
 */
int _gnutls_PRF( const opaque * secret, int secret_size, const uint8 * label, int label_size, opaque * seed, int seed_size, int total_bytes, void* ret)
{
	int l_s, s_seed_size;
	const char *s1, *s2;
	opaque s_seed[MAX_SEED_SIZE];
	opaque o1[MAX_PRF_BYTES], o2[MAX_PRF_BYTES];
	int result;

	if (total_bytes > MAX_PRF_BYTES) {
		gnutls_assert();
		return GNUTLS_E_INTERNAL_ERROR;
	}
	/* label+seed = s_seed */
	s_seed_size = seed_size + label_size;

	if (s_seed_size > MAX_SEED_SIZE) {
		gnutls_assert();
		return GNUTLS_E_INTERNAL_ERROR;
	}

	memcpy(s_seed, label, label_size);
	memcpy(&s_seed[label_size], seed, seed_size);

	l_s = secret_size / 2;
	s1 = &secret[0];
	s2 = &secret[l_s];

	if (secret_size % 2 != 0) {
		l_s++;
	}

	result = _gnutls_P_hash( GNUTLS_MAC_MD5, s1, l_s, s_seed, s_seed_size, total_bytes, o1);
	if (result<0) {
		gnutls_assert();
		return result;
	}

	result = _gnutls_P_hash( GNUTLS_MAC_SHA, s2, l_s, s_seed, s_seed_size, total_bytes, o2);
	if (result<0) {
		gnutls_assert();
		return result;
	}

	_gnutls_xor(o1, o2, total_bytes);

	memcpy( ret, o1, total_bytes);

	return 0; /* ok */

}

/**
  * gnutls_session_is_resumed - Used to check whether this session is a resumed one
  * @state: is a &GNUTLS_STATE structure.
  *
  * This function will return non zero if this session is a resumed one,
  * or a zero if this is a new session.
  *
  **/
int gnutls_session_is_resumed(GNUTLS_STATE state)
{
	if (state->security_parameters.entity==GNUTLS_CLIENT) {
		if (memcmp( state->security_parameters.session_id,
			state->gnutls_internals.resumed_security_parameters.session_id,
			state->security_parameters.session_id_size)==0)
			return 1;
	} else {
		if (state->gnutls_internals.resumed==RESUME_TRUE)
			return 1;
	}

	return 0;
}

/**
  * gnutls_state_get_ptr - Used to get the user pointer from the state structure
  * @state: is a &GNUTLS_STATE structure.
  *
  * This function will return the user given pointer from the state structure.
  * This is the pointer set with gnutls_state_set_ptr().
  *
  **/
void* gnutls_state_get_ptr(GNUTLS_STATE state)
{
	return state->gnutls_internals.user_ptr;
}

/**
  * gnutls_state_set_ptr - Used to set the user pointer to the state structure
  * @state: is a &GNUTLS_STATE structure.
  * @ptr: is the user pointer
  *
  * This function will set (assosiate) the user given pointer to the state structure.
  * This is pointer can be accessed with gnutls_state_get_ptr().
  *
  **/
void gnutls_state_set_ptr(GNUTLS_STATE state, void* ptr)
{
	state->gnutls_internals.user_ptr = ptr;
}
