/*
 *      Copyright (C) 2002 Nikos Mavroyanopoulos
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

	(*state)->gnutls_internals.resumable = RESUME_TRUE;

	gnutls_protocol_set_priority( *state, default_protocol_list); /* default */
	
	(*state)->gnutls_key = gnutls_calloc(1, sizeof(struct GNUTLS_KEY_INT));
	if ( (*state)->gnutls_key == NULL) {
		gnutls_free( *state);
		return GNUTLS_E_MEMORY_ERROR;
	}

	(*state)->gnutls_internals.resumed = RESUME_FALSE;

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
	(*state)->gnutls_internals.proposed_record_size = DEFAULT_MAX_RECORD_SIZE;

	/* by default no selected certificate */
	(*state)->gnutls_internals.selected_cert_index = -1;
	
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
void gnutls_deinit(GNUTLS_STATE state)
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
