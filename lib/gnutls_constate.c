/*
 *      Copyright (C) 2001 Nikos Mavroyanopoulos
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
#include <gnutls_constate.h>
#include <gnutls_errors.h>
#include <gnutls_kx.h>
#include <gnutls_algorithms.h>
#include <gnutls_num.h>
#include <gnutls_datum.h>

/* This function is to be called after handshake, when master_secret,
 *  client_random and server_random have been initialized. 
 * This function creates the keys and stores them into pending state.
 * (state->cipher_specs)
 */
int _gnutls_set_keys(GNUTLS_STATE state, int hash_size, int IV_size, int key_size)
{
	opaque *key_block;
	char keyexp[] = "key expansion";
	char random[2*TLS_RANDOM_SIZE];
	int pos;
	int block_size;
	
	if (state->cipher_specs.generated_keys!=0) {
		/* keys have already been generated.
		 * reset generated_keys and exit normally.
		 */
		 state->cipher_specs.generated_keys=0;
		 return 0;
	}
	

	block_size = 2 * hash_size + 2 * key_size + 2 * IV_size;

	memcpy(random, state->security_parameters.server_random, TLS_RANDOM_SIZE);
	memcpy(&random[TLS_RANDOM_SIZE], state->security_parameters.client_random, TLS_RANDOM_SIZE);

	if ( state->security_parameters.version == GNUTLS_SSL3) { /* SSL 3 */
		key_block = gnutls_ssl3_generate_random( state->security_parameters.master_secret, TLS_MASTER_SIZE, random, 2*TLS_RANDOM_SIZE,
			block_size);
	} else { /* TLS 1.0 */
		key_block =
		    gnutls_PRF( state->security_parameters.master_secret, TLS_MASTER_SIZE,
			       keyexp, strlen(keyexp), random, 2*TLS_RANDOM_SIZE, 
			       block_size);
	}
	
	if (key_block==NULL) return GNUTLS_E_MEMORY_ERROR;

#ifdef HARD_DEBUG
	_gnutls_log( "KEY BLOCK[%d]: %s\n",block_size, _gnutls_bin2hex(key_block, block_size));
#endif

	pos = 0;
	if (hash_size > 0) {
		if (gnutls_sset_datum( &state->cipher_specs.client_write_mac_secret, &key_block[pos], hash_size) < 0 )
			return GNUTLS_E_MEMORY_ERROR;
		pos+=hash_size;

		if (gnutls_sset_datum( &state->cipher_specs.server_write_mac_secret, &key_block[pos], hash_size) < 0 )
			return GNUTLS_E_MEMORY_ERROR;
		pos+=hash_size;
	}
	
	if (key_size > 0) {
		if (gnutls_sset_datum( &state->cipher_specs.client_write_key, &key_block[pos], key_size) < 0 )
			return GNUTLS_E_MEMORY_ERROR;
		pos+=key_size;

		if (gnutls_sset_datum( &state->cipher_specs.server_write_key, &key_block[pos], key_size) < 0 )
			return GNUTLS_E_MEMORY_ERROR;
		pos+=key_size;
	}
	if (IV_size > 0) {
		if (gnutls_sset_datum( &state->cipher_specs.client_write_IV, &key_block[pos], IV_size) < 0 )
			return GNUTLS_E_MEMORY_ERROR;
		pos+=IV_size;
	
		if (gnutls_sset_datum( &state->cipher_specs.server_write_IV, &key_block[pos], IV_size) < 0 )
			return GNUTLS_E_MEMORY_ERROR;
		pos+=IV_size;
	}
	
	secure_free(key_block);

	state->cipher_specs.generated_keys = 1;

	return 0;
}

int _gnutls_set_read_keys(GNUTLS_STATE state)
{
	int hash_size;
	int IV_size;
	int key_size;
	BulkCipherAlgorithm algo;
	MACAlgorithm mac_algo;
	
	mac_algo = state->security_parameters.read_mac_algorithm;
	algo = state->security_parameters.read_bulk_cipher_algorithm;

	hash_size = _gnutls_mac_get_digest_size( mac_algo);
	IV_size = _gnutls_cipher_get_iv_size( algo);
	key_size = _gnutls_cipher_get_key_size( algo);

	return _gnutls_set_keys( state, hash_size, IV_size, key_size);
}

int _gnutls_set_write_keys(GNUTLS_STATE state)
{
	int hash_size;
	int IV_size;
	int key_size;
	BulkCipherAlgorithm algo;
	MACAlgorithm mac_algo;
	
	mac_algo = state->security_parameters.write_mac_algorithm;
	algo = state->security_parameters.write_bulk_cipher_algorithm;

	hash_size = _gnutls_mac_get_digest_size( mac_algo);
	IV_size = _gnutls_cipher_get_iv_size( algo);
	key_size = _gnutls_cipher_get_key_size( algo);

	return _gnutls_set_keys( state, hash_size, IV_size, key_size);
}

#define CPY_COMMON dst->entity = src->entity; \
	dst->kx_algorithm = src->kx_algorithm; \
	memcpy( &dst->current_cipher_suite, &src->current_cipher_suite, sizeof(GNUTLS_CipherSuite)); \
	memcpy( dst->master_secret, src->master_secret, TLS_MASTER_SIZE); \
	memcpy( dst->client_random, src->client_random, TLS_RANDOM_SIZE); \
	memcpy( dst->server_random, src->server_random, TLS_RANDOM_SIZE); \
	memcpy( dst->session_id, src->session_id, TLS_MAX_SESSION_ID_SIZE); \
	dst->session_id_size = src->session_id_size; \
	dst->timestamp = src->timestamp; \
	dst->max_record_size = src->max_record_size; \
	dst->version = src->version; \
	memcpy( &dst->extensions, &src->extensions, sizeof(TLSExtensions));
	
static void _gnutls_cpy_read_security_parameters( SecurityParameters * dst, SecurityParameters* src) {
	CPY_COMMON;	

	dst->read_bulk_cipher_algorithm = src->read_bulk_cipher_algorithm;
	dst->read_mac_algorithm = src->read_mac_algorithm;
	dst->read_compression_algorithm = src->read_compression_algorithm;
}

static void _gnutls_cpy_write_security_parameters( SecurityParameters * dst, SecurityParameters* src) {
	CPY_COMMON;
		
	dst->write_bulk_cipher_algorithm = src->write_bulk_cipher_algorithm;
	dst->write_mac_algorithm = src->write_mac_algorithm;
	dst->write_compression_algorithm = src->write_compression_algorithm;
}

/* Sets the current connection state to conform with the
 * Security parameters(pending state), and initializes encryption.
 * Actually it initializes and starts encryption ( so it needs
 * secrets and random numbers to have been negotiated)
 * This is to be called after sending the Change Cipher Spec packet.
 */
int _gnutls_connection_state_init(GNUTLS_STATE state)
{
	int ret;

/* Setup the master secret 
 */
	if ( (ret = _gnutls_generate_master(state)) < 0) {
		gnutls_assert();
		return ret;
	}


	return 0;
}


/* Initializes the read connection state
 * (read encrypted data)
 */
int _gnutls_read_connection_state_init(GNUTLS_STATE state) {
int mac_size;
int rc;

	uint64zero(&state->connection_state.read_sequence_number);

/* Update internals from CipherSuite selected.
 * If we are resuming just copy the connection state
 */
 	if (state->gnutls_internals.resumed==RESUME_FALSE) {
		rc =
		    _gnutls_set_read_cipher(state,
			       _gnutls_cipher_suite_get_cipher_algo
			       (state->security_parameters.current_cipher_suite));
		if (rc < 0)
			return rc;
		rc =
		    _gnutls_set_read_mac(state,
			    _gnutls_cipher_suite_get_mac_algo
			    (state->security_parameters.current_cipher_suite));
		if (rc < 0)
			return rc;

		rc =
		    _gnutls_set_kx(state,
			    _gnutls_cipher_suite_get_kx_algo
			    (state->security_parameters.current_cipher_suite));
		if (rc < 0)
			return rc;

		rc =
		    _gnutls_set_read_compression(state,
				    state->gnutls_internals.compression_method);
		if (rc < 0)
			return rc;
	} else { /* RESUME_TRUE */
		_gnutls_cpy_read_security_parameters( &state->security_parameters, &state->gnutls_internals.resumed_security_parameters);
	}


	_gnutls_set_read_keys(state);
	 
#ifdef HANDSHAKE_DEBUG
	_gnutls_log( "Cipher Suite: %s\n",
		_gnutls_cipher_suite_get_name(state->
					      security_parameters.current_cipher_suite));
#endif

	if (_gnutls_compression_is_ok(state->security_parameters.read_compression_algorithm) != 0) {
		gnutls_assert();
		return GNUTLS_E_UNKNOWN_COMPRESSION_ALGORITHM;
	}

	if (_gnutls_mac_is_ok(state->security_parameters.read_mac_algorithm) != 0) {
		gnutls_assert();
		return GNUTLS_E_UNKNOWN_MAC_ALGORITHM;
	}

	/* Free all the previous keys/ states etc.
	 */
	if ( state->connection_state.read_mac_secret.data != NULL)
		gnutls_sfree_datum( &state->connection_state.read_mac_secret);

	if (state->connection_state.read_cipher_state != NULL)
		gnutls_cipher_deinit(state->connection_state.
				     read_cipher_state);


	mac_size =
	    _gnutls_mac_get_digest_size(state->security_parameters.
						read_mac_algorithm);

#ifdef HANDSHAKE_DEBUG
	_gnutls_log( "Handshake: Initializing internal [read] cipher states\n");
#endif

	switch (state->security_parameters.entity) {
	case GNUTLS_SERVER:
		/* initialize cipher state
		 */
		state->connection_state.read_cipher_state =
		    gnutls_cipher_init(state->security_parameters.
				       read_bulk_cipher_algorithm,
				       state->cipher_specs.client_write_key,
				       state->cipher_specs.client_write_IV);
		if (state->connection_state.read_cipher_state ==
		    GNUTLS_CIPHER_FAILED
		    && state->security_parameters.read_bulk_cipher_algorithm !=
		    GNUTLS_CIPHER_NULL) {
			gnutls_assert();
			return GNUTLS_E_UNKNOWN_CIPHER;
		}

		/* copy mac secrets from cipherspecs, to connection
		 * state.
		 */
		if (mac_size > 0) {
			gnutls_sset_datum( &state->connection_state.read_mac_secret,
				state->cipher_specs.client_write_mac_secret.data,
				state->cipher_specs.client_write_mac_secret.size);

		}


		break;

	case GNUTLS_CLIENT:
		state->connection_state.read_cipher_state =
		    gnutls_cipher_init(state->security_parameters.
				       read_bulk_cipher_algorithm,
				       state->cipher_specs.
				       server_write_key,
				       state->cipher_specs.server_write_IV);
				       
		if (state->connection_state.read_cipher_state ==
		    GNUTLS_CIPHER_FAILED
		    && state->security_parameters.read_bulk_cipher_algorithm !=
		    GNUTLS_CIPHER_NULL) {
			gnutls_assert();
			return GNUTLS_E_UNKNOWN_CIPHER;
		}


		/* copy mac secret to connection state
		 */
		if (mac_size > 0) {
			gnutls_sset_datum( &state->connection_state.read_mac_secret,
				state->cipher_specs.server_write_mac_secret.data,
				state->cipher_specs.server_write_mac_secret.size);
		}

		break;

	default:
		gnutls_assert();
		return GNUTLS_E_UNKNOWN_ERROR;
	}

	return 0;
}



/* Initializes the write connection state
 * (write encrypted data)
 */
int _gnutls_write_connection_state_init(GNUTLS_STATE state) {
int mac_size;
int rc;

	uint64zero(&state->connection_state.write_sequence_number);

/* Update internals from CipherSuite selected.
 * If we are resuming just copy the connection state
 */
 	if (state->gnutls_internals.resumed==RESUME_FALSE) {
		rc =
		    _gnutls_set_write_cipher(state,
			       _gnutls_cipher_suite_get_cipher_algo
			       (state->security_parameters.current_cipher_suite));
		if (rc < 0)
			return rc;
		rc =
		    _gnutls_set_write_mac(state,
			    _gnutls_cipher_suite_get_mac_algo
			    (state->security_parameters.current_cipher_suite));
		if (rc < 0)
			return rc;

		rc =
		    _gnutls_set_kx(state,
			    _gnutls_cipher_suite_get_kx_algo
			    (state->security_parameters.current_cipher_suite));
		if (rc < 0)
			return rc;

		rc =
		    _gnutls_set_write_compression(state,
				    state->gnutls_internals.compression_method);
		if (rc < 0)
			return rc;
	} else { /* RESUME_TRUE */
		_gnutls_cpy_write_security_parameters( &state->security_parameters, &state->gnutls_internals.resumed_security_parameters);
	}
	
	_gnutls_set_write_keys(state);

#ifdef HANDSHAKE_DEBUG
	_gnutls_log( "Cipher Suite: %s\n",
		_gnutls_cipher_suite_get_name(state->
					      security_parameters.current_cipher_suite));
#endif

	if (_gnutls_compression_is_ok(state->security_parameters.write_compression_algorithm) != 0) {
		gnutls_assert();
		return GNUTLS_E_UNKNOWN_COMPRESSION_ALGORITHM;
	}

	if (_gnutls_mac_is_ok(state->security_parameters.write_mac_algorithm) != 0) {
		gnutls_assert();
		return GNUTLS_E_UNKNOWN_MAC_ALGORITHM;
	}



	/* Free all the previous keys/ states etc.
	 */
	if (state->connection_state.write_mac_secret.data != NULL)
		gnutls_sfree_datum( &state->connection_state.write_mac_secret);

	if (state->connection_state.write_cipher_state != NULL)
		gnutls_cipher_deinit(state->connection_state.
				     write_cipher_state);

	mac_size =
	    _gnutls_mac_get_digest_size(state->security_parameters.
					write_mac_algorithm);

#ifdef HANDSHAKE_DEBUG
	_gnutls_log( "Handshake: Initializing internal [write] cipher states\n");
#endif

	switch (state->security_parameters.entity) {
	case GNUTLS_SERVER:
		/* initialize cipher state
		 */
		state->connection_state.write_cipher_state =
		    gnutls_cipher_init(state->security_parameters.write_bulk_cipher_algorithm,
				       state->cipher_specs.server_write_key,
				       state->cipher_specs.server_write_IV);

		if (state->connection_state.write_cipher_state == GNUTLS_CIPHER_FAILED
		    && state->security_parameters.write_bulk_cipher_algorithm != GNUTLS_CIPHER_NULL) {
			gnutls_assert();
			return GNUTLS_E_UNKNOWN_CIPHER;
		}

		/* copy mac secrets from cipherspecs, to connection
		 * state.
		 */
		if (mac_size > 0) {
			gnutls_sset_datum( &state->connection_state.write_mac_secret,
				state->cipher_specs.server_write_mac_secret.data,
				state->cipher_specs.server_write_mac_secret.size);

		}


		break;

	case GNUTLS_CLIENT:
		state->connection_state.write_cipher_state =
		    gnutls_cipher_init(state->security_parameters.
				       write_bulk_cipher_algorithm,
				       state->cipher_specs.client_write_key,
				       state->cipher_specs.client_write_IV);

		if (state->connection_state.write_cipher_state ==
		    GNUTLS_CIPHER_FAILED
		    && state->security_parameters.write_bulk_cipher_algorithm !=
		    GNUTLS_CIPHER_NULL) {
			gnutls_assert();
			return GNUTLS_E_UNKNOWN_CIPHER;
		}

		/* copy mac secret to connection state
		 */
		if (mac_size > 0) {
			gnutls_sset_datum( &state->connection_state.write_mac_secret,
				state->cipher_specs.client_write_mac_secret.data,
				state->cipher_specs.client_write_mac_secret.size);
		}

		break;

	default:
		gnutls_assert();
		return GNUTLS_E_UNKNOWN_ERROR;
	}

	return 0;
}

/* Sets the specified cipher into the pending state 
 */
int _gnutls_set_read_cipher(GNUTLS_STATE state, BulkCipherAlgorithm algo)
{

	if (_gnutls_cipher_is_ok(algo) == 0) {
		if (_gnutls_cipher_priority(state, algo) < 0) {
			gnutls_assert();
			return GNUTLS_E_UNWANTED_ALGORITHM;
		}

		state->security_parameters.read_bulk_cipher_algorithm = algo;

	} else {
		gnutls_assert();
		return GNUTLS_E_UNKNOWN_CIPHER;
	}

	return 0;

}

int _gnutls_set_write_cipher(GNUTLS_STATE state, BulkCipherAlgorithm algo)
{

	if (_gnutls_cipher_is_ok(algo) == 0) {
		if (_gnutls_cipher_priority(state, algo) < 0) {
			gnutls_assert();
			return GNUTLS_E_UNWANTED_ALGORITHM;
		}

		state->security_parameters.write_bulk_cipher_algorithm = algo;

	} else {
		gnutls_assert();
		return GNUTLS_E_UNKNOWN_CIPHER;
	}

	return 0;

}


/* Sets the specified algorithm into pending compression state 
 */
int _gnutls_set_read_compression(GNUTLS_STATE state, CompressionMethod algo)
{

	if (_gnutls_compression_is_ok(algo)==0) {
		state->security_parameters.read_compression_algorithm = algo;
	} else {
		gnutls_assert();
		return GNUTLS_E_UNKNOWN_COMPRESSION_ALGORITHM;
	}
	return 0;

}

int _gnutls_set_write_compression(GNUTLS_STATE state, CompressionMethod algo)
{

	if (_gnutls_compression_is_ok(algo)==0) {
		state->security_parameters.write_compression_algorithm = algo;
	} else {
		gnutls_assert();
		return GNUTLS_E_UNKNOWN_COMPRESSION_ALGORITHM;
	}
	return 0;

}

/* Sets the specified kx algorithm into pending state 
 */
int _gnutls_set_kx(GNUTLS_STATE state, KXAlgorithm algo)
{

	if (_gnutls_kx_is_ok(algo) == 0) {
		state->security_parameters.kx_algorithm = algo;
	} else {
		gnutls_assert();
		return GNUTLS_E_UNKNOWN_KX_ALGORITHM;
	}
	if (_gnutls_kx_priority(state, algo) < 0) {
		gnutls_assert();
		/* we shouldn't get here */
		return GNUTLS_E_UNWANTED_ALGORITHM;
	}

	return 0;

}

/* Sets the specified mac algorithm into pending state */
int _gnutls_set_read_mac(GNUTLS_STATE state, MACAlgorithm algo)
{

	if (_gnutls_mac_is_ok(algo) == 0) {
		state->security_parameters.read_mac_algorithm = algo;
	} else {
		gnutls_assert();
		return GNUTLS_E_UNKNOWN_MAC_ALGORITHM;
	}
	if (_gnutls_mac_priority(state, algo) < 0) {
		gnutls_assert();
		return GNUTLS_E_UNWANTED_ALGORITHM;
	}


	return 0;

}

int _gnutls_set_write_mac(GNUTLS_STATE state, MACAlgorithm algo)
{

	if (_gnutls_mac_is_ok(algo) == 0) {
		state->security_parameters.write_mac_algorithm = algo;
	} else {
		gnutls_assert();
		return GNUTLS_E_UNKNOWN_MAC_ALGORITHM;
	}
	if (_gnutls_mac_priority(state, algo) < 0) {
		gnutls_assert();
		return GNUTLS_E_UNWANTED_ALGORITHM;
	}


	return 0;

}

