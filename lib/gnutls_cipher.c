/*
 * Copyright (C) 2000 Nikos Mavroyanopoulos
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
#include "gnutls_compress.h"
#include "gnutls_cipher.h"
#include "gnutls_algorithms.h"
#include "gnutls_hash_int.h"
#include "gnutls_cipher_int.h"
#include "debug.h"
#include "gnutls_random.h"
#include "gnutls_num.h"
#include "gnutls_datum.h"

int _gnutls_encrypt(GNUTLS_STATE state, const char *data, size_t data_size,
		    uint8 ** ciphertext, ContentType type)
{
	gnutls_datum plain = { (char*)data, data_size };
	gnutls_datum comp, ciph;
	int err;

	if (data_size == 0)
		return 0;

	err = _gnutls_plaintext2TLSCompressed(state, &comp, plain);
	if (err < 0) {
		gnutls_assert();
		return err;
	}

	err = _gnutls_compressed2TLSCiphertext(state, &ciph, comp, type);
	if (err < 0) {
		gnutls_assert();
		return err;
	}

	gnutls_free_datum(&comp);

	*ciphertext = ciph.data;

	return ciph.size;
}

int _gnutls_decrypt(GNUTLS_STATE state, char *ciphertext,
		    size_t ciphertext_size, uint8 ** data,
		    ContentType type)
{
	gnutls_datum gtxt;
	gnutls_datum gcomp;
	gnutls_datum gcipher;
	int ret;

	if (ciphertext_size == 0)
		return 0;

	gcipher.size = ciphertext_size;
	gcipher.data = ciphertext;

	ret = _gnutls_ciphertext2TLSCompressed(state, &gcomp, gcipher, type);
	if (ret < 0) {
		return ret;
	}

	ret = _gnutls_TLSCompressed2plaintext(state, &gtxt, gcomp);
	if (ret < 0) {
		return ret;
	}

	gnutls_free_datum(&gcomp);

	ret = gtxt.size;

	*data = gtxt.data;
	
	return ret;
}


/* Sets the specified cipher into the pending state */
int _gnutls_set_cipher(GNUTLS_STATE state, BulkCipherAlgorithm algo)
{

	if (_gnutls_cipher_is_ok(algo) == 0) {
		if (_gnutls_cipher_priority(state, algo) < 0) {
			gnutls_assert();
			return GNUTLS_E_UNWANTED_ALGORITHM;
		}

		state->security_parameters.bulk_cipher_algorithm = algo;

		state->security_parameters.key_material_length =
		    state->security_parameters.key_size =
		    _gnutls_cipher_get_key_size(algo);
		state->security_parameters.IV_size =
		    _gnutls_cipher_get_iv_size(algo);
	} else {
		gnutls_assert();
		return GNUTLS_E_UNKNOWN_CIPHER;
	}

	return 0;

}

/* Sets the specified algorithm into pending compression state */
int _gnutls_set_compression(GNUTLS_STATE state, CompressionMethod algo)
{

	if (_gnutls_compression_is_ok(algo)==0) {
		state->security_parameters.compression_algorithm = algo;
	} else {
		gnutls_assert();
		return GNUTLS_E_UNKNOWN_COMPRESSION_ALGORITHM;
	}
	return 0;

}

/* Sets the specified kx algorithm into pending state */
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
int _gnutls_set_mac(GNUTLS_STATE state, MACAlgorithm algo)
{

	if (_gnutls_mac_is_ok(algo) == 0) {
		state->security_parameters.mac_algorithm = algo;
		state->security_parameters.hash_size =
		    _gnutls_mac_get_digest_size(algo);
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

/* Sets the current connection state to conform with the
 * Security parameters(pending state), and initializes encryption.
 * Actually it initializes and starts encryption ( so it needs
 * secrets and random numbers to have been negotiated)
 * This is to be called after sending the Change Cipher Spec packet.
 */
int _gnutls_connection_state_init(GNUTLS_STATE state)
{
	int rc, mac_size;

	uint64zero(&state->connection_state.write_sequence_number);
	uint64zero(&state->connection_state.read_sequence_number);

/* Update internals from CipherSuite selected.
 * If we are resuming just copy the connection state
 */
 	if (state->gnutls_internals.resumed==RESUME_FALSE) {
		rc =
		    _gnutls_set_cipher(state,
			       _gnutls_cipher_suite_get_cipher_algo
			       (state->gnutls_internals.current_cipher_suite));
		if (rc < 0)
			return rc;
		rc =
		    _gnutls_set_mac(state,
			    _gnutls_cipher_suite_get_mac_algo
			    (state->gnutls_internals.current_cipher_suite));
		if (rc < 0)
			return rc;

		rc =
		    _gnutls_set_kx(state,
			    _gnutls_cipher_suite_get_kx_algo
			    (state->gnutls_internals.current_cipher_suite));
		if (rc < 0)
			return rc;

		rc =
		    _gnutls_set_compression(state,
				    state->gnutls_internals.compression_method);
		if (rc < 0)
			return rc;
	} else {
		 memcpy( &state->security_parameters, &state->gnutls_internals.resumed_security_parameters, sizeof(SecurityParameters));

		/* clear the resumed security parameters */
		 memset( &state->gnutls_internals.resumed_security_parameters, 0, sizeof(SecurityParameters));
#ifdef HARD_DEBUG
		 fprintf(stderr, "Master Secret: %s\n", _gnutls_bin2hex(state->security_parameters.master_secret, 48));
#endif
	}
/* Setup the keys since we have the master secret 
 */
	_gnutls_set_keys(state);


#ifdef DEBUG
	fprintf(stderr, "Cipher Suite: %s\n",
		_gnutls_cipher_suite_get_name(state->
					      gnutls_internals.current_cipher_suite));
#endif

	if (state->connection_state.write_mac_secret!=NULL)
		gnutls_free(state->connection_state.write_mac_secret);
	if (state->connection_state.read_mac_secret!=NULL)
		gnutls_free(state->connection_state.read_mac_secret);

	if (state->connection_state.read_cipher_state != NULL)
		gnutls_cipher_deinit(state->connection_state.
				     read_cipher_state);

	if (state->connection_state.write_cipher_state != NULL)
		gnutls_cipher_deinit(state->connection_state.
				     write_cipher_state);

	if (state->connection_state.read_compression_state!=NULL)
		gnutls_free(state->connection_state.read_compression_state);
	if (state->connection_state.write_compression_state!=NULL)
		gnutls_free(state->connection_state.write_compression_state);

	if (_gnutls_compression_is_ok(state->security_parameters.compression_algorithm) == 0) {
		state->connection_state.read_compression_state = NULL;
		state->connection_state.write_compression_state = NULL;
	} else {
		gnutls_assert();
		return GNUTLS_E_UNKNOWN_COMPRESSION_ALGORITHM;
	}

	if (_gnutls_mac_is_ok(state->security_parameters.mac_algorithm) == 0) {

		mac_size =
		    _gnutls_mac_get_digest_size(state->security_parameters.
						mac_algorithm);
		state->connection_state.read_mac_secret = NULL;
		state->connection_state.write_mac_secret = NULL;
		state->connection_state.mac_secret_size =
		    state->security_parameters.hash_size;

		if (mac_size > 0) {
			state->connection_state.read_mac_secret =
			    gnutls_malloc(mac_size);
			if (state->connection_state.read_mac_secret==NULL) return GNUTLS_E_MEMORY_ERROR;
			state->connection_state.write_mac_secret =
			    gnutls_malloc(mac_size);
			if (state->connection_state.write_mac_secret==NULL) return GNUTLS_E_MEMORY_ERROR;
		}
	} else {
		gnutls_assert();
		return GNUTLS_E_UNKNOWN_MAC_ALGORITHM;
	}

	switch (state->security_parameters.entity) {
	case GNUTLS_SERVER:
		state->connection_state.write_cipher_state =
		    gnutls_cipher_init(state->security_parameters.
				       bulk_cipher_algorithm,
				       state->cipher_specs.
				       server_write_key,
				       state->security_parameters.key_size,
				       state->cipher_specs.server_write_IV,
				       state->security_parameters.IV_size);
		if (state->connection_state.write_cipher_state ==
		    GNUTLS_CIPHER_FAILED
		    && state->security_parameters.bulk_cipher_algorithm !=
		    GNUTLS_NULL_CIPHER) {
			gnutls_assert();
			return GNUTLS_E_UNKNOWN_CIPHER;
		}

		if (state->connection_state.mac_secret_size > 0) {
			memmove(state->connection_state.read_mac_secret,
				state->
				cipher_specs.client_write_mac_secret,
				state->connection_state.mac_secret_size);
			memmove(state->connection_state.write_mac_secret,
				state->cipher_specs.
				server_write_mac_secret,
				state->connection_state.mac_secret_size);
		}

		state->connection_state.read_cipher_state =
		    gnutls_cipher_init(state->security_parameters.
				       bulk_cipher_algorithm,
				       state->cipher_specs.
				       client_write_key,
				       state->security_parameters.key_size,
				       state->cipher_specs.client_write_IV,
				       state->security_parameters.IV_size);
		if (state->connection_state.read_cipher_state ==
		    GNUTLS_CIPHER_FAILED
		    && state->security_parameters.bulk_cipher_algorithm !=
		    GNUTLS_NULL_CIPHER) {
			gnutls_assert();
			return GNUTLS_E_UNKNOWN_CIPHER;
		}

		break;

	case GNUTLS_CLIENT:
		state->connection_state.read_cipher_state =
		    gnutls_cipher_init(state->security_parameters.
				       bulk_cipher_algorithm,
				       state->cipher_specs.
				       server_write_key,
				       state->security_parameters.key_size,
				       state->cipher_specs.server_write_IV,
				       state->security_parameters.IV_size);
		if (state->connection_state.read_cipher_state ==
		    GNUTLS_CIPHER_FAILED
		    && state->security_parameters.bulk_cipher_algorithm !=
		    GNUTLS_NULL_CIPHER) {
			gnutls_assert();
			return GNUTLS_E_UNKNOWN_CIPHER;
		}

		if (state->connection_state.mac_secret_size > 0) {
			memmove(state->connection_state.read_mac_secret,
				state->
				cipher_specs.server_write_mac_secret,
				state->connection_state.mac_secret_size);
			memmove(state->connection_state.write_mac_secret,
				state->
				cipher_specs.client_write_mac_secret,
				state->connection_state.mac_secret_size);
		}

		state->connection_state.write_cipher_state =
		    gnutls_cipher_init(state->security_parameters.
				       bulk_cipher_algorithm,
				       state->cipher_specs.
				       client_write_key,
				       state->security_parameters.key_size,
				       state->cipher_specs.client_write_IV,
				       state->security_parameters.IV_size);
		if (state->connection_state.write_cipher_state ==
		    GNUTLS_CIPHER_FAILED
		    && state->security_parameters.bulk_cipher_algorithm !=
		    GNUTLS_NULL_CIPHER) {
			gnutls_assert();
			return GNUTLS_E_UNKNOWN_CIPHER;
		}
		break;

	default:
		gnutls_assert();
		return GNUTLS_E_UNKNOWN_ERROR;
	}

	return 0;
}

/* This is the actual encryption 
 * (and also keeps some space for headers in the encrypted data)
 */
int _gnutls_compressed2TLSCiphertext(GNUTLS_STATE state,
					gnutls_datum*
					cipher,
					gnutls_datum compressed, ContentType _type)
{
	uint8 *MAC = NULL;
	uint16 c_length;
	uint8 *data;
	uint8 pad;
	uint8 rand;
	uint64 seq_num;
	int length;
	GNUTLS_MAC_HANDLE td;
	uint8 type = _type;
	uint8 major, minor;
	int blocksize =
	    _gnutls_cipher_get_block_size(state->security_parameters.
					  bulk_cipher_algorithm);

	minor = _gnutls_version_get_minor(state->connection_state.version);
	major = _gnutls_version_get_major(state->connection_state.version);

	if (_gnutls_version_ssl3(state->connection_state.version) == 0) { /* SSL 3.0 */
		td =
		    gnutls_mac_init_ssl3(state->security_parameters.
					  mac_algorithm,
					  state->connection_state.
					  write_mac_secret,
					  state->connection_state.
					  mac_secret_size);
	} else {
		td =
		    gnutls_hmac_init(state->security_parameters.
				     mac_algorithm,
				     state->connection_state.
				     write_mac_secret,
				     state->connection_state.
				     mac_secret_size);
	}
	if (td == GNUTLS_MAC_FAILED
	    && state->security_parameters.mac_algorithm != GNUTLS_NULL_MAC) {
		gnutls_assert();
		return GNUTLS_E_UNKNOWN_MAC_ALGORITHM;
	}

	c_length = CONVuint16(compressed.size);
	seq_num =
	    CONVuint64(&state->connection_state.write_sequence_number);

	if (td != GNUTLS_MAC_FAILED) {	/* actually when the algorithm in not the NULL one */
		gnutls_hmac(td, UINT64DATA(seq_num), 8);
		
		gnutls_hmac(td, &type, 1);
		if (_gnutls_version_ssl3(state->connection_state.version) != 0) { /* TLS 1.0 only */
			gnutls_hmac(td, &major, 1);
			gnutls_hmac(td, &minor, 1);
		}
		gnutls_hmac(td, &c_length, 2);
		gnutls_hmac(td, compressed.data, compressed.size);
		if (_gnutls_version_ssl3(state->connection_state.version) == 0) { /* SSL 3.0 */
			MAC = gnutls_mac_deinit_ssl3(td);
		} else {
			MAC = gnutls_hmac_deinit(td);
		}
	}
	switch (_gnutls_cipher_is_block(state->security_parameters.bulk_cipher_algorithm)) {
	case CIPHER_STREAM:
		length =
		    compressed.size +
		    state->security_parameters.hash_size;

		data = gnutls_malloc(length);
		if (data==NULL) {
			gnutls_assert();
			return GNUTLS_E_MEMORY_ERROR;
		}
		memmove(data, compressed.data, compressed.size);
		memmove(&data[compressed.size], MAC,
			state->security_parameters.hash_size);

		gnutls_cipher_encrypt(state->connection_state.
				      write_cipher_state, data, length);
		cipher->data = data;
		cipher->size = length;

		break;
	case CIPHER_BLOCK:
		if (_gnutls_get_random(&rand, 1, GNUTLS_WEAK_RANDOM) < 0) {
			gnutls_assert();
			return GNUTLS_E_MEMORY_ERROR;
		}

		/* make rand a multiple of blocksize */
		if (_gnutls_version_ssl3(state->connection_state.version) == 0) {
			rand = 0;
		} else {
			rand = (rand / blocksize) * blocksize;
			/* added to avoid the case of pad calculated 0
			 * seen below for pad calculation.
			 */
			if (rand > blocksize) rand-=blocksize;
		}

		length =
		    compressed.size +
		    state->security_parameters.hash_size;

		pad = (uint8) (blocksize - (length % blocksize)) + rand;

		length += pad;
		data = gnutls_malloc(length);
		if (data==NULL) {
			gnutls_assert();
			return GNUTLS_E_MEMORY_ERROR;
		}
		memset(&data[length - pad], pad - 1, pad);
		memmove(data, compressed.data, compressed.size);
		memmove(&data[compressed.size], MAC,
			state->security_parameters.hash_size);

		gnutls_cipher_encrypt(state->connection_state.
				      write_cipher_state, data, length);

		cipher->data = data;
		cipher->size = length;

		break;
	default:
		gnutls_assert();
		return GNUTLS_E_UNKNOWN_CIPHER_TYPE;
	}

	if (td != GNUTLS_MAC_FAILED)
		gnutls_free(MAC);

	return 0;
}

int _gnutls_ciphertext2TLSCompressed(GNUTLS_STATE state,
					gnutls_datum *
					compress,
					gnutls_datum ciphertext, uint8 type)
{
	uint8 *MAC = NULL;
	uint16 c_length;
	uint8 *data;
	uint8 pad;
	uint64 seq_num;
	uint16 length;
	GNUTLS_MAC_HANDLE td;
	int blocksize;
	uint8 major, minor;

	minor = _gnutls_version_get_minor(state->connection_state.version);
	major = _gnutls_version_get_major(state->connection_state.version);

	blocksize = _gnutls_cipher_get_block_size(state->security_parameters.
					  bulk_cipher_algorithm);

	if (_gnutls_version_ssl3(state->connection_state.version) == 0) {
		td =
		    gnutls_mac_init_ssl3(state->security_parameters.
					  mac_algorithm,
					  state->connection_state.
					  read_mac_secret,
					  state->connection_state.
					  mac_secret_size);
	} else {
		td =
		    gnutls_hmac_init(state->security_parameters.
				     mac_algorithm,
				     state->connection_state.
				     read_mac_secret,
				     state->connection_state.
				     mac_secret_size);
	}
	if (td == GNUTLS_MAC_FAILED
	    && state->security_parameters.mac_algorithm != GNUTLS_NULL_MAC) {
		gnutls_assert();
		return GNUTLS_E_UNKNOWN_MAC_ALGORITHM;
	}

	switch (_gnutls_cipher_is_block(state->security_parameters.bulk_cipher_algorithm)) {
	case CIPHER_STREAM:
		length =
		    ciphertext.size -
		    state->security_parameters.hash_size;
		data = gnutls_malloc(length);
		if (data==NULL) {
			gnutls_assert();
			return GNUTLS_E_MEMORY_ERROR;
		}

		memmove(data, ciphertext.data, length);

		compress->data = data;
		compress->size = length;
		break;
	case CIPHER_BLOCK:
		if ((ciphertext.size < blocksize)
		    || (ciphertext.size % blocksize != 0)) {
			gnutls_assert();
			return GNUTLS_E_DECRYPTION_FAILED;
		}
		gnutls_cipher_decrypt(state->connection_state.
				      read_cipher_state, ciphertext.data,
				      ciphertext.size);

		pad = ciphertext.data[ciphertext.size - 1] + 1;	/* pad */
		length =
		    ciphertext.size -
		    state->security_parameters.hash_size - pad;

		if (pad >
		    ciphertext.size -
		    state->security_parameters.hash_size) {
			gnutls_assert();
			return GNUTLS_E_RECEIVED_BAD_MESSAGE;
		}
		data = gnutls_malloc(length);
		if (data==NULL) {
			gnutls_assert();
			return GNUTLS_E_MEMORY_ERROR;
		}

		memmove(data, ciphertext.data, length);
		compress->data = data;
		compress->size = length;
		break;
	default:
		gnutls_assert();
		return GNUTLS_E_UNKNOWN_CIPHER_TYPE;
	}

	c_length = CONVuint16((uint16) compress->size);
	seq_num = CONVuint64( &state->connection_state.read_sequence_number);

	if (td != GNUTLS_MAC_FAILED) {
		gnutls_hmac(td, UINT64DATA(seq_num), 8);
		
		gnutls_hmac(td, &type, 1);
		if (_gnutls_version_ssl3(state->connection_state.version) != 0) { /* TLS 1.0 only */
			gnutls_hmac(td, &major, 1);
			gnutls_hmac(td, &minor, 1);
		}
		gnutls_hmac(td, &c_length, 2);
		gnutls_hmac(td, data, compress->size);
		if (_gnutls_version_ssl3(state->connection_state.version) == 0) { /* SSL 3.0 */
			MAC = gnutls_mac_deinit_ssl3(td);
		} else {
			MAC = gnutls_hmac_deinit(td);
		}
	}
	/* HMAC was not the same. */
	if (memcmp
	    (MAC, &ciphertext.data[compress->size],
	     state->security_parameters.hash_size) != 0) {
		gnutls_assert();
		return GNUTLS_E_MAC_FAILED;
	}


	if (td != GNUTLS_MAC_FAILED)
		gnutls_free(MAC);

	return 0;
}

