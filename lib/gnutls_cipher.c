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
#include "gnutls_compress.h"
#include "gnutls_cipher.h"
#include "gnutls_algorithms.h"

int _gnutls_make_mul(int x, int y)
{
	int ret = 0;

	do {
		ret += y;
	} while (ret < x);

	return ret;

}

/* Sets the specified cipher into the pending state */
int _gnutls_set_cipher(GNUTLS_STATE state, BulkCipherAlgorithm algo)
{

	if (_gnutls_cipher_is_ok(algo) == 0) {
		state->security_parameters.bulk_cipher_algorithm = algo;
		if (_gnutls_cipher_is_block(algo) == 1) {
			state->security_parameters.cipher_type =
			    CIPHER_BLOCK;
		} else {
			state->security_parameters.cipher_type =
			    CIPHER_STREAM;
		}
		state->security_parameters.is_exportable =
		    EXPORTABLE_FALSE;
		state->security_parameters.key_material_length =
		    state->security_parameters.key_size =
		    _gnutls_cipher_get_key_size(algo);
		state->security_parameters.IV_size =
		    _gnutls_cipher_get_iv_size(algo);
	} else {
		return GNUTLS_E_UNKNOWN_CIPHER;
	}

	return 0;

}

/* Sets the specified algorithm into pending compression state */
int _gnutls_set_compression(GNUTLS_STATE state, CompressionMethod algo)
{

	switch (algo) {
	case COMPRESSION_NULL:
		break;

	default:
		return GNUTLS_E_UNKNOWN_COMPRESSION_ALGORITHM;
	}
	return 0;

}

/* Sets the specified mac algorithm into pending state */
int _gnutls_set_mac(GNUTLS_STATE state, MACAlgorithm algo)
{

	if (_gnutls_hash_is_ok(algo) == 0) {
		state->security_parameters.mac_algorithm = algo;
	} else {
		return GNUTLS_E_UNKNOWN_MAC_ALGORITHM;
	}
	
	state->security_parameters.hash_size = _gnutls_hash_get_digest_size(algo);
	
	return 0;

}

/* Sets the current connection state to conform with the
 * Security parameters(pending state), and initializes encryption.
 */
int _gnutls_connection_state_init(GNUTLS_STATE state)
{
	int rc, mac_size;

/* Update internals from CipherSuite selected */

	rc =
	    _gnutls_set_cipher(state,
			       _gnutls_cipher_suite_get_cipher_algo(state->
								    gnutls_internals.
								    current_cipher_suite));
	if (rc < 0)
		return rc;
	rc =
	    _gnutls_set_mac(state,
			    _gnutls_cipher_suite_get_mac_algo(state->
							      gnutls_internals.
							      current_cipher_suite));
	if (rc < 0)
		return rc;

/* Setup the keys since we have the master secret 
 */
	_gnutls_set_keys(state);


/* FIXME: Compression is not implemented (no compression algorithms used)
 */

#ifdef DEBUG
	fprintf(stderr, "Cipher Suite: %s\n",
		_gnutls_cipher_suite_get_name(state->gnutls_internals.
					      current_cipher_suite));
	fprintf(stderr, "Compression: %s\n", "null");
#endif

	gnutls_free(state->connection_state.write_mac_secret);
	gnutls_free(state->connection_state.read_mac_secret);

	if (state->connection_state.read_cipher_state != NULL)
		gcry_cipher_close(state->
				  connection_state.read_cipher_state);

	if (state->connection_state.write_cipher_state != NULL)
		gcry_cipher_close(state->
				  connection_state.write_cipher_state);

	gnutls_free(state->connection_state.read_compression_state);
	gnutls_free(state->connection_state.write_compression_state);

	switch (state->security_parameters.compression_algorithm) {
	case COMPRESSION_NULL:
		state->connection_state.read_compression_state = NULL;
		state->connection_state.write_compression_state = NULL;
		break;
	default:
		return GNUTLS_E_UNKNOWN_COMPRESSION_ALGORITHM;
	}

	if (_gnutls_hash_is_ok(state->security_parameters.mac_algorithm)==0) {

		mac_size = _gnutls_hash_get_digest_size(state->security_parameters.mac_algorithm);
		state->connection_state.read_mac_secret = NULL;
		state->connection_state.write_mac_secret = NULL;

		if ( mac_size > 0) {
			state->connection_state.read_mac_secret = gnutls_malloc(mac_size);
			state->connection_state.write_mac_secret = gnutls_malloc(mac_size);
		}
	} else {
		return GNUTLS_E_UNKNOWN_MAC_ALGORITHM;
	}

	switch (state->security_parameters.bulk_cipher_algorithm) {
	case GNUTLS_NULL:
		state->connection_state.read_cipher_state = NULL;
		state->connection_state.write_cipher_state = NULL;
		break;
	case GNUTLS_3DES:
		state->connection_state.read_cipher_state =
		    gcry_cipher_open(GCRY_CIPHER_3DES,
				     GCRY_CIPHER_MODE_CBC, 0);
		state->connection_state.write_cipher_state =
		    gcry_cipher_open(GCRY_CIPHER_3DES,
				     GCRY_CIPHER_MODE_CBC, 0);
		break;
	default:
		return GNUTLS_E_UNKNOWN_CIPHER;
	}


	switch (state->security_parameters.entity) {
	case GNUTLS_SERVER:
		if (state->connection_state.write_cipher_state != NULL) {
			rc =
			    gcry_cipher_setkey(state->
					       connection_state.write_cipher_state,
					       state->
					       cipher_specs.server_write_key,
					       state->
					       security_parameters.key_size);
			gcry_cipher_setiv(state->
					  connection_state.write_cipher_state,
					  state->
					  cipher_specs.server_write_IV,
					  state->
					  security_parameters.IV_size);

		}
		if (state->connection_state.mac_secret_size > 0) {
			memmove(state->connection_state.read_mac_secret,
				state->cipher_specs.
				client_write_mac_secret,
				state->connection_state.mac_secret_size);
			memmove(state->connection_state.write_mac_secret,
				state->
				cipher_specs.server_write_mac_secret,
				state->connection_state.mac_secret_size);
		}

		if (state->connection_state.read_cipher_state != NULL) {
			rc =
			    gcry_cipher_setkey(state->
					       connection_state.read_cipher_state,
					       state->
					       cipher_specs.client_write_key,
					       state->
					       security_parameters.key_size);
			gcry_cipher_setiv(state->
					  connection_state.read_cipher_state,
					  state->
					  cipher_specs.client_write_IV,
					  state->
					  security_parameters.IV_size);
		}
		break;

	case GNUTLS_CLIENT:
		if (state->connection_state.read_cipher_state != NULL) {
			rc =
			    gcry_cipher_setkey(state->
					       connection_state.read_cipher_state,
					       state->
					       cipher_specs.server_write_key,
					       state->
					       security_parameters.key_size);
			gcry_cipher_setiv(state->
					  connection_state.read_cipher_state,
					  state->
					  cipher_specs.server_write_IV,
					  state->
					  security_parameters.IV_size);

		}
		if (state->connection_state.mac_secret_size > 0) {
			memmove(state->connection_state.read_mac_secret,
				state->cipher_specs.
				server_write_mac_secret,
				state->connection_state.mac_secret_size);
			memmove(state->connection_state.write_mac_secret,
				state->cipher_specs.
				client_write_mac_secret,
				state->connection_state.mac_secret_size);
		}

		if (state->connection_state.write_cipher_state != NULL) {
			gcry_cipher_setiv(state->
					  connection_state.write_cipher_state,
					  state->
					  cipher_specs.client_write_IV,
					  state->
					  security_parameters.IV_size);
			rc =
			    gcry_cipher_setkey(state->
					       connection_state.write_cipher_state,
					       state->
					       cipher_specs.client_write_key,
					       state->
					       security_parameters.key_size);
		}
		break;

	default:
		return GNUTLS_E_UNKNOWN_ERROR;
	}

	return 0;
}

int _gnutls_TLSCompressed2TLSCiphertext(GNUTLS_STATE state,
					GNUTLSCiphertext **
					cipher,
					GNUTLSCompressed * compressed)
{
	GNUTLSCiphertext *ciphertext;
	uint8 *padding, *content, *MAC;
	uint16 c_length;
	uint8 *data;
	uint8 pad;
	uint8 *rand;
	uint64 seq_num;
	int length;
	MHASH td;

	content = gnutls_malloc(compressed->length);
	memmove(content, compressed->fragment, compressed->length);

/* not needed since in mhash the buffer is automaticaly allocated */
/*	if (state->connection_state.mac_secret_size>0) {
		MAC = gnutls_malloc(state->connection_state.mac_secret_size);
	}*/

	*cipher = gnutls_malloc(sizeof(GNUTLSCiphertext));
	ciphertext = *cipher;

	switch (state->security_parameters.mac_algorithm) {
	case GNUTLS_MAC_NULL:
		td = MHASH_FAILED;
		break;
	case GNUTLS_MAC_SHA:
		td =
		    mhash_hmac_init(MHASH_SHA1,
				    state->
				    connection_state.write_mac_secret,
				    state->
				    connection_state.mac_secret_size,
				    mhash_get_hash_pblock(MHASH_SHA1));
		break;
	case GNUTLS_MAC_MD5:
		td =
		    mhash_hmac_init(MHASH_MD5,
				    state->
				    connection_state.write_mac_secret,
				    state->
				    connection_state.mac_secret_size,
				    mhash_get_hash_pblock(MHASH_MD5));
		break;
	default:
		gnutls_free(*cipher);
		gnutls_free(content);
		return GNUTLS_E_UNKNOWN_MAC_ALGORITHM;
	}

#ifdef WORDS_BIGENDIAN
	seq_num = state->connection_state.write_sequence_number;
	c_length = compressed->length;
#else
	c_length = byteswap16(compressed->length);
	seq_num =
	    byteswap64(state->connection_state.write_sequence_number);
#endif
	if (td != MHASH_FAILED) {
		mhash(td, &seq_num, 8);
		mhash(td, &compressed->type, 1);
		mhash(td, &compressed->version.major, 1);
		mhash(td, &compressed->version.minor, 1);
		mhash(td, &c_length, 2);
		mhash(td, compressed->fragment, compressed->length);
		MAC = mhash_hmac_end(td);
	}
	switch (state->security_parameters.cipher_type) {
	case CIPHER_STREAM:
		switch (state->security_parameters.bulk_cipher_algorithm) {
		case GNUTLS_NULL:
			length =
			    compressed->length +
			    state->connection_state.mac_secret_size;

			data = gnutls_malloc(length);
			memmove(data, content, compressed->length);
			memmove(&data[compressed->length], MAC,
				state->connection_state.mac_secret_size);
			ciphertext->fragment = data;
			ciphertext->length = length;
			ciphertext->type = compressed->type;
			ciphertext->version.major =
			    compressed->version.major;
			ciphertext->version.minor =
			    compressed->version.minor;
			break;
		default:
			gnutls_free(*cipher);
			gnutls_free(content);
			return GNUTLS_E_UNKNOWN_CIPHER;

		}
		break;
	case CIPHER_BLOCK:
		switch (state->security_parameters.bulk_cipher_algorithm) {
		case GNUTLS_3DES:

			rand = gcry_random_bytes(1, GCRY_STRONG_RANDOM);
			rand[0] = rand[0] % (255-_gnutls_cipher_get_block_size(GNUTLS_3DES));
			
			length =
			    compressed->length +
			    state->connection_state.mac_secret_size +
			    rand[0] +
			    1;
			length =
			    _gnutls_make_mul(length,
				     _gnutls_cipher_get_block_size
				     (GNUTLS_3DES));
			pad =
			    length - compressed->length -
			    state->connection_state.mac_secret_size - 1;
			
			/* set pad bytes pad */
			padding = gnutls_malloc(pad);
			memset(padding, pad, pad);

			data = gnutls_malloc(length);
			memmove(data, content, compressed->length);
			memmove(&data[compressed->length], MAC,
				state->connection_state.mac_secret_size);
			memmove(&data
				[state->connection_state.mac_secret_size +
				 compressed->length], padding, pad);
			memmove(&data
				[pad +
				 state->connection_state.mac_secret_size +
				 compressed->length], &pad, 1);

			gnutls_free(padding);

			gcry_cipher_encrypt(state->
					    connection_state.write_cipher_state,
					    data, length, data, length);

			ciphertext->fragment = data;
			ciphertext->length = length;
			ciphertext->type = compressed->type;
			ciphertext->version.major =
			    compressed->version.major;
			ciphertext->version.minor =
			    compressed->version.minor;

			gcry_free(rand);
			break;
		default:
			gnutls_free(*cipher);
			gnutls_free(content);
			return GNUTLS_E_UNKNOWN_CIPHER;
		}
		break;
	default:
		gnutls_free(*cipher);
		gnutls_free(content);
		return GNUTLS_E_UNKNOWN_CIPHER_TYPE;
	}

//      gnutls_free( MAC);
	if (td != MHASH_FAILED)
		free(MAC);
	gnutls_free(content);

	return 0;
}

int _gnutls_TLSCiphertext2TLSCompressed(GNUTLS_STATE state,
					GNUTLSCompressed **
					compress,
					GNUTLSCiphertext * ciphertext)
{
	GNUTLSCompressed *compressed;
	uint8 *content, *MAC;
	uint16 c_length;
	uint8 *data;
	uint8 pad;
	uint64 seq_num;
	uint16 length;
	MHASH td;


	content = gnutls_malloc(ciphertext->length);
	memmove(content, ciphertext->fragment, ciphertext->length);

/*	if (state->connection_state.mac_secret_size>0) {
		MAC = gnutls_malloc(state->connection_state.mac_secret_size);
	}*/

	*compress = gnutls_malloc(sizeof(GNUTLSCompressed));
	compressed = *compress;


	switch (state->security_parameters.mac_algorithm) {
	case GNUTLS_MAC_NULL:
		td = MHASH_FAILED;
		break;
	case GNUTLS_MAC_SHA:
		td =
		    mhash_hmac_init(MHASH_SHA1,
				    state->
				    connection_state.read_mac_secret,
				    state->
				    connection_state.mac_secret_size,
				    mhash_get_hash_pblock(MHASH_SHA1));
		break;
	case GNUTLS_MAC_MD5:
		td =
		    mhash_hmac_init(MHASH_MD5,
				    state->
				    connection_state.read_mac_secret,
				    state->
				    connection_state.mac_secret_size,
				    mhash_get_hash_pblock(MHASH_MD5));
		break;
	default:
		gnutls_free(*compress);
		gnutls_free(content);
		return GNUTLS_E_UNKNOWN_MAC_ALGORITHM;
	}


	switch (state->security_parameters.cipher_type) {
	case CIPHER_STREAM:
		switch (state->security_parameters.bulk_cipher_algorithm) {
		case GNUTLS_NULL:
			length =
			    ciphertext->length -
			    state->connection_state.mac_secret_size;
			data = gnutls_malloc(length);
			memmove(data, content, length);

			compressed->fragment = data;
			compressed->length = length;
			compressed->type = ciphertext->type;
			compressed->version.major =
			    ciphertext->version.major;
			compressed->version.minor =
			    ciphertext->version.minor;
			break;
		default:
			gnutls_free(*compress);
			gnutls_free(content);
			return GNUTLS_E_UNKNOWN_CIPHER;

		}
		break;
	case CIPHER_BLOCK:
		switch (state->security_parameters.bulk_cipher_algorithm) {
		case GNUTLS_3DES:
			gcry_cipher_decrypt(state->
					    connection_state.read_cipher_state,
					    content, ciphertext->length,
					    content, ciphertext->length);

			pad = content[ciphertext->length - 1];	/* pad */
			length =
			    ciphertext->length -
			    state->connection_state.mac_secret_size - pad -
			    1;

			if (pad > ciphertext->length - state->connection_state.mac_secret_size)
				return GNUTLS_E_RECEIVED_BAD_MESSAGE;
			data = gnutls_malloc(length);
			memmove(data, content, length);

			compressed->fragment = data;
			compressed->length = length;
			compressed->type = ciphertext->type;
			compressed->version.major =
			    ciphertext->version.major;
			compressed->version.minor =
			    ciphertext->version.minor;

			break;
		default:
			gnutls_free(*compress);
			gnutls_free(content);
			return GNUTLS_E_UNKNOWN_CIPHER;
		}
		break;
	default:
		gnutls_free(*compress);
		gnutls_free(content);
		return GNUTLS_E_UNKNOWN_CIPHER_TYPE;
	}

#ifdef WORDS_BIGENDIAN
	seq_num = state->connection_state.read_sequence_number;
	c_length = compressed->length;
#else
	seq_num = byteswap64(state->connection_state.read_sequence_number);
	c_length = byteswap16((uint16) compressed->length);
#endif


	if (td != MHASH_FAILED) {
		mhash(td, &seq_num, 8);
		mhash(td, &compressed->type, 1);
		mhash(td, &compressed->version.major, 1);
		mhash(td, &compressed->version.minor, 1);
		mhash(td, &c_length, 2);
		mhash(td, data, compressed->length);
		MAC = mhash_hmac_end(td);
	}
	/* HMAC was not the same. */
	if (memcmp
	    (MAC, &content[compressed->length],
	     state->connection_state.mac_secret_size) != 0) {
#ifdef DEBUG
		fprintf(stderr, "MAC FAILED\n");
#endif
		return GNUTLS_E_MAC_FAILED;
	}


	if (td != MHASH_FAILED)
		mhash_free(MAC);
	gnutls_free(content);

	return 0;
}




int _gnutls_freeTLSCiphertext(GNUTLSCiphertext * ciphertext)
{
	if (ciphertext == NULL)
		return 0;

	gnutls_free(ciphertext->fragment);
	gnutls_free(ciphertext);

	return 0;
}
