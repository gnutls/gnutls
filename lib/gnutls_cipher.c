/*
 *  Copyright (C) 2000,2001,2002,2003 Nikos Mavroyanopoulos
 *
 *  This file is part of GNUTLS.
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

/* Some high level functions to be used in the record encryption are
 * included here.
 */

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
#include "gnutls_kx.h"
#include "gnutls_record.h"
#include "gnutls_constate.h"

inline static int
is_write_comp_null( gnutls_session session) {
	if (session->security_parameters.write_compression_algorithm == GNUTLS_COMP_NULL)
		return 0;
		
	return 1;
}

inline static int
is_read_comp_null( gnutls_session session) {
	if (session->security_parameters.read_compression_algorithm == GNUTLS_COMP_NULL)
		return 0;
		
	return 1;
}


/* returns ciphertext which contains the headers too. This also
 * calculates the size in the header field.
 * 
 * If random pad != 0 then the random pad data will be appended.
 */
int _gnutls_encrypt(gnutls_session session, const char* headers, size_t headers_size,
		const char *data, size_t data_size,
		opaque * ciphertext, size_t ciphertext_size, ContentType type, int random_pad)
{
	const gnutls_datum plain = { (opaque*) data, data_size };
	gnutls_datum comp;
	int ret;
	int free_comp = 1;

	if (plain.size == 0 || is_write_comp_null( session)==0) { 
		comp = plain;
		free_comp = 0;
	} else {
		/* Here comp is allocated and must be 
		 * freed.
		 */
		ret = _gnutls_m_plaintext2compressed(session, &comp, plain);
		if (ret < 0) {
			gnutls_assert();
			return ret;
		}
	}

	ret = _gnutls_compressed2ciphertext(session, &ciphertext[headers_size], 
		ciphertext_size - headers_size, comp, type, random_pad);

	if (free_comp)
		_gnutls_free_datum(&comp);

	if (ret < 0) {
		gnutls_assert();
		return ret;
	}


	/* copy the headers */
	memcpy( ciphertext, headers, headers_size);
	_gnutls_write_uint16( ret, &ciphertext[3]);

	return ret+headers_size;
}


int _gnutls_decrypt(gnutls_session session, char *ciphertext,
		    size_t ciphertext_size, uint8 * data, size_t data_size,
		    ContentType type)
{
	gnutls_datum gtxt;
	gnutls_datum gcipher;
	int ret;

	if (ciphertext_size == 0)
		return 0;

	gcipher.size = ciphertext_size;
	gcipher.data = ciphertext;

	ret = _gnutls_ciphertext2compressed(session, data, data_size, gcipher, type);
	if (ret < 0) {
		return ret;
	}

	if (ret==0 || is_read_comp_null( session)==0) {
		/* ret == ret */

	} else {
		gnutls_datum gcomp;

		/* compression has this malloc overhead.
		 */

		gcomp.data = data;
		gcomp.size = ret;
		ret = _gnutls_m_compressed2plaintext(session, &gtxt, gcomp);
		if (ret < 0) {
			return ret;
		}
		
		if (gtxt.size > data_size) {
			gnutls_assert();
			_gnutls_free_datum( &gtxt);
			return GNUTLS_E_MEMORY_ERROR;
		}
		
		memcpy( data, gtxt.data, gtxt.size);
		ret = gtxt.size;

		_gnutls_free_datum( &gtxt);
	}
	
	return ret;
}

inline
static GNUTLS_MAC_HANDLE mac_init( gnutls_mac_algorithm mac, opaque* secret, int secret_size, int ver) {
GNUTLS_MAC_HANDLE td;

	if ( ver == GNUTLS_SSL3) { /* SSL 3.0 */
		td =
		    _gnutls_mac_init_ssl3( mac, secret,
		    		secret_size);
	} else { /* TLS 1 */
		td =
		    _gnutls_hmac_init( mac, secret, secret_size);
	}

	return td;
}

inline
static void mac_deinit( GNUTLS_MAC_HANDLE td, opaque* res, int ver) {
	if ( ver == GNUTLS_SSL3) { /* SSL 3.0 */
		_gnutls_mac_deinit_ssl3(td, res);
	} else {
		_gnutls_hmac_deinit(td, res);
	}
}

inline
static int calc_enc_length( gnutls_session session, int data_size, int hash_size, uint8* pad, int random_pad, 
	CipherType block_algo, uint16 blocksize) 
{
uint8 rand;
int length;

	*pad = 0;
	
	switch ( block_algo) {
	case CIPHER_STREAM:
		length =
		    data_size + hash_size;

		break;
	case CIPHER_BLOCK:
		if (_gnutls_get_random(&rand, 1, GNUTLS_WEAK_RANDOM) < 0) {
			gnutls_assert();
			return GNUTLS_E_MEMORY_ERROR;
		}

		/* make rand a multiple of blocksize */
		if ( session->security_parameters.version == GNUTLS_SSL3 ||
			random_pad==0) {
			rand = 0;
		} else {
			rand = (rand / blocksize) * blocksize;
			/* added to avoid the case of pad calculated 0
			 * seen below for pad calculation.
			 */
			if (rand > blocksize) rand-=blocksize;
		}

		length =
		    data_size +
		    hash_size;

		*pad = (uint8) (blocksize - (length % blocksize)) + rand;

		length += *pad;

		break;
	default:
		gnutls_assert();
		return GNUTLS_E_INTERNAL_ERROR;
	}

	return length;
}

/* This is the actual encryption 
 * Encrypts the given compressed datum, and puts the result to cipher_data,
 * which has cipher_size size.
 * return the actual encrypted data length.
 */
int _gnutls_compressed2ciphertext(gnutls_session session,
					opaque*	cipher_data, int cipher_size,
					gnutls_datum compressed, ContentType _type, 
					int random_pad)
{
	uint8 MAC[MAX_HASH_SIZE];
	uint16 c_length;
	uint8 pad;
	uint64 seq_num;
	int length,ret;
	GNUTLS_MAC_HANDLE td;
	uint8 type = _type;
	uint8 major, minor;
	int hash_size = _gnutls_mac_get_digest_size(session->security_parameters.write_mac_algorithm);
	gnutls_protocol_version ver;
	int blocksize =
	    _gnutls_cipher_get_block_size(session->security_parameters.
					  write_bulk_cipher_algorithm);
	CipherType block_algo = _gnutls_cipher_is_block(session->security_parameters.write_bulk_cipher_algorithm);


	ver = gnutls_protocol_get_version( session);
	minor = _gnutls_version_get_minor( ver);
	major = _gnutls_version_get_major( ver);


	/* Initialize MAC */
	td = mac_init(session->security_parameters.write_mac_algorithm,
		  session->connection_state.write_mac_secret.data,
		  session->connection_state.write_mac_secret.size, ver);

	if (td == GNUTLS_MAC_FAILED
	    && session->security_parameters.write_mac_algorithm != GNUTLS_MAC_NULL) {
		gnutls_assert();
		return GNUTLS_E_INTERNAL_ERROR;
	}

	c_length = _gnutls_conv_uint16(compressed.size);
	seq_num =
	    _gnutls_conv_uint64(&session->connection_state.write_sequence_number);

	if (td != GNUTLS_MAC_FAILED) {	/* actually when the algorithm in not the NULL one */
		_gnutls_hmac(td, UINT64DATA(seq_num), 8);
		
		_gnutls_hmac(td, &type, 1);
		if ( ver != GNUTLS_SSL3) { /* TLS 1.0 only */
			_gnutls_hmac(td, &major, 1);
			_gnutls_hmac(td, &minor, 1);
		}
		_gnutls_hmac(td, &c_length, 2);
		_gnutls_hmac(td, compressed.data, compressed.size);
		mac_deinit( td, MAC, ver);
	}


	/* Calculate the encrypted length (padding etc.)
	 */
	length = calc_enc_length( session, compressed.size, hash_size, &pad, random_pad, block_algo,
		blocksize);
	if (length < 0) {
		gnutls_assert();
		return length;
	}

	/* copy the encrypted data to cipher_data.
	 */
	if (cipher_size < length) {
		gnutls_assert();
		return GNUTLS_E_MEMORY_ERROR;
	}

	memcpy(cipher_data, compressed.data, compressed.size);
	if (hash_size > 0)
		memcpy(&cipher_data[compressed.size], MAC, hash_size);
	if (block_algo==CIPHER_BLOCK && pad > 0)
		memset(&cipher_data[ length - pad], pad - 1, pad);


	/* Actual encryption (inplace).
	 */
	if ( (ret = _gnutls_cipher_encrypt(session->connection_state.
			      write_cipher_state, cipher_data, 
			      length)) < 0) {
		return ret;
	}

	return length;
}

/* Deciphers the ciphertext packet, and puts the result to compress_data, of compress_size.
 * Returns the actual compressed packet size.
 */
int _gnutls_ciphertext2compressed(gnutls_session session,
					opaque* compress_data, int compress_size,
					gnutls_datum ciphertext, uint8 type)
{
	uint8 MAC[MAX_HASH_SIZE];
	uint16 c_length;
	uint8 pad;
	uint64 seq_num;
	uint16 length;
	GNUTLS_MAC_HANDLE td;
	uint16 blocksize;
	int ret, i, pad_failed = 0;
	uint8 major, minor;
	gnutls_protocol_version ver;
	int hash_size = _gnutls_mac_get_digest_size(session->security_parameters.read_mac_algorithm);

	ver = gnutls_protocol_get_version( session);
	minor = _gnutls_version_get_minor(ver);
	major = _gnutls_version_get_major(ver);

	blocksize = _gnutls_cipher_get_block_size(session->security_parameters.
					  read_bulk_cipher_algorithm);

	/* initialize MAC 
	 */
	td = mac_init( session->security_parameters.read_mac_algorithm,
	  session->connection_state.read_mac_secret.data,
	  session->connection_state.read_mac_secret.size, ver); 
	
	if (td == GNUTLS_MAC_FAILED
	    && session->security_parameters.read_mac_algorithm != GNUTLS_MAC_NULL) {
		gnutls_assert();
		return GNUTLS_E_INTERNAL_ERROR;
	}


	/* actual decryption (inplace)
	 */
	switch (_gnutls_cipher_is_block(session->security_parameters.read_bulk_cipher_algorithm)) {
	case CIPHER_STREAM:
		if ( (ret = _gnutls_cipher_decrypt(session->connection_state.
			      read_cipher_state, ciphertext.data,
			      ciphertext.size)) < 0) {
			gnutls_assert();
			return ret;
		}

		length =
		    ciphertext.size - hash_size;

		break;
	case CIPHER_BLOCK:
		if ((ciphertext.size < blocksize)
		    || (ciphertext.size % blocksize != 0)) {
			gnutls_assert();
			return GNUTLS_E_DECRYPTION_FAILED;
		}

		if ( (ret = _gnutls_cipher_decrypt(session->connection_state.
			      read_cipher_state, ciphertext.data,
			      ciphertext.size)) < 0) {
			gnutls_assert();
			return ret;
		}

		pad = ciphertext.data[ciphertext.size - 1] + 1;	/* pad */

		length =
		    ciphertext.size - hash_size - pad;

		if (pad >
		    ciphertext.size - hash_size) {
			gnutls_assert();
			/* We do not fail here. We check below for the
			 * the pad_failed. If zero means success.
			 */
			pad_failed = GNUTLS_E_DECRYPTION_FAILED;
		}
		
		/* Check the pading bytes (TLS 1.0 only)
		 */
		if ( ver == GNUTLS_TLS1)
		for (i=2;i<pad;i++) {
			if (ciphertext.data[ciphertext.size-i] != ciphertext.data[ciphertext.size - 1]) {
				gnutls_assert();
				pad_failed = GNUTLS_E_DECRYPTION_FAILED;
			}
		}
		
		break;
	default:
		gnutls_assert();
		return GNUTLS_E_INTERNAL_ERROR;
	}


	/* copy the decrypted stuff to compress_data.
	 */
	if (compress_size < length) {
		gnutls_assert();
		return GNUTLS_E_MEMORY_ERROR;
	}
	memcpy( compress_data, ciphertext.data, length);


	c_length = _gnutls_conv_uint16((uint16) length);
	seq_num = _gnutls_conv_uint64( &session->connection_state.read_sequence_number);

	/* Pass the type, version, length and compressed through
	 * MAC.
	 */
	if (td != GNUTLS_MAC_FAILED) {
		_gnutls_hmac(td, UINT64DATA(seq_num), 8);
		
		_gnutls_hmac(td, &type, 1);
		if ( ver != GNUTLS_SSL3) { /* TLS 1.0 only */
			_gnutls_hmac(td, &major, 1);
			_gnutls_hmac(td, &minor, 1);
		}
		_gnutls_hmac(td, &c_length, 2);
		
		if (length!=0)
			_gnutls_hmac(td, compress_data, length);

		mac_deinit( td, MAC, ver);
	}

	/* HMAC was not the same. 
	 */
	if (memcmp
	    (MAC, &ciphertext.data[length], hash_size) != 0) {
		gnutls_assert();
		return GNUTLS_E_DECRYPTION_FAILED;
	}
	
	/* This one was introduced to avoid a timing attack against the TLS
	 * 1.0 protocol.
	 */
	if (pad_failed != 0) return pad_failed;

	return length;
}

