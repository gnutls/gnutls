#include <defines.h>
#include "gnutls_record.h"
#include "gnutls_handshake.h"
#include "gnutls_errors.h"
#include "debug.h"
#include "gnutls_compress.h"
#include "gnutls_plaintext.h"
#include "gnutls_cipher.h"
#include "gnutls_buffers.h"
#include <stdio.h>
#include <stdlib.h>
#include <mhash.h>

int gnutls_init(GNUTLS_STATE * state, ConnectionEnd con_end)
{
	*state = gnutls_calloc(1, sizeof(GNUTLS_STATE_INT));
	memset(*state, 0, sizeof(GNUTLS_STATE));
	(*state)->security_parameters.entity = con_end;

/* Set the defaults (only to remind me that they should be allocated ) */
	(*state)->security_parameters.bulk_cipher_algorithm = CIPHER_NULL;
	(*state)->security_parameters.mac_algorithm = MAC_NULL;
	(*state)->security_parameters.compression_algorithm = COMPRESSION_NULL;

	(*state)->connection_state.compression_state = NULL;
	(*state)->connection_state.mac_secret = NULL;

	(*state)->cipher_specs.server_write_mac_secret = NULL;
	(*state)->cipher_specs.client_write_mac_secret = NULL;
	(*state)->cipher_specs.server_write_IV = NULL;
	(*state)->cipher_specs.client_write_IV = NULL;
	(*state)->cipher_specs.server_write_key = NULL;
	(*state)->cipher_specs.client_write_key = NULL;

	(*state)->gnutls_internals.buffer = NULL;
}

int gnutls_deinit(GNUTLS_STATE * state)
{
	gnutls_free((*state)->connection_state.compression_state);
	gnutls_free((*state)->connection_state.mac_secret);

	secure_free((*state)->cipher_specs.server_write_mac_secret);
	secure_free((*state)->cipher_specs.client_write_mac_secret);
	secure_free((*state)->cipher_specs.server_write_IV);
	secure_free((*state)->cipher_specs.client_write_IV);
	secure_free((*state)->cipher_specs.server_write_key);
	secure_free((*state)->cipher_specs.client_write_key);

	
	gnutls_free(*state);
}

/* Produces "total_bytes" bytes using the hash algorithm specified.
 * (used in the PRF function)
 */
svoid* gnutls_P_hash( hashid algorithm, opaque* secret, int secret_size, 
		opaque* seed, int seed_size, int total_bytes) {

	MHASH td1, td2;
	char* ret=secure_malloc(total_bytes);
	void* A;
	int i=0, times, copy_bytes=0, how;
	void *final;
	
	do {
		i += mhash_get_block_size(algorithm);
	} while( i < total_bytes);
	
	A = seed;
	times = i / mhash_get_block_size(algorithm);

	for (i=0;i<times;i++) {
		td2 = hmac_mhash_init( algorithm, secret, secret_size, mhash_get_hash_pblock(algorithm));

		td1 = hmac_mhash_init( algorithm, secret, secret_size, mhash_get_hash_pblock(algorithm));
		mhash( td1, A, seed_size);

		A=hmac_mhash_end( td1);
		
		mhash( td2, A, mhash_get_block_size(algorithm));
		mhash( td2, seed, seed_size);
		final = hmac_mhash_end( td2);

		copy_bytes=mhash_get_block_size(algorithm);
		if ((i+1)*copy_bytes < total_bytes) {
			how = mhash_get_block_size(algorithm);
		} else {
			how = total_bytes - (i)*copy_bytes;
		}

 		if ( how>0) {
			memmove( &ret[i*copy_bytes], final, how);
		}
		free(final);
		if (i>0) free(A); 
	}

	return ret;
}


/* The PRF function expands a given secret */
svoid *gnutls_PRF( opaque* secret, int secret_size, uint8* label, int label_size, 
			opaque* seed, int seed_size, int total_bytes)
{
	int l_s1, l_s2, i, s_seed_size;
	char* o1, *o2;
	char* s1, *s2;
	char* ret;
	char* s_seed;
	
	/* label+seed = s_seed */
	s_seed_size = seed_size+label_size;
	s_seed=gnutls_malloc(s_seed_size);
	memmove( s_seed, label, label_size);
	memmove( &s_seed[label_size], seed, seed_size);
	
	
	if (secret_size%2 == 0) {
		l_s1 = l_s2 = secret_size/2;
		s1 = &secret[0];
		s2 = &secret[l_s1+1];
	} else {
		l_s1 = l_s2 = (secret_size/2) + 1;
		s1 = &secret[0];
		s2 = &secret[l_s1];
	}
	
	o1 = gnutls_P_hash( MHASH_MD5, s1, l_s1, s_seed, s_seed_size, total_bytes);
	o2 = gnutls_P_hash( MHASH_SHA1, s2, l_s2, s_seed, s_seed_size, total_bytes);

	ret = secure_malloc( total_bytes);
	gnutls_free( s_seed);
	for (i=0;i<total_bytes;i++) {
		ret[i] = o1[i] ^ o2[i];
	}

	secure_free(o1);
	secure_free(o2);

	return ret;
	
}

/* if  master_secret, client_random and server_random have been initialized,
 * this function creates the keys and stores them into state->cipher_specs
 */
int _gnutls_set_keys( GNUTLS_STATE state) {
	char* key_block;
	char keyexp[]="key expansion";
	char* random = gnutls_malloc(64);
	int hash_size;
	int IV_size;
	int key_size;
	
	hash_size = state->security_parameters.hash_size;
	IV_size = state->security_parameters.IV_size;
	key_size = state->security_parameters.key_material_length;

	memmove(random, state->security_parameters.server_random, 32);
	memmove(&random[32], state->security_parameters.client_random, 32);
	
	key_block = gnutls_PRF( state->security_parameters.master_secret, 48,
			keyexp, strlen(keyexp),
			random, 64, 
			2*hash_size + 
			2*key_size +
			2*IV_size);

	state->cipher_specs.client_write_mac_secret = secure_malloc( hash_size);
	memmove( state->cipher_specs.client_write_mac_secret, &key_block[0], hash_size);

	state->cipher_specs.server_write_mac_secret = secure_malloc( hash_size);
	memmove( state->cipher_specs.server_write_mac_secret, &key_block[hash_size], hash_size);

	state->cipher_specs.client_write_key = secure_malloc( key_size);
	memmove( state->cipher_specs.client_write_key, &key_block[2*hash_size], key_size);

	state->cipher_specs.server_write_key = secure_malloc( key_size);
	memmove( state->cipher_specs.server_write_key, &key_block[2*hash_size+key_size], key_size);

	state->cipher_specs.client_write_IV = secure_malloc( IV_size);
	memmove( state->cipher_specs.client_write_IV, &key_block[2*key_size+2*hash_size], IV_size);

	state->cipher_specs.server_write_IV = secure_malloc( IV_size);
	memmove( state->cipher_specs.server_write_IV, &key_block[2*hash_size+2*key_size+IV_size], IV_size);

	secure_free( key_block);
	return 0;
}

int _gnutls_send_alert( int cd, GNUTLS_STATE state, AlertLevel level, AlertDescription desc) {
Alert alert;

	alert.level=level;
	alert.description=desc;
	
	return gnutls_send_int( cd, state, GNUTLS_ALERT, &alert, sizeof(alert));

}

int gnutls_send_int(int cd, GNUTLS_STATE state, ContentType type, char* data, int sizeofdata) {
        GNUTLSPlaintext *gtxt;
        GNUTLSCompressed *gcomp;
        GNUTLSCiphertext *gcipher;
	int iterations, i, err;
	uint16 length;
	int ret=0, Size;
	
	if (sizeofdata==0) return 0;
	if (state->gnutls_internals.valid_connection==VALID_FALSE) return GNUTLS_E_INVALID_SESSION;
	
	if (sizeofdata<16384) {
		iterations=1;
		Size=sizeofdata;
	} else {
		iterations = sizeofdata/16384; 
		Size = 16384;
	}
	for (i=0;i<iterations;i++) {
		err = _gnutls_text2TLSPlaintext(type, &gtxt, &data[i*Size], Size);
		if (err<0) {
			/*gnutls_perror(err);*/
			return err;
		}

	        err = _gnutls_TLSPlaintext2TLSCompressed(state, &gcomp, gtxt);
		if (err<0) {
			/*gnutls_perror(err);*/
			return err;
		}

		_gnutls_freeTLSPlaintext(gtxt);
	
		err = _gnutls_TLSCompressed2TLSCiphertext( state, &gcipher, gcomp);
		if (err<0) {
			/*gnutls_perror(err);*/
			return err;
		}

		_gnutls_freeTLSCompressed(gcomp);
		
		if (write( cd, &gcipher->type, sizeof(ContentType)) != sizeof(ContentType)) {
			state->gnutls_internals.valid_connection=VALID_FALSE;
			return GNUTLS_E_UNABLE_SEND_DATA;
		}
		if (write( cd, &gcipher->version.major, 1) != 1) {
			state->gnutls_internals.valid_connection=VALID_FALSE;
			return GNUTLS_E_UNABLE_SEND_DATA;
		}
		if (write( cd, &gcipher->version.minor, 1) != 1) {
			state->gnutls_internals.valid_connection=VALID_FALSE;
			return GNUTLS_E_UNABLE_SEND_DATA;
		}
#ifdef WORDS_BIGENDIAN
		length=gcipher->length;
#else
		length=byteswap16(gcipher->length);
#endif
		if (write( cd, &length, sizeof(uint16)) != sizeof(uint16)) {
			state->gnutls_internals.valid_connection=VALID_FALSE;
			return GNUTLS_E_UNABLE_SEND_DATA;
		}
//		_print_TLSCiphertext( gcipher);
		if (write( cd, gcipher->fragment, gcipher->length) != gcipher->length) {
			state->gnutls_internals.valid_connection=VALID_FALSE;
			return GNUTLS_E_UNABLE_SEND_DATA;
		}
		state->connection_state.write_sequence_number++;
		ret += Size;
		
		_gnutls_freeTLSCiphertext(gcipher);
	}
	/* rest data */
	if (iterations>1) {
		Size=sizeofdata%16384;
		err = _gnutls_text2TLSPlaintext(type, &gtxt, &data[ret], Size);
		if (err<0) {
			/*gnutls_perror(err);*/
			return err;
		}

	        err = _gnutls_TLSPlaintext2TLSCompressed(state, &gcomp, gtxt);
		if (err<0) {
			/*gnutls_perror(err);*/
			return err;
		}

		_gnutls_freeTLSPlaintext(gtxt);
	
		err = _gnutls_TLSCompressed2TLSCiphertext( state, &gcipher, gcomp);
		if (err<0) {
			/*gnutls_perror(err);*/
			return err;
		}
		_gnutls_freeTLSCompressed(gcomp);
#ifdef WORDS_BIGENDIAN
		length=gcipher->length;
#else
		length=byteswap16(gcipher->length);
#endif
		if (write( cd, &gcipher->type, sizeof(ContentType)) != sizeof(ContentType)) {
			state->gnutls_internals.valid_connection=VALID_FALSE;
			return GNUTLS_E_UNABLE_SEND_DATA;
		}
		if (write( cd, &gcipher->version.major, 1) != 1) {
			state->gnutls_internals.valid_connection=VALID_FALSE;
			return GNUTLS_E_UNABLE_SEND_DATA;
		}
		if (write( cd, &gcipher->version.minor, 1) != 1) {
			state->gnutls_internals.valid_connection=VALID_FALSE;
			return GNUTLS_E_UNABLE_SEND_DATA;
		}
		if (write( cd, &length, sizeof(uint16)) != sizeof(uint16)) {
			state->gnutls_internals.valid_connection=VALID_FALSE;
			return GNUTLS_E_UNABLE_SEND_DATA;
		}
		if (write( cd, gcipher->fragment, gcipher->length) != gcipher->length) {
			state->gnutls_internals.valid_connection=VALID_FALSE;
			return GNUTLS_E_UNABLE_SEND_DATA;
		}
		state->connection_state.write_sequence_number++;
		ret += Size;
		
		_gnutls_freeTLSCiphertext(gcipher);
	}

	return ret;
}


int gnutls_recv_int(int cd, GNUTLS_STATE state, ContentType type, char* data, int sizeofdata) {
        GNUTLSPlaintext *gtxt;
        GNUTLSCompressed *gcomp;
        GNUTLSCiphertext gcipher;
	int iterations, i, err;
	char* tmpdata;
	int ret=0;
	
	if (sizeofdata==0) return 0;

	while( gnutls_getDataBufferSize(state, type) < sizeofdata) {

		if (state->gnutls_internals.valid_connection==VALID_FALSE) return GNUTLS_E_INVALID_SESSION;
		if (read( cd, &gcipher.type, sizeof(ContentType)) != sizeof(ContentType)) {
			state->gnutls_internals.valid_connection=VALID_FALSE;
			_gnutls_send_alert( cd, state, GNUTLS_FATAL, GNUTLS_INTERNAL_ERROR);
			return GNUTLS_E_UNEXPECTED_PACKET_LENGTH;
		}
		if (read( cd, &gcipher.version, sizeof(ProtocolVersion)) != sizeof(ProtocolVersion)) {
			state->gnutls_internals.valid_connection=VALID_FALSE;
			_gnutls_send_alert( cd, state, GNUTLS_FATAL, GNUTLS_INTERNAL_ERROR);
			return GNUTLS_E_UNEXPECTED_PACKET_LENGTH;
		}
		if ( gcipher.version.major != GNUTLS_VERSION_MAJOR || gcipher.version.minor != GNUTLS_VERSION_MINOR) {
			_gnutls_send_alert( cd, state, GNUTLS_FATAL, GNUTLS_PROTOCOL_VERSION);
			return GNUTLS_E_UNSUPPORTED_VERSION_PACKET;
 		}

		if (read( cd, &gcipher.length, sizeof(uint16)) != sizeof(uint16)) {
			state->gnutls_internals.valid_connection=VALID_FALSE;
			_gnutls_send_alert( cd, state, GNUTLS_FATAL, GNUTLS_INTERNAL_ERROR);
			return GNUTLS_E_UNEXPECTED_PACKET_LENGTH;
		}
#ifndef WORDS_BIGENDIAN
		gcipher.length = byteswap16(gcipher.length);
#endif
		gcipher.fragment = gnutls_malloc(gcipher.length);
	
		/* read ciphertext */
		if (read( cd, gcipher.fragment, gcipher.length) != gcipher.length) {
			gnutls_free(gcipher.fragment);
			state->gnutls_internals.valid_connection=VALID_FALSE;
			_gnutls_send_alert( cd, state, GNUTLS_FATAL, GNUTLS_INTERNAL_ERROR);
			return GNUTLS_E_UNEXPECTED_PACKET_LENGTH;
		}

		if (ret = _gnutls_TLSCiphertext2TLSCompressed( state, &gcomp, &gcipher) < 0){
			gnutls_free(gcipher.fragment);
			state->gnutls_internals.valid_connection=VALID_FALSE;
			if (ret=GNUTLS_E_MAC_FAILED) {
				_gnutls_send_alert( cd, state, GNUTLS_FATAL, GNUTLS_BAD_RECORD_MAC);
			} else {
				_gnutls_send_alert( cd, state, GNUTLS_FATAL, GNUTLS_DECRYPTION_FAILED);
			}
			return ret;
		}
		gnutls_free(gcipher.fragment);
	
		if (ret = _gnutls_TLSCompressed2TLSPlaintext( state, &gtxt, gcomp) < 0){
			state->gnutls_internals.valid_connection=VALID_FALSE;
			_gnutls_send_alert( cd, state, GNUTLS_FATAL, GNUTLS_DECOMPRESSION_FAILURE);
			return ret;
		}
		_gnutls_freeTLSCompressed(gcomp);
		
		if (ret = _gnutls_TLSPlaintext2text( &tmpdata, gtxt) < 0){
			state->gnutls_internals.valid_connection=VALID_FALSE;
			_gnutls_send_alert( cd, state, GNUTLS_FATAL, GNUTLS_INTERNAL_ERROR);
			return ret;
		}

		gnutls_insertDataBuffer(state, type, tmpdata, gtxt->length);

		_gnutls_freeTLSPlaintext(gtxt);

		/* Incread sequence number */
		state->connection_state.read_sequence_number++;
		
	}

	ret = gnutls_getDataFromBuffer(state, type, data, sizeofdata);
	
	return ret;
}
