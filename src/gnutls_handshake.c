#include <defines.h>
#include "gnutls_int.h"
#include "gnutls_errors.h"
#include "debug.h"
#include "gnutls_compress.h"
#include "gnutls_plaintext.h"
#include "gnutls_cipher.h"
#include "gnutls_buffers.h"



int SelectSuite( opaque ret[2], char* data, int datalen) {
int x, pos=0, i,j;
GNUTLS_CipherSuite *ciphers;

	x = _gnutls_supported_ciphersuites(ciphers);
	memset( ret, '\0', sizeof(GNUTLS_CipherSuite));
	
	for ( j=0;j<datalen;j+=2) {
		for (i=0;i<x;i++) {
			if ( memcmp( &ciphers[i].CipherSuite, &data[j], 2) == 0) {
				memmove( ret, &ciphers[i].CipherSuite, 2);
				gnutls_free(ciphers);
				return 0;
			}
		}
	}
	
	
	gnutls_free(ciphers);
	return GNUTLS_E_UNKNOWN_CIPHER;

}

int SelectCompMethod( CompressionMethod* ret, char* data, int datalen) {
int x, pos=0, i,j;
CompressionMethod *ciphers;

	x = _gnutls_supported_compression_methods(ciphers);
	memset( ret, '\0', sizeof(CompressionMethod));
	
	for ( j=0;j<datalen;j++) {
		for (i=0;i<x;i++) {
			if ( memcmp( &ciphers[i], &data[j], 1) == 0) {
				memmove( ret, &ciphers[i], 1);
				gnutls_free(ciphers);
				return 0;
			}
		}
	}
	
	
	gnutls_free(ciphers);
	return GNUTLS_E_UNKNOWN_COMPRESSION_ALGORITHM;

}


#define SUPPORTED_CIPHERSUITES 1
int _gnutls_supported_ciphersuites(GNUTLS_CipherSuite **ciphers) {

	int i;

	*ciphers = gnutls_malloc( SUPPORTED_CIPHERSUITES * sizeof(GNUTLS_CipherSuite));

	for (i=0;i<SUPPORTED_CIPHERSUITES;i++) {
		(*ciphers)[i].CipherSuite[0] = 0x00;
	}

	/* GNUTLS_DH_anon_WITH_3DES_EDE_CBC_SHA */
//	(*ciphers)[0].CipherSuite[1] = 0x1B;

	/* GNUTLS_NULL_WITH_NULL_NULL */
	(*ciphers)[0].CipherSuite[1] = 0x0;

	return SUPPORTED_CIPHERSUITES;
}


#define SUPPORTED_COMPRESSION_METHODS 1
int _gnutls_supported_compression_methods(CompressionMethod **comp) {

	int i;

	*comp = gnutls_malloc( SUPPORTED_COMPRESSION_METHODS * sizeof(CompressionMethod));

/* NULL Compression */
	(*comp)[0] = COMPRESSION_NULL;

	return SUPPORTED_COMPRESSION_METHODS;
}

int _gnutls_send_handshake(int cd, GNUTLS_STATE state, void* i_data, uint32 i_datasize, HandshakeType type) {
	int ret;
	char *data;
	uint24 length;
	uint32 datasize;
	int pos=0;
	
#ifdef WORDS_BIGENDIAN
	datasize = i_datasize;
#else 
	datasize = byteswap32(i_datasize);
#endif	
	
	length.pint[0] = ((uint8*)i_datasize)[1];
	length.pint[1] = ((uint8*)i_datasize)[2];
	length.pint[2] = ((uint8*)i_datasize)[3];
	
	data = gnutls_malloc( i_datasize + 3 + 1);
	memmove( &data[pos++], &type, 1);
	memmove( &data[pos++], &length.pint[0], 1);
	memmove( &data[pos++], &length.pint[1], 1);
	memmove( &data[pos++], &length.pint[2], 1);
	memmove( &data[pos], i_data, i_datasize);

	ret = gnutls_send_int( cd, state, GNUTLS_HANDSHAKE, data, i_datasize);
	
	return ret;
}




int _gnutls_send_hello(int cd, GNUTLS_STATE state, opaque* SessionID) {
	char* rand;
	char *data=NULL;
	uint8 session_id_len=0, z;
	uint32 cur_time;
	int pos=0;
	GNUTLS_CipherSuite* cipher_suites;
	CompressionMethod* compression_methods;
	int i, datalen, ret;
	uint16 x;
	
	if (SessionID!=NULL) session_id_len=strlen(SessionID);
	rand=gcry_random_bytes( 28, GCRY_STRONG_RANDOM);

	
	if (state->security_parameters.entity == GNUTLS_CLIENT) {

		data[pos++] = GNUTLS_VERSION_MAJOR;
		data[pos++] = GNUTLS_VERSION_MINOR;		
#ifdef WORDS_BIGENDIAN
		cur_time = time(NULL);
#else
		cur_time = byteswap32(time(NULL));
#endif
		memmove( state->security_parameters.client_random, &cur_time, 4);
		memmove( &state->security_parameters.client_random[4], rand, 28);
		datalen = sizeof(uint32) + session_id_len + 28;
		data = gnutls_malloc ( datalen);

		memmove( &data[pos], &cur_time, sizeof(uint32));
		pos += sizeof(uint32);
		memmove( &data[pos], rand, 28);
		pos+=28;

		memmove( &data[pos++], &session_id_len, sizeof(uint8));		
		if (session_id_len>0) {
			memmove( &data[pos], SessionID, session_id_len);
		}
		pos+=session_id_len;
		
		x = _gnutls_supported_ciphersuites( &cipher_suites);

#ifdef WORDS_BIGENDIAN
		memmove( &data[pos], &x, sizeof(uint16));
#else
		x=byteswap16(x);
		memmove( &data[pos], &x, sizeof(uint16));
		x=byteswap16(x);
#endif
		pos+=2;
		for (i=0;i<x;i++) {
			datalen += 2;
			data = gnutls_realloc( data, datalen);
			memmove( &data[pos], &cipher_suites[i].CipherSuite, 2);
			pos+=2;
		}
		z = _gnutls_supported_compression_methods( &compression_methods);

#ifdef WORDS_BIGENDIAN
		memmove( &data[pos++], &z, sizeof(uint8));
#endif
		for (i=0;i<z;i++) {
			datalen += 1;
			data = gnutls_realloc( data, datalen);
			memmove( &data[pos], &compression_methods[i], 1);
			pos++;
		}
		ret = _gnutls_send_handshake( cd, state, data, datalen, GNUTLS_CLIENT_HELLO);
		gnutls_free(data);
		gcry_free(rand);

		gnutls_free(cipher_suites);
		gnutls_free(compression_methods);
	} else {
	
	}

	return ret;
}


/* RECEIVE A HELLO MESSAGE. This should be called from gnutls_recv_int only if a
 * hello message is expected. It uses the gnutls_internals.current_cipher_suite
 * and gnutls_internals.compression_method.
 */
int _gnutls_recv_hello(int cd, GNUTLS_STATE state, char* data, int datalen, opaque** SessionID, int SessionIDnum) {
	uint8 session_id_len=0, z;
	uint32 cur_time;
	int pos=0;
	GNUTLS_CipherSuite cipher_suite, *cipher_suites;
	CompressionMethod compression_method, *compression_methods;
	int i, ret;
	uint16 x, sizeOfSuites;
	
	if (state->security_parameters.entity == GNUTLS_CLIENT) {

		if (datalen < 38) return GNUTLS_E_UNSUPPORTED_VERSION_PACKET;
		
		if (data[pos++] != GNUTLS_VERSION_MAJOR) 
			return GNUTLS_E_UNSUPPORTED_VERSION_PACKET;
		if (data[pos++] != GNUTLS_VERSION_MINOR)
			return GNUTLS_E_UNSUPPORTED_VERSION_PACKET;

		memmove( state->security_parameters.server_random, &data[pos], 32);
		pos+=32;
		
		memmove( &session_id_len, &data[pos++], 1);

		if (datalen < 38+session_id_len) return GNUTLS_E_UNSUPPORTED_VERSION_PACKET;
		pos+=session_id_len;
		
		/* We should resume an old connection here. This is not
		 * implemented yet.
		 */

		memmove( &cipher_suite.CipherSuite, &data[pos], 2);
		pos+=2;

		z=1;
		x = _gnutls_supported_ciphersuites( &cipher_suites);
		for (i=0;i<x;i++) {
			if ( memcmp( &cipher_suites[i], cipher_suite.CipherSuite, 2) == 0) {
				z=0;

			}
		}
		if (z!=0) return GNUTLS_E_UNKNOWN_CIPHER_TYPE;
		memmove( state->gnutls_internals.current_cipher_suite.CipherSuite, cipher_suite.CipherSuite, 2);
		
		z=1;
		memmove( &compression_method, &data[pos++], 1);
		z = _gnutls_supported_compression_methods( &compression_methods);
		for (i=0;i<z;i++) {
			if (memcmp( &compression_methods[i], &compression_method, 1)==0) {
				z=0;

			}
		}
		if (z!=0) return GNUTLS_E_UNKNOWN_COMPRESSION_ALGORITHM;
		memmove( &state->gnutls_internals.compression_method, &compression_method, 1);


		gnutls_free(cipher_suites);
		gnutls_free(compression_methods);

	} else { /* Server side reading a client hello */

		if (datalen < 35) return GNUTLS_E_UNSUPPORTED_VERSION_PACKET;

		if (data[pos++] != GNUTLS_VERSION_MAJOR)
			return GNUTLS_E_UNSUPPORTED_VERSION_PACKET;
		if (data[pos++] != GNUTLS_VERSION_MINOR)
			return GNUTLS_E_UNSUPPORTED_VERSION_PACKET;

		memmove( state->security_parameters.client_random, &data[pos], 32);
		pos+=32;
		
		memmove( &session_id_len, &data[pos++], 1);
		pos+=session_id_len;
		
		/* We should resume an old connection here. This is not
		 * implemented yet.
		 */


		/* Select a ciphersuite */
		memmove( &sizeOfSuites, &data[pos], 2);
		pos+=2;
#ifndef WORDS_BIGENDIAN
		sizeOfSuites=byteswap16(sizeOfSuites);
#endif
		SelectSuite( state->gnutls_internals.current_cipher_suite.CipherSuite, &data[pos], sizeOfSuites); 
		pos+=sizeOfSuites;
		
		memmove( &z, &data[pos++], 1);
		SelectCompMethod( &state->gnutls_internals.compression_method, &data[pos], z);
		
		gnutls_free(cipher_suites);
		gnutls_free(compression_methods);	
	}

	return ret;
}

