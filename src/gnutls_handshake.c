#include <defines.h>
#include "gnutls_int.h"
#include "gnutls_errors.h"
#include "debug.h"
#include "gnutls_compress.h"
#include "gnutls_plaintext.h"
#include "gnutls_cipher.h"
#include "gnutls_buffers.h"

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
	int session_id_len=0;
	uint32 cur_time;
	int pos=0;
	GNUTLS_CipherSuite* cipher_suites;
	CompressionMethod* compression_methods;
	int i,x, datalen, ret;
	
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
		datalen = sizeof(uint32) + session_id_len + 28;
		data = gnutls_malloc ( datalen);

		memmove( &data[pos], &cur_time, sizeof(uint32));
		pos += sizeof(uint32);
		memmove( &data[pos], rand, 28);
		pos+=28;
		
		if (session_id_len>0) memmove( &data[pos], SessionID, session_id_len);
		pos+=session_id_len;
		
		x = _gnutls_supported_ciphersuites( &cipher_suites);
		
		for (i=0;i<x;i++) {
			datalen += 2;
			data = gnutls_realloc( data, datalen);
			memmove( &data[pos], &cipher_suites[i], sizeof(uint8)*2);
			pos+=2;
		}
		x = _gnutls_supported_compression_methods( &compression_methods);
		for (i=0;i<x;i++) {
			datalen += 1;
			data = gnutls_realloc( data, datalen);
			memmove( &data[pos], &compression_methods[i], 1);
			pos++;
		}
		ret = _gnutls_send_handshake( cd, state, data, datalen, GNUTLS_CLIENT_HELLO);
		gnutls_free(data);
		gcry_free(rand);
		

	} else {
	
	}

	return ret;
}

