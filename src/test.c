#include <defines.h>
#include <gnutls.h>
#include "gnutls_compress.h"
#include "gnutls_plaintext.h"
#include "gnutls_cipher.h"
#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>

                     
int main()
{
	GNUTLS_STATE state;
	char text[] = "ena xelidoni sto bouno\n";
	GNUTLSPlaintext *gtxt;
	GNUTLSCompressed *gcomp;
	GNUTLSCiphertext *gcipher;
	int cd;
	
	
	gnutls_init(&state, GNUTLS_CLIENT);
	_gnutls_set_cipher(state, CIPHER_3DES);
	_gnutls_set_compression( state, COMPRESSION_NULL);
	_gnutls_set_mac(state, MAC_NULL);
	_print_state(state);

	_gnutls_set_keys( state);
	_gnutls_connection_state_init( state);

	remove("ciphertext");
	cd = open( "ciphertext", O_WRONLY|O_CREAT, S_IRWXU);

	gnutls_send( cd, state, text, strlen(text));

	close(cd);
	gnutls_deinit(&state);
	return 0;
}
