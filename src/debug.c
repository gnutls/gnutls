#include <stdio.h>
#include <stdlib.h>
#include <defines.h>
#include "gnutls_int.h"
#include "gnutls_errors.h"


static char hexconvtab[] = "0123456789abcdef";

char * bin2hex(const unsigned char *old, const size_t oldlen)
{
	unsigned char *new = NULL;
	int i, j;

	new = malloc(oldlen * 2 * sizeof(char) + 1);
	if (!new)
		return (new);

	for (i = j = 0; i < oldlen; i++) {
		new[j++] = hexconvtab[old[i] >> 4];
		new[j++] = hexconvtab[old[i] & 15];
	}
	new[j] = '\0';

	return (new);
}


void _print_state(GNUTLS_STATE state)
{

	fprintf(stderr, "GNUTLS State:\n");
	fprintf(stderr, "Connection End: %d\n",
		state->security_parameters.entity);
	fprintf(stderr, "Cipher Algorithm: %d\n",
		state->security_parameters.bulk_cipher_algorithm);
	fprintf(stderr, "Cipher Type: %d\n",
		state->security_parameters.cipher_type);
	fprintf(stderr, "Key Size: %d\n",
		state->security_parameters.key_size);
	fprintf(stderr, "Key Material: %d\n",
		state->security_parameters.key_material_length);
	fprintf(stderr, "Exportable: %d\n",
		state->security_parameters.is_exportable);
	fprintf(stderr, "MAC algorithm: %d\n",
		state->security_parameters.mac_algorithm);
	fprintf(stderr, "Hash size: %d\n",
		state->security_parameters.hash_size);
	fprintf(stderr, "Compression Algorithm: %d\n",
		state->security_parameters.compression_algorithm);
	fprintf(stderr, "\n");

}

void _print_TLSCompressed(GNUTLSCompressed * compressed)
{
	fprintf(stderr, "TLSCompressed packet:\n");
	fprintf(stderr, "type: %d\n", compressed->type);
	fprintf(stderr, "version: %d,%d\n", compressed->version.major,
		compressed->version.minor);
	fprintf(stderr, "length: %d\n", compressed->length);
	fprintf(stderr, "fragment: %s\n", bin2hex(compressed->fragment, compressed->length));
	fprintf(stderr, "\n");
}


void _print_TLSPlaintext(GNUTLSPlaintext * plaintext)
{
	fprintf(stderr, "TLSPlaintext packet:\n");
	fprintf(stderr, "type: %d\n", plaintext->type);
	fprintf(stderr, "version: %d,%d\n", plaintext->version.major,
		plaintext->version.minor);
	fprintf(stderr, "length: %d\n", plaintext->length);
	fprintf(stderr, "fragment: %s\n", bin2hex(plaintext->fragment, plaintext->length));
	fprintf(stderr, "\n");
}


void _print_TLSCiphertext( GNUTLSCiphertext * ciphertext)
{

	fprintf(stderr, "TLSCiphertext packet:\n");
	fprintf(stderr, "type: %d\n", ciphertext->type);
	fprintf(stderr, "version: %d,%d\n", ciphertext->version.major,
		ciphertext->version.minor);
	fprintf(stderr, "length: %d\n", ciphertext->length);

	fprintf(stderr, "fragment: %s\n", bin2hex(ciphertext->fragment, ciphertext->length));
	fprintf(stderr, "\n");
}
