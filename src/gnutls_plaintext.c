#include <defines.h>
#include "gnutls.h"



/* Plaintext Handling */
int _gnutls_text2TLSPlaintext(ContentType type, GNUTLSPlaintext** plain, char *text, uint16 length)
{
	GNUTLSPlaintext *plaintext;

	if (length > 16384)
		return GNUTLS_E_LARGE_PACKET;

	*plain = gnutls_malloc(sizeof(GNUTLSPlaintext));
	plaintext = *plain;

	plaintext->fragment = gnutls_malloc(length);
	memmove(plaintext->fragment, text, length);
	plaintext->length = length;
	plaintext->type = type;
	plaintext->version.major = GNUTLS_VERSION_MAJOR;
	plaintext->version.minor = GNUTLS_VERSION_MINOR;

	return 0;
}

int _gnutls_TLSPlaintext2text( char** txt, GNUTLSPlaintext* plaintext)
{
	char *text;

	if (plaintext->length > 16384)
		return GNUTLS_E_LARGE_PACKET;

	*txt = gnutls_malloc(plaintext->length);
	text = *txt;
	
	memmove(text, plaintext->fragment, plaintext->length);

	return 0;
}

int _gnutls_freeTLSPlaintext(GNUTLSPlaintext * plaintext)
{
	if (plaintext == NULL)
		return 0;

	gnutls_free(plaintext->fragment);
	gnutls_free(plaintext);

	return 0;
}
