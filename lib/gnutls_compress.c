#include <defines.h>
#include "gnutls_int.h"
#include "gnutls_compress.h"
#include "gnutls_errors.h"

int _gnutls_TLSPlaintext2TLSCompressed(GNUTLS_STATE state,
						     GNUTLSCompressed **
						     compress,
						     GNUTLSPlaintext *
						     plaintext)
{
	GNUTLSCompressed *compressed;

	*compress = gnutls_malloc(sizeof(GNUTLSCompressed));
	compressed = *compress;

	switch (state->security_parameters.compression_algorithm) {
	case COMPRESSION_NULL:

		compressed->fragment = gnutls_malloc(plaintext->length);

		memmove(compressed->fragment, plaintext->fragment,
			plaintext->length);
		compressed->length = plaintext->length;
		compressed->type = plaintext->type;
		compressed->version.major = plaintext->version.major;
		compressed->version.minor = plaintext->version.minor;
		break;
	default:
		gnutls_free(*compress);
		return GNUTLS_E_UNKNOWN_COMPRESSION_ALGORITHM;
	}

	return 0;
}

int _gnutls_TLSCompressed2TLSPlaintext(GNUTLS_STATE state,
						     GNUTLSPlaintext**
						     plain,
						     GNUTLSCompressed *
						     compressed)
{
	GNUTLSPlaintext *plaintext;

	*plain = gnutls_malloc(sizeof(GNUTLSPlaintext));
	plaintext = *plain;
	
	switch (state->security_parameters.compression_algorithm) {
	case COMPRESSION_NULL:
		plaintext->fragment = gnutls_malloc(compressed->length);
		memmove(plaintext->fragment, compressed->fragment,
			compressed->length);
		plaintext->length = compressed->length;
		plaintext->type = compressed->type;
		plaintext->version.major = compressed->version.major;
		plaintext->version.minor = compressed->version.minor;
		break;
	default:
		gnutls_free(*plain);
		return GNUTLS_E_UNKNOWN_COMPRESSION_ALGORITHM;
	}

	return 0;
}




int _gnutls_freeTLSCompressed(GNUTLSCompressed * compressed)
{
	if (compressed == NULL)
		return 0;

	gnutls_free(compressed->fragment);
	gnutls_free(compressed);

	return 0;
}
