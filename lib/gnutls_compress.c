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
