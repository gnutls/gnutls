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
#include "gnutls_compress_int.h"

int _gnutls_TLSPlaintext2TLSCompressed(GNUTLS_STATE state,
						     GNUTLSCompressed **
						     compress,
						     GNUTLSPlaintext *
						     plaintext)
{
	int size;
	GNUTLSCompressed *compressed;
	char *data;
	
	*compress = gnutls_malloc(sizeof(GNUTLSCompressed));
	compressed = *compress;

	data=NULL;
	
	size = gnutls_compress( state->security_parameters.compression_algorithm, plaintext->fragment, plaintext->length, &data);
	if (size < 0) {
		if (data!=NULL) gnutls_free(data);
		gnutls_free(*compress);
		return GNUTLS_E_UNKNOWN_COMPRESSION_ALGORITHM;
	}
	compressed->fragment = data;
	compressed->length = size;
	compressed->type = plaintext->type;
	compressed->version.major = plaintext->version.major;
	compressed->version.minor = plaintext->version.minor;

	return 0;
}

int _gnutls_TLSCompressed2TLSPlaintext(GNUTLS_STATE state,
						     GNUTLSPlaintext**
						     plain,
						     GNUTLSCompressed *
						     compressed)
{
	GNUTLSPlaintext *plaintext;
	int size;
	char* data;

	*plain = gnutls_malloc(sizeof(GNUTLSPlaintext));
	plaintext = *plain;

	data=NULL;
	
	size = gnutls_decompress( state->security_parameters.compression_algorithm, compressed->fragment, compressed->length, &data);
	if (size < 0) {
		if (data!=NULL) gnutls_free(data);
		gnutls_free(*plain);
		return GNUTLS_E_UNKNOWN_COMPRESSION_ALGORITHM;
	}
	plaintext->fragment = data;
	plaintext->length = size;
	plaintext->type = compressed->type;
	plaintext->version.major = compressed->version.major;
	plaintext->version.minor = compressed->version.minor;

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
