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
#include "gnutls_errors.h"
#include "gnutls_algorithms.h"

/* Plaintext Handling */
int _gnutls_text2TLSPlaintext(GNUTLS_STATE state, ContentType type, GNUTLSPlaintext** plain, const char *text, uint16 length)
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
	plaintext->version.major = _gnutls_version_get_major(state->connection_state.version);
	plaintext->version.minor = _gnutls_version_get_minor(state->connection_state.version);

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
