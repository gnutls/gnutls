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

#include "gnutls_int.h"
#include "gnutls_compress.h"
#include "gnutls_errors.h"
#include "gnutls_compress_int.h"

/* These functions allocate the return value internally
 */
int _gnutls_m_plaintext2compressed(GNUTLS_STATE state,
						     gnutls_datum*
						     compress,
						     gnutls_datum plaintext)
{
	int size;
	char *data;
	
	data=NULL;
	
	size = _gnutls_compress( state->connection_state.write_compression_state,
		plaintext.data, plaintext.size, &data, MAX_RECORD_SIZE+1024);
	if (size < 0) {
		gnutls_assert();
		return GNUTLS_E_COMPRESSION_FAILED;
	}
	compress->data = data;
	compress->size = size;

	return 0;
}

int _gnutls_m_compressed2plaintext(GNUTLS_STATE state,
						     gnutls_datum* plain,
						     gnutls_datum
						     compressed)
{
	int size;
	char* data;

	data=NULL;
	
	size = _gnutls_decompress( state->connection_state.read_compression_state,
		compressed.data, compressed.size, &data, MAX_RECORD_SIZE);
	if (size < 0) {
		gnutls_assert();
		return GNUTLS_E_DECOMPRESSION_FAILED;
	}
	plain->data = data;
	plain->size = size;

	return 0;
}




