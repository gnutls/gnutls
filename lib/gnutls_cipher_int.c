/*
 * Copyright (C) 2000 Nikos Mavroyanopoulos
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

GNUTLS_CIPHER_HANDLE gnutls_cipher_init( BulkCipherAlgorithm cipher, void* key, int keysize, void* iv, int ivsize)
{
GNUTLS_CIPHER_HANDLE ret;

	switch (cipher) {
	case GNUTLS_NULL:
		ret = GNUTLS_CIPHER_FAILED;
		break;
	case GNUTLS_3DES:
		ret = gcry_cipher_open(GCRY_CIPHER_3DES, GCRY_CIPHER_MODE_CBC, 0);
		break;
	default:
		ret = GNUTLS_CIPHER_FAILED;
	}
	if (ret!=NULL) {
		gcry_cipher_setkey(ret, key, keysize);
		gcry_cipher_setiv(ret, iv, ivsize);
	}

return ret;	
}

int gnutls_cipher_encrypt(GNUTLS_CIPHER_HANDLE handle, void* text, int textlen) {
	if (handle!=NULL) {
		gcry_cipher_encrypt( handle, text, textlen, text, textlen);
	}
	return 0;
}

int gnutls_cipher_decrypt(GNUTLS_CIPHER_HANDLE handle, void* ciphertext, int ciphertextlen) {
	if (handle!=NULL) {
		gcry_cipher_decrypt( handle, ciphertext, ciphertextlen, ciphertext, ciphertextlen);
	}
	return 0;
}

void gnutls_cipher_deinit(GNUTLS_CIPHER_HANDLE handle) {
	if (handle!=NULL) {
		gcry_cipher_close(handle);
	}
}
