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
#include <gnutls_int.h>
#include <gnutls_errors.h>
#include <gnutls_cipher_int.h>

GNUTLS_CIPHER_HANDLE gnutls_cipher_init( BulkCipherAlgorithm cipher, void* key, int keysize, void* iv, int ivsize)
{
GNUTLS_CIPHER_HANDLE ret;

	switch (cipher) {
	case GNUTLS_NULL_CIPHER:
		ret = GNUTLS_CIPHER_FAILED;
		break;
	case GNUTLS_RIJNDAEL:
#ifdef USE_MCRYPT
		ret = mcrypt_module_open( "rijndael-128", NULL, "cbc", NULL);
#else
		ret = gcry_cipher_open(GCRY_CIPHER_RIJNDAEL, GCRY_CIPHER_MODE_CBC, 0);
#endif
		break;
	case GNUTLS_3DES:
#ifdef USE_MCRYPT
		ret = mcrypt_module_open( "tripledes", NULL, "cbc", NULL);
#else
		ret = gcry_cipher_open(GCRY_CIPHER_3DES, GCRY_CIPHER_MODE_CBC, 0);
#endif
		break;
	case GNUTLS_ARCFOUR:
#ifdef USE_MCRYPT
		ret = mcrypt_module_open( "arcfour", NULL, "stream", NULL);
#else
		ret = gcry_cipher_open(GCRY_CIPHER_ARCFOUR, GCRY_CIPHER_MODE_STREAM, 0);
#endif
		break;
	default:
		ret = GNUTLS_CIPHER_FAILED;
	}
	if (ret!=GNUTLS_CIPHER_FAILED) {
#ifdef USE_MCRYPT
		/* ivsize is assumed to be blocksize */
		if ( mcrypt_generic_init( ret, key, keysize, iv) < 0) {
			return GNUTLS_CIPHER_FAILED;
		}; 
#else
		gcry_cipher_setkey(ret, key, keysize);
		if (iv!=NULL && ivsize>0) gcry_cipher_setiv(ret, iv, ivsize);
#endif
	}

return ret;	
}

int gnutls_cipher_encrypt(GNUTLS_CIPHER_HANDLE handle, void* text, int textlen) {
	if (handle!=NULL) {
#ifdef USE_MCRYPT
		mcrypt_generic( handle, text, textlen);
#else
		gcry_cipher_encrypt( handle, text, textlen, text, textlen);
#endif
	}
	return 0;
}

int gnutls_cipher_decrypt(GNUTLS_CIPHER_HANDLE handle, void* ciphertext, int ciphertextlen) {
	if (handle!=NULL) {
#ifdef USE_MCRYPT
		mdecrypt_generic( handle, ciphertext, ciphertextlen);
#else
		gcry_cipher_decrypt( handle, ciphertext, ciphertextlen, ciphertext, ciphertextlen);
#endif
	}
	return 0;
}

void gnutls_cipher_deinit(GNUTLS_CIPHER_HANDLE handle) {
	if (handle!=NULL) {
#ifdef USE_MCRYPT
		mcrypt_generic_end( handle);
#else
		gcry_cipher_close(handle);
#endif
	}
}
