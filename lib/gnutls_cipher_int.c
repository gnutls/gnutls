/*
 * Copyright (C) 2000 Nikos Mavroyanopoulos
 *
 * This file is part of GNUTLS.
 *
 *  The GNUTLS library is free software; you can redistribute it and/or
 *  modify it under the terms of the GNU Lesser General Public   
 *  License as published by the Free Software Foundation; either 
 *  version 2.1 of the License, or (at your option) any later version.
 *
 *  This library is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of 
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 *  Lesser General Public License for more details.
 *
 *  You should have received a copy of the GNU Lesser General Public
 *  License along with this library; if not, write to the Free Software
 *  Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA 02111-1307  USA
 *
 */

#include <gnutls_int.h>
#include <gnutls_errors.h>
#include <gnutls_cipher_int.h>
#include <gnutls_datum.h>

GNUTLS_CIPHER_HANDLE _gnutls_cipher_init( gnutls_cipher_algorithm cipher, gnutls_datum key, gnutls_datum iv)
{
GNUTLS_CIPHER_HANDLE ret;

	switch (cipher) {
	case GNUTLS_CIPHER_NULL:
		ret = GNUTLS_CIPHER_FAILED;
		break;
	case GNUTLS_CIPHER_RIJNDAEL_128_CBC:
#ifdef USE_MCRYPT
		ret = mcrypt_module_open( "rijndael-128", NULL, "cbc", NULL);
#else
		ret = gcry_cipher_open(GCRY_CIPHER_RIJNDAEL, GCRY_CIPHER_MODE_CBC, 0);
#endif
		break;
	case GNUTLS_CIPHER_RIJNDAEL_256_CBC:
#ifdef USE_MCRYPT
		ret = mcrypt_module_open( "rijndael-128", NULL, "cbc", NULL);
#else
		ret = gcry_cipher_open(GCRY_CIPHER_RIJNDAEL256, GCRY_CIPHER_MODE_CBC, 0);
#endif
		break;
	case GNUTLS_CIPHER_TWOFISH_128_CBC:
#ifdef USE_MCRYPT
		ret = mcrypt_module_open( "twofish", NULL, "cbc", NULL);
#else
		ret = gcry_cipher_open(GCRY_CIPHER_TWOFISH, GCRY_CIPHER_MODE_CBC, 0);
#endif
		break;
	case GNUTLS_CIPHER_3DES_CBC:
#ifdef USE_MCRYPT
		ret = mcrypt_module_open( "tripledes", NULL, "cbc", NULL);
#else
		ret = gcry_cipher_open(GCRY_CIPHER_3DES, GCRY_CIPHER_MODE_CBC, 0);
#endif
		break;
	case GNUTLS_CIPHER_ARCFOUR_128:
	case GNUTLS_CIPHER_ARCFOUR_40:
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
		if ( mcrypt_generic_init( ret, key.data, key.size, iv.data) < 0) {
			return GNUTLS_CIPHER_FAILED;
		};
#else
		gcry_cipher_setkey(ret, key.data, key.size);
		if (iv.data!=NULL && iv.size>0) gcry_cipher_setiv(ret, iv.data, iv.size);
#endif
	}

return ret;	
}

int _gnutls_cipher_encrypt(GNUTLS_CIPHER_HANDLE handle, void* text, int textlen) {
	if (handle!=GNUTLS_CIPHER_FAILED) {
#ifdef USE_MCRYPT
		mcrypt_generic( handle, text, textlen);
#else
		if (gcry_cipher_encrypt( handle, text, textlen, NULL, textlen)!=0) {
			gnutls_assert();
			return GNUTLS_E_UNKNOWN_ERROR;
		}
#endif
	}
	return 0;
}

int _gnutls_cipher_decrypt(GNUTLS_CIPHER_HANDLE handle, void* ciphertext, int ciphertextlen) {
	if (handle!=GNUTLS_CIPHER_FAILED) {
#ifdef USE_MCRYPT
		mdecrypt_generic( handle, ciphertext, ciphertextlen);
#else
		if (gcry_cipher_decrypt( handle, ciphertext, ciphertextlen, NULL, ciphertextlen)!=0) {
			gnutls_assert();
			return GNUTLS_E_UNKNOWN_ERROR;
		}
#endif
	}
	return 0;
}

void _gnutls_cipher_deinit(GNUTLS_CIPHER_HANDLE handle) {
	if (handle!=GNUTLS_CIPHER_FAILED) {
#ifdef USE_MCRYPT
		mcrypt_generic_end( handle);
#else
		gcry_cipher_close(handle);
#endif
	}
}
