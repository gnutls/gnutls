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

#ifndef GNUTLS_CIPHER_INT
# define GNUTLS_CIPHER_INT

#ifdef USE_MCRYPT
# include <mcrypt.h>
# define GNUTLS_CIPHER_HANDLE MCRYPT
# define GNUTLS_CIPHER_FAILED MCRYPT_FAILED
#else
# include <gcrypt.h>
# define GNUTLS_CIPHER_HANDLE GCRY_CIPHER_HD
# define GNUTLS_CIPHER_FAILED NULL
#endif

GNUTLS_CIPHER_HANDLE gnutls_cipher_init( BulkCipherAlgorithm cipher, void* key, int keysize, void* iv, int ivsize);
int gnutls_cipher_encrypt(GNUTLS_CIPHER_HANDLE handle, void* text, int textlen);
int gnutls_cipher_decrypt(GNUTLS_CIPHER_HANDLE handle, void* ciphertext, int ciphertextlen);
void gnutls_cipher_deinit(GNUTLS_CIPHER_HANDLE handle);

#endif /* GNUTLS_CIPHER_INT */
