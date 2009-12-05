/*
 * Copyright (C) 2000, 2004, 2005, 2008 Free Software Foundation
 *
 * Author: Nikos Mavrogiannopoulos
 *
 * This file is part of GNUTLS.
 *
 * The GNUTLS library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public License
 * as published by the Free Software Foundation; either version 2.1 of
 * the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301,
 * USA
 *
 */

#include <gnutls_int.h>
#include <gnutls_errors.h>
#include <gnutls_cipher_int.h>
#include <gnutls_datum.h>
#include <gnutls/crypto.h>
#include <crypto.h>

int
gnutls_cipher_init (gnutls_cipher_hd_t * handle, gnutls_cipher_algorithm_t cipher,
		     const gnutls_datum_t * key, const gnutls_datum_t * iv)
{
  *handle = gnutls_malloc(sizeof(cipher_hd_st));
  if (*handle == NULL) {
    gnutls_assert();
    return GNUTLS_E_MEMORY_ERROR;
  }
  
  return _gnutls_cipher_init(((cipher_hd_st*)*handle), cipher, key, iv);
}

int gnutls_cipher_encrypt (gnutls_cipher_hd_t handle, void *text, int textlen)
{
  return _gnutls_cipher_encrypt((cipher_hd_st*)handle, text, textlen);
}

int
gnutls_cipher_decrypt (gnutls_cipher_hd_t handle, void *ciphertext,
			int ciphertextlen)
{
  return _gnutls_cipher_decrypt((cipher_hd_st*)handle, ciphertext, ciphertextlen);
}

void
gnutls_cipher_deinit (gnutls_cipher_hd_t handle)
{
  return _gnutls_cipher_deinit((cipher_hd_st*)handle);
}


/* HMAC */
int
gnutls_hmac_init (gnutls_hmac_hd_t * dig, gnutls_digest_algorithm_t algorithm,
		   const void *key, int keylen)
{
  *dig = gnutls_malloc(sizeof(digest_hd_st));
  if (*dig == NULL) {
    gnutls_assert();
    return GNUTLS_E_MEMORY_ERROR;
  }
  
  return _gnutls_hmac_init(((digest_hd_st*)*dig), algorithm, key, keylen);
}

int gnutls_hmac (gnutls_hmac_hd_t handle, const void *text, size_t textlen)
{
  return _gnutls_hmac((digest_hd_st*)handle, text, textlen);
}

void
gnutls_hmac_output (gnutls_hmac_hd_t handle, void *digest)
{
  return _gnutls_hmac_output((digest_hd_st*)handle, digest);
}

void
gnutls_hmac_deinit (gnutls_hmac_hd_t handle, void *digest)
{
  _gnutls_hmac_deinit((digest_hd_st*)handle, digest);
}

int gnutls_hmac_get_len( gnutls_mac_algorithm_t algorithm)
{
  return _gnutls_hmac_get_algo_len(algorithm);
}

int gnutls_hmac_fast( gnutls_mac_algorithm_t algorithm, const void* key, int keylen, 
	const void* text, size_t textlen, void* digest)
{
  return _gnutls_hmac_fast(algorithm, key, keylen, text, textlen, digest);
}

/* HASH */
int
gnutls_hash_init (gnutls_hash_hd_t * dig, gnutls_digest_algorithm_t algorithm)
{
  *dig = gnutls_malloc(sizeof(digest_hd_st));
  if (*dig == NULL) {
    gnutls_assert();
    return GNUTLS_E_MEMORY_ERROR;
  }
  
  return _gnutls_hash_init(((digest_hd_st*)*dig), algorithm);
}

int gnutls_hash (gnutls_hash_hd_t handle, const void *text, size_t textlen)
{
  return _gnutls_hash((digest_hd_st*)handle, text, textlen);
}

void
gnutls_hash_output (gnutls_hash_hd_t handle, void *digest)
{
  return _gnutls_hash_output((digest_hd_st*)handle, digest);
}

void
gnutls_hash_deinit (gnutls_hash_hd_t handle, void *digest)
{
  _gnutls_hash_deinit((digest_hd_st*)handle, digest);
}

int gnutls_hash_get_len( gnutls_digest_algorithm_t algorithm)
{
  return _gnutls_hash_get_algo_len(algorithm);
}

int gnutls_hash_fast (gnutls_digest_algorithm_t algorithm,
                   const void *text, size_t textlen, void *digest)
{
  return _gnutls_hash_fast(algorithm, text, textlen, digest);
}
