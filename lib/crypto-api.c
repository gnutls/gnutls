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
gnutls_hash_init (gnutls_hash_hd_t * dig, gnutls_digest_algorithm_t algorithm,
		   const void *key, int keylen)
{
  *dig = gnutls_malloc(sizeof(hash_hd_st));
  if (*dig == NULL) {
    gnutls_assert();
    return GNUTLS_E_MEMORY_ERROR;
  }
  
  return _gnutls_hash_init(((hash_hd_st*)*dig), algorithm, key, keylen);
}

int gnutls_hash (gnutls_hash_hd_t handle, const void *text, size_t textlen)
{
  return _gnutls_hash((hash_hd_st*)handle, text, textlen);
}

void
gnutls_hash_output (gnutls_hash_hd_t handle, void *digest)
{
  return _gnutls_hash_output((hash_hd_st*)handle, digest);
}

void
gnutls_hash_reset (gnutls_hash_hd_t handle)
{
  _gnutls_hash_reset((hash_hd_st*)handle);
}

void
gnutls_hash_deinit (gnutls_hash_hd_t handle, void *digest)
{
  _gnutls_hash_deinit((hash_hd_st*)handle, digest);
}
