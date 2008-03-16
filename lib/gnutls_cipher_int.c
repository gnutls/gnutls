/*
 * Copyright (C) 2000, 2004, 2005 Free Software Foundation
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

#define SR(x) if ( (x)<0 ) { \
  gnutls_assert(); \
  err = GNUTLS_E_INTERNAL_ERROR; \
  goto cc_cleanup; \
  }

int
_gnutls_cipher_init (cipher_hd_st* handle, gnutls_cipher_algorithm_t cipher,
		     const gnutls_datum_t * key, const gnutls_datum_t * iv)
{
  int err = GC_INVALID_CIPHER;	/* doesn't matter */
  gnutls_crypto_cipher_st * cc = NULL;

  /* check if a cipher has been registered 
   */
  cc = _gnutls_get_registered_cipher( cipher);
  if (cc != NULL) {
    handle->registered = 1;
    handle->hd.rh.cc = cc;
    SR( cc->init(&handle->hd.rh.ctx) );
    SR(cc->setkey( handle->hd.rh.ctx, key->data, key->size));
    if (iv->data && iv->size && cc->setiv)
      SR(cc->setiv( handle->hd.rh.ctx, iv->data, iv->size));
    return 0;
  }

  handle->registered = 0;  
  /* otherwise use included ciphers 
   */
  switch (cipher)
    {
    case GNUTLS_CIPHER_AES_128_CBC:
      err = gc_cipher_open (GC_AES128, GC_CBC, &handle->hd.gc);
      break;

    case GNUTLS_CIPHER_AES_256_CBC:
      err = gc_cipher_open (GC_AES256, GC_CBC, &handle->hd.gc);
      break;

    case GNUTLS_CIPHER_3DES_CBC:
      err = gc_cipher_open (GC_3DES, GC_CBC, &handle->hd.gc);
      break;

    case GNUTLS_CIPHER_DES_CBC:
      err = gc_cipher_open (GC_DES, GC_CBC, &handle->hd.gc);
      break;

    case GNUTLS_CIPHER_ARCFOUR_128:
      err = gc_cipher_open (GC_ARCFOUR128, GC_STREAM, &handle->hd.gc);
      break;

    case GNUTLS_CIPHER_ARCFOUR_40:
      err = gc_cipher_open (GC_ARCFOUR40, GC_STREAM, &handle->hd.gc);
      break;

    case GNUTLS_CIPHER_RC2_40_CBC:
      err = gc_cipher_open (GC_ARCTWO40, GC_CBC, &handle->hd.gc);
      break;

#ifdef	ENABLE_CAMELLIA
    case GNUTLS_CIPHER_CAMELLIA_128_CBC:
      err = gc_cipher_open (GC_CAMELLIA128, GC_CBC, &handle->hd.gc);
      break;

    case GNUTLS_CIPHER_CAMELLIA_256_CBC:
      err = gc_cipher_open (GC_CAMELLIA256, GC_CBC, &handle->hd.gc);
      break;
#endif

    default:
      gnutls_assert();
      return GNUTLS_E_INVALID_REQUEST;
    }

  if (err == 0)
    {
      gc_cipher_setkey (handle->hd.gc, key->size, key->data);
      if (iv->data != NULL && iv->size > 0)
	gc_cipher_setiv (handle->hd.gc, iv->size, iv->data);
    }
  else if (cipher != GNUTLS_CIPHER_NULL)
    {
      gnutls_assert ();
      _gnutls_x509_log ("Crypto cipher[%d] error: %d\n", cipher, err);
      return GNUTLS_E_INTERNAL_ERROR;
      /* FIXME: gc_strerror */
    }

  return 0;

cc_cleanup:

  if (handle->hd.rh.cc)
    cc->deinit(handle->hd.rh.ctx);
  
  return err;
}

int
_gnutls_cipher_encrypt (const cipher_hd_st* handle, void *text, int textlen)
{
  if (handle != GNUTLS_CIPHER_FAILED)
    {
      if (handle->registered) {
        return handle->hd.rh.cc->encrypt( handle->hd.rh.ctx, text, textlen, text, textlen);
      }
      if (gc_cipher_encrypt_inline (handle->hd.gc, textlen, text) != 0)
	{
	  gnutls_assert ();
	  return GNUTLS_E_INTERNAL_ERROR;
	}
    }
  return 0;
}

int
_gnutls_cipher_decrypt (const cipher_hd_st *handle, void *ciphertext,
			int ciphertextlen)
{
  if (handle != GNUTLS_CIPHER_FAILED)
    {
      if (handle->registered) {
        return handle->hd.rh.cc->decrypt( handle->hd.rh.ctx, ciphertext, ciphertextlen, ciphertext, ciphertextlen);
      }
      if (gc_cipher_decrypt_inline (handle->hd.gc, ciphertextlen, ciphertext) != 0)
	{
	  gnutls_assert ();
	  return GNUTLS_E_INTERNAL_ERROR;
	}
    }
  return 0;
}

void
_gnutls_cipher_deinit (cipher_hd_st* handle)
{
  if (handle != GNUTLS_CIPHER_FAILED)
    {
      if (handle->registered) {
        return handle->hd.rh.cc->deinit( handle->hd.rh.ctx);
      }
      gc_cipher_close (handle);
    }
}
