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

#define SR(x, cleanup) if ( (x)<0 ) { \
  gnutls_assert(); \
  ret = GNUTLS_E_INTERNAL_ERROR; \
  goto cleanup; \
  }

int
_gnutls_cipher_init (cipher_hd_st* handle, gnutls_cipher_algorithm_t cipher,
		     const gnutls_datum_t * key, const gnutls_datum_t * iv)
{
  int ret = GNUTLS_E_INTERNAL_ERROR;
  gnutls_crypto_single_cipher_st * cc = NULL;

  /* check if a cipher has been registered 
   */
  cc = _gnutls_get_crypto_cipher( cipher);
  if (cc != NULL) {
    handle->registered = 1;
    handle->hd.rh.cc = cc;
    SR(cc->init(&handle->hd.rh.ctx), cc_cleanup);
    SR(cc->setkey( handle->hd.rh.ctx, key->data, key->size), cc_cleanup);
    if (iv->data && iv->size && cc->setiv)
      SR(cc->setiv( handle->hd.rh.ctx, iv->data, iv->size), cc_cleanup);
    return 0;
  }

  handle->registered = 0;
  
  /* otherwise use generic cipher interface
   */
  ret = _gnutls_cipher_ops.init( cipher, &handle->hd.gc);
  if (ret < 0) {
    gnutls_assert();
    return ret;
  }

  ret = _gnutls_cipher_ops.setkey (handle->hd.gc, key->data, key->size);
  if (ret < 0) {
    _gnutls_cipher_ops.deinit( handle->hd.gc);
    gnutls_assert();
    return ret;
  }

  if (iv->data != NULL && iv->size > 0)
    _gnutls_cipher_ops.setiv (handle->hd.gc, iv->data, iv->size);
    
  return 0;

cc_cleanup:

  if (handle->hd.rh.cc)
    cc->deinit(handle->hd.rh.ctx);
  
  return ret;
}

int
_gnutls_cipher_encrypt (const cipher_hd_st* handle, void *text, int textlen)
{
  if (handle != NULL)
    {
      if (handle->registered) {
        if (handle->hd.rh.ctx == NULL) return 0;
        return handle->hd.rh.cc->encrypt( handle->hd.rh.ctx, text, textlen, text, textlen);
      }
      
      if (handle->hd.gc == NULL) return 0;
      return _gnutls_cipher_ops.encrypt( handle->hd.gc, text, textlen, text, textlen);
    }
  return 0;
}

int
_gnutls_cipher_decrypt (const cipher_hd_st *handle, void *ciphertext,
			int ciphertextlen)
{
  if (handle != NULL)
    {
      if (handle->registered) {
        if (handle->hd.rh.ctx == NULL) return 0;
        return handle->hd.rh.cc->decrypt( handle->hd.rh.ctx, ciphertext, ciphertextlen, ciphertext, ciphertextlen);
      }

      if (handle->hd.gc == NULL) return 0;
      return _gnutls_cipher_ops.decrypt (handle->hd.gc, ciphertext, ciphertextlen, ciphertext, ciphertextlen);
    }
  return 0;
}

void
_gnutls_cipher_deinit (cipher_hd_st* handle)
{
  if (handle != NULL)
    {
      if (handle->registered && handle->hd.rh.ctx != NULL) {
        return handle->hd.rh.cc->deinit( handle->hd.rh.ctx);
      }
      _gnutls_cipher_ops.deinit (handle->hd.gc);
    }
}
