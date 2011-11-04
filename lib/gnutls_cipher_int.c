/*
 * Copyright (C) 2009, 2010 Free Software Foundation, Inc.
 *
 * Author: Nikos Mavrogiannopoulos
 *
 * This file is part of GnuTLS.
 *
 * The GnuTLS is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public License
 * as published by the Free Software Foundation; either version 3 of
 * the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>
 *
 */

#include <gnutls_int.h>
#include <gnutls_errors.h>
#include <gnutls_cipher_int.h>
#include <gnutls_datum.h>
#include <gnutls/crypto.h>
#include <crypto.h>
#include <algorithms.h>

#define SR(x, cleanup) if ( (x)<0 ) { \
  gnutls_assert(); \
  ret = GNUTLS_E_INTERNAL_ERROR; \
  goto cleanup; \
  }

int
_gnutls_cipher_init (cipher_hd_st * handle, gnutls_cipher_algorithm_t cipher,
                     const gnutls_datum_t * key, const gnutls_datum_t * iv, int enc)
{
  int ret = GNUTLS_E_INTERNAL_ERROR;
  const gnutls_crypto_cipher_st *cc = NULL;

  if (cipher == GNUTLS_CIPHER_NULL)
    return gnutls_assert_val(GNUTLS_E_INVALID_REQUEST);

  handle->is_aead = _gnutls_cipher_algo_is_aead(cipher);
  if (handle->is_aead)
     handle->tag_size = gnutls_cipher_get_block_size(cipher);

  /* check if a cipher has been registered
   */
  cc = _gnutls_get_crypto_cipher (cipher);
  if (cc != NULL)
    {
      handle->encrypt = cc->encrypt;
      handle->decrypt = cc->decrypt;
      handle->deinit = cc->deinit;
      handle->auth = cc->auth;
      handle->tag = cc->tag;
      handle->setiv = cc->setiv;

      SR (cc->init (cipher, &handle->handle, enc), cc_cleanup);
      SR (cc->setkey( handle->handle, key->data, key->size), cc_cleanup);
      if (iv)
        {
          SR (cc->setiv( handle->handle, iv->data, iv->size), cc_cleanup);
        }

      return 0;
    }

  handle->encrypt = _gnutls_cipher_ops.encrypt;
  handle->decrypt = _gnutls_cipher_ops.decrypt;
  handle->deinit = _gnutls_cipher_ops.deinit;
  handle->auth = _gnutls_cipher_ops.auth;
  handle->tag = _gnutls_cipher_ops.tag;
  handle->setiv = _gnutls_cipher_ops.setiv;

  /* otherwise use generic cipher interface
   */
  ret = _gnutls_cipher_ops.init (cipher, &handle->handle, enc);
  if (ret < 0)
    {
      gnutls_assert ();
      return ret;
    }

  ret = _gnutls_cipher_ops.setkey(handle->handle, key->data, key->size);
  if (ret < 0)
    {
      gnutls_assert ();
      goto cc_cleanup;
    }

  if (iv)
    {
      ret = _gnutls_cipher_ops.setiv(handle->handle, iv->data, iv->size);
      if (ret < 0)
        {
          gnutls_assert ();
          goto cc_cleanup;
        }
    }

  return 0;

cc_cleanup:

  if (handle->handle)
    handle->deinit (handle->handle);

  return ret;
}

/* Auth_cipher API 
 */
int _gnutls_auth_cipher_init (auth_cipher_hd_st * handle, 
  gnutls_cipher_algorithm_t cipher,
  const gnutls_datum_t * cipher_key,
  const gnutls_datum_t * iv,
  gnutls_mac_algorithm_t mac,
  const gnutls_datum_t * mac_key,
  int ssl_hmac, int enc)
{
int ret;

  memset(handle, 0, sizeof(*handle));

  if (cipher != GNUTLS_CIPHER_NULL)
    {
      ret = _gnutls_cipher_init(&handle->cipher, cipher, cipher_key, iv, enc);
      if (ret < 0)
        return gnutls_assert_val(ret);
    }
  else
    handle->is_null = 1;

  if (mac != GNUTLS_MAC_AEAD)
    {
      handle->is_mac = 1;
      handle->ssl_hmac = ssl_hmac;

      if (ssl_hmac)
        ret = _gnutls_mac_init_ssl3(&handle->mac, mac, mac_key->data, mac_key->size);
      else
        ret = _gnutls_hmac_init(&handle->mac, mac, mac_key->data, mac_key->size);
      if (ret < 0)
        {
          gnutls_assert();
          goto cleanup;
        }

      handle->tag_size = _gnutls_hash_get_algo_len(mac);
    }
  else if (_gnutls_cipher_is_aead(&handle->cipher))
    handle->tag_size = _gnutls_cipher_tag_len(&handle->cipher);

  return 0;
cleanup:
  if (handle->is_null == 0)
    _gnutls_cipher_deinit(&handle->cipher);
  return ret;

}

int _gnutls_auth_cipher_add_auth (auth_cipher_hd_st * handle, const void *text,
                             int textlen)
{
  if (handle->is_mac)
    {
      if (handle->ssl_hmac)
        return _gnutls_hash(&handle->mac, text, textlen);
      else
        return _gnutls_hmac(&handle->mac, text, textlen);
    }
  else if (_gnutls_cipher_is_aead(&handle->cipher))
    return _gnutls_cipher_auth(&handle->cipher, text, textlen);
  else
    return 0;
}

int _gnutls_auth_cipher_encrypt2_tag (auth_cipher_hd_st * handle, const uint8_t *text,
                      int textlen, void *ciphertext, int ciphertextlen, 
                      void* tag_ptr, int tag_size,
                      int auth_size)
{
int ret;

  if (handle->is_mac)
    {
      if (handle->ssl_hmac)
        ret = _gnutls_hash(&handle->mac, text, auth_size);
      else
        ret = _gnutls_hmac(&handle->mac, text, auth_size);
      if (ret < 0)
        {
          gnutls_assert();
          return ret;
        }
      ret = _gnutls_auth_cipher_tag(handle, tag_ptr, tag_size);
      if (ret < 0)
        return gnutls_assert_val(ret);

      if (handle->is_null==0)
        {
          ret = _gnutls_cipher_encrypt2(&handle->cipher, text, textlen, ciphertext, ciphertextlen);
          if (ret < 0)
            return gnutls_assert_val(ret);
        }
    }
  else if (_gnutls_cipher_is_aead(&handle->cipher))
    {
      ret = _gnutls_cipher_encrypt2(&handle->cipher, text, textlen, ciphertext, ciphertextlen);
      if (ret < 0)
        return gnutls_assert_val(ret);

      ret = _gnutls_auth_cipher_tag(handle, tag_ptr, tag_size);
      if (ret < 0)
        return gnutls_assert_val(ret);
    }

  return 0;
}

int _gnutls_auth_cipher_decrypt2 (auth_cipher_hd_st * handle,
                             const void *ciphertext, int ciphertextlen,
                             void *text, int textlen)
{
int ret;

  if (handle->is_null==0)
    {
      ret = _gnutls_cipher_decrypt2(&handle->cipher, ciphertext, ciphertextlen, 
        text, textlen);
      if (ret < 0)
        return gnutls_assert_val(ret);
    }

  if (handle->is_mac)
    {
      /* The MAC is not to be hashed */
      textlen -= handle->tag_size;

      if (handle->ssl_hmac)
        return _gnutls_hash(&handle->mac, text, textlen);
      else
        return _gnutls_hmac(&handle->mac, text, textlen);
    }

  return 0;
}

int _gnutls_auth_cipher_tag(auth_cipher_hd_st * handle, void* tag, int tag_size)
{
int ret = 0;
  if (handle->is_mac)
    {
      if (handle->ssl_hmac)
        {
          ret = _gnutls_mac_output_ssl3 (&handle->mac, tag);
          if (ret < 0)
            return gnutls_assert_val(ret);

          _gnutls_mac_reset_ssl3 (&handle->mac);
        }
      else
        {
          _gnutls_hmac_output (&handle->mac, tag);
          _gnutls_hmac_reset (&handle->mac);
        }
    }
  else if (_gnutls_cipher_is_aead(&handle->cipher))
    {
      _gnutls_cipher_tag(&handle->cipher, tag, tag_size);
    }
    
  return 0;
}

void _gnutls_auth_cipher_deinit (auth_cipher_hd_st * handle)
{
  if (handle->is_mac)
    {
      if (handle->ssl_hmac) /* failure here doesn't matter */
        _gnutls_mac_deinit_ssl3 (&handle->mac, NULL);
      else
        _gnutls_hmac_deinit(&handle->mac, NULL);
    }
  if (handle->is_null==0)
    _gnutls_cipher_deinit(&handle->cipher);
}
