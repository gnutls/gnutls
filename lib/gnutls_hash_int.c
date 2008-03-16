/*
 * Copyright (C) 2000, 2001, 2004, 2005, 2007, 2008 Free Software Foundation
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

/* This file handles all the internal functions that cope with hashes
 * and HMACs.
 */

#include <gnutls_int.h>
#include <gnutls_hash_int.h>
#include <gnutls_errors.h>

static inline Gc_hash _gnutls_mac2gc (gnutls_mac_algorithm_t mac)
{
  switch (mac)
    {
    case GNUTLS_MAC_NULL:
      return -1;
      break;
    case GNUTLS_MAC_SHA1:
      return GC_SHA1;
      break;
    case GNUTLS_MAC_SHA256:
      return GC_SHA256;
      break;
    case GNUTLS_MAC_SHA384:
      return GC_SHA384;
      break;
    case GNUTLS_MAC_SHA512:
      return GC_SHA512;
      break;
    case GNUTLS_MAC_MD5:
      return GC_MD5;
      break;
    case GNUTLS_MAC_RMD160:
      return GC_RMD160;
      break;
    case GNUTLS_MAC_MD2:
      return GC_MD2;
      break;
    default:
      gnutls_assert ();
      return -1;
    }
  return -1;
}

int
_gnutls_hash_init (digest_hd_st* dig, gnutls_mac_algorithm_t algorithm)
{
  int result;
  gnutls_crypto_digest_st * cc = NULL;

  dig->algorithm = algorithm;

  /* check if a digest has been registered 
   */
  cc = _gnutls_get_crypto_digest( algorithm);
  if (cc != NULL) {
    dig->registered = 1;
    dig->hd.rh.cc = cc;
    if (cc->init(& dig->hd.rh.ctx) < 0) {
      gnutls_assert();
      return GNUTLS_E_HASH_FAILED;
    }
    return 0;
  }

  dig->registered = 0;  

  result = gc_hash_open (_gnutls_mac2gc (algorithm), 0, &dig->hd.gc);
  if (result)
    {
      gnutls_assert ();
      return GNUTLS_E_HASH_FAILED;
    }

  return 0;
}

int
_gnutls_hash_get_algo_len (gnutls_mac_algorithm_t algorithm)
{
  int ret;

  ret = gc_hash_digest_length (_gnutls_mac2gc (algorithm));

  return ret;

}

int
_gnutls_hash (const digest_hd_st* handle, const void *text, size_t textlen)
{
  if (textlen > 0) {
    if (handle->registered) {
      return handle->hd.rh.cc->hash( handle->hd.rh.ctx, text, textlen);
    }
    gc_hash_write (handle->hd.gc, textlen, text);
  }
  return 0;
}

int _gnutls_hash_copy (digest_hd_st* dst, digest_hd_st* src)
{
  int result;

  dst->algorithm = src->algorithm;
  dst->key = NULL;		/* it's a hash anyway */
  dst->keysize = 0;
  dst->registered = src->registered;

  if (src->registered) {
    return src->hd.rh.cc->copy( &dst->hd.rh.ctx, src->hd.rh.ctx);
  }

  result = gc_hash_clone (src->hd.gc, &dst->hd.gc);

  if (result)
    {
      return GNUTLS_E_HASH_FAILED;
    }

  return 0;
}

void
_gnutls_hash_deinit (digest_hd_st* handle, void *digest)
{
  const opaque *mac;
  int maclen;

  maclen = _gnutls_hash_get_algo_len (handle->algorithm);

  if (handle->registered && handle->hd.rh.ctx != NULL) {
    handle->hd.rh.cc->output( handle->hd.rh.ctx, digest, maclen);
    handle->hd.rh.cc->deinit( handle->hd.rh.ctx);
    return;
  }

  mac = gc_hash_read (handle->hd.gc);
  if (digest != NULL)
    memcpy (digest, mac, maclen);

  gc_hash_close (handle->hd.gc);
}


int _gnutls_hmac_init (digest_hd_st *dig, gnutls_mac_algorithm_t algorithm,
		   const void *key, int keylen)
{
  int result;
  gnutls_crypto_digest_st * cc = NULL;

  dig->algorithm = algorithm;
  dig->key = key;
  dig->keysize = keylen;

  /* check if a digest has been registered 
   */
  cc = _gnutls_get_crypto_mac( algorithm);
  if (cc != NULL) {
    dig->registered = 1;

    dig->hd.rh.cc = cc;
    if (cc->init(&dig->hd.rh.ctx) < 0) {
      gnutls_assert();
      return GNUTLS_E_HASH_FAILED;
    }

    if (cc->setkey( dig->hd.rh.ctx, key, keylen) < 0) {
      gnutls_assert();
      cc->deinit(dig->hd.rh.ctx);
      return GNUTLS_E_HASH_FAILED;
    }

    return 0;
  }

  dig->registered = 0;  

  result = gc_hash_open (_gnutls_mac2gc (algorithm), GC_HMAC, &dig->hd.gc);
  if (result)
    {
      return GNUTLS_E_HASH_FAILED;
    }

  gc_hash_hmac_setkey (dig->hd.gc, keylen, key);

  return 0;
}

void
_gnutls_hmac_deinit (digest_hd_st* handle, void *digest)
{
  const opaque *mac;
  int maclen;

  maclen = _gnutls_hash_get_algo_len (handle->algorithm);

  if (handle->registered && handle->hd.rh.ctx != NULL) {
    handle->hd.rh.cc->output( handle->hd.rh.ctx, digest, maclen);
    handle->hd.rh.cc->deinit( handle->hd.rh.ctx);
    return;
  }

  mac = gc_hash_read (handle->hd.gc);

  if (digest != NULL)
    memcpy (digest, mac, maclen);

  gc_hash_close (handle->hd.gc);

}

inline static int
get_padsize (gnutls_mac_algorithm_t algorithm)
{
  switch (algorithm)
    {
    case GNUTLS_MAC_MD5:
      return 48;
    case GNUTLS_MAC_SHA1:
      return 40;
    default:
      return 0;
    }
}

int _gnutls_mac_init_ssl3 (digest_hd_st* ret, gnutls_mac_algorithm_t algorithm, void *key,
		       int keylen)
{
  opaque ipad[48];
  int padsize, result;

  padsize = get_padsize (algorithm);
  if (padsize == 0)
    {
      gnutls_assert ();
      return GNUTLS_E_HASH_FAILED;
    }

  memset (ipad, 0x36, padsize);

  result = _gnutls_hash_init (ret, algorithm);
  if (result < 0)
    {
      gnutls_assert();
      return result;
    }

    ret->key = key;
    ret->keysize = keylen;

    if (keylen > 0)
      _gnutls_hash (ret, key, keylen);
    _gnutls_hash (ret, ipad, padsize);

  return 0;
}

void
_gnutls_mac_deinit_ssl3 (digest_hd_st* handle, void *digest)
{
  opaque ret[MAX_HASH_SIZE];
  digest_hd_st td;
  opaque opad[48];
  int padsize;
  int block, rc;

  padsize = get_padsize (handle->algorithm);
  if (padsize == 0)
    {
      gnutls_assert ();
      return;
    }

  memset (opad, 0x5C, padsize);

  rc = _gnutls_hash_init (&td, handle->algorithm);
  if (rc < 0)
    {
      gnutls_assert();
      return;
    }

    if (handle->keysize > 0)
      _gnutls_hash (&td, handle->key, handle->keysize);

    _gnutls_hash (&td, opad, padsize);
    block = _gnutls_hmac_get_algo_len (handle->algorithm);
    _gnutls_hash_deinit (handle, ret);	/* get the previous hash */
    _gnutls_hash (&td, ret, block);

    _gnutls_hash_deinit (&td, digest);
    
    return;
}

void
_gnutls_mac_deinit_ssl3_handshake (digest_hd_st* handle,
				   void *digest, opaque * key,
				   uint32_t key_size)
{
  opaque ret[MAX_HASH_SIZE];
  digest_hd_st td;
  opaque opad[48];
  opaque ipad[48];
  int padsize;
  int block, rc;

  padsize = get_padsize (handle->algorithm);
  if (padsize == 0)
    {
      gnutls_assert ();
      return;
    }

  memset (opad, 0x5C, padsize);
  memset (ipad, 0x36, padsize);

  rc = _gnutls_hash_init (&td, handle->algorithm);
  if (rc < 0)
    {
      gnutls_assert();
      return;
    }

    if (key_size > 0)
      _gnutls_hash (&td, key, key_size);

    _gnutls_hash (&td, opad, padsize);
    block = _gnutls_hmac_get_algo_len (handle->algorithm);

    if (key_size > 0)
       _gnutls_hash (handle, key, key_size);
    _gnutls_hash (handle, ipad, padsize);
    _gnutls_hash_deinit (handle, ret);	/* get the previous hash */

    _gnutls_hash (&td, ret, block);

    _gnutls_hash_deinit (&td, digest);

    return;
}

static int
ssl3_sha (int i, opaque * secret, int secret_len,
	  opaque * rnd, int rnd_len, void *digest)
{
  int j, ret;
  opaque text1[26];

  digest_hd_st td;

  for (j = 0; j < i + 1; j++)
    {
      text1[j] = 65 + i;	/* A==65 */
    }

  ret = _gnutls_hash_init (&td, GNUTLS_MAC_SHA1);
  if (ret < 0)
    {
      gnutls_assert ();
      return ret;
    }

  _gnutls_hash (&td, text1, i + 1);
  _gnutls_hash (&td, secret, secret_len);
  _gnutls_hash (&td, rnd, rnd_len);

  _gnutls_hash_deinit (&td, digest);
  return 0;
}

static int
ssl3_md5 (int i, opaque * secret, int secret_len,
	  opaque * rnd, int rnd_len, void *digest)
{
  opaque tmp[MAX_HASH_SIZE];
  digest_hd_st td;
  int ret;

  ret = _gnutls_hash_init (&td, GNUTLS_MAC_MD5);
  if (ret < 0)
    {
      gnutls_assert ();
      return ret;
    }

  _gnutls_hash (&td, secret, secret_len);

  ret = ssl3_sha (i, secret, secret_len, rnd, rnd_len, tmp);
  if (ret < 0)
    {
      gnutls_assert ();
      _gnutls_hash_deinit (&td, digest);
      return ret;
    }

  _gnutls_hash (&td, tmp, _gnutls_hash_get_algo_len (GNUTLS_MAC_SHA1));

  _gnutls_hash_deinit (&td, digest);
  return 0;
}

int
_gnutls_ssl3_hash_md5 (void *first, int first_len,
		       void *second, int second_len, int ret_len,
		       opaque * ret)
{
  opaque digest[MAX_HASH_SIZE];
  digest_hd_st td;
  int block = _gnutls_hash_get_algo_len (GNUTLS_MAC_MD5);
  int rc;

  rc = _gnutls_hash_init (&td, GNUTLS_MAC_MD5);
  if (rc < 0)
    {
      gnutls_assert ();
      return rc;
    }

  _gnutls_hash (&td, first, first_len);
  _gnutls_hash (&td, second, second_len);

  _gnutls_hash_deinit (&td, digest);

  if (ret_len > block)
    {
      gnutls_assert ();
      return GNUTLS_E_INTERNAL_ERROR;
    }

  memcpy (ret, digest, ret_len);

  return 0;

}

int
_gnutls_ssl3_generate_random (void *secret, int secret_len,
			      void *rnd, int rnd_len,
			      int ret_bytes, opaque * ret)
{
  int i = 0, copy, output_bytes;
  opaque digest[MAX_HASH_SIZE];
  int block = _gnutls_hash_get_algo_len (GNUTLS_MAC_MD5);
  int result, times;

  output_bytes = 0;
  do
    {
      output_bytes += block;
    }
  while (output_bytes < ret_bytes);

  times = output_bytes / block;

  for (i = 0; i < times; i++)
    {

      result = ssl3_md5 (i, secret, secret_len, rnd, rnd_len, digest);
      if (result < 0)
	{
	  gnutls_assert ();
	  return result;
	}

      if ((1 + i) * block < ret_bytes)
	{
	  copy = block;
	}
      else
	{
	  copy = ret_bytes - (i) * block;
	}

      memcpy (&ret[i * block], digest, copy);
    }

  return 0;
}
