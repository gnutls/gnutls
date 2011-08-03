/*
 * Copyright (C) 2000-2011 Free Software Foundation, Inc.
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

#ifndef GNUTLS_HASH_INT_H
#define GNUTLS_HASH_INT_H

#include <gnutls_int.h>
#include <gnutls/crypto.h>
#include <crypto-backend.h>
#include <crypto.h>

/* for message digests */

extern int crypto_mac_prio;
extern gnutls_crypto_mac_st _gnutls_mac_ops;

extern int crypto_digest_prio;
extern gnutls_crypto_digest_st _gnutls_digest_ops;

typedef int (*hash_func) (void *handle, const void *text, size_t size);
typedef int (*copy_func) (void **dst_ctx, void *src_ctx);
typedef void (*reset_func) (void *ctx);
typedef int (*output_func) (void *src_ctx, void *digest, size_t digestsize);
typedef void (*deinit_func) (void *handle);

typedef struct
{
  gnutls_mac_algorithm_t algorithm;
  const void *key;
  int keysize;

  hash_func hash;
  copy_func copy;
  reset_func reset;
  output_func output;
  deinit_func deinit;

  void *handle;
} digest_hd_st;

/* basic functions */
int _gnutls_hmac_init (digest_hd_st *, gnutls_mac_algorithm_t algorithm,
                       const void *key, int keylen);
int _gnutls_hash_get_algo_len (gnutls_digest_algorithm_t algorithm);
#define _gnutls_hmac_get_algo_len _gnutls_hash_get_algo_len
int _gnutls_hmac_fast (gnutls_mac_algorithm_t algorithm, const void *key,
                       int keylen, const void *text, size_t textlen,
                       void *digest);

inline static int
_gnutls_hmac (digest_hd_st * handle, const void *text, size_t textlen)
{
  if (textlen > 0)
    {
      return handle->hash (handle->handle, text, textlen);
    }
  return 0;
}

inline static void
_gnutls_hmac_output (digest_hd_st * handle, void *digest)
{
  int maclen;

  maclen = _gnutls_hmac_get_algo_len (handle->algorithm);

  if (digest != NULL)
    {
      handle->output (handle->handle, digest, maclen);
    }
}

void
_gnutls_hmac_deinit (digest_hd_st * handle, void *digest);

inline static void
_gnutls_hmac_reset (digest_hd_st * handle)
{
  if (handle->handle == NULL)
    {
      return;
    }

  handle->reset (handle->handle);
}


/* Hash interface */
int _gnutls_hash_init (digest_hd_st *, gnutls_digest_algorithm_t algorithm);

inline static int
_gnutls_hash (digest_hd_st * handle, const void *text, size_t textlen)
{
  if (textlen > 0)
    {
      handle->hash (handle->handle, text, textlen);
    }
  return 0;
}

/* when the current output is needed without calling deinit
 */
inline static void
_gnutls_hash_output (digest_hd_st * handle, void *digest)
{
  size_t maclen;

  maclen = _gnutls_hash_get_algo_len (handle->algorithm);

  if (digest != NULL)
    {
      handle->output (handle->handle, digest, maclen);
    }
}

inline static void
_gnutls_hash_reset (digest_hd_st * handle)
{
  if (handle->handle == NULL)
    {
      return;
    }

  handle->reset (handle->handle);
}

void
_gnutls_hash_deinit (digest_hd_st * handle, void *digest);

int
_gnutls_hash_fast (gnutls_digest_algorithm_t algorithm,
                   const void *text, size_t textlen, void *digest);

/* help functions */
int _gnutls_mac_init_ssl3 (digest_hd_st *, gnutls_mac_algorithm_t algorithm,
                           void *key, int keylen);
int _gnutls_mac_deinit_ssl3 (digest_hd_st * handle, void *digest);
int _gnutls_mac_output_ssl3 (digest_hd_st * handle, void *digest);

int _gnutls_ssl3_generate_random (void *secret, int secret_len,
                                  void *rnd, int random_len, int bytes,
                                  opaque * ret);
int _gnutls_ssl3_hash_md5 (const void *first, int first_len,
                           const void *second, int second_len,
                           int ret_len, opaque * ret);

void _gnutls_mac_reset_ssl3 (digest_hd_st * handle);

int _gnutls_mac_deinit_ssl3_handshake (digest_hd_st * handle, void *digest,
                                        opaque * key, uint32_t key_size);

int _gnutls_hash_copy (digest_hd_st * dst_handle, digest_hd_st * src_handle);

inline static int IS_SHA(gnutls_digest_algorithm_t algo)
{
  if (algo == GNUTLS_DIG_SHA1 || algo == GNUTLS_DIG_SHA224 ||
      algo == GNUTLS_DIG_SHA256 || algo == GNUTLS_DIG_SHA384 ||
      algo == GNUTLS_DIG_SHA512)
      return 1;
  return 0;
}

#endif /* GNUTLS_HASH_INT_H */
