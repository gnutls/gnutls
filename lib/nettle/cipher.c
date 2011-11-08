/*
 * Copyright (C) 2010 Free Software Foundation, Inc.
 *
 * Author: Nikos Mavrogiannopoulos
 *
 * This file is part of GNUTLS.
 *
 * The GNUTLS library is free software; you can redistribute it and/or
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

/* Here lie nettle's wrappers for cipher support.
 */

#include <gnutls_int.h>
#include <gnutls_errors.h>
#include <gnutls_cipher_int.h>
#include <nettle/aes.h>
#include <nettle/camellia.h>
#include <nettle/arcfour.h>
#include <nettle/arctwo.h>
#include <nettle/des.h>
#include <nettle/nettle-meta.h>
#include <nettle/cbc.h>
#include <nettle/gcm.h>

/* Functions that refer to the libgcrypt library.
 */

#define MAX_BLOCK_SIZE 32

typedef void (*encrypt_func) (void *, nettle_crypt_func, unsigned, uint8_t *,
                              unsigned, uint8_t *, const uint8_t *);
typedef void (*decrypt_func) (void *, nettle_crypt_func, unsigned, uint8_t *,
                              unsigned, uint8_t *, const uint8_t *);
typedef void (*auth_func) (void *, unsigned, const uint8_t *);

typedef void (*tag_func) (void *, unsigned, uint8_t *);

typedef void (*setkey_func) (void *, unsigned, const uint8_t *);

static void
stream_encrypt (void *ctx, nettle_crypt_func func, unsigned block_size,
                uint8_t * iv, unsigned length, uint8_t * dst,
                const uint8_t * src)
{
  func (ctx, length, dst, src);
}

struct nettle_cipher_ctx
{
  union
  {
    struct aes_ctx aes;
    struct camellia_ctx camellia;
    struct arcfour_ctx arcfour;
    struct arctwo_ctx arctwo;
    struct des3_ctx des3;
    struct des_ctx des;
    struct gcm_aes_ctx aes_gcm;
  } ctx;
  void *ctx_ptr;
  uint8_t iv[MAX_BLOCK_SIZE];
  gnutls_cipher_algorithm_t algo;
  size_t block_size;
  nettle_crypt_func *i_encrypt;
  nettle_crypt_func *i_decrypt;
  encrypt_func encrypt;
  decrypt_func decrypt;
  auth_func auth;
  tag_func tag;
  int enc;
};

#define GCM_DEFAULT_NONCE_SIZE 12

static void _gcm_encrypt(void *_ctx, nettle_crypt_func f,  
            unsigned block_size, uint8_t *iv,
            unsigned length, uint8_t *dst,
            const uint8_t *src)
{
  return gcm_aes_encrypt(_ctx, length, dst, src);
}

static void _gcm_decrypt(void *_ctx, nettle_crypt_func f,  
            unsigned block_size, uint8_t *iv,
            unsigned length, uint8_t *dst,
            const uint8_t *src)
{
  return gcm_aes_decrypt(_ctx, length, dst, src);
}

static int
wrap_nettle_cipher_init (gnutls_cipher_algorithm_t algo, void **_ctx, int enc)
{
  struct nettle_cipher_ctx *ctx;

  ctx = gnutls_calloc (1, sizeof (*ctx));
  if (ctx == NULL)
    {
      gnutls_assert ();
      return GNUTLS_E_MEMORY_ERROR;
    }

  ctx->algo = algo;
  ctx->enc = enc;

  switch (algo)
    {
    case GNUTLS_CIPHER_AES_128_GCM:
    case GNUTLS_CIPHER_AES_256_GCM:
      ctx->encrypt = _gcm_encrypt;
      ctx->decrypt = _gcm_decrypt;
      ctx->i_encrypt = (nettle_crypt_func*) aes_encrypt;
      ctx->auth = (auth_func)gcm_aes_update;
      ctx->tag = (tag_func)gcm_aes_digest;
      ctx->ctx_ptr = &ctx->ctx.aes_gcm;
      ctx->block_size = AES_BLOCK_SIZE;
      break;
    case GNUTLS_CIPHER_CAMELLIA_128_CBC:
    case GNUTLS_CIPHER_CAMELLIA_256_CBC:
      ctx->encrypt = cbc_encrypt;
      ctx->decrypt = cbc_decrypt;
      ctx->i_encrypt = (nettle_crypt_func*)camellia_crypt;
      ctx->i_decrypt = (nettle_crypt_func*)camellia_crypt;
      ctx->ctx_ptr = &ctx->ctx.camellia;
      ctx->block_size = CAMELLIA_BLOCK_SIZE;
      break;
    case GNUTLS_CIPHER_AES_128_CBC:
    case GNUTLS_CIPHER_AES_192_CBC:
    case GNUTLS_CIPHER_AES_256_CBC:
      ctx->encrypt = cbc_encrypt;
      ctx->decrypt = cbc_decrypt;
      ctx->i_encrypt = (nettle_crypt_func*)aes_encrypt;
      ctx->i_decrypt = (nettle_crypt_func*)aes_decrypt;
      ctx->ctx_ptr = &ctx->ctx.aes;
      ctx->block_size = AES_BLOCK_SIZE;
      break;
    case GNUTLS_CIPHER_3DES_CBC:
      ctx->encrypt = cbc_encrypt;
      ctx->decrypt = cbc_decrypt;
      ctx->i_encrypt = (nettle_crypt_func *) des3_encrypt;
      ctx->i_decrypt = (nettle_crypt_func *) des3_decrypt;
      ctx->ctx_ptr = &ctx->ctx.des3;
      ctx->block_size = DES3_BLOCK_SIZE;
      break;
    case GNUTLS_CIPHER_DES_CBC:
      ctx->encrypt = cbc_encrypt;
      ctx->decrypt = cbc_decrypt;
      ctx->i_encrypt = (nettle_crypt_func *) des_encrypt;
      ctx->i_decrypt = (nettle_crypt_func *) des_decrypt;
      ctx->ctx_ptr = &ctx->ctx.des;
      ctx->block_size = DES_BLOCK_SIZE;
      break;
    case GNUTLS_CIPHER_ARCFOUR_128:
    case GNUTLS_CIPHER_ARCFOUR_40:
      ctx->encrypt = stream_encrypt;
      ctx->decrypt = stream_encrypt;
      ctx->i_encrypt = (nettle_crypt_func *) arcfour_crypt;
      ctx->i_decrypt = (nettle_crypt_func *) arcfour_crypt;
      ctx->ctx_ptr = &ctx->ctx.arcfour;
      ctx->block_size = 1;
      break;
    case GNUTLS_CIPHER_RC2_40_CBC:
      ctx->encrypt = cbc_encrypt;
      ctx->decrypt = cbc_decrypt;
      ctx->i_encrypt = (nettle_crypt_func *) arctwo_encrypt;
      ctx->i_decrypt = (nettle_crypt_func *) arctwo_decrypt;
      ctx->ctx_ptr = &ctx->ctx.arctwo;
      ctx->block_size = ARCTWO_BLOCK_SIZE;
      break;
    default:
      gnutls_assert ();
      gnutls_free(ctx);
      return GNUTLS_E_INVALID_REQUEST;
    }

  *_ctx = ctx;

  return 0;
}

static int
wrap_nettle_cipher_setkey (void *_ctx, const void *key, size_t keysize)
{
  struct nettle_cipher_ctx *ctx = _ctx;
  opaque des_key[DES3_KEY_SIZE];

  switch (ctx->algo)
    {
    case GNUTLS_CIPHER_AES_128_GCM:
    case GNUTLS_CIPHER_AES_256_GCM:
      gcm_aes_set_key(&ctx->ctx.aes_gcm, keysize, key);
      break;
    case GNUTLS_CIPHER_AES_128_CBC:
    case GNUTLS_CIPHER_AES_192_CBC:
    case GNUTLS_CIPHER_AES_256_CBC:
      if (ctx->enc)
        aes_set_encrypt_key (ctx->ctx_ptr, keysize, key);
      else
        aes_set_decrypt_key (ctx->ctx_ptr, keysize, key);
      break;
    case GNUTLS_CIPHER_CAMELLIA_128_CBC:
    case GNUTLS_CIPHER_CAMELLIA_256_CBC:
      if (ctx->enc)
        camellia_set_encrypt_key (ctx->ctx_ptr, keysize, key);
      else
        camellia_set_decrypt_key (ctx->ctx_ptr, keysize, key);
      break;
    case GNUTLS_CIPHER_3DES_CBC:
      if (keysize != DES3_KEY_SIZE)
        {
          gnutls_assert ();
          return GNUTLS_E_INTERNAL_ERROR;
        }

      des_fix_parity (keysize, des_key, key);

      /* this fails on weak keys */
      if (des3_set_key (ctx->ctx_ptr, des_key) != 1)
        {
          gnutls_assert ();
          return GNUTLS_E_INTERNAL_ERROR;
        }
      break;
    case GNUTLS_CIPHER_DES_CBC:
      if (keysize != DES_KEY_SIZE)
        {
          gnutls_assert ();
          return GNUTLS_E_INTERNAL_ERROR;
        }

      des_fix_parity (keysize, des_key, key);

      if (des_set_key (ctx->ctx_ptr, des_key) != 1)
        {
          gnutls_assert ();
          return GNUTLS_E_INTERNAL_ERROR;
        }
      break;
    case GNUTLS_CIPHER_ARCFOUR_128:
    case GNUTLS_CIPHER_ARCFOUR_40:
      arcfour_set_key (ctx->ctx_ptr, keysize, key);
      break;
    case GNUTLS_CIPHER_RC2_40_CBC:
      arctwo_set_key (ctx->ctx_ptr, keysize, key);
      break;
    default:
      gnutls_assert ();
      return GNUTLS_E_INVALID_REQUEST;
    }

  return 0;
}

static int
wrap_nettle_cipher_setiv (void *_ctx, const void *iv, size_t ivsize)
{
struct nettle_cipher_ctx *ctx = _ctx;

  switch (ctx->algo)
    {
    case GNUTLS_CIPHER_AES_128_GCM:
    case GNUTLS_CIPHER_AES_256_GCM:
      if (ivsize != GCM_DEFAULT_NONCE_SIZE)
        {
          gnutls_assert ();
          return GNUTLS_E_INVALID_REQUEST;
        }

      gcm_aes_set_iv(&ctx->ctx.aes_gcm, GCM_DEFAULT_NONCE_SIZE, iv);
      break;
    default:
      if (ivsize > ctx->block_size)
        {
          gnutls_assert ();
          return GNUTLS_E_INVALID_REQUEST;
        }

      memcpy (ctx->iv, iv, ivsize);
    }

  return 0;
}

static int
wrap_nettle_cipher_decrypt (void *_ctx, const void *encr, size_t encrsize,
                            void *plain, size_t plainsize)
{
  struct nettle_cipher_ctx *ctx = _ctx;

  ctx->decrypt (ctx->ctx_ptr, ctx->i_decrypt, ctx->block_size, ctx->iv,
                encrsize, plain, encr);

  return 0;
}

static int
wrap_nettle_cipher_encrypt (void *_ctx, const void *plain, size_t plainsize,
                            void *encr, size_t encrsize)
{
  struct nettle_cipher_ctx *ctx = _ctx;

  ctx->encrypt (ctx->ctx_ptr, ctx->i_encrypt, ctx->block_size, ctx->iv,
                plainsize, encr, plain);

  return 0;
}

static int
wrap_nettle_cipher_auth (void *_ctx, const void *plain, size_t plainsize)
{
  struct nettle_cipher_ctx *ctx = _ctx;

  ctx->auth (ctx->ctx_ptr, plainsize, plain);

  return 0;
}

static void
wrap_nettle_cipher_tag (void *_ctx, void *tag, size_t tagsize)
{
  struct nettle_cipher_ctx *ctx = _ctx;

  ctx->tag (ctx->ctx_ptr, tagsize, tag);

}

static void
wrap_nettle_cipher_close (void *h)
{
  gnutls_free (h);
}

gnutls_crypto_cipher_st _gnutls_cipher_ops = {
  .init = wrap_nettle_cipher_init,
  .setiv = wrap_nettle_cipher_setiv,
  .setkey = wrap_nettle_cipher_setkey,
  .encrypt = wrap_nettle_cipher_encrypt,
  .decrypt = wrap_nettle_cipher_decrypt,
  .deinit = wrap_nettle_cipher_close,
  .auth = wrap_nettle_cipher_auth,
  .tag = wrap_nettle_cipher_tag,
};
