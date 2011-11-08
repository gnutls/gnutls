/*
 * Copyright (C) 2008, 2010, 2011 Free Software Foundation, Inc.
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

/* This file provides is the backend hash/mac API for libgcrypt.
 */

#include <gnutls_int.h>
#include <gnutls_hash_int.h>
#include <gnutls_errors.h>
#include <nettle/md5.h>
#include <nettle/md2.h>
#include <nettle/sha.h>
#include <nettle/hmac.h>

typedef void (*update_func) (void *, unsigned, const uint8_t *);
typedef void (*digest_func) (void *, unsigned, uint8_t *);
typedef void (*set_key_func) (void *, unsigned, const uint8_t *);

static int wrap_nettle_hash_init (gnutls_digest_algorithm_t algo, void **_ctx);

struct nettle_hash_ctx
{
  union
  {
    struct md5_ctx md5;
    struct md2_ctx md2;
    struct sha224_ctx sha224;
    struct sha256_ctx sha256;
    struct sha384_ctx sha384;
    struct sha512_ctx sha512;
    struct sha1_ctx sha1;
  } ctx;
  void *ctx_ptr;
  gnutls_digest_algorithm_t algo;
  size_t length;
  update_func update;
  digest_func digest;
};

struct nettle_hmac_ctx
{
  union
  {
    struct hmac_md5_ctx md5;
    struct hmac_sha224_ctx sha224;
    struct hmac_sha256_ctx sha256;
    struct hmac_sha384_ctx sha384;
    struct hmac_sha512_ctx sha512;
    struct hmac_sha1_ctx sha1;
  } ctx;
  
  /* this is the context just after
   * the set_key. Used in reset().
   */
  union
  {
    struct hmac_md5_ctx md5;
    struct hmac_sha224_ctx sha224;
    struct hmac_sha256_ctx sha256;
    struct hmac_sha384_ctx sha384;
    struct hmac_sha512_ctx sha512;
    struct hmac_sha1_ctx sha1;
  } init_ctx;
  void *ctx_ptr;
  gnutls_mac_algorithm_t algo;
  size_t length;
  update_func update;
  digest_func digest;
  set_key_func setkey;
};

static int _hmac_ctx_init(gnutls_mac_algorithm_t algo, struct nettle_hmac_ctx *ctx)
{
  switch (algo)
    {
    case GNUTLS_MAC_MD5:
      ctx->update = (update_func) hmac_md5_update;
      ctx->digest = (digest_func) hmac_md5_digest;
      ctx->setkey = (set_key_func) hmac_md5_set_key;
      ctx->ctx_ptr = &ctx->ctx.md5;
      ctx->length = MD5_DIGEST_SIZE;
      break;
    case GNUTLS_MAC_SHA1:
      ctx->update = (update_func) hmac_sha1_update;
      ctx->digest = (digest_func) hmac_sha1_digest;
      ctx->setkey = (set_key_func) hmac_sha1_set_key;
      ctx->ctx_ptr = &ctx->ctx.sha1;
      ctx->length = SHA1_DIGEST_SIZE;
      break;
    case GNUTLS_MAC_SHA224:
      ctx->update = (update_func) hmac_sha224_update;
      ctx->digest = (digest_func) hmac_sha224_digest;
      ctx->setkey = (set_key_func) hmac_sha224_set_key;
      ctx->ctx_ptr = &ctx->ctx.sha224;
      ctx->length = SHA224_DIGEST_SIZE;
      break;
    case GNUTLS_MAC_SHA256:
      ctx->update = (update_func) hmac_sha256_update;
      ctx->digest = (digest_func) hmac_sha256_digest;
      ctx->setkey = (set_key_func) hmac_sha256_set_key;
      ctx->ctx_ptr = &ctx->ctx.sha256;
      ctx->length = SHA256_DIGEST_SIZE;
      break;
    case GNUTLS_MAC_SHA384:
      ctx->update = (update_func) hmac_sha384_update;
      ctx->digest = (digest_func) hmac_sha384_digest;
      ctx->setkey = (set_key_func) hmac_sha384_set_key;
      ctx->ctx_ptr = &ctx->ctx.sha384;
      ctx->length = SHA384_DIGEST_SIZE;
      break;
    case GNUTLS_MAC_SHA512:
      ctx->update = (update_func) hmac_sha512_update;
      ctx->digest = (digest_func) hmac_sha512_digest;
      ctx->setkey = (set_key_func) hmac_sha512_set_key;
      ctx->ctx_ptr = &ctx->ctx.sha512;
      ctx->length = SHA512_DIGEST_SIZE;
      break;
    default:
      gnutls_assert ();
      return GNUTLS_E_INVALID_REQUEST;
    }
  
  return 0;
}

static int wrap_nettle_hmac_fast(gnutls_mac_algorithm_t algo, 
  const void *key, size_t key_size, const void* text, size_t text_size, 
  void* digest)
{
  struct nettle_hmac_ctx ctx;
  int ret;
  
  ret = _hmac_ctx_init(algo, &ctx);
  if (ret < 0)
    return gnutls_assert_val(ret);

  ctx.setkey (&ctx, key_size, key);
  ctx.update (&ctx, text_size, text);
  ctx.digest (&ctx, ctx.length, digest);
  
  return 0;
}

static int
wrap_nettle_hmac_init (gnutls_mac_algorithm_t algo, void **_ctx)
{
  struct nettle_hmac_ctx *ctx;
  int ret;

  ctx = gnutls_calloc (1, sizeof (struct nettle_hmac_ctx));
  if (ctx == NULL)
    {
      gnutls_assert ();
      return GNUTLS_E_MEMORY_ERROR;
    }

  ctx->algo = algo;

  ret = _hmac_ctx_init(algo, ctx);
  if (ret < 0)
    {
      gnutls_free(ctx);
      return gnutls_assert_val(ret);
    }

  *_ctx = ctx;

  return 0;
}

static int
wrap_nettle_hmac_setkey (void *_ctx, const void *key, size_t keylen)
{
  struct nettle_hmac_ctx *ctx = _ctx;

  ctx->setkey (ctx->ctx_ptr, keylen, key);
  
  memcpy(&ctx->init_ctx, &ctx->ctx, sizeof(ctx->ctx));

  return GNUTLS_E_SUCCESS;
}

static void
wrap_nettle_hmac_reset (void *_ctx)
{
  struct nettle_hmac_ctx *ctx = _ctx;

  memcpy(&ctx->ctx, &ctx->init_ctx, sizeof(ctx->ctx));
}

static int
wrap_nettle_hmac_update (void *_ctx, const void *text, size_t textsize)
{
  struct nettle_hmac_ctx *ctx = _ctx;

  ctx->update (ctx->ctx_ptr, textsize, text);

  return GNUTLS_E_SUCCESS;
}

static int
wrap_nettle_hmac_output (void *src_ctx, void *digest, size_t digestsize)
{
  struct nettle_hmac_ctx *ctx;
  ctx = src_ctx;

  if (digestsize < ctx->length)
    {
      gnutls_assert ();
      return GNUTLS_E_SHORT_MEMORY_BUFFER;
    }

  ctx->digest (ctx->ctx_ptr, digestsize, digest);

  return 0;
}

static void
wrap_nettle_hmac_deinit (void *hd)
{
  gnutls_free (hd);
}

/* Hash functions 
 */
static int
wrap_nettle_hash_update (void *_ctx, const void *text, size_t textsize)
{
  struct nettle_hash_ctx *ctx = _ctx;

  ctx->update (ctx->ctx_ptr, textsize, text);

  return GNUTLS_E_SUCCESS;
}

static int
wrap_nettle_hash_copy (void **bhd, void *ahd)
{
  struct nettle_hash_ctx *ctx = ahd;
  struct nettle_hash_ctx *dst_ctx;
  int ret;

  ret = wrap_nettle_hash_init (ctx->algo, bhd);
  if (ret < 0)
    {
      gnutls_assert ();
      return ret;
    }

  dst_ctx = *bhd;

  memcpy (&dst_ctx->ctx, &ctx->ctx, sizeof (ctx->ctx));

  return 0;
}

static void
wrap_nettle_hash_deinit (void *hd)
{
  gnutls_free (hd);
}

static int _ctx_init(gnutls_digest_algorithm_t algo, struct nettle_hash_ctx *ctx)
{
  switch (algo)
    {
    case GNUTLS_DIG_MD5:
      md5_init (&ctx->ctx.md5);
      ctx->update = (update_func) md5_update;
      ctx->digest = (digest_func) md5_digest;
      ctx->ctx_ptr = &ctx->ctx.md5;
      ctx->length = MD5_DIGEST_SIZE;
      break;
    case GNUTLS_DIG_SHA1:
      sha1_init (&ctx->ctx.sha1);
      ctx->update = (update_func) sha1_update;
      ctx->digest = (digest_func) sha1_digest;
      ctx->ctx_ptr = &ctx->ctx.sha1;
      ctx->length = SHA1_DIGEST_SIZE;
      break;
    case GNUTLS_DIG_MD2:
      md2_init (&ctx->ctx.md2);
      ctx->update = (update_func) md2_update;
      ctx->digest = (digest_func) md2_digest;
      ctx->ctx_ptr = &ctx->ctx.md2;
      ctx->length = MD2_DIGEST_SIZE;
      break;
    case GNUTLS_DIG_SHA224:
      sha224_init (&ctx->ctx.sha224);
      ctx->update = (update_func) sha224_update;
      ctx->digest = (digest_func) sha224_digest;
      ctx->ctx_ptr = &ctx->ctx.sha224;
      ctx->length = SHA224_DIGEST_SIZE;
      break;
    case GNUTLS_DIG_SHA256:
      sha256_init (&ctx->ctx.sha256);
      ctx->update = (update_func) sha256_update;
      ctx->digest = (digest_func) sha256_digest;
      ctx->ctx_ptr = &ctx->ctx.sha256;
      ctx->length = SHA256_DIGEST_SIZE;
      break;
    case GNUTLS_DIG_SHA384:
      sha384_init (&ctx->ctx.sha384);
      ctx->update = (update_func) sha384_update;
      ctx->digest = (digest_func) sha384_digest;
      ctx->ctx_ptr = &ctx->ctx.sha384;
      ctx->length = SHA384_DIGEST_SIZE;
      break;
    case GNUTLS_DIG_SHA512:
      sha512_init (&ctx->ctx.sha512);
      ctx->update = (update_func) sha512_update;
      ctx->digest = (digest_func) sha512_digest;
      ctx->ctx_ptr = &ctx->ctx.sha512;
      ctx->length = SHA512_DIGEST_SIZE;
      break;
    default:
      gnutls_assert ();
      return GNUTLS_E_INVALID_REQUEST;
    }
    
    return 0;
}

static int wrap_nettle_hash_fast(gnutls_digest_algorithm_t algo, 
  const void* text, size_t text_size, 
  void* digest)
{
  struct nettle_hash_ctx ctx;
  int ret;
  
  ret = _ctx_init(algo, &ctx);
  if (ret < 0)
    return gnutls_assert_val(ret);

  ctx.update (&ctx, text_size, text);
  ctx.digest (&ctx, ctx.length, digest);
  
  return 0;
}

static int
wrap_nettle_hash_init (gnutls_digest_algorithm_t algo, void **_ctx)
{
  struct nettle_hash_ctx *ctx;
  int ret;

  ctx = gnutls_malloc (sizeof (struct nettle_hash_ctx));
  if (ctx == NULL)
    {
      gnutls_assert ();
      return GNUTLS_E_MEMORY_ERROR;
    }

  ctx->algo = algo;

  if ((ret=_ctx_init( algo, ctx)) < 0)
    {
      gnutls_assert ();
      gnutls_free(ctx);
      return ret;
    }

  *_ctx = ctx;

  return 0;
}

static int
wrap_nettle_hash_output (void *src_ctx, void *digest, size_t digestsize)
{
  struct nettle_hash_ctx *ctx;
  ctx = src_ctx;

  if (digestsize < ctx->length)
    {
      gnutls_assert ();
      return GNUTLS_E_SHORT_MEMORY_BUFFER;
    }

  ctx->digest (ctx->ctx_ptr, digestsize, digest);

  return 0;
}

static void
wrap_nettle_hash_reset (void *src_ctx)
{
  struct nettle_hash_ctx *ctx;
  ctx = src_ctx;

  _ctx_init(ctx->algo, ctx->ctx_ptr);
}


gnutls_crypto_mac_st _gnutls_mac_ops = {
  .init = wrap_nettle_hmac_init,
  .setkey = wrap_nettle_hmac_setkey,
  .hash = wrap_nettle_hmac_update,
  .reset = wrap_nettle_hmac_reset,
  .output = wrap_nettle_hmac_output,
  .deinit = wrap_nettle_hmac_deinit,
  .fast = wrap_nettle_hmac_fast,
};

gnutls_crypto_digest_st _gnutls_digest_ops = {
  .init = wrap_nettle_hash_init,
  .hash = wrap_nettle_hash_update,
  .reset = wrap_nettle_hash_reset,
  .copy = wrap_nettle_hash_copy,
  .output = wrap_nettle_hash_output,
  .deinit = wrap_nettle_hash_deinit,
  .fast = wrap_nettle_hash_fast,
};
