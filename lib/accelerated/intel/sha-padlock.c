/*
 * Copyright (C) 2011 Free Software Foundation, Inc.
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
#include <gnutls_hash_int.h>
#include <gnutls_errors.h>
#include <nettle/sha.h>
#include <aes-padlock.h>

/* This enables padlock's SHA capabilities for HMAC operations. 
 * Unfortunately due to padlock's inner workings only the final hash
 * of the HMAC() is being hardware accelerated. The rest is plain
 * software.
 */

typedef void (*update_func) (void *, unsigned, const uint8_t *);
typedef void (*digest_func) (void *, unsigned, uint8_t *);
typedef void (*padlock_hash_func) (void* digest, const void* src, size_t len);

#define SHA_BLOCK_SIZE 64
#define MAX_SHA_DIGEST_SIZE 32
#define IPAD 0x36
#define OPAD 0x5c

struct padlock_hmac_ctx
{
  gnutls_buffer_st buf;

  gnutls_mac_algorithm_t algo;
  size_t length;

  unsigned char ipad[SHA_BLOCK_SIZE];
  unsigned char opad[SHA_BLOCK_SIZE];
};

static int
wrap_padlock_hmac_init (gnutls_mac_algorithm_t algo, void **_ctx)
{
  struct padlock_hmac_ctx *ctx;
  
  if (algo != GNUTLS_MAC_SHA1 && algo != GNUTLS_MAC_SHA256)
    return gnutls_assert_val(GNUTLS_E_INVALID_REQUEST);

  ctx = gnutls_calloc (1, sizeof (struct padlock_hmac_ctx));
  if (ctx == NULL)
    {
      gnutls_assert ();
      return GNUTLS_E_MEMORY_ERROR;
    }

  ctx->algo = algo;
  _gnutls_buffer_init(&ctx->buf);

  *_ctx = ctx;

  return 0;
}


static int
wrap_padlock_hmac_setkey (void *_ctx, const void *key, size_t key_size)
{
  struct padlock_hmac_ctx *ctx = _ctx;
  padlock_hash_func hash;
  unsigned char hkey[MAX_SHA_DIGEST_SIZE];

  if (key_size > SHA_BLOCK_SIZE) 
    {
      if (ctx->algo == GNUTLS_MAC_SHA1)
        hash = padlock_sha1_oneshot;
      else
        hash = padlock_sha256_oneshot;

      hash(hkey, key, key_size);
      key = hkey;
      key_size = _gnutls_hmac_get_algo_len(ctx->algo);
    }

  memset (ctx->ipad, IPAD, SHA_BLOCK_SIZE);
  memxor (ctx->ipad, key, key_size);

  _gnutls_buffer_append_data( &ctx->buf, ctx->ipad, SHA_BLOCK_SIZE);

  return GNUTLS_E_SUCCESS;
}

static void
wrap_padlock_hmac_reset (void *_ctx)
{
  struct padlock_hmac_ctx *ctx = _ctx;

  _gnutls_buffer_reset(&ctx->buf);
  _gnutls_buffer_append_data( &ctx->buf, ctx->ipad, SHA_BLOCK_SIZE);
}

static int
wrap_padlock_hmac_update (void *_ctx, const void *text, size_t textsize)
{
  struct padlock_hmac_ctx *ctx = _ctx;

  _gnutls_buffer_append_data( &ctx->buf, text, textsize);

  return GNUTLS_E_SUCCESS;
}

static void
wrap_padlock_hmac_deinit (void *_ctx)
{
  struct padlock_hmac_ctx *ctx = _ctx;

  _gnutls_buffer_clear(&ctx->buf);
  gnutls_free (ctx);
}

static int
wrap_padlock_hmac_output (void *_ctx, void *digest, size_t digestsize)
{
  struct padlock_hmac_ctx *ctx = _ctx;
  unsigned char pad[SHA_BLOCK_SIZE + MAX_SHA_DIGEST_SIZE];
  padlock_hash_func hash;

  if (ctx->algo == GNUTLS_MAC_SHA1)
    hash = padlock_sha1_oneshot;
  else
    hash = padlock_sha256_oneshot;

  if (digestsize < ctx->length)
    {
      gnutls_assert ();
      return GNUTLS_E_SHORT_MEMORY_BUFFER;
    }

  memcpy (pad, ctx->opad, SHA_BLOCK_SIZE);
  hash(&pad[SHA_BLOCK_SIZE], ctx->buf.data, ctx->buf.length);

  hash(digest, pad, ctx->length + SHA_BLOCK_SIZE);

  return 0;
}


static int wrap_padlock_hmac_fast(gnutls_mac_algorithm_t algo, 
  const void *key, size_t key_size, const void* text, size_t text_size, 
  void* digest)
{
  unsigned char *pad;
  unsigned char pad2[SHA_BLOCK_SIZE + MAX_SHA_DIGEST_SIZE];
  unsigned char hkey[MAX_SHA_DIGEST_SIZE];
  padlock_hash_func hash;

  if (algo == GNUTLS_MAC_SHA1)
    hash = padlock_sha1_oneshot;
  else
    hash = padlock_sha256_oneshot;

  if (key_size > SHA_BLOCK_SIZE) 
    {
      hash(hkey, key, key_size);
      key = hkey;
      key_size = _gnutls_hmac_get_algo_len(algo);
    }

  pad = gnutls_malloc(text_size + SHA_BLOCK_SIZE);
  if (pad == NULL)
    return gnutls_assert_val(GNUTLS_E_MEMORY_ERROR);
  
  memset (pad, IPAD, SHA_BLOCK_SIZE);
  memxor (pad, key, key_size);
  
  memcpy (&pad[SHA_BLOCK_SIZE], text, text_size);
  
  hash(&pad2[SHA_BLOCK_SIZE], pad, text_size + SHA_BLOCK_SIZE);
  
  gnutls_free(pad);

  memset (pad2, OPAD, SHA_BLOCK_SIZE);
  memxor (pad2, key, key_size);
  
  hash(digest, pad2, SHA1_DIGEST_SIZE + SHA_BLOCK_SIZE);
  
  return 0;
}

const gnutls_crypto_mac_st hmac_sha_padlock_struct = {
  .init = wrap_padlock_hmac_init,
  .setkey = wrap_padlock_hmac_setkey,
  .hash = wrap_padlock_hmac_update,
  .reset = wrap_padlock_hmac_reset,
  .output = wrap_padlock_hmac_output,
  .deinit = wrap_padlock_hmac_deinit,
  .fast = wrap_padlock_hmac_fast
};


struct padlock_hash_ctx
{
  gnutls_buffer_st buf;
  gnutls_digest_algorithm_t algo;
  size_t length; /* output length */
};

static int
wrap_padlock_hash_init (gnutls_digest_algorithm_t algo, void **_ctx)
{
  struct padlock_hash_ctx *ctx;
  
  if (algo != GNUTLS_DIG_SHA1 && algo != GNUTLS_DIG_SHA256)
    return gnutls_assert_val(GNUTLS_E_INVALID_REQUEST);

  ctx = gnutls_calloc (1, sizeof (struct padlock_hash_ctx));
  if (ctx == NULL)
    {
      gnutls_assert ();
      return GNUTLS_E_MEMORY_ERROR;
    }

  ctx->algo = algo;
  _gnutls_buffer_init(&ctx->buf);

  *_ctx = ctx;

  return 0;
}

static int
wrap_padlock_hash_update (void *_ctx, const void *text, size_t textsize)
{
  struct padlock_hash_ctx *ctx = _ctx;

  _gnutls_buffer_append_data( &ctx->buf, text, textsize);

  return GNUTLS_E_SUCCESS;
}

static void
wrap_padlock_hash_deinit (void *_ctx)
{
  struct padlock_hash_ctx *ctx = _ctx;

  _gnutls_buffer_clear(&ctx->buf);
  gnutls_free (ctx);
}

static int
wrap_padlock_hash_output (void *_ctx, void *digest, size_t digestsize)
{
  struct padlock_hash_ctx *ctx = _ctx;

  if (ctx->algo == GNUTLS_DIG_SHA1)
    padlock_sha1_oneshot (digest, ctx->buf.data, ctx->buf.length);
  else
    padlock_sha256_oneshot (digest, ctx->buf.data, ctx->buf.length);

  return 0;
}

static int wrap_padlock_hash_fast(gnutls_digest_algorithm_t algo, 
  const void* text, size_t text_size, 
  void* digest)
{
  if (algo == GNUTLS_DIG_SHA1)
    padlock_sha1_oneshot (digest, text, text_size);
  else
    padlock_sha256_oneshot (digest, text, text_size);
  
  return 0;
}

const gnutls_crypto_digest_st sha_padlock_struct = {
  .init = wrap_padlock_hash_init,
  .hash = wrap_padlock_hash_update,
  .output = wrap_padlock_hash_output,
  .deinit = wrap_padlock_hash_deinit,
  .fast = wrap_padlock_hash_fast
};
