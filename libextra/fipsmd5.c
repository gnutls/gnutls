/*
 * Copyright (C) 2008 Free Software Foundation
 *
 * Author: Simon Josefsson
 *
 * This file is part of GNUTLS-EXTRA.
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 *
 */

#include <gnutls_int.h>
#include <gnutls/crypto.h>
#include <gnutls/extra.h>

#include <md5.h>
#include <hmac.h>

struct hmacctx
{
  char *data;
  size_t datasize;
  char *key;
  size_t keysize;
};

static int
hmacmd5init (gnutls_digest_algorithm_t ign, void **ctx)
{
  struct hmacctx *p;

  p = gnutls_malloc (sizeof (struct hmacctx));
  if (!p)
    return -1;

  p->data = NULL;
  p->datasize = 0;
  p->key = NULL;
  p->keysize = 0;

  *ctx = p;

  return 0;
}

static int
hmacmd5setkey (void *ctx, const void *key, size_t keysize)
{
  struct hmacctx *p = ctx;

  if (p->key)
    gnutls_free (p->key);

  p->key = gnutls_malloc (keysize);
  if (!p->key)
    return -1;

  memcpy (p->key, key, keysize);
  p->keysize = keysize;

  return 0;
}

static int
hmacmd5hash (void *ctx, const void *text, size_t textsize)
{
  struct hmacctx *p = ctx;
  char *new;

  new = gnutls_realloc (p->data, p->datasize + textsize);
  if (!new)
    return -1;

  memcpy (new + p->datasize, text, textsize);

  p->data = new;
  p->datasize += textsize;

  return 0;
}

static int
hmacmd5copy (void **dst_ctx, void *src_ctx)
{
  struct hmacctx *p = src_ctx;
  struct hmacctx *q;

  q = gnutls_calloc (1, sizeof (struct hmacctx));
  if (!q)
    return -1;

  q->data = gnutls_malloc (p->datasize);
  if (!q->data)
    {
      gnutls_free (q);
      return -1;
    }
  memcpy (q->data, p->data, p->datasize);
  q->datasize = p->datasize;

  if (p->key) 
    {
      q->key = gnutls_malloc (p->keysize);
      if (!q->key)
        {
          gnutls_free (q);
          gnutls_free (q->data);
          return -1;
        }
      memcpy (q->key, p->key, p->keysize);
      q->keysize = p->keysize;
    }

  *dst_ctx = q;

  return 0;
}

static int
hmacmd5output (void *ctx, void *digest, size_t digestsize)
{
  struct hmacctx *p = ctx;
  char out[MD5_DIGEST_SIZE];
  int ret;

  ret = hmac_md5 (p->key, p->keysize, p->data, p->datasize, out);
  if (ret)
    return GNUTLS_E_HASH_FAILED;

  memcpy (digest, out, digestsize);

  return 0;
}

static void
hmacmd5deinit (void *ctx)
{
  struct hmacctx *p = ctx;

  if (p->data)
    gnutls_free (p->data);
  if (p->key)
    gnutls_free (p->key);

  gnutls_free (p);
}

static gnutls_crypto_digest_st mac = {
  hmacmd5init,
  hmacmd5setkey,
  hmacmd5hash,
  hmacmd5copy,
  hmacmd5output,
  hmacmd5deinit
};

/**
 * gnutls_register_md5_handler:
 *
 * Register a non-libgcrypt based MD5 and HMAC-MD5 handler.  This is
 * useful if you run Libgcrypt in FIPS-mode.  Normally TLS requires
 * use of MD5, so without this you cannot use GnuTLS with libgcrypt in
 * FIPS mode.
 *
 * Returns: %GNUTLS_E_SUCCESS on success, otherwise an error.
 *
 * Since: 2.6.0
 **/
int
gnutls_register_md5_handler (void)
{
  int ret;

  ret = gnutls_crypto_single_digest_register (GNUTLS_DIG_MD5, INT_MAX, &mac);
  if (ret)
    return ret;

  return 0;
}
