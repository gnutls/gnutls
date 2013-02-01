/*
 * Copyright (C) 2011-2012 Free Software Foundation, Inc.
 *
 * Author: Nikos Mavrogiannopoulos
 *
 * This file is part of GnuTLS.
 *
 * The GnuTLS is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public License
 * as published by the Free Software Foundation; either version 2.1 of
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

/*
 * The following code is an implementation of the AES-128-CBC cipher
 * using VIA Padlock instruction set. 
 */

#include <gnutls_errors.h>
#include <gnutls_int.h>
#include <gnutls/crypto.h>
#include <gnutls_errors.h>
#include <aes-x86.h>
#include <x86.h>
#ifdef HAVE_LIBNETTLE
#include <nettle/aes.h>         /* for key generation in 192 and 256 bits */
#include <sha-padlock.h>
#endif
#include <aes-padlock.h>

static int
aes_cipher_init (gnutls_cipher_algorithm_t algorithm, void **_ctx, int enc)
{
  /* we use key size to distinguish */
  if (algorithm != GNUTLS_CIPHER_AES_128_CBC
      && algorithm != GNUTLS_CIPHER_AES_192_CBC
      && algorithm != GNUTLS_CIPHER_AES_256_CBC)
    return GNUTLS_E_INVALID_REQUEST;

  *_ctx = gnutls_calloc (1, sizeof (struct padlock_ctx));
  if (*_ctx == NULL)
    {
      gnutls_assert ();
      return GNUTLS_E_MEMORY_ERROR;
    }

  ((struct padlock_ctx *) (*_ctx))->enc = enc;
  return 0;
}

int
padlock_aes_cipher_setkey (void *_ctx, const void *userkey, size_t keysize)
{
  struct padlock_ctx *ctx = _ctx;
  struct padlock_cipher_data *pce;
#ifdef HAVE_LIBNETTLE
  struct aes_ctx nc;
#endif

  memset (_ctx, 0, sizeof (struct padlock_cipher_data));

  pce = ALIGN16 (&ctx->expanded_key);

  pce->cword.b.encdec = (ctx->enc == 0);

  switch (keysize)
    {
    case 16:
      pce->cword.b.ksize = 0;
      pce->cword.b.rounds = 10;
      memcpy (pce->ks.rd_key, userkey, 16);
      pce->cword.b.keygen = 0;
      break;
#ifdef HAVE_LIBNETTLE
    case 24:
      pce->cword.b.ksize = 1;
      pce->cword.b.rounds = 12;
      goto common_24_32;
    case 32:
      pce->cword.b.ksize = 2;
      pce->cword.b.rounds = 14;
    common_24_32:
      /* expand key using nettle */
      if (ctx->enc)
        aes_set_encrypt_key (&nc, keysize, userkey);
      else
        aes_set_decrypt_key (&nc, keysize, userkey);

      memcpy (pce->ks.rd_key, nc.keys, sizeof (nc.keys));
      pce->ks.rounds = nc.nrounds;

      pce->cword.b.keygen = 1;
      break;
#endif
    default:
      return gnutls_assert_val (GNUTLS_E_ENCRYPTION_FAILED);
    }

  padlock_reload_key ();

  return 0;
}

static int
aes_setiv (void *_ctx, const void *iv, size_t iv_size)
{
  struct padlock_ctx *ctx = _ctx;
  struct padlock_cipher_data *pce;

  pce = ALIGN16 (&ctx->expanded_key);

  memcpy (pce->iv, iv, 16);

  return 0;
}

static int
padlock_aes_cbc_encrypt (void *_ctx, const void *src, size_t src_size,
                         void *dst, size_t dst_size)
{
  struct padlock_ctx *ctx = _ctx;
  struct padlock_cipher_data *pce;

  pce = ALIGN16 (&ctx->expanded_key);

  padlock_cbc_encrypt (dst, src, pce, src_size);

  return 0;
}


static int
padlock_aes_cbc_decrypt (void *_ctx, const void *src, size_t src_size,
                         void *dst, size_t dst_size)
{
  struct padlock_ctx *ctx = _ctx;
  struct padlock_cipher_data *pcd;

  pcd = ALIGN16 (&ctx->expanded_key);

  padlock_cbc_encrypt (dst, src, pcd, src_size);

  return 0;
}

static void
aes_deinit (void *_ctx)
{
  gnutls_free (_ctx);
}

static const gnutls_crypto_cipher_st aes_padlock_struct = {
  .init = aes_cipher_init,
  .setkey = padlock_aes_cipher_setkey,
  .setiv = aes_setiv,
  .encrypt = padlock_aes_cbc_encrypt,
  .decrypt = padlock_aes_cbc_decrypt,
  .deinit = aes_deinit,
};

static int
check_padlock (void)
{
  unsigned int edx = padlock_capability ();

  return ((edx & (0x3 << 6)) == (0x3 << 6));
}

static int
check_phe (void)
{
  unsigned int edx = padlock_capability ();

  return ((edx & (0x3 << 10)) == (0x3 << 10));
}

/* We are actually checking for SHA512 */
static int
check_phe_sha512 (void)
{
  unsigned int edx = padlock_capability ();

  return ((edx & (0x3 << 25)) == (0x3 << 25));
}

static int
check_phe_partial (void)
{
  const char* text = "test and test";
  uint32_t iv[5] = { 0x67452301UL, 0xEFCDAB89UL,
       0x98BADCFEUL, 0x10325476UL, 0xC3D2E1F0UL };

  padlock_sha1_blocks (iv, text, sizeof(text)-1);
  padlock_sha1_blocks (iv, text, sizeof(text)-1);

  if (iv[0] == 0x9096E2D8UL && iv[1] == 0xA33074EEUL &&
      iv[2] == 0xCDBEE447UL && iv[3] == 0xEC7979D2UL &&
      iv[4] == 0x9D3FF5CFUL)
      return 1;
  else
    return 0;
}

static unsigned
check_via (void)
{
  unsigned int a, b, c, d;
  gnutls_cpuid (0, &a, &b, &c, &d);

  if ((memcmp (&b, "Cent", 4) == 0 &&
       memcmp (&d, "aurH", 4) == 0 && memcmp (&c, "auls", 4) == 0))
    {
      return 1;
    }

  return 0;
}

void
register_padlock_crypto (void)
{
  int ret, phe;

  if (check_via () == 0)
    return;
  if (check_padlock ())
    {
      _gnutls_debug_log ("Padlock AES accelerator was detected\n");
      ret =
        gnutls_crypto_single_cipher_register
        (GNUTLS_CIPHER_AES_128_CBC, 80, &aes_padlock_struct);
      if (ret < 0)
        {
          gnutls_assert ();
        }

      /* register GCM ciphers */
      ret =
        gnutls_crypto_single_cipher_register
        (GNUTLS_CIPHER_AES_128_GCM, 80, &aes_gcm_padlock_struct);
      if (ret < 0)
        {
          gnutls_assert ();
        }
#ifdef HAVE_LIBNETTLE
      ret =
        gnutls_crypto_single_cipher_register (GNUTLS_CIPHER_AES_192_CBC,
                                              80, &aes_padlock_struct);
      if (ret < 0)
        {
          gnutls_assert ();
        }

      ret =
        gnutls_crypto_single_cipher_register (GNUTLS_CIPHER_AES_256_CBC,
                                              80, &aes_padlock_struct);
      if (ret < 0)
        {
          gnutls_assert ();
        }

      ret =
        gnutls_crypto_single_cipher_register (GNUTLS_CIPHER_AES_256_GCM,
                                              80, &aes_gcm_padlock_struct);
      if (ret < 0)
        {
          gnutls_assert ();
        }

#endif
    }

#ifdef HAVE_LIBNETTLE
  phe = check_phe ();

  if (phe && check_phe_partial ())
    {
      _gnutls_debug_log ("Padlock SHA1 and SHA256 (partial) accelerator was detected\n");
      if (check_phe_sha512 ())
        {
          _gnutls_debug_log ("Padlock SHA512 (partial) accelerator was detected\n");
          ret =
            gnutls_crypto_single_digest_register (GNUTLS_DIG_SHA384,
                                                  80,
                                                  &sha_padlock_nano_struct);
          if (ret < 0)
            {
              gnutls_assert ();
            }

          ret =
            gnutls_crypto_single_digest_register (GNUTLS_DIG_SHA512,
                                                  80,
                                                  &sha_padlock_nano_struct);
          if (ret < 0)
            {
              gnutls_assert ();
            }

          ret =
            gnutls_crypto_single_mac_register (GNUTLS_MAC_SHA384,
                                               80,
                                               &hmac_sha_padlock_nano_struct);
          if (ret < 0)
            {
              gnutls_assert ();
            }

          ret =
            gnutls_crypto_single_mac_register (GNUTLS_MAC_SHA512,
                                               80,
                                               &hmac_sha_padlock_nano_struct);
          if (ret < 0)
            {
              gnutls_assert ();
            }
        }

      ret =
        gnutls_crypto_single_digest_register (GNUTLS_DIG_SHA1,
                                              80, &sha_padlock_nano_struct);
      if (ret < 0)
        {
          gnutls_assert ();
        }

      ret =
        gnutls_crypto_single_digest_register (GNUTLS_DIG_SHA224,
                                              80, &sha_padlock_nano_struct);
      if (ret < 0)
        {
          gnutls_assert ();
        }

      ret =
        gnutls_crypto_single_digest_register (GNUTLS_DIG_SHA256,
                                              80, &sha_padlock_nano_struct);
      if (ret < 0)
        {
          gnutls_assert ();
        }

      ret =
        gnutls_crypto_single_mac_register (GNUTLS_MAC_SHA1,
                                           80, &hmac_sha_padlock_nano_struct);
      if (ret < 0)
        {
          gnutls_assert ();
        }

      /* we don't register MAC_SHA224 because it is not used by TLS */

      ret =
        gnutls_crypto_single_mac_register (GNUTLS_MAC_SHA256,
                                           80, &hmac_sha_padlock_nano_struct);
      if (ret < 0)
        {
          gnutls_assert ();
        }
    }
  else if (phe)
    {
      /* Original padlock PHE. Does not support incremental operations.
       */
      _gnutls_debug_log ("Padlock SHA1 and SHA256 accelerator was detected\n");
      ret =
        gnutls_crypto_single_digest_register (GNUTLS_DIG_SHA1,
                                              80, &sha_padlock_struct);
      if (ret < 0)
        {
          gnutls_assert ();
        }

      ret =
        gnutls_crypto_single_digest_register (GNUTLS_DIG_SHA256,
                                              80, &sha_padlock_struct);
      if (ret < 0)
        {
          gnutls_assert ();
        }

      ret =
        gnutls_crypto_single_mac_register (GNUTLS_MAC_SHA1,
                                           80, &hmac_sha_padlock_struct);
      if (ret < 0)
        {
          gnutls_assert ();
        }

      ret =
        gnutls_crypto_single_mac_register (GNUTLS_MAC_SHA256,
                                           80, &hmac_sha_padlock_struct);
      if (ret < 0)
        {
          gnutls_assert ();
        }
    }
#endif

  return;
}
