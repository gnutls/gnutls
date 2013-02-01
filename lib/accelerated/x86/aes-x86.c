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
 * using intel's AES instruction set. 
 */

#include <gnutls_errors.h>
#include <gnutls_int.h>
#include <gnutls/crypto.h>
#include <gnutls_errors.h>
#include <aes-x86.h>
#include <x86.h>

struct aes_ctx
{
  AES_KEY expanded_key;
  uint8_t iv[16];
  int enc;
};

static int
aes_cipher_init (gnutls_cipher_algorithm_t algorithm, void **_ctx, int enc)
{
  /* we use key size to distinguish */
  if (algorithm != GNUTLS_CIPHER_AES_128_CBC
      && algorithm != GNUTLS_CIPHER_AES_192_CBC
      && algorithm != GNUTLS_CIPHER_AES_256_CBC)
    return GNUTLS_E_INVALID_REQUEST;

  *_ctx = gnutls_calloc (1, sizeof (struct aes_ctx));
  if (*_ctx == NULL)
    {
      gnutls_assert ();
      return GNUTLS_E_MEMORY_ERROR;
    }

  ((struct aes_ctx*)(*_ctx))->enc = enc;

  return 0;
}

static int
aes_cipher_setkey (void *_ctx, const void *userkey, size_t keysize)
{
  struct aes_ctx *ctx = _ctx;
  int ret;

  if (ctx->enc)
    ret = aesni_set_encrypt_key (userkey, keysize * 8, ALIGN16(&ctx->expanded_key));
  else
    ret = aesni_set_decrypt_key (userkey, keysize * 8, ALIGN16(&ctx->expanded_key));

  if (ret != 0)
    return gnutls_assert_val (GNUTLS_E_ENCRYPTION_FAILED);

  return 0;
}

static int
aes_setiv (void *_ctx, const void *iv, size_t iv_size)
{
  struct aes_ctx *ctx = _ctx;

  memcpy (ctx->iv, iv, 16);
  return 0;
}

static int
aes_encrypt (void *_ctx, const void *src, size_t src_size,
             void *dst, size_t dst_size)
{
  struct aes_ctx *ctx = _ctx;

  aesni_cbc_encrypt (src, dst, src_size, ALIGN16(&ctx->expanded_key), ctx->iv, 1);
  return 0;
}

static int
aes_decrypt (void *_ctx, const void *src, size_t src_size,
             void *dst, size_t dst_size)
{
  struct aes_ctx *ctx = _ctx;

  aesni_cbc_encrypt (src, dst, src_size, ALIGN16(&ctx->expanded_key), ctx->iv, 0);

  return 0;
}

static void
aes_deinit (void *_ctx)
{
  gnutls_free (_ctx);
}

static const gnutls_crypto_cipher_st cipher_struct = {
  .init = aes_cipher_init,
  .setkey = aes_cipher_setkey,
  .setiv = aes_setiv,
  .encrypt = aes_encrypt,
  .decrypt = aes_decrypt,
  .deinit = aes_deinit,
};

static unsigned
check_optimized_aes (void)
{
  unsigned int a, b, c, d;
  gnutls_cpuid (1, &a, &b, &c, &d);

  return (c & 0x2000000);
}

#ifdef ASM_X86_64
static unsigned
check_pclmul (void)
{
  unsigned int a, b, c, d;
  gnutls_cpuid (1, &a, &b, &c, &d);

  return (c & 0x2);
}
#endif

static unsigned
check_intel_or_amd (void)
{
  unsigned int a, b, c, d;
  gnutls_cpuid (0, &a, &b, &c, &d);

  if ((memcmp (&b, "Genu", 4) == 0 &&
       memcmp (&d, "ineI", 4) == 0 &&
       memcmp (&c, "ntel", 4) == 0) ||
      (memcmp (&b, "Auth", 4) == 0 &&
       memcmp (&d, "enti", 4) == 0 && memcmp (&c, "cAMD", 4) == 0))
    {
      return 1;
    }

  return 0;
}

void
register_x86_crypto (void)
{
  int ret;

  if (check_intel_or_amd () == 0)
    return;

  if (check_optimized_aes ())
    {
      _gnutls_debug_log ("Intel AES accelerator was detected\n");
      ret =
        gnutls_crypto_single_cipher_register (GNUTLS_CIPHER_AES_128_CBC, 80,
                                              &cipher_struct);
      if (ret < 0)
        {
          gnutls_assert ();
        }

      ret =
        gnutls_crypto_single_cipher_register (GNUTLS_CIPHER_AES_192_CBC, 80,
                                              &cipher_struct);
      if (ret < 0)
        {
          gnutls_assert ();
        }

      ret =
        gnutls_crypto_single_cipher_register (GNUTLS_CIPHER_AES_256_CBC, 80,
                                              &cipher_struct);
      if (ret < 0)
        {
          gnutls_assert ();
        }

#ifdef ASM_X86_64
      if (check_pclmul ())
        {
          /* register GCM ciphers */
          _gnutls_debug_log ("Intel GCM accelerator was detected\n");
          ret =
            gnutls_crypto_single_cipher_register (GNUTLS_CIPHER_AES_128_GCM,
                                                  80, &aes_gcm_struct);
          if (ret < 0)
            {
              gnutls_assert ();
            }

          ret =
            gnutls_crypto_single_cipher_register (GNUTLS_CIPHER_AES_256_GCM,
                                                  80, &aes_gcm_struct);
          if (ret < 0)
            {
              gnutls_assert ();
            }
          
          if (ret >= 0)
            _gnutls_priority_prefer_aes_gcm();
        }
#endif
    }

  return;
}
