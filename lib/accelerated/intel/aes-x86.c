/*
 * Copyright (C) 2011, Free Software Foundation
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
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301,
 * USA
 *
 * The following code is an implementation of the AES-128-CBC cipher
 * using intel's AES instruction set. It is based on Intel reference
 * code.
 */

#include <gnutls_errors.h>
#include <gnutls_int.h>
#include <gnutls/crypto.h>
#include <gnutls_errors.h>
#include <aes-x86.h>
#include <x86.h>
#include "iaes_asm_interface.h"

#ifdef __GNUC__
# define ALIGN16 __attribute__ ((aligned (16))) 
#else
# define ALIGN16
#endif

typedef void (*enc_func)(sAesData*);

struct aes_ctx {
	uint8_t ALIGN16 expanded_key[16*16];
	uint8_t ALIGN16 expanded_key_dec[16*16];
	uint8_t iv[16];
	enc_func enc;
	enc_func dec;
	size_t keysize;
};

static int
aes_cipher_init (gnutls_cipher_algorithm_t algorithm, void **_ctx)
{
  struct aes_ctx *ctx;
  
  /* we use key size to distinguish */
  if (algorithm != GNUTLS_CIPHER_AES_128_CBC && algorithm != GNUTLS_CIPHER_AES_192_CBC 
    && algorithm != GNUTLS_CIPHER_AES_256_CBC)
    return GNUTLS_E_INVALID_REQUEST;

  *_ctx = gnutls_calloc (1, sizeof (struct aes_ctx));
  if (*_ctx == NULL)
    {
      gnutls_assert ();
      return GNUTLS_E_MEMORY_ERROR;
    }

  ctx = *_ctx;

  return 0;
}

static int
aes_cipher_setkey (void *_ctx, const void *userkey, size_t keysize)
{
struct aes_ctx *ctx = _ctx;

  if (keysize == 128/8)
    {
      iEncExpandKey128((void*)userkey, ctx->expanded_key);
      iDecExpandKey128((void*)userkey, ctx->expanded_key_dec);
      ctx->enc = iEnc128_CBC;
      ctx->dec = iDec128_CBC;
    }
  else if (keysize == 192/8)
    {
      iEncExpandKey192((void*)userkey, ctx->expanded_key);
      iDecExpandKey192((void*)userkey, ctx->expanded_key_dec);
      ctx->enc = iEnc192_CBC;
      ctx->dec = iDec192_CBC;
    }
  else if (keysize == 256/8)
    {
      iEncExpandKey256((void*)userkey, ctx->expanded_key);
      iDecExpandKey256((void*)userkey, ctx->expanded_key_dec);
      ctx->enc = iEnc256_CBC;
      ctx->dec = iDec256_CBC;
    }
  else
    return gnutls_assert_val(GNUTLS_E_INVALID_REQUEST);

  ctx->keysize = keysize;

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
aes_encrypt (void *_ctx, const void *plain, size_t plainsize,
                   void *encr, size_t length)
{
struct aes_ctx *ctx = _ctx;
sAesData aesData;
  
  aesData.iv = ctx->iv;
  aesData.in_block = (void*)plain;
  aesData.out_block = encr;
  aesData.expanded_key = ctx->expanded_key;
  aesData.num_blocks = (plainsize + 1) / 16;

  ctx->enc(&aesData);

  return 0;
}

static int
aes_decrypt (void *_ctx, const void *encr, size_t encrsize,
                   void *plain, size_t length)
{
struct aes_ctx *ctx = _ctx;
sAesData aesData;

  aesData.iv = ctx->iv;
  aesData.in_block = (void*)encr;
  aesData.out_block = plain;
  aesData.expanded_key = ctx->expanded_key_dec;
  aesData.num_blocks = (encrsize + 1) / 16;

  ctx->dec(&aesData);

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

static unsigned check_optimized_aes(void)
{
unsigned int a,b,c,d;
  cpuid(1, a,b,c,d);
  
  return (c & 0x2000000);
}

void
register_x86_crypto (void)
{
int ret;
	if (check_optimized_aes()) {
	        fprintf(stderr, "Intel AES accelerator was detected\n");
		ret = gnutls_crypto_single_cipher_register (GNUTLS_CIPHER_AES_128_CBC, 80, &cipher_struct);
		if (ret < 0)
		{
		  gnutls_assert ();
		}

		ret = gnutls_crypto_single_cipher_register (GNUTLS_CIPHER_AES_192_CBC, 80, &cipher_struct);
		if (ret < 0)
		{
		  gnutls_assert ();
		}

		ret = gnutls_crypto_single_cipher_register (GNUTLS_CIPHER_AES_256_CBC, 80, &cipher_struct);
		if (ret < 0)
		{
		  gnutls_assert ();
		}
	}

	return;
}
