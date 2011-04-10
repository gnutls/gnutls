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
#include <wmmintrin.h>
#include <aes-x86.h>
#include <x86.h>

struct aes_ctx {
	uint8_t iv[16];
	uint8_t key[16*10];
	size_t keysize;
};

static int
aes_cipher_init (gnutls_cipher_algorithm_t algorithm, void **_ctx)
{
  struct aes_ctx *ctx;
  
  if (algorithm != GNUTLS_CIPHER_AES_128_CBC)
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

inline static __m128i aes128_assist (__m128i temp1, __m128i temp2)
{
__m128i temp3;
	temp2 = _mm_shuffle_epi32 (temp2 ,0xff);
	temp3 = _mm_slli_si128 (temp1, 0x4);
	temp1 = _mm_xor_si128 (temp1, temp3);
	temp3 = _mm_slli_si128 (temp3, 0x4);
	temp1 = _mm_xor_si128 (temp1, temp3);
	temp3 = _mm_slli_si128 (temp3, 0x4);
	temp1 = _mm_xor_si128 (temp1, temp3);
	temp1 = _mm_xor_si128 (temp1, temp2);

	return temp1;
}

static int
aes_cipher_setkey (void *_ctx, const void *userkey, size_t keysize)
{
struct aes_ctx *ctx = _ctx;
__m128i temp1, temp2;
__m128i *Key_Schedule = (__m128i*)ctx->key;

	temp1 = _mm_loadu_si128((__m128i*)userkey);
	Key_Schedule[0] = temp1;
	temp2 = _mm_aeskeygenassist_si128 (temp1 ,0x1);
	temp1 = aes128_assist(temp1, temp2);
	Key_Schedule[1] = temp1;
	temp2 = _mm_aeskeygenassist_si128 (temp1,0x2);
	temp1 = aes128_assist(temp1, temp2);
	Key_Schedule[2] = temp1;
	temp2 = _mm_aeskeygenassist_si128 (temp1,0x4);
	temp1 = aes128_assist(temp1, temp2);
	Key_Schedule[3] = temp1;
	temp2 = _mm_aeskeygenassist_si128 (temp1,0x8);
	temp1 = aes128_assist(temp1, temp2);
	Key_Schedule[4] = temp1;
	temp2 = _mm_aeskeygenassist_si128 (temp1,0x10);
	temp1 = aes128_assist(temp1, temp2);
	Key_Schedule[5] = temp1;
	temp2 = _mm_aeskeygenassist_si128 (temp1,0x20);
	temp1 = aes128_assist(temp1, temp2);
	Key_Schedule[6] = temp1;
	temp2 = _mm_aeskeygenassist_si128 (temp1,0x40);
	temp1 = aes128_assist(temp1, temp2);
	Key_Schedule[7] = temp1;
	temp2 = _mm_aeskeygenassist_si128 (temp1,0x80);
	temp1 = aes128_assist(temp1, temp2);
	Key_Schedule[8] = temp1;
	temp2 = _mm_aeskeygenassist_si128 (temp1,0x1b);
	temp1 = aes128_assist(temp1, temp2);
	Key_Schedule[9] = temp1;
	temp2 = _mm_aeskeygenassist_si128 (temp1,0x36);
	temp1 = aes128_assist(temp1, temp2);
	Key_Schedule[10] = temp1;

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

#define AES_128_ROUNDS 10

static int
aes_encrypt (void *_ctx, const void *plain, size_t plainsize,
                   void *encr, size_t length)
{
struct aes_ctx *ctx = _ctx;
__m128i feedback,data;
int i,j;

	feedback=_mm_loadu_si128 ((__m128i*)ctx->iv);
	for(i=0; i < length; i++) {
		data = _mm_loadu_si128 (&((__m128i*)plain)[i]);
		feedback = _mm_xor_si128 (data,feedback);
		feedback = _mm_xor_si128 (feedback,((__m128i*)ctx->key)[0]);
    
		for(j=1; j <AES_128_ROUNDS; j++)
			feedback = _mm_aesenc_si128 (feedback,((__m128i*)ctx->key)[j]);

		feedback = _mm_aesenclast_si128 (feedback,((__m128i*)ctx->key)[j]);
		_mm_storeu_si128 (&((__m128i*)encr)[i],feedback);
	}

  return 0;
}

static int
aes_decrypt (void *_ctx, const void *encr, size_t encrsize,
                   void *plain, size_t length)
{
struct aes_ctx *ctx = _ctx;
__m128i data,feedback,last_in;
int i,j;

	feedback=_mm_loadu_si128 ((__m128i*)ctx->iv);

	for(i=0; i < length; i++) {
		last_in=_mm_loadu_si128 (&((__m128i*)encr)[i]);
		data = _mm_xor_si128 (last_in,((__m128i*)ctx->key)[0]);
    
		for(j=1; j <AES_128_ROUNDS; j++)
			data = _mm_aesdec_si128 (data,((__m128i*)ctx->key)[j]);

		data = _mm_aesdeclast_si128 (data,((__m128i*)ctx->key)[j]);
		data = _mm_xor_si128 (data,feedback);
		_mm_storeu_si128 (&((__m128i*)plain)[i],data);
		feedback=last_in;
	}

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
		ret = gnutls_crypto_single_cipher_register (GNUTLS_CIPHER_AES_128_CBC, 90, &cipher_struct);
		if (ret < 0)
		{
		  gnutls_assert ();
		}
	}

	return;
}
