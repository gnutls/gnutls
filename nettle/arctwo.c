/* arctwo.c  - The cipher described in rfc2268; aka Ron's Cipher 2.
 * Copyright (C) 2004 Simon Josefsson
 * Copyright (C) 2003 Nikos Mavroyanopoulos
 * Copyright (C) 2004 Free Software Foundation, Inc.
 *
 * This file is part of Libgcrypt
 *
 * Libgcrypt is free software; you can redistribute it and/or modify
 * it under the terms of the GNU Lesser general Public License as
 * published by the Free Software Foundation; either version 2.1 of
 * the License, or (at your option) any later version.
 *
 * Libgcrypt is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA
 */

/* This implementation was written by Nikos Mavroyanopoulos for GNUTLS
 * as a Libgcrypt module (gnutls/lib/x509/rc2.c) and later adapted for
 * direct use by Libgcrypt by Werner Koch and later adapted for direct
 * use by Nettle by Simon Josefsson.
 *
 * The implementation here is based on Peter Gutmann's RRC.2 paper and
 * RFC 2268.
 */

#if HAVE_CONFIG_H
# include "config.h"
#endif

#include <assert.h>

#include "arctwo.h"

#include "macros.h"

static const uint8_t arctwo_sbox[] = {
  0xd9, 0x78, 0xf9, 0xc4, 0x19, 0xdd, 0xb5, 0xed,
  0x28, 0xe9, 0xfd, 0x79, 0x4a, 0xa0, 0xd8, 0x9d,
  0xc6, 0x7e, 0x37, 0x83, 0x2b, 0x76, 0x53, 0x8e,
  0x62, 0x4c, 0x64, 0x88, 0x44, 0x8b, 0xfb, 0xa2,
  0x17, 0x9a, 0x59, 0xf5, 0x87, 0xb3, 0x4f, 0x13,
  0x61, 0x45, 0x6d, 0x8d, 0x09, 0x81, 0x7d, 0x32,
  0xbd, 0x8f, 0x40, 0xeb, 0x86, 0xb7, 0x7b, 0x0b,
  0xf0, 0x95, 0x21, 0x22, 0x5c, 0x6b, 0x4e, 0x82,
  0x54, 0xd6, 0x65, 0x93, 0xce, 0x60, 0xb2, 0x1c,
  0x73, 0x56, 0xc0, 0x14, 0xa7, 0x8c, 0xf1, 0xdc,
  0x12, 0x75, 0xca, 0x1f, 0x3b, 0xbe, 0xe4, 0xd1,
  0x42, 0x3d, 0xd4, 0x30, 0xa3, 0x3c, 0xb6, 0x26,
  0x6f, 0xbf, 0x0e, 0xda, 0x46, 0x69, 0x07, 0x57,
  0x27, 0xf2, 0x1d, 0x9b, 0xbc, 0x94, 0x43, 0x03,
  0xf8, 0x11, 0xc7, 0xf6, 0x90, 0xef, 0x3e, 0xe7,
  0x06, 0xc3, 0xd5, 0x2f, 0xc8, 0x66, 0x1e, 0xd7,
  0x08, 0xe8, 0xea, 0xde, 0x80, 0x52, 0xee, 0xf7,
  0x84, 0xaa, 0x72, 0xac, 0x35, 0x4d, 0x6a, 0x2a,
  0x96, 0x1a, 0xd2, 0x71, 0x5a, 0x15, 0x49, 0x74,
  0x4b, 0x9f, 0xd0, 0x5e, 0x04, 0x18, 0xa4, 0xec,
  0xc2, 0xe0, 0x41, 0x6e, 0x0f, 0x51, 0xcb, 0xcc,
  0x24, 0x91, 0xaf, 0x50, 0xa1, 0xf4, 0x70, 0x39,
  0x99, 0x7c, 0x3a, 0x85, 0x23, 0xb8, 0xb4, 0x7a,
  0xfc, 0x02, 0x36, 0x5b, 0x25, 0x55, 0x97, 0x31,
  0x2d, 0x5d, 0xfa, 0x98, 0xe3, 0x8a, 0x92, 0xae,
  0x05, 0xdf, 0x29, 0x10, 0x67, 0x6c, 0xba, 0xc9,
  0xd3, 0x00, 0xe6, 0xcf, 0xe1, 0x9e, 0xa8, 0x2c,
  0x63, 0x16, 0x01, 0x3f, 0x58, 0xe2, 0x89, 0xa9,
  0x0d, 0x38, 0x34, 0x1b, 0xab, 0x33, 0xff, 0xb0,
  0xbb, 0x48, 0x0c, 0x5f, 0xb9, 0xb1, 0xcd, 0x2e,
  0xc5, 0xf3, 0xdb, 0x47, 0xe5, 0xa5, 0x9c, 0x77,
  0x0a, 0xa6, 0x20, 0x68, 0xfe, 0x7f, 0xc1, 0xad
};

#define rotl16(x,n)   (((x) << ((uint16_t)(n))) | ((x) >> (16 - (uint16_t)(n))))
#define rotr16(x,n)   (((x) >> ((uint16_t)(n))) | ((x) << (16 - (uint16_t)(n))))

void
arctwo_encrypt(struct arctwo_ctx *ctx,
	       unsigned length, uint8_t *dst,
	       const uint8_t *src)
{
  FOR_BLOCKS(length, dst, src, ARCTWO_BLOCK_SIZE)
    {
      register int i, j;
      uint16_t word0 = 0, word1 = 0, word2 = 0, word3 = 0;

      word0 = (word0 << 8) | src[1];
      word0 = (word0 << 8) | src[0];
      word1 = (word1 << 8) | src[3];
      word1 = (word1 << 8) | src[2];
      word2 = (word2 << 8) | src[5];
      word2 = (word2 << 8) | src[4];
      word3 = (word3 << 8) | src[7];
      word3 = (word3 << 8) | src[6];

      for (i = 0; i < 16; i++)
	{
	  j = i * 4;
	  /* For some reason I cannot combine those steps. */
	  word0 += (word1 & ~word3) + (word2 & word3) + ctx->S[j];
	  word0 = rotl16(word0, 1);

	  word1 += (word2 & ~word0) + (word3 & word0) + ctx->S[j + 1];
	  word1 = rotl16(word1, 2);

	  word2 += (word3 & ~word1) + (word0 & word1) + ctx->S[j + 2];
	  word2 = rotl16(word2, 3);

	  word3 += (word0 & ~word2) + (word1 & word2) + ctx->S[j + 3];
	  word3 = rotl16(word3, 5);

	  if (i == 4 || i == 10)
	    {
	      word0 += ctx->S[word3 & 63];
	      word1 += ctx->S[word0 & 63];
	      word2 += ctx->S[word1 & 63];
	      word3 += ctx->S[word2 & 63];
	    }
	}

      dst[0] = word0 & 255;
      dst[1] = word0 >> 8;
      dst[2] = word1 & 255;
      dst[3] = word1 >> 8;
      dst[4] = word2 & 255;
      dst[5] = word2 >> 8;
      dst[6] = word3 & 255;
      dst[7] = word3 >> 8;
    }
}

void
arctwo_decrypt(struct arctwo_ctx *ctx,
	       unsigned length, uint8_t *dst,
	       const uint8_t *src)
{
  FOR_BLOCKS(length, dst, src, ARCTWO_BLOCK_SIZE)
    {
      register int i, j;
      uint16_t word0 = 0, word1 = 0, word2 = 0, word3 = 0;

      word0 = (word0 << 8) | src[1];
      word0 = (word0 << 8) | src[0];
      word1 = (word1 << 8) | src[3];
      word1 = (word1 << 8) | src[2];
      word2 = (word2 << 8) | src[5];
      word2 = (word2 << 8) | src[4];
      word3 = (word3 << 8) | src[7];
      word3 = (word3 << 8) | src[6];

      for (i = 15; i >= 0; i--)
	{
	  j = i * 4;

	  word3 = rotr16(word3, 5);
	  word3 -= (word0 & ~word2) + (word1 & word2) + ctx->S[j + 3];

	  word2 = rotr16(word2, 3);
	  word2 -= (word3 & ~word1) + (word0 & word1) + ctx->S[j + 2];

	  word1 = rotr16(word1, 2);
	  word1 -= (word2 & ~word0) + (word3 & word0) + ctx->S[j + 1];

	  word0 = rotr16(word0, 1);
	  word0 -= (word1 & ~word3) + (word2 & word3) + ctx->S[j];

	  if (i == 5 || i == 11)
	    {
	      word3 = word3 - ctx->S[word2 & 63];
	      word2 = word2 - ctx->S[word1 & 63];
	      word1 = word1 - ctx->S[word0 & 63];
	      word0 = word0 - ctx->S[word3 & 63];
	    }

	}

      dst[0] = word0 & 255;
      dst[1] = word0 >> 8;
      dst[2] = word1 & 255;
      dst[3] = word1 >> 8;
      dst[4] = word2 & 255;
      dst[5] = word2 >> 8;
      dst[6] = word3 & 255;
      dst[7] = word3 >> 8;
    }
}

static void
setkey_core(struct arctwo_ctx *ctx,
	    unsigned length, const uint8_t *key,
	    int with_phase2)
{
  unsigned i;
  uint8_t *S, x;

  assert(length >= ARCTWO_MIN_KEY_SIZE);
  assert(length <= ARCTWO_MAX_KEY_SIZE);

  S = (uint8_t *) ctx->S;

  for (i = 0; i < length; i++)
    S[i] = key[i];

  /* Phase 1: Expand input key to 128 bytes */
  for (i = length; i < ARCTWO_MAX_KEY_SIZE; i++)
    S[i] = arctwo_sbox[(S[i - length] + S[i - 1]) & 255];

  S[0] = arctwo_sbox[S[0]];

  /* Phase 2 - reduce effective key size to "bits".
   *
   * This was not discussed in Gutmann's paper. I've copied that from
   * the public domain code posted in sci.crypt. */
  if (with_phase2)
    {
      int bits = length * 8;
      int len = (bits + 7) >> 3;
      i = 128 - len;
      x = arctwo_sbox[S[i] & (255 >> (7 & -bits))];
      S[i] = x;

      while (i--)
	{
	  x = arctwo_sbox[x ^ S[i + len]];
	  S[i] = x;
	}
    }

  /* Make the expanded key, endian independent. */
  for (i = 0; i < 64; i++)
    ctx->S[i] = ( (uint16_t) S[i * 2] | (((uint16_t) S[i * 2 + 1]) << 8));
}

void
gutmann_arctwo_set_key(struct arctwo_ctx *ctx,
		      unsigned length, const uint8_t *key)
{
  setkey_core (ctx, length, key, 0);
}

void
arctwo_set_key(struct arctwo_ctx *ctx,
	       unsigned length, const uint8_t *key)
{
  setkey_core (ctx, length, key, 1);
}

#ifdef TEST

#include <stdio.h>

int main (void)
{
  struct arctwo_ctx ctx;
  uint8_t scratch[16];

  /* Test vectors from Peter Gutmann's paper. */
  static uint8_t key_1[] =
    { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
      0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
    };
  static uint8_t plaintext_1[] =
    { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };
  static const uint8_t ciphertext_1[] =
    { 0x1C, 0x19, 0x8A, 0x83, 0x8D, 0xF0, 0x28, 0xB7 };

  static uint8_t key_2[] =
    { 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
      0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F
    };
  static uint8_t plaintext_2[] =
    { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };
  static uint8_t ciphertext_2[] =
    { 0x50, 0xDC, 0x01, 0x62, 0xBD, 0x75, 0x7F, 0x31 };

  /* This one was checked against libmcrypt's RFC2268. */
  static uint8_t key_3[] =
    { 0x30, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
      0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
    };
  static uint8_t plaintext_3[] =
    { 0x10, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };
  static uint8_t ciphertext_3[] =
    { 0x8f, 0xd1, 0x03, 0x89, 0x33, 0x6b, 0xf9, 0x5e };

  /* Test vectors from RFC 2268. */
  static uint8_t key_4[] =
    { 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff };
  static uint8_t plaintext_4[] =
    { 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff };
  static const uint8_t ciphertext_4[] =
    { 0x27, 0x8b, 0x27, 0xe4, 0x2e, 0x2f, 0x0d, 0x49 };

  static uint8_t key_5[] =
    { 0x30, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };
  static uint8_t plaintext_5[] =
    { 0x10, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01 };
  static const uint8_t ciphertext_5[] =
    { 0x30, 0x64, 0x9e, 0xdf, 0x9b, 0xe7, 0xd2, 0xc2 };

  static uint8_t key_6[] =
    { 0x88, 0xbc, 0xa9, 0x0e, 0x90, 0x87, 0x5a, 0x7f,
      0x0f, 0x79, 0xc3, 0x84, 0x62, 0x7b, 0xaf, 0xb2 };
  static uint8_t plaintext_6[] =
    { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };
  static const uint8_t ciphertext_6[] =
    { 0x22, 0x69, 0x55, 0x2a, 0xb0, 0xf8, 0x5c, 0xa6 };

  /* First test. */
  gutmann_arctwo_set_key (&ctx, sizeof(key_1), key_1);
  arctwo_encrypt (&ctx, ARCTWO_BLOCK_SIZE, scratch, plaintext_1);
  if (memcmp (scratch, ciphertext_1, sizeof(ciphertext_1)))
    puts ("RFC2268 encryption test 1 failed.");

  gutmann_arctwo_set_key (&ctx, sizeof(key_1), key_1);
  arctwo_decrypt (&ctx, ARCTWO_BLOCK_SIZE, scratch, scratch);
  if (memcmp (scratch, plaintext_1, sizeof(plaintext_1)))
    puts ("RFC2268 decryption test 1 failed.");

  /* Second test. */
  gutmann_arctwo_set_key (&ctx, sizeof(key_2), key_2);
  arctwo_encrypt (&ctx, ARCTWO_BLOCK_SIZE, scratch, plaintext_2);
  if (memcmp (scratch, ciphertext_2, sizeof(ciphertext_2)))
    puts ("RFC2268 encryption test 2 failed.");

  gutmann_arctwo_set_key (&ctx, sizeof(key_2), key_2);
  arctwo_decrypt (&ctx, ARCTWO_BLOCK_SIZE, scratch, scratch);
  if (memcmp (scratch, plaintext_2, sizeof(plaintext_2)))
    puts ("RFC2268 decryption test 2 failed.");

  /* Third test. */
  gutmann_arctwo_set_key(&ctx, sizeof(key_3), key_3);
  arctwo_encrypt (&ctx, ARCTWO_BLOCK_SIZE, scratch, plaintext_3);
  if (memcmp(scratch, ciphertext_3, sizeof(ciphertext_3)))
    puts ("RFC2268 encryption test 3 failed.");

  gutmann_arctwo_set_key (&ctx, sizeof(key_3), key_3);
  arctwo_decrypt (&ctx, ARCTWO_BLOCK_SIZE, scratch, scratch);
  if (memcmp(scratch, plaintext_3, sizeof(plaintext_3)))
    puts ("RFC2268 decryption test 3 failed.");

  /* Fourth test. */
  arctwo_set_key (&ctx, sizeof(key_4), key_4);
  arctwo_encrypt (&ctx, ARCTWO_BLOCK_SIZE, scratch, plaintext_4);
  if (memcmp (scratch, ciphertext_4, sizeof(ciphertext_4)))
    puts ("RFC2268 encryption test 4 failed.");

  arctwo_set_key (&ctx, sizeof(key_4), key_4);
  arctwo_decrypt (&ctx, ARCTWO_BLOCK_SIZE, scratch, scratch);
  if (memcmp (scratch, plaintext_4, sizeof(plaintext_4)))
    puts ("RFC2268 decryption test 4 failed.");

  /* Fifth test. */
  arctwo_set_key (&ctx, sizeof(key_5), key_5);
  arctwo_encrypt (&ctx, ARCTWO_BLOCK_SIZE, scratch, plaintext_5);
  if (memcmp (scratch, ciphertext_5, sizeof(ciphertext_5)))
    puts ("RFC2268 encryption test 5 failed.");

  arctwo_set_key (&ctx, sizeof(key_5), key_5);
  arctwo_decrypt (&ctx, ARCTWO_BLOCK_SIZE, scratch, scratch);
  if (memcmp (scratch, plaintext_5, sizeof(plaintext_5)))
    puts ("RFC2268 decryption test 5 failed.");

  /* Sixth test. */
  arctwo_set_key (&ctx, sizeof(key_6), key_6);
  arctwo_encrypt (&ctx, ARCTWO_BLOCK_SIZE, scratch, plaintext_6);
  if (memcmp (scratch, ciphertext_6, sizeof(ciphertext_6)))
    puts ("RFC2268 encryption test 6 failed.");

  arctwo_set_key (&ctx, sizeof(key_6), key_6);
  arctwo_decrypt (&ctx, ARCTWO_BLOCK_SIZE, scratch, scratch);
  if (memcmp (scratch, plaintext_6, sizeof(plaintext_6)))
    puts ("RFC2268 decryption test 6 failed.");

  puts ("Done");

  return 0;
}
#endif /* TEST */
