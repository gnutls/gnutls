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
 * use by Nettle by Simon Josefsson.  This implementation is not only
 * useful for pkcs#12 descryption.
 *
 * The implementation here is based on Peter Gutmann's RRC.2 paper.
 */

#if HAVE_CONFIG_H
# include "config.h"
#endif

#include <assert.h>

#include "arctwo.h"

#include "macros.h"

static const uint8_t arctwo_sbox[] = {
  217, 120, 249, 196,  25, 221, 181, 237,
   40, 233, 253, 121,  74, 160, 216, 157,
  198, 126,  55, 131,  43, 118,  83, 142,
   98,  76, 100, 136,  68, 139, 251, 162,
   23, 154,  89, 245, 135, 179,  79,  19,
   97,  69, 109, 141,   9, 129, 125,  50,
  189, 143,  64, 235, 134, 183, 123,  11,
  240, 149,  33,  34,  92, 107,  78, 130,
   84, 214, 101, 147, 206,  96, 178,  28,
  115,  86, 192,  20, 167, 140, 241, 220,
   18, 117, 202,  31,  59, 190, 228, 209,
   66,  61, 212,  48, 163,  60, 182,  38,
  111, 191,  14, 218,  70, 105,   7,  87,
   39, 242,  29, 155, 188, 148,  67,   3,
  248,  17, 199, 246, 144, 239,  62, 231,
    6, 195, 213,  47, 200, 102,  30, 215,
    8, 232, 234, 222, 128,  82, 238, 247,
  132, 170, 114, 172,  53,  77, 106,  42,
  150,  26, 210, 113,  90,  21,  73, 116,
   75, 159, 208,  94,   4,  24, 164, 236,
  194, 224,  65, 110,  15,  81, 203, 204,
   36, 145, 175,  80, 161, 244, 112,  57,
  153, 124,  58, 133,  35, 184, 180, 122,
  252,   2,  54,  91,  37,  85, 151,  49,
   45,  93, 250, 152, 227, 138, 146, 174,
    5, 223,  41,  16, 103, 108, 186, 201,
  211,   0, 230, 207, 225, 158, 168,  44,
   99,  22,   1,  63,  88, 226, 137, 169,
   13,  56,  52,  27, 171,  51, 255, 176,
  187,  72,  12,  95, 185, 177, 205,  46,
  197, 243, 219,  71, 229, 165, 156, 119,
   10, 166,  32, 104, 254, 127, 193, 173
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

  S = (unsigned char *) ctx->S;

  for (i = 0; i < length; i++)
    S[i] = key[i];

  for (i = length; i < 128; i++)
    S[i] = arctwo_sbox[(S[i - length] + S[i - 1]) & 255];

  S[0] = arctwo_sbox[S[0]];

  /* Phase 2 - reduce effective key size to "bits". This was not
   * discussed in Gutmann's paper. I've copied that from the public
   * domain code posted in sci.crypt. */
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
pkcs12_arctwo_set_key(struct arctwo_ctx *ctx,
		      unsigned length, const uint8_t *key)
{
  setkey_core (ctx, length, key, 1);
}

void
arctwo_set_key(struct arctwo_ctx *ctx,
	       unsigned length, const uint8_t *key)
{
  setkey_core (ctx, length, key, 0);
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

  /* First test. */
  arctwo_set_key (&ctx, sizeof(key_1), key_1);
  arctwo_encrypt (&ctx, ARCTWO_BLOCK_SIZE, scratch, plaintext_1);
  if (memcmp (scratch, ciphertext_1, sizeof(ciphertext_1)))
    puts ("RFC2268 encryption test 1 failed.");

  arctwo_set_key (&ctx, sizeof(key_1), key_1);
  arctwo_decrypt (&ctx, ARCTWO_BLOCK_SIZE, scratch, scratch);
  if (memcmp (scratch, plaintext_1, sizeof(plaintext_1)))
    puts ("RFC2268 decryption test 1 failed.");

  /* Second test. */
  arctwo_set_key (&ctx, sizeof(key_2), key_2);
  arctwo_encrypt (&ctx, ARCTWO_BLOCK_SIZE, scratch, plaintext_2);
  if (memcmp (scratch, ciphertext_2, sizeof(ciphertext_2)))
    puts ("RFC2268 encryption test 2 failed.");

  arctwo_set_key (&ctx, sizeof(key_2), key_2);
  arctwo_decrypt (&ctx, ARCTWO_BLOCK_SIZE, scratch, scratch);
  if (memcmp (scratch, plaintext_2, sizeof(plaintext_2)))
    puts ("RFC2268 decryption test 2 failed.");

  /* Third test. */
  arctwo_set_key(&ctx, sizeof(key_3), key_3);
  arctwo_encrypt (&ctx, ARCTWO_BLOCK_SIZE, scratch, plaintext_3);
  if (memcmp(scratch, ciphertext_3, sizeof(ciphertext_3)))
    puts ("RFC2268 encryption test 3 failed.");

  arctwo_set_key (&ctx, sizeof(key_3), key_3);
  arctwo_decrypt (&ctx, ARCTWO_BLOCK_SIZE, scratch, scratch);
  if (memcmp(scratch, plaintext_3, sizeof(plaintext_3)))
    puts ("RFC2268 decryption test 3 failed.");

  puts ("Done");

  return 0;
}
#endif /* TEST */
