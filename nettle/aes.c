/* aes.c
 *
 * The aes/rijndael block cipher.
 */

/* nettle, low-level cryptographics library
 *
 * Copyright (C) 2000, 2001 Rafael R. Sevilla, Niels Möller
 *  
 * The nettle library is free software; you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License as published by
 * the Free Software Foundation; either version 2.1 of the License, or (at your
 * option) any later version.
 * 
 * The nettle library is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY
 * or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU Lesser General Public
 * License for more details.
 * 
 * You should have received a copy of the GNU Lesser General Public License
 * along with the nettle library; see the file COPYING.LIB.  If not, write to
 * the Free Software Foundation, Inc., 59 Temple Place - Suite 330, Boston,
 * MA 02111-1307, USA.
 */

/* Originally written by Rafael R. Sevilla <dido@pacific.net.ph> */

#if HAVE_CONFIG_H
# include "config.h"
#endif

#include <assert.h>

#include "aes-internal.h"

#include "macros.h"

#ifndef AES_DEBUG
# define AES_DEBUG 0
#endif

#if AES_DEBUG
# include <stdio.h>

static void
d4(const char *name, unsigned r, const uint32_t *data)
{
  unsigned j;
  
  fprintf(stderr, "aes, %d, %s: ", r, name);

  for (j = 0; j<4; j++)
    fprintf(stderr, "%08x, ", data[j]);
  fprintf(stderr, "\n");
}
static void
d2(const char *aname, uint32_t a, const char *bname,  uint32_t b)
{
  fprintf(stderr, "aes, %s: %08x, %s, %08x\n",
	  aname, a, bname, b);
}
# define D4(x) d4 x
# define D2(x) d2 x
#else
# define D4(x)
# define D2(x)
#endif

/* Get the byte with index 0, 1, 2 and 3 */
#define B0(x) ((x) & 0xff)
#define B1(x) (((x) >> 8) & 0xff)
#define B2(x) (((x) >> 16) & 0xff)
#define B3(x) (((x) >> 24) & 0xff)

#define IDX0(j) (j)
#define IDX1(j) (T->idx[0][j])
#define IDX2(j) (T->idx[1][j])
#define IDX3(j) (T->idx[2][j])

void
_aes_crypt(const struct aes_ctx *ctx,
	   const struct aes_table *T,
	   unsigned length, uint8_t *dst,
	   const uint8_t *src)
{
  FOR_BLOCKS(length, dst, src, AES_BLOCK_SIZE)
    {
      uint32_t wtxt[4];		/* working ciphertext */
      unsigned i;
      unsigned round;
      
      /* Get clear text, using little-endian byte order.
       * Also XOR with the first subkey. */
      for (i = 0; i<4; i++)
	wtxt[i] = LE_READ_UINT32(src + 4*i) ^ ctx->keys[i];

      for (round = 1; round < ctx->nrounds; round++)
	{
	  uint32_t t[4];
	  unsigned j;

	  D4(("wtxt", round, wtxt));
	  D4(("key", round, &ctx->keys[4*round]));

	  /* What's the best way to order this loop? Ideally,
	   * we'd want to keep both t and wtxt in registers. */

	  for (j=0; j<4; j++)
	    {
	      /* FIXME: Figure out how the indexing should really be
	       * done. With the current idx arrays, it looks like the
	       * code shifts the rows in the wrong direction. But it
	       * passes the testsuite. Perhaps the tables are rotated
	       * in the wrong direction, but I don't think so. */

#if AES_SMALL
	      t[j] =         T->table[0][ B0(wtxt[IDX0(j)]) ] ^
		ROTRBYTE(    T->table[0][ B1(wtxt[IDX1(j)]) ]^
		  ROTRBYTE(  T->table[0][ B2(wtxt[IDX2(j)]) ] ^
		    ROTRBYTE(T->table[0][ B3(wtxt[IDX3(j)]) ])));
#else /* !AES_SMALL */
	      t[j] = (  T->table[0][ B0(wtxt[IDX0(j)]) ]
		      ^ T->table[1][ B1(wtxt[IDX1(j)]) ]
		      ^ T->table[2][ B2(wtxt[IDX2(j)]) ]
		      ^ T->table[3][ B3(wtxt[IDX3(j)]) ]);
#endif /* !AES_SMALL */
	    }
	  D4(("t", round, t));

	  for (j = 0; j<4; j++)
	    wtxt[j] = t[j] ^ ctx->keys[4*round + j];
	}
      /* Final round */
      {
	uint32_t out;
	unsigned j;
	for (j = 0; j<4; j++)
	  {
	    /* FIXME: Figure out how the indexing should really be done.
	     * It looks like this code shifts the rows in the wrong
	     * direction, but it passes the testsuite. */

	    out = (   (uint32_t) T->sbox[ B0(wtxt[IDX0(j)]) ]
		   | ((uint32_t) T->sbox[ B1(wtxt[IDX1(j)]) ] << 8)
		   | ((uint32_t) T->sbox[ B2(wtxt[IDX2(j)]) ] << 16)
		   | ((uint32_t) T->sbox[ B3(wtxt[IDX3(j)]) ] << 24));

	    D2(("t", out, "key", ctx->keys[4*round + j]));

	    out ^= ctx->keys[4*round + j];

	    LE_WRITE_UINT32(dst + 4*j, out);
	  }
      }
    }
}
