/* des.c
 *
 * The des block cipher.
 *
 */

/* nettle, low-level cryptographics library
 *
 * Copyright (C) 2001 Niels Möller
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

/*	des - fast & portable DES encryption & decryption.
 *	Copyright (C) 1992  Dana L. How
 *	Please see the file `descore.README' for the complete copyright notice.
 */

#if HAVE_CONFIG_H
# include "config.h"
#endif

#include <assert.h>

#include "des.h"

#include "desCode.h"

/* various tables */

static const uint32_t
des_keymap[] = {
#include	"keymap.h"
};

static const uint8_t
rotors[] = {
#include	"rotors.h"
};

static const char
parity[] = {
#include	"parity.h"
};

static ENCRYPT(DesSmallFipsEncrypt,TEMPSMALL, LOADFIPS,KEYMAPSMALL,SAVEFIPS)
static DECRYPT(DesSmallFipsDecrypt,TEMPSMALL, LOADFIPS,KEYMAPSMALL,SAVEFIPS)

void
des_fix_parity(unsigned length, uint8_t *dst,
	       const uint8_t *src)
{
  unsigned i;
  for (i = 0; i<length; i++)
    dst[i] = src[i] ^ (parity[src[i]] == 8);
}

int
des_set_key(struct des_ctx *ctx, const uint8_t *key)
{
  register uint32_t n, w;
  register char * b0, * b1;
  char bits0[56], bits1[56];
  uint32_t *method;
  const uint8_t *k;

  {
    register const char *b;
    /* check for bad parity and weak keys */
    b = parity;
    n  = b[key[0]]; n <<= 4;
    n |= b[key[1]]; n <<= 4;
    n |= b[key[2]]; n <<= 4;
    n |= b[key[3]]; n <<= 4;
    n |= b[key[4]]; n <<= 4;
    n |= b[key[5]]; n <<= 4;
    n |= b[key[6]]; n <<= 4;
    n |= b[key[7]];
    w  = 0x88888888l;
  }
  
  /* report bad parity in key */
  if ( n & w )
    {
      ctx->status = DES_BAD_PARITY;
      return 0;
    }
  ctx->status = DES_OK; 

  /* report a weak or semi-weak key */
  if ( !((n - (w >> 3)) & w) ) {	/* 1 in 10^10 keys passes this test */
    if ( n < 0X41415151 ) {
      if ( n < 0X31312121 ) {
	if ( n < 0X14141515 ) {
	  /* 01 01 01 01 01 01 01 01 */
	  if ( n == 0X11111111 ) goto weak;
	  /* 01 1F 01 1F 01 0E 01 0E */
	  if ( n == 0X13131212 ) goto weak;
	} else {
	  /* 01 E0 01 E0 01 F1 01 F1 */
	  if ( n == 0X14141515 ) goto weak;
	  /* 01 FE 01 FE 01 FE 01 FE */
	  if ( n == 0X16161616 ) goto weak;
	}
      } else {
	if ( n < 0X34342525 ) {
	  /* 1F 01 1F 01 0E 01 0E 01 */
	  if ( n == 0X31312121 ) goto weak;
	  /* 1F 1F 1F 1F 0E 0E 0E 0E */	/* ? */
	  if ( n == 0X33332222 ) goto weak;
	} else {
	  /* 1F E0 1F E0 0E F1 0E F1 */
	  if ( n == 0X34342525 ) goto weak;
	  /* 1F FE 1F FE 0E FE 0E FE */
	  if ( n == 0X36362626 ) goto weak;
	}
      }
    } else {
      if ( n < 0X61616161 ) {
	if ( n < 0X44445555 ) {
	  /* E0 01 E0 01 F1 01 F1 01 */
	  if ( n == 0X41415151 ) goto weak;
	  /* E0 1F E0 1F F1 0E F1 0E */
	  if ( n == 0X43435252 ) goto weak;
	} else {
	  /* E0 E0 E0 E0 F1 F1 F1 F1 */	/* ? */
	  if ( n == 0X44445555 ) goto weak;
	  /* E0 FE E0 FE F1 FE F1 FE */
	  if ( n == 0X46465656 ) goto weak;
	}
      } else {
	if ( n < 0X64646565 ) {
	  /* FE 01 FE 01 FE 01 FE 01 */
	  if ( n == 0X61616161 ) goto weak;
	  /* FE 1F FE 1F FE 0E FE 0E */
	  if ( n == 0X63636262 ) goto weak;
	} else {
	  /* FE E0 FE E0 FE F1 FE F1 */
	  if ( n == 0X64646565 ) goto weak;
	  /* FE FE FE FE FE FE FE FE */
	  if ( n == 0X66666666 )
          {
          weak:
            ctx->status = DES_WEAK_KEY;
          }
	}
      }
    }
  }

  /* NOTE: We go on and expand the key, even if it was weak */
  /* explode the bits */
  n = 56;
  b0 = bits0;
  b1 = bits1;
  do {
    w = (256 | *key++) << 2;
    do {
      --n;
      b1[n] = 8 & w;
      w >>= 1;
      b0[n] = 4 & w;
    } while ( w >= 16 );
  } while ( n );

  /* put the bits in the correct places */
  n = 16;
  k = rotors;
  method = ctx->key;
  
  do {
    w   = (b1[k[ 0   ]] | b0[k[ 1   ]]) << 4;
    w  |= (b1[k[ 2   ]] | b0[k[ 3   ]]) << 2;
    w  |=  b1[k[ 4   ]] | b0[k[ 5   ]];
    w <<= 8;
    w  |= (b1[k[ 6   ]] | b0[k[ 7   ]]) << 4;
    w  |= (b1[k[ 8   ]] | b0[k[ 9   ]]) << 2;
    w  |=  b1[k[10   ]] | b0[k[11   ]];
    w <<= 8;
    w  |= (b1[k[12   ]] | b0[k[13   ]]) << 4;
    w  |= (b1[k[14   ]] | b0[k[15   ]]) << 2;
    w  |=  b1[k[16   ]] | b0[k[17   ]];
    w <<= 8;
    w  |= (b1[k[18   ]] | b0[k[19   ]]) << 4;
    w  |= (b1[k[20   ]] | b0[k[21   ]]) << 2;
    w  |=  b1[k[22   ]] | b0[k[23   ]];

    method[0] = w;

    w   = (b1[k[ 0+24]] | b0[k[ 1+24]]) << 4;
    w  |= (b1[k[ 2+24]] | b0[k[ 3+24]]) << 2;
    w  |=  b1[k[ 4+24]] | b0[k[ 5+24]];
    w <<= 8;
    w  |= (b1[k[ 6+24]] | b0[k[ 7+24]]) << 4;
    w  |= (b1[k[ 8+24]] | b0[k[ 9+24]]) << 2;
    w  |=  b1[k[10+24]] | b0[k[11+24]];
    w <<= 8;
    w  |= (b1[k[12+24]] | b0[k[13+24]]) << 4;
    w  |= (b1[k[14+24]] | b0[k[15+24]]) << 2;
    w  |=  b1[k[16+24]] | b0[k[17+24]];
    w <<= 8;
    w  |= (b1[k[18+24]] | b0[k[19+24]]) << 4;
    w  |= (b1[k[20+24]] | b0[k[21+24]]) << 2;
    w  |=  b1[k[22+24]] | b0[k[23+24]];

    ROR(w, 4, 28);		/* could be eliminated */
    method[1] = w;

    k	+= 48;
    method	+= 2;
  } while ( --n );

  return (ctx->status == DES_OK);
}

void
des_encrypt(const struct des_ctx *ctx,
	    unsigned length, uint8_t *dst,
	    const uint8_t *src)
{
  assert(!(length % DES_BLOCK_SIZE));
  assert(ctx->status == DES_OK);
  
  while (length)
    {
      DesSmallFipsEncrypt(dst, ctx->key, src);
      length -= DES_BLOCK_SIZE;
      src += DES_BLOCK_SIZE;
      dst += DES_BLOCK_SIZE;
    }
}

void
des_decrypt(const struct des_ctx *ctx,
	    unsigned length, uint8_t *dst,
	    const uint8_t *src)
{
  assert(!(length % DES_BLOCK_SIZE));
  assert(ctx->status == DES_OK);

  while (length)
    {
      DesSmallFipsDecrypt(dst, ctx->key, src);
      length -= DES_BLOCK_SIZE;
      src += DES_BLOCK_SIZE;
      dst += DES_BLOCK_SIZE;
    }
}
