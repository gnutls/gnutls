/* arctwo.h
 *
 * The arctwo/rfc2268 block cipher.
 */

/* nettle, low-level cryptographics library
 *
 * Copyright (C) 2004 Simon Josefsson
 * Copyright (C) 2002 Niels Möller
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
 
#ifndef NETTLE_ARCTWO_H_INCLUDED
#define NETTLE_ARCTWO_H_INCLUDED

#include "nettle-types.h"

/* Name mangling */
#define arctwo_set_key nettle_arctwo_set_key
#define arctwo_encrypt nettle_arctwo_encrypt
#define arctwo_decrypt nettle_arctwo_decrypt

#define gutmann_arctwo_ctx arctwo_ctx
#define gutmann_arctwo_encrypt arctwo_encrypt
#define gutmann_arctwo_decrypt arctwo_decrypt

#define ARCTWO_BLOCK_SIZE 8

/* Variable key size from 1 byte to 128 bytes. */
#define ARCTWO_MIN_KEY_SIZE 1
#define ARCTWO_MAX_KEY_SIZE 128

#define ARCTWO_KEY_SIZE 8

struct arctwo_ctx
{
  uint16_t S[64];
};

void
arctwo_set_key(struct arctwo_ctx *ctx,
	       unsigned length, const uint8_t *key);
void
gutmann_arctwo_set_key(struct arctwo_ctx *ctx,
		       unsigned length, const uint8_t *key);

void
arctwo_encrypt(struct arctwo_ctx *ctx,
	       unsigned length, uint8_t *dst,
	       const uint8_t *src);
void
arctwo_decrypt(struct arctwo_ctx *ctx,
	       unsigned length, uint8_t *dst,
	       const uint8_t *src);

#endif /* NETTLE_ARCTWO_H_INCLUDED */
