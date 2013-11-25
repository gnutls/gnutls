/* drbg-aes.c */

/* Copyright (C) 2013 Red Hat
 *
 * This file is part of GnuTLS.
 *  
 * The GnuTLS library is free software; you can redistribute it and/or modify
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
 * the Free Software Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston,
 * MA 02111-1301, USA.
 */

#include <config.h>
#include <drbg-aes.h>
#include <nettle/memxor.h>
#include <string.h>
#include <stdio.h>

int
drbg_aes_set_key(struct drbg_aes_ctx *ctx, unsigned length,
		 const uint8_t * key)
{
	if (length != 16 && length != 24 && length != 32)
		return 0;

	aes_set_encrypt_key(&ctx->key, length, key);
	ctx->seeded = 0;
	ctx->prev_block_present = 0;

	return 1;
}

/* Set's V value */
void
drbg_aes_seed(struct drbg_aes_ctx *ctx, const uint8_t seed[AES_BLOCK_SIZE])
{
	memcpy(ctx->v, seed, AES_BLOCK_SIZE);
	ctx->seeded = 1;
}

int
drbg_aes_random(struct drbg_aes_ctx *ctx, unsigned length, uint8_t * dst,
		void *dt_priv, aes_dt dt_func)
{
	uint8_t dt[AES_BLOCK_SIZE];
	uint8_t intermediate[AES_BLOCK_SIZE];
	uint8_t tmp[AES_BLOCK_SIZE];
	unsigned left;

	if (ctx->seeded == 0)
		return 0;

	/* Throw the first block generated. FIPS 140-2 requirement 
	 */
	if (ctx->prev_block_present == 0) {
		dt_func(dt_priv, dt);

		/* I = AES_K(dt) */
		aes_encrypt(&ctx->key, AES_BLOCK_SIZE, intermediate, dt);

		/* tmp = I XOR V */
		memxor3(tmp, ctx->v, intermediate, AES_BLOCK_SIZE);

		/* dst = R = AES_K(I XOR V) */
		aes_encrypt(&ctx->key, AES_BLOCK_SIZE, ctx->prev_block,
			    tmp);

		/* V = AES_K(R XOR I) */
		memxor3(tmp, ctx->prev_block, intermediate,
			AES_BLOCK_SIZE);
		aes_encrypt(&ctx->key, AES_BLOCK_SIZE, ctx->v, tmp);

		ctx->prev_block_present = 1;
	}

	/* Perform the actual encryption */
	for (left = length; left >= AES_BLOCK_SIZE;
	     left -= AES_BLOCK_SIZE, dst += AES_BLOCK_SIZE) {
		dt_func(dt_priv, dt);

		/* I = AES_K(dt) */
		aes_encrypt(&ctx->key, AES_BLOCK_SIZE, intermediate, dt);

		/* tmp = I XOR V */
		memxor3(tmp, ctx->v, intermediate, AES_BLOCK_SIZE);

		/* dst = R = AES_K(I XOR V) */
		aes_encrypt(&ctx->key, AES_BLOCK_SIZE, dst, tmp);

		/* if detected loop */
		if (memcmp(dst, ctx->prev_block, AES_BLOCK_SIZE) == 0)
			return 0;

		memcpy(ctx->prev_block, dst, AES_BLOCK_SIZE);

		/* V = AES_K(R XOR I) */
		memxor3(tmp, dst, intermediate, AES_BLOCK_SIZE);
		aes_encrypt(&ctx->key, AES_BLOCK_SIZE, ctx->v, tmp);
	}

	if (left > 0) {		/* partial fill */

		/* I = AES_K(dt) */
		aes_encrypt(&ctx->key, AES_BLOCK_SIZE, intermediate, dt);
		memxor3(tmp, ctx->v, intermediate, AES_BLOCK_SIZE);

		/* tmp = R = AES_K(I XOR V) */
		aes_encrypt(&ctx->key, AES_BLOCK_SIZE, tmp, tmp);

		/* if detected loop */
		if (memcmp(tmp, ctx->prev_block, AES_BLOCK_SIZE) == 0)
			return 0;

		memcpy(ctx->prev_block, tmp, AES_BLOCK_SIZE);
		memcpy(dst, tmp, left);

		/* V = AES_K(R XOR I) */
		memxor(tmp, intermediate, AES_BLOCK_SIZE);
		aes_encrypt(&ctx->key, AES_BLOCK_SIZE, ctx->v, tmp);
	}

	return 1;
}

int drbg_aes_is_seeded(struct drbg_aes_ctx *ctx)
{
	return ctx->seeded;
}
