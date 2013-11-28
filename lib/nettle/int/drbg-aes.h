/* drbg-aes.h
 *
 * The ANSI X9.31 Appendix A.2.4 AES-based DRBG.
 */

/* Copyright (C) 2013 Red Hat
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
 * the Free Software Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston,
 * MA 02111-1301, USA.
 */

#ifndef DRBG_AES_H_INCLUDED
#define DRBG_AES_H_INCLUDED

#include <config.h>
#include <nettle/aes.h>

/* This is the AES-based random-number generator from ANSI X9.31 
 * Appendix A.2.4. Note that the DT value from the document is obtained
 * during seeding. Then it is used as an 128-bit counter which is
 * incremented on block encrypted in drbg_aes_random().
 */
struct drbg_aes_ctx {
	unsigned seeded;
	/* The current key and counter block */
	struct aes_ctx key;
	uint8_t v[AES_BLOCK_SIZE];

	/* An initial value based on timestamp */
	uint8_t dt[AES_BLOCK_SIZE];

	unsigned prev_block_present;
	uint8_t prev_block[AES_BLOCK_SIZE];
};

typedef int (*aes_dt) (void *priv, uint8_t dt[AES_BLOCK_SIZE]);

/* should return zero on error */
int
drbg_aes_set_key(struct drbg_aes_ctx *ctx, unsigned length,
		 const uint8_t * key);

/* Set's V value */
void
drbg_aes_seed(struct drbg_aes_ctx *ctx,
	      const uint8_t seed[AES_BLOCK_SIZE],
	      void *dt_priv, aes_dt dt);

int
drbg_aes_random(struct drbg_aes_ctx *ctx, unsigned length,
		uint8_t * dst);

int drbg_aes_is_seeded(struct drbg_aes_ctx *ctx);

int drbg_aes_self_test(void);

#endif				/* DRBG_AES_H_INCLUDED */
