/* hmac.h
 *
 * HMAC message authentication code (RFC-2104).
 */

/* nettle, low-level cryptographics library
 *
 * Copyright (C) 2001, 2002 Niels Möller
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

#ifndef NETTLE_HMAC_H_INCLUDED
#define NETTLE_HMAC_H_INCLUDED

#include "nettle-meta.h"

#include "md5.h"
#include "sha.h"

/* Namespace mangling */
#define hmac_set_key nettle_hmac_set_key
#define hmac_update nettle_hmac_update
#define hmac_digest nettle_hmac_digest
#define hmac_md5_set_key nettle_hmac_md5_set_key
#define hmac_md5_update nettle_hmac_md5_update
#define hmac_md5_digest nettle_hmac_md5_digest
#define hmac_sha1_set_key nettle_hmac_sha1_set_key
#define hmac_sha1_update nettle_hmac_sha1_update
#define hmac_sha1_digest nettle_hmac_sha1_digest
#define hmac_sha256_set_key nettle_hmac_sha256_set_key
#define hmac_sha256_update nettle_hmac_sha256_update
#define hmac_sha256_digest nettle_hmac_sha256_digest

void
hmac_set_key(void *outer, void *inner, void *state,
	     const struct nettle_hash *hash,
	     unsigned length, const uint8_t *key);

/* This function is not strictly needed, it's s just the same as the
 * hash update function. */
void
hmac_update(void *state,
	    const struct nettle_hash *hash,
	    unsigned length, const uint8_t *data);

void
hmac_digest(const void *outer, const void *inner, void *state,
	    const struct nettle_hash *hash,
	    unsigned length, uint8_t *digest);


#define HMAC_CTX(type) \
{ type outer; type inner; type state; }

#define HMAC_SET_KEY(ctx, hash, length, key)			\
  hmac_set_key( &(ctx)->outer, &(ctx)->inner, &(ctx)->state,	\
                (hash), (length), (key) )

#define HMAC_DIGEST(ctx, hash, length, digest)			\
  hmac_digest( &(ctx)->outer, &(ctx)->inner, &(ctx)->state,	\
               (hash), (length), (digest) )

/* HMAC using specific hash functions */

/* hmac-md5 */
struct hmac_md5_ctx HMAC_CTX(struct md5_ctx);

void
hmac_md5_set_key(struct hmac_md5_ctx *ctx,
		 unsigned key_length, const uint8_t *key);

void
hmac_md5_update(struct hmac_md5_ctx *ctx,
		unsigned length, const uint8_t *data);

void
hmac_md5_digest(struct hmac_md5_ctx *ctx,
		unsigned length, uint8_t *digest);


/* hmac-sha1 */
struct hmac_sha1_ctx HMAC_CTX(struct sha1_ctx);

void
hmac_sha1_set_key(struct hmac_sha1_ctx *ctx,
		  unsigned key_length, const uint8_t *key);

void
hmac_sha1_update(struct hmac_sha1_ctx *ctx,
		 unsigned length, const uint8_t *data);

void
hmac_sha1_digest(struct hmac_sha1_ctx *ctx,
		 unsigned length, uint8_t *digest);

/* hmac-sha256 */
struct hmac_sha256_ctx HMAC_CTX(struct sha256_ctx);

void
hmac_sha256_set_key(struct hmac_sha256_ctx *ctx,
		    unsigned key_length, const uint8_t *key);

void
hmac_sha256_update(struct hmac_sha256_ctx *ctx,
		   unsigned length, const uint8_t *data);

void
hmac_sha256_digest(struct hmac_sha256_ctx *ctx,
		   unsigned length, uint8_t *digest);

#endif /* NETTLE_HMAC_H_INCLUDED */
