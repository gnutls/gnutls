/*
 * Copyright (C) 2024 Red Hat, Inc.
 *
 * This file is part of GNUTLS.
 *
 * The GNUTLS library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public License
 * as published by the Free Software Foundation; either version 2.1 of
 * the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with this program.  If not, see <https://www.gnu.org/licenses/>
 *
 */

#include "config.h"

#include "liboqs/sha2.h"

#include "dlwrap/oqs.h"
#include <assert.h>
#include <gnutls/crypto.h>
#include <string.h>

#undef SHA2_BLOCK_SIZE
#define SHA2_BLOCK_SIZE 64

/* SHA2-256 */

static void SHA2_sha256(uint8_t *output, const uint8_t *input, size_t inplen)
{
	gnutls_hash_fast(GNUTLS_DIG_SHA256, input, inplen, output);
}

/* SHA2-256 incremental */

static void SHA2_sha256_inc_init(OQS_SHA2_sha256_ctx *state)
{
	gnutls_hash_hd_t hd;
	int ret;

	ret = gnutls_hash_init(&hd, GNUTLS_DIG_SHA256);
	assert(ret == 0);
	state->ctx = hd;
}

static void SHA2_sha256_inc(OQS_SHA2_sha256_ctx *state, const uint8_t *in,
			    size_t len)
{
	int ret;

	ret = gnutls_hash((gnutls_hash_hd_t)state->ctx, in, len);
	assert(ret == 0);
}

static void SHA2_sha256_inc_blocks(OQS_SHA2_sha256_ctx *state,
				   const uint8_t *in, size_t inblocks)
{
	int ret;

	ret = gnutls_hash((gnutls_hash_hd_t)state->ctx, in,
			  inblocks * SHA2_BLOCK_SIZE);
	assert(ret == 0);
}

static void SHA2_sha256_inc_finalize(uint8_t *out, OQS_SHA2_sha256_ctx *state,
				     const uint8_t *in, size_t inlen)
{
	if (inlen > 0) {
		int ret;

		ret = gnutls_hash((gnutls_hash_hd_t)state->ctx, in, inlen);
		assert(ret == 0);
	}
	gnutls_hash_output((gnutls_hash_hd_t)state->ctx, out);
}

static void SHA2_sha256_inc_ctx_release(OQS_SHA2_sha256_ctx *state)
{
	gnutls_hash_deinit((gnutls_hash_hd_t)state->ctx, NULL);
}

static void SHA2_sha256_inc_ctx_clone(OQS_SHA2_sha256_ctx *dest,
				      const OQS_SHA2_sha256_ctx *src)
{
	dest->ctx = gnutls_hash_copy((gnutls_hash_hd_t)src->ctx);
}

/* SHA2-384 */

static void SHA2_sha384(uint8_t *output, const uint8_t *input, size_t inplen)
{
	gnutls_hash_fast(GNUTLS_DIG_SHA384, input, inplen, output);
}

/* SHA2-384 incremental */

static void SHA2_sha384_inc_init(OQS_SHA2_sha384_ctx *state)
{
	gnutls_hash_hd_t hd;
	int ret;

	ret = gnutls_hash_init(&hd, GNUTLS_DIG_SHA384);
	assert(ret == 0);
	state->ctx = hd;
}

static void SHA2_sha384_inc_blocks(OQS_SHA2_sha384_ctx *state,
				   const uint8_t *in, size_t inblocks)
{
	int ret;

	ret = gnutls_hash((gnutls_hash_hd_t)state->ctx, in,
			  inblocks * SHA2_BLOCK_SIZE);
	assert(ret == 0);
}

static void SHA2_sha384_inc_finalize(uint8_t *out, OQS_SHA2_sha384_ctx *state,
				     const uint8_t *in, size_t inlen)
{
	if (inlen > 0) {
		int ret;

		ret = gnutls_hash((gnutls_hash_hd_t)state->ctx, in, inlen);
		assert(ret == 0);
	}
	gnutls_hash_output((gnutls_hash_hd_t)state->ctx, out);
}

static void SHA2_sha384_inc_ctx_release(OQS_SHA2_sha384_ctx *state)
{
	gnutls_hash_deinit((gnutls_hash_hd_t)state->ctx, NULL);
}

static void SHA2_sha384_inc_ctx_clone(OQS_SHA2_sha384_ctx *dest,
				      const OQS_SHA2_sha384_ctx *src)
{
	dest->ctx = gnutls_hash_copy((gnutls_hash_hd_t)src->ctx);
}

/* SHA2-512 */

static void SHA2_sha512(uint8_t *output, const uint8_t *input, size_t inplen)
{
	gnutls_hash_fast(GNUTLS_DIG_SHA512, input, inplen, output);
}

/* SHA2-512 incremental */

static void SHA2_sha512_inc_init(OQS_SHA2_sha512_ctx *state)
{
	gnutls_hash_hd_t hd;
	int ret;

	ret = gnutls_hash_init(&hd, GNUTLS_DIG_SHA512);
	assert(ret == 0);
	state->ctx = hd;
}

static void SHA2_sha512_inc_blocks(OQS_SHA2_sha512_ctx *state,
				   const uint8_t *in, size_t inblocks)
{
	int ret;

	ret = gnutls_hash((gnutls_hash_hd_t)state->ctx, in,
			  inblocks * SHA2_BLOCK_SIZE);
	assert(ret == 0);
}

static void SHA2_sha512_inc_finalize(uint8_t *out, OQS_SHA2_sha512_ctx *state,
				     const uint8_t *in, size_t inlen)
{
	if (inlen > 0) {
		int ret;

		ret = gnutls_hash((gnutls_hash_hd_t)state->ctx, in, inlen);
		assert(ret == 0);
	}
	gnutls_hash_output((gnutls_hash_hd_t)state->ctx, out);
}

static void SHA2_sha512_inc_ctx_release(OQS_SHA2_sha512_ctx *state)
{
	gnutls_hash_deinit((gnutls_hash_hd_t)state->ctx, NULL);
}

static void SHA2_sha512_inc_ctx_clone(OQS_SHA2_sha512_ctx *dest,
				      const OQS_SHA2_sha512_ctx *src)
{
	dest->ctx = gnutls_hash_copy((gnutls_hash_hd_t)src->ctx);
}

struct OQS_SHA2_callbacks sha2_callbacks = {
	SHA2_sha256,
	SHA2_sha256_inc_init,
	SHA2_sha256_inc_ctx_clone,
	SHA2_sha256_inc,
	SHA2_sha256_inc_blocks,
	SHA2_sha256_inc_finalize,
	SHA2_sha256_inc_ctx_release,
	SHA2_sha384,
	SHA2_sha384_inc_init,
	SHA2_sha384_inc_ctx_clone,
	SHA2_sha384_inc_blocks,
	SHA2_sha384_inc_finalize,
	SHA2_sha384_inc_ctx_release,
	SHA2_sha512,
	SHA2_sha512_inc_init,
	SHA2_sha512_inc_ctx_clone,
	SHA2_sha512_inc_blocks,
	SHA2_sha512_inc_finalize,
	SHA2_sha512_inc_ctx_release,
};

void _gnutls_liboqs_sha2_init(void)
{
	GNUTLS_OQS_FUNC(OQS_SHA2_set_callbacks)(&sha2_callbacks);
}

void _gnutls_liboqs_sha2_deinit(void)
{
}
