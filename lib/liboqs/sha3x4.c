/*
 * Copyright (C) 2024 David Dudas
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

#include "liboqs/sha3x4.h"

#include "attribute.h"
#include "dlwrap/oqs.h"
#include "gnutls_int.h"
#include <gnutls/crypto.h>
#include <string.h>

#define SHA3_N 4

struct sha3_x4_context_st {
	gnutls_hash_hd_t hds[SHA3_N];
};

static void sha3_x4_context_deinit(struct sha3_x4_context_st *context)
{
	if (!context)
		return;

	for (size_t i = 0; i < SHA3_N; i++) {
		if (context->hds[i])
			gnutls_hash_deinit(context->hds[i], NULL);
	}
	gnutls_free(context);
}

static int sha3_x4_context_init(struct sha3_x4_context_st **context,
				gnutls_digest_algorithm_t algo)
{
	struct sha3_x4_context_st *p;
	int ret = 0;

	p = gnutls_calloc(1, sizeof(struct sha3_x4_context_st));
	if (!p)
		return gnutls_assert_val(GNUTLS_E_MEMORY_ERROR);

	for (size_t i = 0; i < sizeof(p->hds) / sizeof(p->hds[0]); i++) {
		ret = gnutls_hash_init(&p->hds[i], algo);
		if (ret < 0)
			goto out;
	}

	/* steal the result */
	*context = p;
	p = NULL;

out:
	sha3_x4_context_deinit(p);
	return ret;
}

static struct sha3_x4_context_st *
sha3_x4_context_copy(const struct sha3_x4_context_st *src)
{
	struct sha3_x4_context_st *copy = NULL, *p;

	p = gnutls_calloc(1, sizeof(struct sha3_x4_context_st));
	if (!p)
		return NULL;

	for (size_t i = 0; i < sizeof(p->hds) / sizeof(p->hds[0]); i++) {
		p->hds[i] = gnutls_hash_copy(src->hds[i]);
		if (!p->hds[i])
			goto out;
	}

	/* steal the result */
	copy = p;
	p = NULL;

out:
	sha3_x4_context_deinit(p);
	return copy;
}

static void sha3_x4_reset(struct sha3_x4_context_st *context)
{
	for (size_t i = 0; i < SHA3_N; i++)
		gnutls_hash_output(context->hds[i], NULL);
}

static int sha3_x4_absorb(struct sha3_x4_context_st *context,
			  const uint8_t *in[SHA3_N], size_t inlen)
{
	for (size_t i = 0; i < SHA3_N; i++) {
		int ret;

		ret = gnutls_hash(context->hds[i], in[i], inlen);
		if (unlikely(ret < 0)) {
			return gnutls_assert_val(ret);
		}
	}

	return 0;
}

static int sha3_x4_squeeze(struct sha3_x4_context_st *context,
			   uint8_t *out[SHA3_N], size_t outlen)
{
	for (size_t i = 0; i < SHA3_N; i++) {
		int ret;

		ret = gnutls_hash_squeeze(context->hds[i], out[i], outlen);
		if (unlikely(ret < 0)) {
			return gnutls_assert_val(ret);
		}
	}

	return 0;
}

static int sha3_x4(gnutls_digest_algorithm_t algo, uint8_t *out[SHA3_N],
		   const uint8_t *in[SHA3_N], size_t len)
{
	for (size_t i = 0; i < SHA3_N; i++) {
		int ret;

		ret = gnutls_hash_fast(algo, in[i], len, out[i]);
		if (unlikely(ret < 0)) {
			return gnutls_assert_val(ret);
		}
	}

	return 0;
}

static void SHA3_shake128_x4(uint8_t *out0, uint8_t *out1, uint8_t *out2,
			     uint8_t *out3, size_t outlen, const uint8_t *in0,
			     const uint8_t *in1, const uint8_t *in2,
			     const uint8_t *in3, size_t inlen)
{
	const uint8_t *in[SHA3_N] = { in0, in1, in2, in3 };
	uint8_t *out[SHA3_N] = { out0, out1, out2, out3 };
	int ret;

	ret = sha3_x4(GNUTLS_DIG_SHAKE_128, out, in, inlen);
	if (unlikely(ret < 0)) {
		abort();
	}
}

static void SHA3_shake128_x4_inc_init(OQS_SHA3_shake128_x4_inc_ctx *state)
{
	struct sha3_x4_context_st *context;
	int ret;

	ret = sha3_x4_context_init(&context, GNUTLS_DIG_SHAKE_128);
	if (unlikely(ret < 0)) {
		abort();
	}
	state->ctx = context;
}

static void SHA3_shake128_x4_inc_absorb(OQS_SHA3_shake128_x4_inc_ctx *state,
					const uint8_t *in0, const uint8_t *in1,
					const uint8_t *in2, const uint8_t *in3,
					size_t inlen)
{
	const uint8_t *in[SHA3_N] = { in0, in1, in2, in3 };
	int ret;

	ret = sha3_x4_absorb((struct sha3_x4_context_st *)state->ctx, in,
			     inlen);
	if (unlikely(ret < 0)) {
		abort();
	}
}

static void
SHA3_shake128_x4_inc_finalize(OQS_SHA3_shake128_x4_inc_ctx *state MAYBE_UNUSED)
{
}

static void SHA3_shake128_x4_inc_squeeze(uint8_t *out0, uint8_t *out1,
					 uint8_t *out2, uint8_t *out3,
					 size_t outlen,
					 OQS_SHA3_shake128_x4_inc_ctx *state)
{
	uint8_t *out[SHA3_N] = { out0, out1, out2, out3 };
	int ret;

	ret = sha3_x4_squeeze((struct sha3_x4_context_st *)state->ctx, out,
			      outlen);
	if (unlikely(ret < 0)) {
		abort();
	}
}

static void
SHA3_shake128_x4_inc_ctx_release(OQS_SHA3_shake128_x4_inc_ctx *state)
{
	sha3_x4_context_deinit((struct sha3_x4_context_st *)state->ctx);
}

static void
SHA3_shake128_x4_inc_ctx_clone(OQS_SHA3_shake128_x4_inc_ctx *dest,
			       const OQS_SHA3_shake128_x4_inc_ctx *src)
{
	dest->ctx = sha3_x4_context_copy(src->ctx);
}

static void SHA3_shake128_x4_inc_ctx_reset(OQS_SHA3_shake128_x4_inc_ctx *state)
{
	sha3_x4_reset((struct sha3_x4_context_st *)state->ctx);
}

static void SHA3_shake256_x4(uint8_t *out0, uint8_t *out1, uint8_t *out2,
			     uint8_t *out3, size_t outlen, const uint8_t *in0,
			     const uint8_t *in1, const uint8_t *in2,
			     const uint8_t *in3, size_t inlen)
{
	const uint8_t *in[SHA3_N] = { in0, in1, in2, in3 };
	uint8_t *out[SHA3_N] = { out0, out1, out2, out3 };
	int ret;

	ret = sha3_x4(GNUTLS_DIG_SHAKE_256, out, in, inlen);
	if (unlikely(ret < 0)) {
		abort();
	}
}

static void SHA3_shake256_x4_inc_init(OQS_SHA3_shake256_x4_inc_ctx *state)
{
	struct sha3_x4_context_st *context;
	int ret;

	ret = sha3_x4_context_init(&context, GNUTLS_DIG_SHAKE_256);
	if (unlikely(ret < 0)) {
		abort();
	}
	state->ctx = context;
}

static void SHA3_shake256_x4_inc_absorb(OQS_SHA3_shake256_x4_inc_ctx *state,
					const uint8_t *in0, const uint8_t *in1,
					const uint8_t *in2, const uint8_t *in3,
					size_t inlen)
{
	const uint8_t *in[SHA3_N] = { in0, in1, in2, in3 };
	int ret;

	ret = sha3_x4_absorb((struct sha3_x4_context_st *)state->ctx, in,
			     inlen);
	if (unlikely(ret < 0)) {
		abort();
	}
}

static void
SHA3_shake256_x4_inc_finalize(OQS_SHA3_shake256_x4_inc_ctx *state MAYBE_UNUSED)
{
}

static void SHA3_shake256_x4_inc_squeeze(uint8_t *out0, uint8_t *out1,
					 uint8_t *out2, uint8_t *out3,
					 size_t outlen,
					 OQS_SHA3_shake256_x4_inc_ctx *state)
{
	uint8_t *out[SHA3_N] = { out0, out1, out2, out3 };
	int ret;

	ret = sha3_x4_squeeze((struct sha3_x4_context_st *)state->ctx, out,
			      outlen);
	if (unlikely(ret < 0)) {
		abort();
	}
}

static void
SHA3_shake256_x4_inc_ctx_release(OQS_SHA3_shake256_x4_inc_ctx *state)
{
	sha3_x4_context_deinit((struct sha3_x4_context_st *)state->ctx);
}

static void
SHA3_shake256_x4_inc_ctx_clone(OQS_SHA3_shake256_x4_inc_ctx *dest,
			       const OQS_SHA3_shake256_x4_inc_ctx *src)
{
	dest->ctx = sha3_x4_context_copy(src->ctx);
}

static void SHA3_shake256_x4_inc_ctx_reset(OQS_SHA3_shake256_x4_inc_ctx *state)
{
	sha3_x4_reset((struct sha3_x4_context_st *)state->ctx);
}

struct OQS_SHA3_x4_callbacks sha3_x4_callbacks = {
	SHA3_shake128_x4,
	SHA3_shake128_x4_inc_init,
	SHA3_shake128_x4_inc_absorb,
	SHA3_shake128_x4_inc_finalize,
	SHA3_shake128_x4_inc_squeeze,
	SHA3_shake128_x4_inc_ctx_release,
	SHA3_shake128_x4_inc_ctx_clone,
	SHA3_shake128_x4_inc_ctx_reset,
	SHA3_shake256_x4,
	SHA3_shake256_x4_inc_init,
	SHA3_shake256_x4_inc_absorb,
	SHA3_shake256_x4_inc_finalize,
	SHA3_shake256_x4_inc_squeeze,
	SHA3_shake256_x4_inc_ctx_release,
	SHA3_shake256_x4_inc_ctx_clone,
	SHA3_shake256_x4_inc_ctx_reset,
};

void _gnutls_liboqs_sha3x4_init(void)
{
	GNUTLS_OQS_FUNC(OQS_SHA3_x4_set_callbacks)(&sha3_x4_callbacks);
}

void _gnutls_liboqs_sha3x4_deinit(void)
{
}
