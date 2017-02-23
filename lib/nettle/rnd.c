/*
 * Copyright (C) 2010-2012 Free Software Foundation, Inc.
 * Copyright (C) 2000, 2001, 2008 Niels Möller
 *
 * Author: Nikos Mavrogiannopoulos
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
 * along with this program.  If not, see <http://www.gnu.org/licenses/>
 *
 */

#include "gnutls_int.h"
#include "errors.h"
#include <locks.h>
#include <num.h>
#include <nettle/chacha.h>
#include <rnd-common.h>
#include <system.h>
#include <atfork.h>
#include <errno.h>
#include <minmax.h>

#define PRNG_KEY_SIZE CHACHA_KEY_SIZE
/* after this number of bytes PRNG will rekey */
#define PRNG_RESEED_BYTES (1048576)

struct prng_ctx_st {
	struct chacha_ctx ctx;
	size_t counter;
	unsigned int forkid;
};

struct generators_ctx_st {
	struct prng_ctx_st nonce;  /* GNUTLS_RND_NONCE */
	struct prng_ctx_st normal; /* GNUTLS_RND_RANDOM */
	struct prng_ctx_st strong; /* GNUTLS_RND_KEY */
};


static void wrap_nettle_rnd_deinit(void *_ctx)
{
	gnutls_free(_ctx);
}

/* Initializes the nonce level random generator.
 *
 * the @new_key must be provided.
 *
 * @init must be non zero on first initialization, and
 * zero on any subsequent reinitializations.
 */
static int single_prng_init(struct prng_ctx_st *ctx,
			    uint8_t new_key[PRNG_KEY_SIZE],
			    unsigned new_key_size,
			    unsigned init)
{
	uint8_t nonce[CHACHA_NONCE_SIZE];

	memset(nonce, 0, sizeof(nonce)); /* to prevent valgrind from whinning */

	if (init == 0) {
		/* use the previous key to generate IV as well */
		chacha_crypt(&ctx->ctx, sizeof(nonce), nonce, nonce);

		/* Add key continuity by XORing the new key with data generated
		 * from the old key */
		chacha_crypt(&ctx->ctx, new_key_size, new_key, new_key);
	} else {
		struct timespec now; /* current time */

		ctx->forkid = _gnutls_get_forkid();

		gettime(&now);
		memcpy(nonce, &now, MIN(sizeof(nonce), sizeof(now)));
	}

	chacha_set_key(&ctx->ctx, new_key);
	chacha_set_nonce(&ctx->ctx, nonce);

	zeroize_key(new_key, new_key_size);

	ctx->counter = 0;

	return 0;
}

/* API functions */

static int wrap_nettle_rnd_init(void **_ctx)
{
	int ret;
	uint8_t new_key[PRNG_KEY_SIZE*3];
	struct generators_ctx_st *ctx;

	ctx = calloc(1, sizeof(*ctx));
	if (ctx == NULL)
		return gnutls_assert_val(GNUTLS_E_MEMORY_ERROR);

	/* initialize the nonce RNG */
	ret = _rnd_get_system_entropy(new_key, sizeof(new_key));
	if (ret < 0) {
		gnutls_assert();
		goto fail;
	}

	ret = single_prng_init(&ctx->nonce, new_key, PRNG_KEY_SIZE, 1);
	if (ret < 0) {
		gnutls_assert();
		goto fail;
	}

	/* initialize the normal RNG */
	ret = single_prng_init(&ctx->normal, new_key+PRNG_KEY_SIZE, PRNG_KEY_SIZE, 1);
	if (ret < 0) {
		gnutls_assert();
		goto fail;
	}

	ret = single_prng_init(&ctx->strong, new_key+2*PRNG_KEY_SIZE, PRNG_KEY_SIZE, 1);
	if (ret < 0) {
		gnutls_assert();
		goto fail;
	}

	*_ctx = ctx;

	return 0;
 fail:
	gnutls_free(ctx);
	return ret;
}

static int
wrap_nettle_rnd(void *_ctx, int level, void *data, size_t datasize)
{
	struct generators_ctx_st *ctx = _ctx;
	struct prng_ctx_st *prng_ctx;
	int ret, reseed = 0;

	if (level == GNUTLS_RND_RANDOM)
		prng_ctx = &ctx->normal;
	else if (level == GNUTLS_RND_KEY)
		prng_ctx = &ctx->strong;
	else
		prng_ctx = &ctx->nonce;

	/* we don't really need memset here, but otherwise we
	 * get filled with valgrind warnings */
	memset(data, 0, datasize);

	if (_gnutls_detect_fork(prng_ctx->forkid)) {
		reseed = 1;
	}

	if (reseed != 0 || prng_ctx->counter > PRNG_RESEED_BYTES) {
		uint8_t new_key[PRNG_KEY_SIZE];

		if (level == GNUTLS_RND_NONCE) {
			ret = wrap_nettle_rnd(_ctx, GNUTLS_RND_RANDOM, new_key, sizeof(new_key));
		} else {
			/* we use the system entropy for KEY and RANDOM to reduce
			 * the impact of a temporal state compromise for these two levels. */
			ret = _rnd_get_system_entropy(new_key, sizeof(new_key));
		}

		if (ret < 0) {
			gnutls_assert();
			goto cleanup;
		}

		ret = single_prng_init(prng_ctx, new_key, sizeof(new_key), 0);
		if (ret < 0) {
			gnutls_assert();
			goto cleanup;
		}

		prng_ctx->forkid = _gnutls_get_forkid();
	}

	chacha_crypt(&prng_ctx->ctx, datasize, data, data);
	prng_ctx->counter += datasize;

	ret = 0;

cleanup:
	return ret;
}

static void wrap_nettle_rnd_refresh(void *_ctx)
{
	struct generators_ctx_st *ctx = _ctx;
	char tmp;

	/* force reseed */
	ctx->nonce.counter = PRNG_RESEED_BYTES+1;
	ctx->normal.counter = PRNG_RESEED_BYTES+1;
	ctx->strong.counter = PRNG_RESEED_BYTES+1;

	wrap_nettle_rnd(_ctx, GNUTLS_RND_NONCE, &tmp, 1);
	wrap_nettle_rnd(_ctx, GNUTLS_RND_RANDOM, &tmp, 1);
	wrap_nettle_rnd(_ctx, GNUTLS_RND_KEY, &tmp, 1);

	return;
}

int crypto_rnd_prio = INT_MAX;

gnutls_crypto_rnd_st _gnutls_rnd_ops = {
	.init = wrap_nettle_rnd_init,
	.deinit = wrap_nettle_rnd_deinit,
	.rnd = wrap_nettle_rnd,
	.rnd_refresh = wrap_nettle_rnd_refresh,
	.self_test = NULL,
};
