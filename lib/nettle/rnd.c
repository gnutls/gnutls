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

/* Here is the random generator layer. This code was based on the LSH 
 * random generator (the trivia and device source functions for POSIX)
 * and modified to fit gnutls' needs. Relicenced with permission. 
 * Original author Niels Möller.
 */

#include "gnutls_int.h"
#include "errors.h"
#include <locks.h>
#include <num.h>
#include <nettle/yarrow.h>
#include <nettle/salsa20.h>
#include <rnd-common.h>
#include <system.h>
#include <atfork.h>
#include <errno.h>

#define NONCE_KEY_SIZE SALSA20_KEY_SIZE
#define SOURCES 2

enum {
	RANDOM_SOURCE_TRIVIA = 0,
	RANDOM_SOURCE_DEVICE,
};


struct nonce_ctx_st {
	struct salsa20_ctx ctx;
	unsigned int counter;
	unsigned int forkid;
};

struct rnd_ctx_st {
	struct yarrow256_ctx yctx;
	struct yarrow_source ysources[SOURCES];
	struct timespec device_last_read;
	time_t trivia_previous_time;
	time_t trivia_time_count;
	unsigned forkid;
};

struct ext_ctx_st {
	struct rnd_ctx_st rng;
	struct nonce_ctx_st nonce;
};

/* after this number of bytes salsa20 will rekey */
#define NONCE_RESEED_BYTES (1048576)

inline static unsigned int
timespec_sub_sec(struct timespec *a, struct timespec *b)
{
	return (a->tv_sec - b->tv_sec);
}

#define DEVICE_READ_INTERVAL (21600)
/* universal functions */

static int do_trivia_source(struct rnd_ctx_st *ctx, int init, struct event_st *event)
{
	unsigned entropy = 0;

	if (init) {
		ctx->trivia_time_count = 0;
	} else {
		ctx->trivia_time_count++;

		if (event->now.tv_sec != ctx->trivia_previous_time) {
			/* Count one bit of entropy if we either have more than two
			 * invocations in one second, or more than two seconds
			 * between invocations. */
			if ((ctx->trivia_time_count > 2)
			    || ((event->now.tv_sec - ctx->trivia_previous_time) > 2))
				entropy++;

			ctx->trivia_time_count = 0;
		}
	}
	ctx->trivia_previous_time = event->now.tv_sec;

	return yarrow256_update(&ctx->yctx, RANDOM_SOURCE_TRIVIA, entropy,
				sizeof(*event), (void *) event);
}

#define DEVICE_READ_SIZE 16
#define DEVICE_READ_SIZE_MAX 32

static int do_device_source(struct rnd_ctx_st *ctx, int init, struct event_st *event)
{
	unsigned int read_size = DEVICE_READ_SIZE;
	int ret;

	if (init) {
		memcpy(&ctx->device_last_read, &event->now,
		       sizeof(ctx->device_last_read));

		read_size = DEVICE_READ_SIZE_MAX;	/* initially read more data */
	}

	if ((init
	     || (timespec_sub_sec(&event->now, &ctx->device_last_read) >
		 DEVICE_READ_INTERVAL))) {
		/* More than 20 minutes since we last read the device */
		uint8_t buf[DEVICE_READ_SIZE_MAX];

		ret = _rnd_get_system_entropy(buf, read_size);
		if (ret < 0)
			return gnutls_assert_val(ret);

		memcpy(&ctx->device_last_read, &event->now,
		       sizeof(ctx->device_last_read));

		return yarrow256_update(&ctx->yctx, RANDOM_SOURCE_DEVICE,
					read_size * 8 /
					2 /* we trust the RNG */ ,
					read_size, buf);
	}
	return 0;
}

static void wrap_nettle_rnd_deinit(void *_ctx)
{
	struct ext_ctx_st *ctx = _ctx;
	_rnd_system_entropy_deinit();
	gnutls_free(ctx);
}

/* Initializes the nonce level random generator.
 *
 * the @nonce_key must be provided.
 *
 * @init must be non zero on first initialization, and
 * zero on any subsequent reinitializations.
 */
static int nonce_rng_init(struct nonce_ctx_st *ctx,
			  uint8_t nonce_key[NONCE_KEY_SIZE],
			  unsigned nonce_key_size,
			  unsigned init)
{
	uint8_t iv[8];
	int ret;

	if (init == 0) {
		/* use the previous key to generate IV as well */
		memset(iv, 0, sizeof(iv)); /* to prevent valgrind from whinning */
		salsa20r12_crypt(&ctx->ctx, sizeof(iv), iv, iv);

		/* Add key continuity by XORing the new key with data generated
		 * from the old key */
		salsa20r12_crypt(&ctx->ctx, nonce_key_size, nonce_key, nonce_key);
	} else {
		ctx->forkid = _gnutls_get_forkid();

		/* when initializing read the IV from the system randomness source */
		ret = _rnd_get_system_entropy(iv, sizeof(iv));
		if (ret < 0)
			return gnutls_assert_val(ret);
	}

	salsa20_set_key(&ctx->ctx, nonce_key_size, nonce_key);
	salsa20_set_iv(&ctx->ctx, iv);

	zeroize_key(nonce_key, nonce_key_size);

	ctx->counter = 0;

	return 0;
}

/* API functions */

static int wrap_nettle_rnd_init(void **_ctx)
{
	int ret;
	struct event_st event;
	uint8_t nonce_key[NONCE_KEY_SIZE];
	struct ext_ctx_st *ctx;

	ctx = calloc(1, sizeof(*ctx));
	if (ctx == NULL)
		return gnutls_assert_val(GNUTLS_E_MEMORY_ERROR);

	/* initialize the main RNG */
	yarrow256_init(&ctx->rng.yctx, SOURCES, ctx->rng.ysources);

	_rnd_get_event(&event);

	ctx->rng.forkid = _gnutls_get_forkid();

	ret = do_device_source(&ctx->rng, 1, &event);
	if (ret < 0) {
		gnutls_assert();
		goto fail;
	}

	ret = do_trivia_source(&ctx->rng, 1, &event);
	if (ret < 0) {
		gnutls_assert();
		goto fail;
	}

	yarrow256_slow_reseed(&ctx->rng.yctx);

	/* initialize the nonce RNG */
	ret = _rnd_get_system_entropy(nonce_key, sizeof(nonce_key));
	if (ret < 0) {
		gnutls_assert();
		goto fail;
	}

	ret = nonce_rng_init(&ctx->nonce, nonce_key, sizeof(nonce_key), 1);
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
wrap_nettle_rnd_nonce(struct nonce_ctx_st *nonce_ctx, void *data, size_t datasize)
{
	int ret, reseed = 0;
	uint8_t nonce_key[NONCE_KEY_SIZE];

	/* we don't really need memset here, but otherwise we
	 * get filled with valgrind warnings */
	memset(data, 0, datasize);

	if (_gnutls_detect_fork(nonce_ctx->forkid)) {
		reseed = 1;
	}

	if (reseed != 0 || nonce_ctx->counter > NONCE_RESEED_BYTES) {
		/* reseed nonce */
		ret = _rnd_get_system_entropy(nonce_key, sizeof(nonce_key));
		if (ret < 0) {
			gnutls_assert();
			goto cleanup;
		}

		ret = nonce_rng_init(nonce_ctx, nonce_key, sizeof(nonce_key), 0);
		if (ret < 0) {
			gnutls_assert();
			goto cleanup;
		}

		nonce_ctx->forkid = _gnutls_get_forkid();
	}

	salsa20r12_crypt(&nonce_ctx->ctx, datasize, data, data);
	nonce_ctx->counter += datasize;

	ret = 0;

cleanup:
	return ret;
}


static int
wrap_nettle_rnd(void *_ctx, int level, void *data, size_t datasize)
{
	int ret, reseed = 0;
	struct event_st event;
	struct ext_ctx_st *ctx = _ctx;

	if (level == GNUTLS_RND_NONCE)
		return wrap_nettle_rnd_nonce(&ctx->nonce, data, datasize);

	_rnd_get_event(&event);

	if (_gnutls_detect_fork(ctx->rng.forkid)) {	/* fork() detected */
		memset(&ctx->rng.device_last_read, 0, sizeof(ctx->rng.device_last_read));
		reseed = 1;
	}

	/* reseed main */
	ret = do_trivia_source(&ctx->rng, 0, &event);
	if (ret < 0) {
		gnutls_assert();
		goto cleanup;
	}

	ret = do_device_source(&ctx->rng, 0, &event);
	if (ret < 0) {
		gnutls_assert();
		goto cleanup;
	}

	if (reseed != 0) {
		yarrow256_slow_reseed(&ctx->rng.yctx);
		ctx->rng.forkid = _gnutls_get_forkid();
	}

	yarrow256_random(&ctx->rng.yctx, datasize, data);
	ret = 0;

cleanup:
	return ret;
}

static void wrap_nettle_rnd_refresh(void *_ctx)
{
	uint8_t nonce_key[NONCE_KEY_SIZE];
	struct ext_ctx_st *ctx = _ctx;

	/* obtain some fresh data to use as nonce */
	wrap_nettle_rnd(_ctx, GNUTLS_RND_RANDOM, nonce_key, sizeof(nonce_key));

	/* refresh nonce */
	nonce_rng_init(&ctx->nonce, nonce_key, sizeof(nonce_key), 0);

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
