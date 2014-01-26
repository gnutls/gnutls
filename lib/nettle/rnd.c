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

#include <gnutls_int.h>
#include <gnutls_errors.h>
#include <locks.h>
#include <gnutls_num.h>
#include <nettle/yarrow.h>
#include <nettle/salsa20.h>
#ifdef HAVE_GETPID
#include <unistd.h>		/* getpid */
#endif
#include <rnd-common.h>
#include <errno.h>

#define SOURCES 2

#define RND_LOCK if (gnutls_mutex_lock(&rnd_mutex)!=0) abort()
#define RND_UNLOCK if (gnutls_mutex_unlock(&rnd_mutex)!=0) abort()

enum {
	RANDOM_SOURCE_TRIVIA = 0,
	RANDOM_SOURCE_DEVICE,
};

static struct yarrow256_ctx yctx;
static struct yarrow_source ysources[SOURCES];

struct nonce_ctx_st {
	struct salsa20_ctx ctx;
	unsigned int counter;
#ifdef HAVE_GETPID
	pid_t pid;		/* detect fork() */
#endif
};

/* after this number of bytes salsa20 will reseed */
#define NONCE_RESEED_BYTES (1048576)
static struct nonce_ctx_st nonce_ctx;

static struct timespec device_last_read = { 0, 0 };

static time_t trivia_previous_time = 0;
static time_t trivia_time_count = 0;
#ifdef HAVE_GETPID
static pid_t pid;		/* detect fork() */
#endif

static void *rnd_mutex;

inline static unsigned int
timespec_sub_sec(struct timespec *a, struct timespec *b)
{
	return (a->tv_sec - b->tv_sec);
}

#define DEVICE_READ_INTERVAL (1200)
/* universal functions */

static int do_trivia_source(int init, struct event_st *event)
{
	unsigned entropy = 0;

	if (init) {
		trivia_time_count = 0;
	} else {
		trivia_time_count++;

		if (event->now.tv_sec != trivia_previous_time) {
			/* Count one bit of entropy if we either have more than two
			 * invocations in one second, or more than two seconds
			 * between invocations. */
			if ((trivia_time_count > 2)
			    || ((event->now.tv_sec - trivia_previous_time) > 2))
				entropy++;

			trivia_time_count = 0;
		}
	}
	trivia_previous_time = event->now.tv_sec;

	return yarrow256_update(&yctx, RANDOM_SOURCE_TRIVIA, entropy,
				sizeof(*event), (void *) event);
}

#define DEVICE_READ_SIZE 16
#define DEVICE_READ_SIZE_MAX 32

static int do_device_source(int init, struct event_st *event)
{
	unsigned int read_size = DEVICE_READ_SIZE;
	int ret;

	if (init) {
#ifdef HAVE_GETPID
		pid = event->pid;
#endif

		ret = _rnd_system_entropy_init();
		if (ret < 0) {
			_gnutls_debug_log("Cannot initialize entropy gatherer\n");
			return gnutls_assert_val(ret);
		}

		memcpy(&device_last_read, &event->now,
		       sizeof(device_last_read));

		read_size = DEVICE_READ_SIZE_MAX;	/* initially read more data */
	}

	if ((init
	     || (timespec_sub_sec(&event->now, &device_last_read) >
		 DEVICE_READ_INTERVAL))) {
		/* More than 20 minutes since we last read the device */
		uint8_t buf[DEVICE_READ_SIZE_MAX];

		ret = _rnd_get_system_entropy(buf, read_size);
		if (ret < 0)
			return gnutls_assert_val(ret);

		memcpy(&device_last_read, &event->now,
		       sizeof(device_last_read));

		return yarrow256_update(&yctx, RANDOM_SOURCE_DEVICE,
					read_size * 8 /
					2 /* we trust the RNG */ ,
					read_size, buf);
	}
	return 0;
}

static void wrap_nettle_rnd_deinit(void *ctx)
{
	RND_LOCK;
	_rnd_system_entropy_deinit();
	RND_UNLOCK;

	gnutls_mutex_deinit(&rnd_mutex);
	rnd_mutex = NULL;
}

static int nonce_rng_init(struct nonce_ctx_st *ctx)
{
	uint8_t buffer[SALSA20_KEY_SIZE];
	int ret;

	/* Get a key from the standard RNG or from the entropy source.  */
	ret = _rnd_get_system_entropy(buffer, sizeof(buffer));
	if (ret < 0)
		return gnutls_assert_val(ret);

	salsa20_set_key(&ctx->ctx, sizeof(buffer), buffer);

	zeroize_key(buffer, sizeof(buffer));

	ctx->counter = 0;
#ifdef HAVE_GETPID
	ctx->pid = getpid();
#endif

	return 0;
}

/* API functions */

static int wrap_nettle_rnd_init(void **ctx)
{
	int ret;
	struct event_st event;

	ret = gnutls_mutex_init(&rnd_mutex);
	if (ret < 0) {
		gnutls_assert();
		return ret;
	}

	ret = _rnd_system_entropy_init();
	if (ret < 0) {
		gnutls_assert();
		return ret;
	}

	/* initialize the main RNG */
	yarrow256_init(&yctx, SOURCES, ysources);

	_rnd_get_event(&event);

	ret = do_device_source(1, &event);
	if (ret < 0) {
		gnutls_assert();
		return ret;
	}

	ret = do_trivia_source(1, &event);
	if (ret < 0) {
		gnutls_assert();
		return ret;
	}

	yarrow256_slow_reseed(&yctx);

	/* initialize the nonce RNG */
	ret = nonce_rng_init(&nonce_ctx);
	if (ret < 0)
		return gnutls_assert_val(ret);

	return 0;
}

static int
wrap_nettle_rnd_nonce(void *_ctx, void *data, size_t datasize)
{
	int ret, reseed = 0;
#ifdef HAVE_GETPID
	pid_t tpid = getpid();
#endif

	RND_LOCK;

#ifdef HAVE_GETPID
	if (tpid != nonce_ctx.pid) {	/* fork() detected */
		reseed = 1;
	}
#endif

	if (reseed != 0 || nonce_ctx.counter > NONCE_RESEED_BYTES) {
		/* reseed nonce */
		ret = nonce_rng_init(&nonce_ctx);
		if (ret < 0) {
			gnutls_assert();
			goto cleanup;
		}
	}

	/* we don't really need memset here, but otherwise we
	 * get filled with valgrind warnings */
	memset(data, 0, datasize);
	salsa20r12_crypt(&nonce_ctx.ctx, datasize, data, data);
	nonce_ctx.counter += datasize;

	ret = 0;

cleanup:
	RND_UNLOCK;
	return ret;
}



static int
wrap_nettle_rnd(void *_ctx, int level, void *data, size_t datasize)
{
	int ret, reseed = 0;
	struct event_st event;

	if (level == GNUTLS_RND_NONCE)
		return wrap_nettle_rnd_nonce(_ctx, data, datasize);

	_rnd_get_event(&event);

	RND_LOCK;

#ifdef HAVE_GETPID
	if (event.pid != pid) {	/* fork() detected */
		memset(&device_last_read, 0, sizeof(device_last_read));
		pid = event.pid;
		reseed = 1;
	}
#endif

	/* reseed main */
	ret = do_trivia_source(0, &event);
	if (ret < 0) {
		gnutls_assert();
		goto cleanup;
	}

	ret = do_device_source(0, &event);
	if (ret < 0) {
		gnutls_assert();
		goto cleanup;
	}

	if (reseed != 0)
		yarrow256_slow_reseed(&yctx);

	yarrow256_random(&yctx, datasize, data);
	ret = 0;

cleanup:
	RND_UNLOCK;
	return ret;
}

static void wrap_nettle_rnd_refresh(void *_ctx)
{
	struct event_st event;

	_rnd_get_event(&event);

	RND_LOCK;
	do_trivia_source(0, &event);
	do_device_source(0, &event);

	RND_UNLOCK;
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
