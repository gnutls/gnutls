/*
 * Copyright (C) 2008, 2010 Free Software Foundation, Inc.
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
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301,
 * USA
 *
 */

/* Here is the libgcrypt random generator layer.
 */

#include <gnutls_int.h>
#include <gnutls_errors.h>
#include <gnutls_num.h>
#include <nettle/yarrow.h>
#include <time.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <fcntl.h>

#include <pthread.h>

#define SOURCES 2

static pthread_mutex_t rnd_mutex = PTHREAD_MUTEX_INITIALIZER;

#define RND_LOCK_INIT
#define RND_LOCK if (pthread_mutex_lock(&rnd_mutex)!=0) abort()
#define RND_UNLOCK if (pthread_mutex_unlock(&rnd_mutex)!=0) abort()

enum {
	RANDOM_SOURCE_TRIVIA=0,
	RANDOM_SOURCE_DEVICE,
};

static struct yarrow256_ctx yctx;
static struct yarrow_source ysources[SOURCES];
static time_t device_last_read = 0;
static int device_fd;

static time_t trivia_previous_time = 0;
static time_t trivia_time_count = 0;

static int do_trivia_source(int init)
{
    struct {
		struct timeval now;
#ifdef HAVE_GETRUSAGE
		struct rusage rusage;
#endif
		unsigned count;
		pid_t pid;
    } event;

    unsigned entropy = 0;

    if (gettimeofday(&event.now, NULL) < 0) {
		_gnutls_debug_log("gettimeofday failed: %s\n", strerror(errno));
		abort();
	}
#ifdef HAVE_GETRUSAGE
    if (getrusage(RUSAGE_SELF, &event.rusage) < 0) {
		_gnutls_debug_log("getrusage failed: %s\n", strerror(errno));
		abort();
	}
#endif

    event.count = 0;
    if (init) {
		trivia_time_count = 0;
    } else {
		event.count = trivia_time_count++;

		if (event.now.tv_sec != trivia_previous_time) {
			/* Count one bit of entropy if we either have more than two
			 * invocations in one second, or more than two seconds
			 * between invocations. */
			if ((trivia_time_count > 2)
			|| ((event.now.tv_sec - trivia_previous_time) > 2))
				entropy++;

			trivia_time_count = 0;
		}
    }
    trivia_previous_time = event.now.tv_sec;
    event.pid = getpid();

    return yarrow256_update(&yctx, RANDOM_SOURCE_TRIVIA, entropy,
			    sizeof(event), (const uint8_t *) &event);
}

#define DEVICE_READ_SIZE 16
#define DEVICE_READ_SIZE_MAX 32
#define DEVICE_READ_INTERVAL 360
static int do_device_source(int init)
{
    time_t now = time(NULL);
	int read_size = DEVICE_READ_SIZE;

    if (init) {
		int old;
		
		device_fd = open("/dev/urandom", O_RDONLY);
		if (device_fd < 0) {
			_gnutls_debug_log("Cannot open urandom!\n");
			abort();
		}

		old = fcntl(device_fd, F_GETFD);
		fcntl(device_fd, F_SETFD, old | 1);
		device_last_read = now;
		
		read_size = DEVICE_READ_SIZE_MAX; /* initially read more data */
    }

    if ((device_fd > 0)
		&& (init || ((now - device_last_read) > DEVICE_READ_INTERVAL))) {

		/* More than a minute since we last read the device */
		uint8_t buf[DEVICE_READ_SIZE_MAX];
		uint32_t done;

		for (done = 0; done < read_size;) {
			int res;
			do
			res =
				read(device_fd, buf + done, sizeof(buf) - done);
			while (res < 0 && errno == EINTR);

			if (res <= 0) {
				if (res < 0) {
					_gnutls_debug_log("Failed to read /dev/urandom: %s\n",
							  strerror(errno));
				} else {
					_gnutls_debug_log
					("Failed to read /dev/urandom: end of file\n");
				}

				return 0;
			}

			done += res;
		}

		device_last_read = now;
		return yarrow256_update(&yctx, RANDOM_SOURCE_DEVICE, read_size*8/3 /* be more conservative */,
					read_size, buf);
    }
    return 0;
}

static void wrap_nettle_rnd_deinit(void* ctx)
{
	RND_LOCK;
	close(device_fd);
	RND_UNLOCK;
}

static int wrap_nettle_rnd_init(void **ctx)
{
	RND_LOCK_INIT;
	
    yarrow256_init(&yctx, SOURCES, ysources);
	do_device_source(1);
	do_trivia_source(1);

	yarrow256_slow_reseed(&yctx);

    return 0;
}



static int
wrap_nettle_rnd(void *_ctx, int level, void *data, size_t datasize)
{
	RND_LOCK;
	do_trivia_source( 0);
	do_device_source( 0);

    yarrow256_random(&yctx, datasize, data);
	RND_UNLOCK;
	return 0;
}

int crypto_rnd_prio = INT_MAX;

gnutls_crypto_rnd_st _gnutls_rnd_ops = {
    .init = wrap_nettle_rnd_init,
    .deinit = wrap_nettle_rnd_deinit,
    .rnd = wrap_nettle_rnd,
};
