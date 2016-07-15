/*
 * Copyright (C) 2010-2016 Free Software Foundation, Inc.
 * Copyright (C) 2015-2016 Red Hat, Inc.
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

/* The Linux style system random generator: That is,
 * getrandom() -> /dev/urandom -> EGD, where "->" indicates fallback.
 */

#include "gnutls_int.h"
#include "errors.h"
#include <locks.h>
#include <num.h>
#include <nettle/yarrow.h>
#include <errno.h>
#include <rnd-common.h>
#include <hash-pjw-bare.h>

#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>

/* gnulib wants to claim strerror even if it cannot provide it. WTF */
#undef strerror

#include <time.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <fcntl.h>
#include <locks.h>
#include "egd.h"

static int _gnutls_urandom_fd = -1;
static ino_t _gnutls_urandom_fd_ino = 0;
static dev_t _gnutls_urandom_fd_rdev = 0;

#if defined(__linux)
# ifdef HAVE_LINUX_GETRANDOM
#  include <linux/random.h>
# else
#  include <sys/syscall.h>
#  undef getrandom
#  define getrandom(dst,s,flags) syscall(__NR_getrandom, (void*)dst, (size_t)s, (unsigned int)flags)
# endif

static unsigned have_getrandom(void)
{
	char c;
	int ret;
	ret = getrandom(&c, 1, 1/*GRND_NONBLOCK*/);
	if (ret == 1 || (ret == -1 && errno == EAGAIN))
		return 1;
	return 0;
}

static int _rnd_get_system_entropy_getrandom(void* _rnd, size_t size)
{
	int ret;
	ret = getrandom(_rnd, size, 0);
	if (ret == -1) {
		gnutls_assert();
		_gnutls_debug_log
			("Failed to use getrandom: %s\n",
					 strerror(errno));
		return GNUTLS_E_RANDOM_DEVICE_ERROR;
	}

	/* This function is only used internally for small sizes which
	 * should be delivered by getrandom(). */
	if ((size_t)ret != size)
		return gnutls_assert_val(GNUTLS_E_RANDOM_DEVICE_ERROR);

	return 0;
}
#else
# define have_getrandom() 0
#endif

static int _rnd_get_system_entropy_urandom(void* _rnd, size_t size)
{
	uint8_t* rnd = _rnd;
	uint32_t done;

	for (done = 0; done < size;) {
		int res;
		do {
			res = read(_gnutls_urandom_fd, rnd + done, size - done);
		} while (res < 0 && errno == EINTR);

		if (res <= 0) {
			if (res < 0) {
				_gnutls_debug_log
					("Failed to read /dev/urandom: %s\n",
					 strerror(errno));
			} else {
				_gnutls_debug_log
					("Failed to read /dev/urandom: end of file\n");
			}

			return GNUTLS_E_RANDOM_DEVICE_ERROR;
		}

		done += res;
	}

	return 0;
}

static
int _rnd_get_system_entropy_egd(void* _rnd, size_t size)
{
	unsigned int done;
	uint8_t* rnd = _rnd;
	int res;

	for (done = 0; done < size;) {
		res =
		    _rndegd_read(&_gnutls_urandom_fd, rnd + done, size - done);
		if (res <= 0) {
			if (res < 0) {
				_gnutls_debug_log("Failed to read egd.\n");
			} else {
				_gnutls_debug_log("Failed to read egd: end of file\n");
			}

			return gnutls_assert_val(GNUTLS_E_RANDOM_DEVICE_ERROR);
		}
		done += res;
	}

	return 0;
}

int _rnd_system_entropy_check(void)
{
	int ret;
	struct stat st;

	if (_gnutls_urandom_fd == -1) /* not using urandom */
		return 0;

	ret = fstat(_gnutls_urandom_fd, &st);
	if (ret < 0 || st.st_ino != _gnutls_urandom_fd_ino || st.st_rdev != _gnutls_urandom_fd_rdev) {
		return _rnd_system_entropy_init();
	}
	return 0;
}

int _rnd_system_entropy_init(void)
{
	int old;
	struct stat st;

#if defined(__linux)
	/* Enable getrandom() usage if available */
	if (have_getrandom()) {
		_rnd_get_system_entropy = _rnd_get_system_entropy_getrandom;
		_gnutls_debug_log("getrandom random generator was detected\n");
		return 0;
	}
#endif

	/* First fallback: /dev/unrandom */
	_gnutls_urandom_fd = open("/dev/urandom", O_RDONLY);
	if (_gnutls_urandom_fd < 0) {
		_gnutls_debug_log("Cannot open urandom!\n");
		goto fallback;
	}

	old = fcntl(_gnutls_urandom_fd, F_GETFD);
	if (old != -1)
		fcntl(_gnutls_urandom_fd, F_SETFD, old | FD_CLOEXEC);

	if (fstat(_gnutls_urandom_fd, &st) >= 0) {
		_gnutls_urandom_fd_ino = st.st_ino;
		_gnutls_urandom_fd_rdev = st.st_rdev;
	}

	_rnd_get_system_entropy = _rnd_get_system_entropy_urandom;

	return 0;
fallback:
	/* Third fallback: EGD */
	_gnutls_urandom_fd = _rndegd_connect_socket();
	if (_gnutls_urandom_fd < 0) {
		_gnutls_debug_log("Cannot open egd socket!\n");
		return
			gnutls_assert_val
			(GNUTLS_E_RANDOM_DEVICE_ERROR);
	}

	if (fstat(_gnutls_urandom_fd, &st) >= 0) {
		_gnutls_urandom_fd_ino = st.st_ino;
		_gnutls_urandom_fd_rdev = st.st_rdev;
	}

	_gnutls_debug_log("EGD random generator was detected\n");
	_rnd_get_system_entropy = _rnd_get_system_entropy_egd;
	
	return 0;
}

void _rnd_system_entropy_deinit(void)
{
	if (_gnutls_urandom_fd >= 0) {
		close(_gnutls_urandom_fd);
		_gnutls_urandom_fd = -1;
	}
}

