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

/* Here are the common parts of the random generator layer. 
 * Some of this code was based on the LSH 
 * random generator (the trivia and device source functions for POSIX)
 * and modified to fit gnutls' needs. Relicenced with permission. 
 * Original author Niels Möller.
 */

#include <gnutls_int.h>
#include <gnutls_errors.h>
#include <locks.h>
#include <gnutls_num.h>
#include <nettle/yarrow.h>
#include <errno.h>
#include <rnd-common.h>
#include <hash-pjw-bare.h>

#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>

/* gnulib wants to claim strerror even if it cannot provide it. WTF */
#undef strerror

#ifdef HAVE_GETRUSAGE
# ifdef RUSAGE_THREAD
#  define ARG_RUSAGE RUSAGE_THREAD
# else
#  define ARG_RUSAGE RUSAGE_SELF
# endif
#endif

void _rnd_get_event(struct event_st *e)
{
	static unsigned count = 0;

	memset(e, 0, sizeof(*e));
	gettime(&e->now);

#ifdef HAVE_GETRUSAGE
	if (getrusage(ARG_RUSAGE, &e->rusage) < 0) {
		_gnutls_debug_log("getrusage failed: %s\n",
			  strerror(errno));
	}
#endif

#ifdef HAVE_GETPID
	e->pid = getpid();
#endif
	e->count = count++;
	e->err = errno;

	return;
}

#ifdef _WIN32
/* The windows randomness gatherer.
 */

#include <windows.h>
#include <wincrypt.h>

static HCRYPTPROV device_fd = 0;

static
int _rnd_get_system_entropy_win32(void* rnd, size_t size)
{
	if (!CryptGenRandom(device_fd, (DWORD) size, rnd)) {
		_gnutls_debug_log("Error in CryptGenRandom: %d\n",
					(int)GetLastError());
		return GNUTLS_E_RANDOM_DEVICE_ERROR;
	}

	return 0;
}

get_entropy_func _rnd_get_system_entropy = _rnd_get_system_entropy_win32;

int _rnd_system_entropy_check(void)
{
	return 0;
}

int _rnd_system_entropy_init(void)
{
	int old;

	if (!CryptAcquireContext
		(&device_fd, NULL, NULL, PROV_RSA_FULL,
		 CRYPT_SILENT | CRYPT_VERIFYCONTEXT)) {
		_gnutls_debug_log
			("error in CryptAcquireContext!\n");
		return GNUTLS_E_RANDOM_DEVICE_ERROR;
	}
	
	return 0;
}

void _rnd_system_entropy_deinit(void)
{
	CryptReleaseContext(device_fd, 0);
}

#else /* POSIX */

/* The POSIX (Linux-BSD) randomness gatherer.
 */

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

get_entropy_func _rnd_get_system_entropy = NULL;

int _rnd_system_entropy_check(void)
{
	int ret;
	struct stat st;

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
#endif

