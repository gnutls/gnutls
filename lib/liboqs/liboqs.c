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

#include "liboqs/liboqs.h"

#ifdef _WIN32
#define RTLD_NOW 0
#define RTLD_GLOBAL 0
#else
#include <dlfcn.h>
#endif

#ifndef OQS_LIBRARY_SONAME
#define OQS_LIBRARY_SONAME "none"
#endif

#include <limits.h>
#include <stdbool.h>
#include <stdlib.h>
#include "errors.h"
#include "locks.h"

#include "dlwrap/oqs.h"
#include "liboqs/rand.h"
#include "liboqs/sha2.h"
#include "liboqs/sha3.h"

/* We can't use GNUTLS_ONCE here, as it wouldn't allow manual unloading */
GNUTLS_STATIC_MUTEX(liboqs_init_mutex);
static int _liboqs_init = 0;

static bool parse_version(const char *version, long *major, long *minor,
			  long *micro)
{
	long components[3] = { 0, 0, 0 };
	const char *start = version, *end = version + strlen(version);

	for (size_t i = 0; start < end && i < 3; i++) {
		char *next;

		components[i] = strtol(start, &next, 10);
		if (components[i] < 0 || components[i] == LONG_MAX)
			return false;

		start = next + 1;
	}
	if (major)
		*major = components[0];
	if (minor)
		*minor = components[1];
	if (micro)
		*micro = components[2];

	return true;
}

static bool check_version(const char *version, long req_major, long req_minor,
			  long req_micro)
{
	long major, minor, micro;

	return parse_version(version, &major, &minor, &micro) &&
	       (major > req_major ||
		(major == req_major &&
		 (minor > req_minor ||
		  (minor == req_minor && micro >= req_micro))));
}

int _gnutls_liboqs_ensure(void)
{
	const char *version;
	int ret;

	if (_liboqs_init)
		return GNUTLS_E_SUCCESS;

	ret = gnutls_static_mutex_lock(&liboqs_init_mutex);
	if (unlikely(ret < 0))
		return gnutls_assert_val(ret);

	if (gnutls_oqs_ensure_library(OQS_LIBRARY_SONAME,
				      RTLD_NOW | RTLD_GLOBAL) < 0) {
		_gnutls_debug_log(
			"liboqs: unable to initialize liboqs functions\n");
		ret = gnutls_assert_val(GNUTLS_E_INTERNAL_ERROR);
		goto out;
	}

	version = GNUTLS_OQS_FUNC(OQS_version)();
	if (unlikely(version == NULL)) {
		_gnutls_debug_log(
			"liboqs: unable to retrieve liboqs version\n");
		ret = gnutls_assert_val(GNUTLS_E_INTERNAL_ERROR);
		goto out;
	}
	if (!check_version(version, MIN_LIBOQS_VERSION_MAJOR,
			   MIN_LIBOQS_VERSION_MINOR,
			   MIN_LIBOQS_VERSION_MICRO)) {
		_gnutls_debug_log("liboqs: unsupported liboqs version\n");
		ret = gnutls_assert_val(GNUTLS_E_INTERNAL_ERROR);
		goto out;
	}

	_gnutls_liboqs_sha2_init();
	_gnutls_liboqs_sha3_init();
	GNUTLS_OQS_FUNC(OQS_init)();
	_gnutls_liboqs_rand_init();

	_liboqs_init = 1;
	ret = GNUTLS_E_SUCCESS;

out:
	(void)gnutls_static_mutex_unlock(&liboqs_init_mutex);

	return ret;
}

/* This is not thread-safe: call this function only from
 * gnutls_global_deinit, which has a proper protection.
 */
void _gnutls_liboqs_deinit(void)
{
	if (_liboqs_init) {
		_gnutls_liboqs_rand_deinit();
		_gnutls_liboqs_sha3_deinit();
		_gnutls_liboqs_sha2_deinit();
		GNUTLS_OQS_FUNC(OQS_destroy)();
	}

	gnutls_oqs_unload_library();
	_liboqs_init = 0;
}
