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

#include "errors.h"

#include "dlwrap/oqs.h"
#include "liboqs/rand.h"
#include "liboqs/sha3.h"

int _gnutls_liboqs_init(void)
{
	if (gnutls_oqs_ensure_library(OQS_LIBRARY_SONAME,
				      RTLD_NOW | RTLD_GLOBAL) < 0)
		return gnutls_assert_val(GNUTLS_E_INTERNAL_ERROR);

	_gnutls_liboqs_sha3_init();
	GNUTLS_OQS_FUNC(OQS_init)();
	_gnutls_liboqs_rand_init();
	return 0;
}

void _gnutls_liboqs_deinit(void)
{
	_gnutls_liboqs_rand_deinit();
	_gnutls_liboqs_sha3_deinit();
	GNUTLS_OQS_FUNC(OQS_destroy)();
	gnutls_oqs_unload_library();
}
