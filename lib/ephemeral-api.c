/*
 * Copyright (C) 2020 Red Hat, Inc.
 *
 * Author: Daiki Ueno
 *
 * This file is part of GnuTLS.
 *
 * The GnuTLS is free software; you can redistribute it and/or
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

#include "gnutls_int.h"
#include <string.h>

/* This will define _gnutls_ephemeral_get */
#include "ephemeral_functions.h"

const void *_gnutls_ephemeral_get(const char *name);

/**
 * _gnutls_ephemeral_get:
 * @name: the name of the ephemeral function
 *
 * Resolves an ephemeral function symbol by the name.
 *
 * Returns: a non-NULL function symbol or %NULL if it is not found
 *
 * Since: 3.6.13
 */
const void *
_gnutls_ephemeral_get(const char *name)
{
	const struct ephemeral_function_st *func;

	func = _gnutls_ephemeral_get_function(name, strlen(name));
	if (func == NULL) {
		gnutls_assert();
		return NULL;
	}

	return func->func;
}
