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

/* Ephemeral functions that are not exposed directly from the ABI. */

#ifndef _GNUTLS_EPHEMERAL_H
#define _GNUTLS_EPHEMERAL_H

/* *INDENT-OFF* */
#ifdef __cplusplus
extern "C" {
#endif
/* *INDENT-ON* */

const void *_gnutls_ephemeral_get(const char *name);

/**
 * GNUTLS_EPHEMERAL_INT:
 * @name: the name of the function
 * @ret: the return type (must be integral)
 * @arglist: the list of argument types
 * @args: the arguments
 *
 * A macro for emitting the wrapper definition of an ephemeral function.
 *
 * Since: 3.6.13
 */
#define GNUTLS_EPHEMERAL_INT(name, ret, arglist, args) \
static inline ret name arglist \
{ \
	const void *func = _gnutls_ephemeral_get(#name); \
	if (func == NULL) \
		return GNUTLS_E_UNIMPLEMENTED_FEATURE; \
	return ((ret (*)arglist)func)args; \
}

GNUTLS_EPHEMERAL_INT(gnutls_prf_get, int, (gnutls_session_t session), (session))

/* *INDENT-OFF* */
#ifdef __cplusplus
}
#endif
/* *INDENT-ON* */

#endif /* _GNUTLS_EPHEMERAL_H */
