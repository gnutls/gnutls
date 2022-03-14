/*
 * Copyright (C) 2010-2012 Free Software Foundation, Inc.
 * Copyright (C) 2022 Tobias Heider <tobias.heider@canonical.com>
 *
 * Author: Nikos Mavrogiannopoulos
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
#include "errors.h"
#include <num.h>
#include <mpi.h>
#include <nettle/bignum.h> /* includes gmp.h */

static void gnutls_free_zero(void *data, size_t size);
static void *gnutls_realloc_zero(void *data, size_t old_size, size_t new_size);

/* Functions that refer to the initialization of the nettle library.
 */

int gnutls_crypto_init(void)
{
	void *(*allocfunc) (size_t);
	void *(*reallocfunc) (void *, size_t, size_t);
	void (*freefunc) (void *, size_t);
	void *(*defallocfunc) (size_t);
	void *(*defreallocfunc) (void *, size_t, size_t);
	void (*deffreefunc) (void *, size_t);

	/* Check if non-default allocators are being used.
	 * Some applications like guile override GMP allocators
	 * with GC capable alternatives. Do nothing if this is
	 * the case.
	 */
	mp_get_memory_functions(&allocfunc, &reallocfunc, &freefunc);
	mp_set_memory_functions(NULL, NULL, NULL);
	mp_get_memory_functions(&defallocfunc, &defreallocfunc, &deffreefunc);
	if (reallocfunc != defreallocfunc || freefunc != deffreefunc) {
		mp_set_memory_functions(allocfunc, reallocfunc, freefunc);
		return (0);
	}

	/* Overload GMP allocators with safe alternatives */
	mp_set_memory_functions(NULL, gnutls_realloc_zero, gnutls_free_zero);
	return 0;
}

/* Functions that refer to the deinitialization of the nettle library.
 */

void gnutls_crypto_deinit(void)
{
}

/*-
 * gnutls_free_zero:
 * @data: the memory to free
 * @size: the size of memory
 *
 * This function will operate similarly to free(), but will safely
 * zeroize the memory pointed to by data before freeing.
 *
 -*/
static void gnutls_free_zero(void *data, size_t size)
{
	explicit_bzero(data, size);
	free(data);
}

/*-
 * gnutls_realloc_zero:
 * @data: the memory to free
 * @old_size: the size of memory before reallocation
 * @new_size: the size of memory after reallocation
 *
 * This function will operate similarly to realloc(), but will safely
 * zeroize discarded memory.
 *
 -*/
static void *gnutls_realloc_zero(void *data, size_t old_size, size_t new_size)
{
	void *newptr = NULL;

	/* mini-gmp always passes old_size of 0 */
	if (old_size == 0) {
		newptr = realloc(data, new_size);
		if (newptr == NULL)
			abort();
		return newptr;
	}

	if (data == NULL) {
		newptr = malloc(new_size);
		if (newptr == NULL)
			abort();
		return newptr;
	}

	if (new_size == 0)
		goto done;

	if (new_size <= old_size) {
		size_t d = old_size - new_size;
		/* Don't bother reallocating */
		if (d < old_size / 2) {
			explicit_bzero((char *)data + new_size, d);
			return data;
		}
	}

	newptr = malloc(new_size);
	if (newptr == NULL)
		abort();

	memcpy(newptr, data, old_size);
 done:
	explicit_bzero(data, old_size);
	free(data);
	return newptr;
}
