/*
 * Copyright (C) 2026 Red Hat, Inc.
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

#ifndef GNUTLS_LIB_NETTLE_INT_MR_H
#define GNUTLS_LIB_NETTLE_INT_MR_H

#include <nettle/bignum.h>
#include <stdbool.h>
#include <stdlib.h>

enum mr_result {
	MR_PROBABLY_PRIME,
	MR_COMPOSITE_WITH_FACTOR, /* factor holds a nontrivial factor of w  */
	MR_COMPOSITE_NOT_PRIME_POWER, /* composite, not a power of a prime */
	MR_ERROR
};

enum mr_result miller_rabin_enhanced(const mpz_t w, size_t iterations,
				     void *rng_ctx, nettle_random_func *rng,
				     mpz_t factor);

#endif /* GNUTLS_LIB_NETTLE_INT_MR_H */
