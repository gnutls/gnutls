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

/* Enhanced Miller-Rabin probabilistic primality test (FIPS 186-5, B.3.2). */

#include "config.h"
#include "mr.h"

/* One round for base b, 1 < b < w-1, where w-1 = 2^a * m with m odd.
 * Returns MR_PROBABLY_PRIME if the round passes. */
static enum mr_result mr_round(const mpz_t w, const mpz_t w_minus_1,
			       const mpz_t m, mp_bitcnt_t a, const mpz_t b,
			       mpz_t factor)
{
	/* g = GCD(b, w); if g > 1, g is a factor of w. */
	mpz_gcd(factor, b, w);
	if (mpz_cmp_ui(factor, 1) > 0)
		return MR_COMPOSITE_WITH_FACTOR;

	mpz_t x, z;
	mpz_inits(x, z, NULL);

	/* z = b^m mod w; if z is 1 or w-1, this round passes. */
	mpz_powm(z, b, m, w);
	if (mpz_cmp_ui(z, 1) == 0 || mpz_cmp(z, w_minus_1) == 0) {
		mpz_clears(x, z, NULL);
		return MR_PROBABLY_PRIME;
	}

	/* Square up to a-1 times, looking for w-1 (pass) or 1 (a
	 * nontrivial square root of 1, x, was found). */
	for (mp_bitcnt_t j = 1; j < a; j++) {
		mpz_set(x, z);
		mpz_powm_ui(z, x, 2, w);

		if (mpz_cmp(z, w_minus_1) == 0) {
			mpz_clears(x, z, NULL);
			return MR_PROBABLY_PRIME;
		}
		if (mpz_cmp_ui(z, 1) == 0) {
			mpz_sub_ui(x, x, 1);
			mpz_gcd(factor, x, w);
			mpz_clears(x, z, NULL);
			return MR_COMPOSITE_WITH_FACTOR;
		}
	}

	/* One more squaring: z = b^(w-1) mod w. */
	mpz_set(x, z);
	mpz_powm_ui(z, x, 2, w);

	if (mpz_cmp_ui(z, 1) == 0) {
		/* x is a nontrivial square root of 1. */
		mpz_sub_ui(x, x, 1);
		mpz_gcd(factor, x, w);
		mpz_clears(x, z, NULL);
		return MR_COMPOSITE_WITH_FACTOR;
	}

	/* Fermat test failed: g = GCD(b^(w-1) - 1, w). */
	mpz_sub_ui(x, z, 1);
	mpz_gcd(factor, x, w);
	enum mr_result res = mpz_cmp_ui(factor, 1) > 0 ?
				     MR_COMPOSITE_WITH_FACTOR :
				     MR_COMPOSITE_NOT_PRIME_POWER;

	mpz_clears(x, z, NULL);
	return res;
}

/* Upper bound on random draws per base.  For an approved DRBG each
 * draw is accepted with probability given in P(w) = (w - 3) / 2^wlen.
 *
 * This can be approximated with (w - 3) / (2^log2(w) + 1), and the
 * worst case is w = 5, P(w) = 0.2.
 *
 * To match with negligible threshold in FIPS 186-5 (2^-64), we chose 155,
 * so that (1 - 0.2)^155 ≈ 2^-64. */
#define MAX_RANDOM_DRAWS 155

enum mr_result miller_rabin_enhanced(const mpz_t w, size_t iterations,
				     void *rng_ctx, nettle_random_func *rng,
				     mpz_t factor)
{
	if (mpz_cmp_ui(w, 3) <= 0 || mpz_even_p(w) || iterations == 0)
		return MR_ERROR;

	mpz_t w_minus_1, m, b;
	mpz_inits(w_minus_1, m, b, NULL);

	/* a: largest integer with 2^a | w-1; m = (w-1) / 2^a */
	mpz_sub_ui(w_minus_1, w, 1);
	mp_bitcnt_t a = mpz_scan1(w_minus_1, 0);
	mpz_tdiv_q_2exp(m, w_minus_1, a);
	size_t wlen = mpz_sizeinbase(w, 2);

	enum mr_result res = MR_PROBABLY_PRIME;
	for (size_t i = 0; i < iterations; i++) {
		/* rejection sampling loop for b: 1 < b < w - 1 */
		size_t j;
		for (j = 0; j < MAX_RANDOM_DRAWS; j++) {
			nettle_mpz_random_size(b, rng_ctx, rng, wlen);
			if (mpz_cmp_ui(b, 1) > 0 && mpz_cmp(b, w_minus_1) < 0)
				break;
		}
		if (j == MAX_RANDOM_DRAWS) {
			res = MR_ERROR;
			break;
		}
		res = mr_round(w, w_minus_1, m, a, b, factor);
		if (res != MR_PROBABLY_PRIME)
			break;
	}

	mpz_clears(w_minus_1, m, b, NULL);
	return res;
}
