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

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <nettle/bignum.h>
#include <nettle/knuth-lfib.h>
#include <stdbool.h>
#include "utils.h"

enum mr_result {
	MR_PROBABLY_PRIME,
	MR_COMPOSITE_WITH_FACTOR, /* factor holds a nontrivial factor of w  */
	MR_COMPOSITE_NOT_PRIME_POWER, /* composite, not a power of a prime      */
	MR_ERROR /* invalid input                          */
};

extern enum mr_result miller_rabin_enhanced(const mpz_t w, size_t iterations,
					    void *rng_ctx,
					    nettle_random_func *rng,
					    mpz_t factor);

#define SEED 13
#define ITERATIONS 40

static const char *mr_result_name(enum mr_result r)
{
	switch (r) {
	case MR_PROBABLY_PRIME:
		return "PROBABLY PRIME";
	case MR_COMPOSITE_WITH_FACTOR:
		return "COMPOSITE WITH FACTOR";
	case MR_COMPOSITE_NOT_PRIME_POWER:
		return "COMPOSITE NOT A POWER OF A PRIME";
	default:
		return "ERROR";
	}
}

/* Run the test on the decimal string dec with a freshly seeded generator.
 * When a factor is reported, also verify 1 < g < w and g | w. */
static enum mr_result run(const char *dec, unsigned iterations)
{
	mpz_t w, g;
	struct knuth_lfib_ctx rng;
	mpz_inits(w, g, NULL);
	if (mpz_set_str(w, dec, 10) != 0)
		fail("bad test literal: %s\n", dec);

	knuth_lfib_init(&rng, SEED);
	enum mr_result r = miller_rabin_enhanced(
		w, iterations, &rng, (nettle_random_func *)knuth_lfib_random,
		g);

	if (r == MR_COMPOSITE_WITH_FACTOR &&
	    (mpz_cmp_ui(g, 1) <= 0 || mpz_cmp(g, w) >= 0 ||
	     !mpz_divisible_p(w, g))) {
		char *gd;
		gmp_asprintf(&gd, "%Zd", g);
		fail("bad factor %s for w=%s\n", gd, dec);
	}
	mpz_clears(w, g, NULL);
	return r;
}

static void expect_where(const char *dec, enum mr_result expected,
			 const char *func, int line)
{
	enum mr_result got = run(dec, ITERATIONS);
	if (got != expected) {
		_fail("%s:%d: w=%s: expected %s, got %s\n", func, line, dec,
		      mr_result_name(expected), mr_result_name(got));
	}
}

#define expect(dec, expected) expect_where(dec, expected, __func__, __LINE__)

void doit(void)
{
	/* Invalid input: even, <= 3, or zero iterations */
	expect("0", MR_ERROR);
	expect("1", MR_ERROR);
	expect("2", MR_ERROR);
	expect("3", MR_ERROR);
	expect("4", MR_ERROR);
	expect("100", MR_ERROR);
	if (run("9", 0) != MR_ERROR) {
		fail("zero iterations should be an error\n");
	}

	/* Primes */
	expect("5", MR_PROBABLY_PRIME);
	expect("7", MR_PROBABLY_PRIME);
	expect("13", MR_PROBABLY_PRIME);
	expect("65537", MR_PROBABLY_PRIME);
	expect("1000000007", MR_PROBABLY_PRIME);

	/* 2^61-1 */
	expect("2305843009213693951", MR_PROBABLY_PRIME);

	/* 2^127-1 */
	expect("170141183460469231731687303715884105727", MR_PROBABLY_PRIME);

	/* Prime powers: composite, but never "not a power of a prime" */
	expect("9", MR_COMPOSITE_WITH_FACTOR);
	expect("25", MR_COMPOSITE_WITH_FACTOR);
	expect("27", MR_COMPOSITE_WITH_FACTOR);
	expect("49", MR_COMPOSITE_WITH_FACTOR);
	expect("121", MR_COMPOSITE_WITH_FACTOR);

	/* 3^40 */
	expect("12157665459056928801", MR_COMPOSITE_WITH_FACTOR);

	/* (2^61-1)^3 */
	expect("12259964326927110850916040267783483001021757281745764351",
	       MR_COMPOSITE_WITH_FACTOR);

	/* Carmichael numbers: a square root of 1 or a shared factor is found */
	expect("561", MR_COMPOSITE_WITH_FACTOR);
	expect("294409", MR_COMPOSITE_WITH_FACTOR);

	/* Chernick */
	expect("1986114220962193666411479745396577410163873092323808013209",
	       MR_COMPOSITE_WITH_FACTOR);

	/* Composites that are not prime powers. For large prime factors the
	 * Fermat test fails with GCD(b^(w-1) - 1, w) = 1 almost surely. */

	/* (2^61-1)(2^89-1) */
	expect("1427247692705959880439315947500961989719490561",
	       MR_COMPOSITE_NOT_PRIME_POWER);

	/* (2^61-1)(2^89-1)(2^107-1) */
	expect("231584178474632390746708341877043077080763485702193985759174890302071266869247",
	       MR_COMPOSITE_NOT_PRIME_POWER);

	/* (2^61-1)^2 (2^89-1) */
	expect("3291009114642412081455442974385869265328206325007317368687296511",
	       MR_COMPOSITE_NOT_PRIME_POWER);

	/* (2^61-1)(2^89-1)^2(2^107-1) */
	expect("143343663499379469413510900941987863157565360119083872567946555306732772618008641296045501923022042300417",
	       MR_COMPOSITE_NOT_PRIME_POWER);
}
