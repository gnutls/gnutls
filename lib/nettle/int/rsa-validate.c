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

/* SP800-56Brev2 6.4.2.2: Partial Public-Key Validation for RSA, based on:
 * SP800-89 5.3.3: (Explicit) Partial Public Key Validation for RSA.
 */

#include "config.h"

#include "rsa-fips.h"
#include "fips.h"
#include "mr.h"

#define R                                                                    \
	"109036770458900756603520216149438572201938340011965187447647876066" \
	"414569797653338734366826340326602490063850586198047063895832245458" \
	"155020344842149584276744979626117006973292189740065794479316396088" \
	"641831369080887268041164681593453560544410298362920842256746157156" \
	"8587963766123806881456648026733413053968363611105"

unsigned rsa_validate_sp800_56b_r2_public(struct rsa_public_key *pub,
					  void *random_ctx,
					  nettle_random_func *random)
{
	/* (a) Length of the modulus: Check that the length of the
	 * modulus n (nlen) is even and provides 112-bit security
	 * strength.
	 */
	size_t nbits = mpz_sizeinbase(pub->n, 2);
	if (nbits < 2048 || nbits % 2 != 0)
		return gnutls_assert_val(0);

	/* (b) Size of the public exponent e: 2^16 < e < 2^256.
	 */
	if (mpz_cmp_ui(pub->e, 65536) <= 0 || mpz_sizeinbase(pub->e, 2) > 256)
		return gnutls_assert_val(0);

	/* (c) Oddness: Check that n and e are odd. */
	if (!(mpz_odd_p(pub->n) && mpz_odd_p(pub->e)))
		return gnutls_assert_val(0);

	/* (f) No very small factors: Check that GCD (n, r) = 1 where
	 * r is the product of the 132 smallest odd primes, from 3 to 751.
	 */
	mpz_t r;
	mpz_init(r);
	mpz_set_str(r, R, 10);
	mpz_gcd(r, r, pub->n);
	if (mpz_cmp_ui(r, 1) != 0) {
		mpz_clear(r);
		return gnutls_assert_val(0);
	}
	mpz_clear(r);

	/* (d) Compositeness: Check that n fails an Approved primality test.
	 * (e) Not a power of a prime: Check that n is not a power of a prime.
	 */
	mpz_t g;
	mpz_init(g);
	enum mr_result res = miller_rabin_enhanced(
		pub->n, 5 /* max. in Table B.1 of FIPS 186-5 */, random_ctx,
		random, g);
	if (res != MR_COMPOSITE_NOT_PRIME_POWER) {
		mpz_clear(g);
		return gnutls_assert_val(0);
	}
	mpz_clear(g);

	return 1;
}
