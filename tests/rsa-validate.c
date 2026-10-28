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

#include <nettle/rsa.h>
#include <nettle/knuth-lfib.h>
#include "utils.h"
#include <assert.h>

#define SEED 13

#define N                                  \
	"00a5c2c2f8ba14af0fd1229aa9ad1779" \
	"a3a16e3fbfd694bdc8f93501641a6701" \
	"21248d2012d17424d5497e2176e8f4e3" \
	"e8838d8c0703e01c3b98aab1cae7b253" \
	"8bbbdf8cd8eb57a964cb23f08594dd11" \
	"4b9f872a35b610126d6dd142abe22816" \
	"5d1f50cb0dd65fc7d5efff40905debea" \
	"0c64ad56fbf11c5e647b0220a115d4fb" \
	"c1fc1c384b4e8f449ec6aa8e89adeec8" \
	"f2095a341afff43e59d7170d97e7e340" \
	"7d484a4ccc5cb96fa5694ef7cf41c56d" \
	"4248b68ff315563294c7ff3bf8f96264" \
	"73ce92c9c3343a9f4a1dfacd02174f41" \
	"596dc7efe05c594d9233dfbdef342e18" \
	"23ec8b07c70fff205a77a45e30045f20" \
	"e43d4dd0f7a75ce7e475c56a38a333d8" \
	"db"

#define E "010001"

/* 2048-bit prime number */
#define P                                  \
	"00e6a55960d862143a6b979e61ad6be9" \
	"37207778aedacba51b14452f5bc70b4c" \
	"6895b01b3d2eff7a8c638c6e44f02505" \
	"dc6ccb166916383df95a384d7bbeb052" \
	"12bfd591bf662f98e91c2471c8f2c8ff" \
	"665540dbca8e91431f6c4ebbddeba4f5" \
	"8a3ed01cc6aa7cdbb5a6f1859073846b" \
	"5c88a1b264d0860ba59b9f6ead53f9cf" \
	"3b9f07316e48e5774938e6eef63f881d" \
	"69912f8d6ca61892f0d0e859a88baf84" \
	"9dff713cbffec3fb46484f4cbce24c6b" \
	"3707ce8f79c1117661808e14ca6e35a3" \
	"15752fb9410b9e6d62e6128fedce193d" \
	"c604d2f1b1ba4a9aec224f1f07cb6280" \
	"e8be05e5561656cc51a4b91fce561e0f" \
	"0d1cea60419e1fc28981e78e41728d07" \
	"8b"

#define P3                                 \
	"2b3f00c2289263caf42c6db250843bba" \
	"561666a0c9062ef513ccf8e135521e53" \
	"9c11051b78cfe6fa52aa54aced06f119" \
	"54661433b42a8b9ec0ea8e8733c10f63" \
	"83f80b53e328ecabb546d555ad85afe3" \
	"2ffc2935fabb3c95e44ec3399c2eee09" \
	"ebc705653ff769320f4d490b15a8d421" \
	"599e5172e719222f0d2de4c07fbed6db" \
	"2dd15944adab065dbaab4cce2be98583" \
	"cb38ea845f249b8d272b90cf9a30e8dd" \
	"9fe53b63ffc4bf1d2d8ede636a6e541a" \
	"5176bae6d4334632481aa3e5f4aa0e94" \
	"05f8f2bc322db4828b237afc96a4bb95" \
	"20e78d5152edfd0c466ed5d17622782b" \
	"a3a11b002430464f4ee2b5f6b025a2d2" \
	"756bf20c4da5f479c85b6aac457a716a" \
	"1"

/* P^2 */
#define PP                                 \
	"cfcd87665adba5de3f28945fdf41917f" \
	"7e97c48014945139504041003ce52c34" \
	"ee53583885d833a688ca7f54747719b2" \
	"c56dbf4b7544e99f0f5dbd05f311f307" \
	"29f862fc74311f3ebcde08182e02e058" \
	"db64eeb705989efc0922e71c6ff55ecb" \
	"387a0469069e6a4c36af874ba1a0499a" \
	"e571acda8053b846eac31c4b3b0e6807" \
	"e51018d180442541b0854c6e8120e0e4" \
	"80da362e878d0a3cb2b0fdfe58cdd942" \
	"8654be905c958051274ffd3d6442c568" \
	"c0cecead0f655eb55b21d561abc4de63" \
	"44e29bc110257e0b94f7ca5d65223c59" \
	"f55e9074714a2d5774fbbf3326165b91" \
	"1ff5486f382566be576d7c36b78c9e36" \
	"8789346ea5b717e458927b77c73bfaa0" \
	"73a2a761f5000f888fa84bd7e72d11d1" \
	"90d233bfbd74511bb4df908e844e4596" \
	"9f63122a5168bf6d720aa0782b4a3105" \
	"4bdae5cedde0227d213c9c41aa205adf" \
	"f5519961fa012530b8f673c96aadb3d3" \
	"5c3c2c4ed0e3d508d409384dc68bdf47" \
	"a1f95f678c61181a884fbba210d73982" \
	"bdbce86a9642325251a17e48af1b5980" \
	"3f48561f27830b335e1163590bbe4c1e" \
	"2c48721734de47e55142ba5f20d8bce9" \
	"a14d37b5fccb86da192b34e0e5ff2cc8" \
	"d9e71442807fb4b43cfd2331c1a2122d" \
	"aa5ae6e8e0e7ebe29c2f63b3a63c85c8" \
	"cbc3c892ff0dd9f4d09d1dd8fa715059" \
	"8df812190b668b985daecba7c240a128" \
	"9ffe8a87c0a646b38617f0ff1b56e579"

extern unsigned rsa_validate_sp800_56b_r2_public(struct rsa_public_key *pub,
						 void *random_ctx,
						 nettle_random_func *random);

static unsigned run(const char *n, const char *e)
{
	struct knuth_lfib_ctx rng;
	knuth_lfib_init(&rng, SEED);

	struct rsa_public_key pub;
	rsa_public_key_init(&pub);

	mpz_set_str(pub.n, n, 16);
	mpz_set_str(pub.e, e, 16);

	unsigned res = rsa_validate_sp800_56b_r2_public(
		&pub, &rng, (nettle_random_func *)knuth_lfib_random);

	rsa_public_key_clear(&pub);

	return res;
}

static void expect_where(const char *n, const char *e, unsigned expected,
			 const char *func, int line)
{
	unsigned got = run(n, e);
	if (got != expected) {
		_fail("%s:%d: n=%s, e=%s, expected %u, got %u\n", func, line, n,
		      e, expected, got);
	}
}

#define expect(n, e, expected) expect_where(n, e, expected, __func__, __LINE__)

void doit(void)
{
	/* Small modulus */
	expect("8000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
	       E, 0);

	/* Odd modulus length */
	expect("100000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
	       E, 0);

	/* Short exponent: 2^16 */
	expect(N, "10000", 0);

	/* Short exponent: 2^16 - 1 */
	expect(N, "ffff", 0);

	/* In range: 2^256 - 1 */
	expect(N,
	       "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
	       1);

	/* Too large exponent: 2^256 */
	expect(N,
	       "10000000000000000000000000000000000000000000000000000000000000000",
	       0);

	/* Too large exponent: 2^256 + 1 */
	expect(N,
	       "10000000000000000000000000000000000000000000000000000000000000001",
	       0);

	/* Even modulus */
	char *n = strdup(N);
	assert(n);
	n[strlen(n) - 1] = '2';
	expect(n, E, 0);
	free(n);

	/* Even exponent */
	char *e = strdup(E);
	assert(e);
	e[strlen(e) - 1] = '2';
	expect(N, e, 0);
	free(e);

	/* Prime modulus */
	expect(P, E, 0);

	/* Very small factor: 3 */
	expect(P3, E, 0);

	/* Power of a prime */
	expect(PP, E, 0);

	/* valid public key */
	expect(N, E, 1);
}
