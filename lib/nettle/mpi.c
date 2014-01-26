/*
 * Copyright (C) 2010-2012 Free Software Foundation, Inc.
 *
 * Author: Nikos Mavrogiannopoulos
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
 * along with this program.  If not, see <http://www.gnu.org/licenses/>
 *
 */

/* Here lie everything that has to do with large numbers, gmp.
 */

#include <gnutls_int.h>
#include <gnutls_errors.h>
#include <algorithms.h>
#include <gnutls_num.h>
#include <gnutls_mpi.h>
#include <gmp.h>
#include <nettle/bignum.h>
#include <gnettle.h>
#include <random.h>

#define TOMPZ(x) (*((mpz_t*)(x)))

static int
wrap_nettle_mpi_print(const bigint_t a, void *buffer, size_t * nbytes,
		      gnutls_bigint_format_t format)
{
	unsigned int size;
	mpz_t *p = (void *) a;

	if (format == GNUTLS_MPI_FORMAT_USG) {
		size = nettle_mpz_sizeinbase_256_u(*p);
	} else if (format == GNUTLS_MPI_FORMAT_STD) {
		size = nettle_mpz_sizeinbase_256_s(*p);
	} else if (format == GNUTLS_MPI_FORMAT_PGP) {
		size = nettle_mpz_sizeinbase_256_u(*p) + 2;
	} else {
		gnutls_assert();
		return GNUTLS_E_INVALID_REQUEST;
	}

	if (buffer == NULL || size > *nbytes) {
		*nbytes = size;
		return GNUTLS_E_SHORT_MEMORY_BUFFER;
	}

	if (format == GNUTLS_MPI_FORMAT_PGP) {
		uint8_t *buf = buffer;
		unsigned int nbits = _gnutls_mpi_get_nbits(a);
		buf[0] = (nbits >> 8) & 0xff;
		buf[1] = (nbits) & 0xff;
		nettle_mpz_get_str_256(size - 2, buf + 2, *p);
	} else {
		nettle_mpz_get_str_256(size, buffer, *p);
	}
	*nbytes = size;

	return 0;
}

static int wrap_nettle_mpi_init(bigint_t *w)
{
mpz_t *r;

	r = gnutls_malloc(sizeof(*r));
	if (r == NULL) {
		gnutls_assert();
		return GNUTLS_E_MEMORY_ERROR;
	}

	mpz_init(*r);
	
	*w = r;

	return 0;
}

static int wrap_nettle_mpi_init_multi(bigint_t *w, ...)
{
	va_list args;
	bigint_t *next;
	mpz_t *r;
	bigint_t* last_failed = NULL;

	r = gnutls_malloc(sizeof(*r));
	if (r == NULL) {
		gnutls_assert();
		return GNUTLS_E_MEMORY_ERROR;
	}

	mpz_init(*r);
	*w = r;
	
	va_start(args, w);
	
	do {
		next = va_arg(args, bigint_t*);
		if (next != NULL) {
			r = gnutls_malloc(sizeof(*r));
			if (r == NULL) {
				gnutls_assert();
				va_end(args);
				last_failed = next;
				goto fail;
			}
			mpz_init(*r);
			*next = r;
		}
	} while(next != 0);
	
	va_end(args);

	return 0;
fail:
	mpz_clear(TOMPZ(*w));
	gnutls_free(*w);
	va_start(args, w);
	
	do {
		next = va_arg(args, bigint_t*);
		if (next != last_failed) {
			mpz_clear(TOMPZ(*next));
			gnutls_free(*next);
		}
	} while(next != last_failed);
	
	va_end(args);
	
	return GNUTLS_E_MEMORY_ERROR;
}

static bigint_t
wrap_nettle_mpi_scan(const void *buffer, size_t nbytes,
		     gnutls_bigint_format_t format)
{
	int ret;
	bigint_t r;
	
	ret = wrap_nettle_mpi_init(&r);
	if (ret < 0) {
		gnutls_assert();
		return NULL;
	}

	if (format == GNUTLS_MPI_FORMAT_USG) {
		nettle_mpz_set_str_256_u(TOMPZ(r), nbytes, buffer);
	} else if (format == GNUTLS_MPI_FORMAT_STD) {
		nettle_mpz_set_str_256_s(TOMPZ(r), nbytes, buffer);
	} else if (format == GNUTLS_MPI_FORMAT_PGP) {
		const uint8_t *buf = buffer;
		size_t size;

		if (nbytes < 3) {
			gnutls_assert();
			goto fail;
		}

		size = (buf[0] << 8) | buf[1];
		size = (size + 7) / 8;

		if (size > nbytes - 2) {
			gnutls_assert();
			goto fail;
		}
		nettle_mpz_set_str_256_u(TOMPZ(r), size, buf + 2);
	} else {
		gnutls_assert();
		goto fail;
	}

	return r;
      fail:
	_gnutls_mpi_release(&r);
	return NULL;

}

static int wrap_nettle_mpi_cmp(const bigint_t u, const bigint_t v)
{
	mpz_t *i1 = u, *i2 = v;

	return mpz_cmp(*i1, *i2);
}

static int wrap_nettle_mpi_cmp_ui(const bigint_t u, unsigned long v)
{
	mpz_t *i1 = u;

	return mpz_cmp_ui(*i1, v);
}

static bigint_t wrap_nettle_mpi_set(bigint_t w, const bigint_t u)
{
	mpz_t *i1, *i2 = u;
	int ret;

	if (w == NULL) {
		ret = wrap_nettle_mpi_init(&w);
		if (ret < 0)
			return NULL;
	}

	i1 = w;

	mpz_set(*i1, *i2);

	return i1;
}

static bigint_t wrap_nettle_mpi_set_ui(bigint_t w, unsigned long u)
{
	mpz_t *i1;
	int ret;

	if (w == NULL) {
		ret = wrap_nettle_mpi_init(&w);
		if (ret < 0)
			return NULL;
	}

	i1 = w;

	mpz_set_ui(*i1, u);

	return i1;
}

static unsigned int wrap_nettle_mpi_get_nbits(bigint_t a)
{
	return mpz_sizeinbase(TOMPZ(a), 2);
}

static void wrap_nettle_mpi_release(bigint_t a)
{
	mpz_clear(TOMPZ(a));
	gnutls_free(a);
}

static void wrap_nettle_mpi_clear(bigint_t a)
{
	memset(TOMPZ(a)[0]._mp_d, 0,
	       TOMPZ(a)[0]._mp_alloc * sizeof(mp_limb_t));
}

static bigint_t wrap_nettle_mpi_modm(bigint_t r, const bigint_t a, const bigint_t b)
{
int ret;

	if (r == NULL) {
		ret = wrap_nettle_mpi_init(&r);
		if (ret < 0)
			return NULL;
	}

	mpz_mod(TOMPZ(r), TOMPZ(a), TOMPZ(b));
	
	return r;
}

static bigint_t
wrap_nettle_mpi_powm(bigint_t w, const bigint_t b, const bigint_t e,
		     const bigint_t m)
{
int ret;

	if (w == NULL) {
		ret = wrap_nettle_mpi_init(&w);
		if (ret < 0)
			return NULL;
	}

	mpz_powm(TOMPZ(w), TOMPZ(b), TOMPZ(e), TOMPZ(m));

	return w;
}

static bigint_t
wrap_nettle_mpi_addm(bigint_t w, const bigint_t a, const bigint_t b,
		     const bigint_t m)
{
int ret;

	if (w == NULL) {
		ret = wrap_nettle_mpi_init(&w);
		if (ret < 0)
			return NULL;
	}

	mpz_add(TOMPZ(w), TOMPZ(b), TOMPZ(a));
	mpz_fdiv_r(TOMPZ(w), TOMPZ(w), TOMPZ(m));

	return w;
}

static bigint_t
wrap_nettle_mpi_subm(bigint_t w, const bigint_t a, const bigint_t b,
		     const bigint_t m)
{
int ret;

	if (w == NULL) {
		ret = wrap_nettle_mpi_init(&w);
		if (ret < 0)
			return NULL;
	}

	mpz_sub(TOMPZ(w), TOMPZ(a), TOMPZ(b));
	mpz_fdiv_r(TOMPZ(w), TOMPZ(w), TOMPZ(m));

	return w;
}

static bigint_t
wrap_nettle_mpi_mulm(bigint_t w, const bigint_t a, const bigint_t b,
		     const bigint_t m)
{
int ret;

	if (w == NULL) {
		ret = wrap_nettle_mpi_init(&w);
		if (ret < 0)
			return NULL;
	}

	mpz_mul(TOMPZ(w), TOMPZ(a), TOMPZ(b));
	mpz_fdiv_r(TOMPZ(w), TOMPZ(w), TOMPZ(m));

	return w;
}

static bigint_t
wrap_nettle_mpi_add(bigint_t w, const bigint_t a, const bigint_t b)
{
int ret;

	if (w == NULL) {
		ret = wrap_nettle_mpi_init(&w);
		if (ret < 0)
			return NULL;
	}

	mpz_add(TOMPZ(w), TOMPZ(a), TOMPZ(b));

	return w;
}

static bigint_t
wrap_nettle_mpi_sub(bigint_t w, const bigint_t a, const bigint_t b)
{
int ret;

	if (w == NULL) {
		ret = wrap_nettle_mpi_init(&w);
		if (ret < 0)
			return NULL;
	}

	mpz_sub(TOMPZ(w), TOMPZ(a), TOMPZ(b));

	return w;
}

static bigint_t
wrap_nettle_mpi_mul(bigint_t w, const bigint_t a, const bigint_t b)
{
int ret;

	if (w == NULL) {
		ret = wrap_nettle_mpi_init(&w);
		if (ret < 0)
			return NULL;
	}

	mpz_mul(TOMPZ(w), TOMPZ(a), TOMPZ(b));

	return w;
}

/* q = a / b */
static bigint_t
wrap_nettle_mpi_div(bigint_t q, const bigint_t a, const bigint_t b)
{
int ret;

	if (q == NULL) {
		ret = wrap_nettle_mpi_init(&q);
		if (ret < 0)
			return NULL;
	}

	mpz_cdiv_q(TOMPZ(q), TOMPZ(a), TOMPZ(b));

	return q;
}

static bigint_t
wrap_nettle_mpi_add_ui(bigint_t w, const bigint_t a, unsigned long b)
{
int ret;

	if (w == NULL) {
		ret = wrap_nettle_mpi_init(&w);
		if (ret < 0)
			return NULL;
	}

	mpz_add_ui(TOMPZ(w), TOMPZ(a), b);

	return w;
}

static bigint_t
wrap_nettle_mpi_sub_ui(bigint_t w, const bigint_t a, unsigned long b)
{
int ret;

	if (w == NULL) {
		ret = wrap_nettle_mpi_init(&w);
		if (ret < 0)
			return NULL;
	}

	mpz_sub_ui(TOMPZ(w), TOMPZ(a), b);

	return w;

}

static bigint_t
wrap_nettle_mpi_mul_ui(bigint_t w, const bigint_t a, unsigned long b)
{
int ret;

	if (w == NULL) {
		ret = wrap_nettle_mpi_init(&w);
		if (ret < 0)
			return NULL;
	}

	mpz_mul_ui(TOMPZ(w), TOMPZ(a), b);

	return w;

}

static int wrap_nettle_prime_check(bigint_t pp)
{
	int ret;

	ret = mpz_probab_prime_p(TOMPZ(pp), PRIME_CHECK_PARAM);
	if (ret > 0) {
		return 0;
	}

	return GNUTLS_E_INTERNAL_ERROR;	/* ignored */
}



int crypto_bigint_prio = INT_MAX;

gnutls_crypto_bigint_st _gnutls_mpi_ops = {
	.bigint_init = wrap_nettle_mpi_init,
	.bigint_init_multi = wrap_nettle_mpi_init_multi,
	.bigint_cmp = wrap_nettle_mpi_cmp,
	.bigint_cmp_ui = wrap_nettle_mpi_cmp_ui,
	.bigint_modm = wrap_nettle_mpi_modm,
	.bigint_set = wrap_nettle_mpi_set,
	.bigint_set_ui = wrap_nettle_mpi_set_ui,
	.bigint_get_nbits = wrap_nettle_mpi_get_nbits,
	.bigint_powm = wrap_nettle_mpi_powm,
	.bigint_addm = wrap_nettle_mpi_addm,
	.bigint_subm = wrap_nettle_mpi_subm,
	.bigint_add = wrap_nettle_mpi_add,
	.bigint_sub = wrap_nettle_mpi_sub,
	.bigint_add_ui = wrap_nettle_mpi_add_ui,
	.bigint_sub_ui = wrap_nettle_mpi_sub_ui,
	.bigint_mul = wrap_nettle_mpi_mul,
	.bigint_mulm = wrap_nettle_mpi_mulm,
	.bigint_mul_ui = wrap_nettle_mpi_mul_ui,
	.bigint_div = wrap_nettle_mpi_div,
	.bigint_prime_check = wrap_nettle_prime_check,
	.bigint_release = wrap_nettle_mpi_release,
	.bigint_clear = wrap_nettle_mpi_clear,
	.bigint_print = wrap_nettle_mpi_print,
	.bigint_scan = wrap_nettle_mpi_scan,
};
