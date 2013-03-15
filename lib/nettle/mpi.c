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
wrap_nettle_mpi_print (const bigint_t a, void *buffer, size_t * nbytes,
                       gnutls_bigint_format_t format)
{
  unsigned int size;
  mpz_t *p = (void *) a;

  if (format == GNUTLS_MPI_FORMAT_USG)
    {
      size = nettle_mpz_sizeinbase_256_u (*p);
    }
  else if (format == GNUTLS_MPI_FORMAT_STD)
    {
      size = nettle_mpz_sizeinbase_256_s (*p);
    }
  else if (format == GNUTLS_MPI_FORMAT_PGP)
    {
      size = nettle_mpz_sizeinbase_256_u (*p) + 2;
    }
  else
    {
      gnutls_assert ();
      return GNUTLS_E_INVALID_REQUEST;
    }

  if (buffer == NULL || size > *nbytes)
    {
      *nbytes = size;
      return GNUTLS_E_SHORT_MEMORY_BUFFER;
    }

  if (format == GNUTLS_MPI_FORMAT_PGP)
    {
      uint8_t *buf = buffer;
      unsigned int nbits = _gnutls_mpi_get_nbits (a);
      buf[0] = (nbits >> 8) & 0xff;
      buf[1] = (nbits) & 0xff;
      nettle_mpz_get_str_256 (size - 2, buf + 2, *p);
    }
  else
    {
      nettle_mpz_get_str_256 (size, buffer, *p);
    }
  *nbytes = size;

  return 0;
}

static bigint_t
wrap_nettle_mpi_new (int nbits)
{
  mpz_t *p;

  p = gnutls_malloc (sizeof (*p));
  if (p == NULL)
    {
      gnutls_assert ();
      return NULL;
    }
  if (nbits == 0)
  	mpz_init(*p);
  else
  	mpz_init2 (*p, nbits);

  return p;
}

static bigint_t
wrap_nettle_mpi_scan (const void *buffer, size_t nbytes,
                      gnutls_bigint_format_t format)
{
  bigint_t r = wrap_nettle_mpi_new (nbytes * 8);

  if (r == NULL)
    {
      gnutls_assert ();
      return r;
    }

  if (format == GNUTLS_MPI_FORMAT_USG)
    {
      nettle_mpz_set_str_256_u (TOMPZ (r), nbytes, buffer);
    }
  else if (format == GNUTLS_MPI_FORMAT_STD)
    {
      nettle_mpz_set_str_256_s (TOMPZ (r), nbytes, buffer);
    }
  else if (format == GNUTLS_MPI_FORMAT_PGP)
    {
      const uint8_t *buf = buffer;
      size_t size;

      if (nbytes < 3)
        {
          gnutls_assert ();
          goto fail;
        }

      size = (buf[0] << 8) | buf[1];
      size = (size + 7) / 8;

      if (size > nbytes - 2)
        {
          gnutls_assert ();
          goto fail;
        }
      nettle_mpz_set_str_256_u (TOMPZ (r), size, buf + 2);
    }
  else
    {
      gnutls_assert ();
      goto fail;
    }

  return r;
fail:
  _gnutls_mpi_release (&r);
  return NULL;

}

static int
wrap_nettle_mpi_cmp (const bigint_t u, const bigint_t v)
{
  mpz_t *i1 = u, *i2 = v;

  return mpz_cmp (*i1, *i2);
}

static int
wrap_nettle_mpi_cmp_ui (const bigint_t u, unsigned long v)
{
  mpz_t *i1 = u;

  return mpz_cmp_ui (*i1, v);
}

static bigint_t
wrap_nettle_mpi_set (bigint_t w, const bigint_t u)
{
  mpz_t *i1, *i2 = u;

  if (w == NULL)
    w = _gnutls_mpi_alloc_like (u);
  i1 = w;

  mpz_set (*i1, *i2);

  return i1;
}

static bigint_t
wrap_nettle_mpi_set_ui (bigint_t w, unsigned long u)
{
  mpz_t *i1;

  if (w == NULL)
    w = wrap_nettle_mpi_new (32);

  i1 = w;

  mpz_set_ui (*i1, u);

  return i1;
}

static unsigned int
wrap_nettle_mpi_get_nbits (bigint_t a)
{
  return mpz_sizeinbase (TOMPZ( a), 2);
}

static void
wrap_nettle_mpi_release (bigint_t a)
{
  mpz_clear (TOMPZ( a));
  gnutls_free (a);
}

static void
wrap_nettle_mpi_clear (bigint_t a)
{
  memset(TOMPZ(a)[0]._mp_d, 0, TOMPZ(a)[0]._mp_alloc*sizeof(mp_limb_t));
}

static bigint_t
wrap_nettle_mpi_mod (const bigint_t a, const bigint_t b)
{
  bigint_t r = wrap_nettle_mpi_new (wrap_nettle_mpi_get_nbits (b));

  if (r == NULL)
    return NULL;

  mpz_mod (TOMPZ( r), TOMPZ( a), TOMPZ( b));

  return r;
}

static bigint_t
wrap_nettle_mpi_powm (bigint_t w, const bigint_t b, const bigint_t e,
                      const bigint_t m)
{
  if (w == NULL)
    w = wrap_nettle_mpi_new (wrap_nettle_mpi_get_nbits (m));

  if (w == NULL)
    return NULL;

  mpz_powm (TOMPZ( w), TOMPZ( b), TOMPZ( e), TOMPZ( m));

  return w;
}

static bigint_t
wrap_nettle_mpi_addm (bigint_t w, const bigint_t a, const bigint_t b,
                      const bigint_t m)
{
  if (w == NULL)
    w = wrap_nettle_mpi_new (wrap_nettle_mpi_get_nbits (a));

  if (w == NULL)
    return NULL;

  mpz_add (TOMPZ( w), TOMPZ( b), TOMPZ( a));
  mpz_fdiv_r (TOMPZ( w), TOMPZ( w), TOMPZ( m));

  return w;
}

static bigint_t
wrap_nettle_mpi_subm (bigint_t w, const bigint_t a, const bigint_t b,
                      const bigint_t m)
{
  if (w == NULL)
    w = wrap_nettle_mpi_new (wrap_nettle_mpi_get_nbits (a));

  if (w == NULL)
    return NULL;

  mpz_sub (TOMPZ( w), TOMPZ( a), TOMPZ( b));
  mpz_fdiv_r (TOMPZ( w), TOMPZ( w), TOMPZ( m));

  return w;
}

static bigint_t
wrap_nettle_mpi_mulm (bigint_t w, const bigint_t a, const bigint_t b,
                      const bigint_t m)
{
  if (w == NULL)
    w = wrap_nettle_mpi_new (wrap_nettle_mpi_get_nbits (m));

  if (w == NULL)
    return NULL;

  mpz_mul (TOMPZ( w), TOMPZ( a), TOMPZ( b));
  mpz_fdiv_r (TOMPZ( w), TOMPZ( w), TOMPZ( m));

  return w;
}

static bigint_t
wrap_nettle_mpi_add (bigint_t w, const bigint_t a, const bigint_t b)
{
  if (w == NULL)
    w = wrap_nettle_mpi_new (wrap_nettle_mpi_get_nbits (b));

  if (w == NULL)
    return NULL;

  mpz_add (TOMPZ( w), TOMPZ( a), TOMPZ( b));

  return w;
}

static bigint_t
wrap_nettle_mpi_sub (bigint_t w, const bigint_t a, const bigint_t b)
{
  if (w == NULL)
    w = wrap_nettle_mpi_new (wrap_nettle_mpi_get_nbits (a));

  if (w == NULL)
    return NULL;

  mpz_sub (TOMPZ( w), TOMPZ( a), TOMPZ( b));

  return w;
}

static bigint_t
wrap_nettle_mpi_mul (bigint_t w, const bigint_t a, const bigint_t b)
{
  if (w == NULL)
    w = wrap_nettle_mpi_new (wrap_nettle_mpi_get_nbits (a));

  if (w == NULL)
    return NULL;

  mpz_mul (TOMPZ( w), TOMPZ( a), TOMPZ( b));

  return w;
}

/* q = a / b */
static bigint_t
wrap_nettle_mpi_div (bigint_t q, const bigint_t a, const bigint_t b)
{
  if (q == NULL)
    q = wrap_nettle_mpi_new (wrap_nettle_mpi_get_nbits (a));

  if (q == NULL)
    return NULL;

  mpz_cdiv_q (TOMPZ( q), TOMPZ( a), TOMPZ( b));

  return q;
}

static bigint_t
wrap_nettle_mpi_add_ui (bigint_t w, const bigint_t a, unsigned long b)
{
  if (w == NULL)
    w = wrap_nettle_mpi_new (wrap_nettle_mpi_get_nbits (a));

  if (w == NULL)
    return NULL;

  mpz_add_ui (TOMPZ( w), TOMPZ( a), b);

  return w;
}

static bigint_t
wrap_nettle_mpi_sub_ui (bigint_t w, const bigint_t a, unsigned long b)
{
  if (w == NULL)
    w = wrap_nettle_mpi_new (wrap_nettle_mpi_get_nbits (a));

  if (w == NULL)
    return NULL;

  mpz_sub_ui (TOMPZ( w), TOMPZ( a), b);

  return w;

}

static bigint_t
wrap_nettle_mpi_mul_ui (bigint_t w, const bigint_t a, unsigned long b)
{
  if (w == NULL)
    w = wrap_nettle_mpi_new (wrap_nettle_mpi_get_nbits (a));

  if (w == NULL)
    return NULL;

  mpz_mul_ui (TOMPZ( w), TOMPZ( a), b);

  return w;

}

static int
wrap_nettle_prime_check (bigint_t pp)
{
  int ret;
  ret = mpz_probab_prime_p (TOMPZ( pp), PRIME_CHECK_PARAM);

  if (ret > 0)
    {
      return 0;
    }

  return GNUTLS_E_INTERNAL_ERROR;       /* ignored */
}


/* generate a prime of the form p=2qw+1
 * The algorithm is simple but probably it has to be modified to gcrypt's
 * since it is slow. Nature did not want 2qw+1 to be prime.
 * The generator will be the generator of a subgroup of order q-1.
 *
 * Algorithm based on the algorithm in "A Computational Introduction to Number 
 * Theory and Algebra" by V. Shoup, sec 11.1 Finding a generator for Z^{*}_p
 *
 */
inline static int
gen_group (mpz_t * prime, mpz_t * generator, unsigned int nbits, unsigned int *q_bits)
{
  mpz_t q, w, r;
  unsigned int p_bytes = nbits / 8;
  uint8_t *buffer = NULL;
  unsigned int q_bytes, w_bytes, r_bytes, w_bits;
  int ret;

  /* security level enforcement. 
   * Values for q are selected according to ECRYPT II recommendations.
   */
  q_bytes = _gnutls_pk_bits_to_subgroup_bits (nbits);
  q_bytes /= 8;

  if (q_bytes == 0 || q_bytes >= p_bytes)
    {
      gnutls_assert ();
      return GNUTLS_E_INVALID_REQUEST;
    }

  if (nbits % 8 != 0)
    p_bytes++;

  w_bits = nbits - q_bytes * 8;
  w_bytes = w_bits / 8;
  if (w_bits % 8 != 0)
    w_bytes++;

  _gnutls_debug_log
    ("Generating group of prime of %u bits and format of 2wq+1. q_size=%u bits\n",
     nbits, q_bytes * 8);
  buffer = gnutls_malloc (p_bytes);     /* p_bytes > q_bytes */
  if (buffer == NULL)
    {
      gnutls_assert ();
      return GNUTLS_E_MEMORY_ERROR;
    }

  mpz_init (q);
  mpz_init (w);
  mpz_init (r);

  /* search for a prime. We are not that unlucky so search
   * forever.
   */
  for (;;)
    {
      ret = _gnutls_rnd (GNUTLS_RND_RANDOM, buffer, w_bytes);
      if (ret < 0)
        {
          gnutls_assert ();
          goto fail;
        }

      nettle_mpz_set_str_256_u (w, w_bytes, buffer);
      /* always odd */
      mpz_setbit (w, 0);

      ret = mpz_probab_prime_p (w, PRIME_CHECK_PARAM);
      if (ret > 0)
        {
          break;
        }
    }

  /* now generate q of size p_bytes - w_bytes */

  _gnutls_debug_log
    ("Found prime w of %u bits. Will look for q of %u bits...\n",
     wrap_nettle_mpi_get_nbits (&w), q_bytes*8);

  for (;;)
    {
      ret = _gnutls_rnd (GNUTLS_RND_RANDOM, buffer, q_bytes);
      if (ret < 0)
        {
          gnutls_assert ();
          return ret;
        }

      nettle_mpz_set_str_256_u (q, q_bytes, buffer);
      /* always odd */
      mpz_setbit (q, 0);

      ret = mpz_probab_prime_p (q, PRIME_CHECK_PARAM);
      if (ret == 0)
        {
          continue;
        }

      /* check if 2wq+1 is prime */
      mpz_mul_ui (*prime, w, 2);
      mpz_mul (*prime, *prime, q);
      mpz_add_ui (*prime, *prime, 1);

      ret = mpz_probab_prime_p (*prime, PRIME_CHECK_PARAM);
      if (ret > 0)
        {
          break;
        }
    }

  *q_bits = wrap_nettle_mpi_get_nbits (&q);
  _gnutls_debug_log ("Found prime q of %u bits. Looking for generator...\n",
                     *q_bits);

  /* finally a prime! Let's calculate generator
   */

  /* c = r^((p-1)/q), r == random
   * c = r^(2w)
   * if c!=1 c is the generator for the subgroup of order q-1
   * 
   */
  r_bytes = p_bytes;

  mpz_mul_ui (w, w, 2);         /* w = w*2 */
  mpz_fdiv_r (w, w, *prime);
  
  for (;;)
    {
      ret = _gnutls_rnd (GNUTLS_RND_NONCE, buffer, r_bytes);
      if (ret < 0)
        {
          gnutls_assert ();
          return ret;
        }

      nettle_mpz_set_str_256_u (r, r_bytes, buffer);
      mpz_fdiv_r (r, r, *prime);

      /* check if r^w mod n != 1 mod n */
      mpz_powm (*generator, r, w, *prime);

      if (mpz_cmp_ui (*generator, 1) == 0)
        continue;
      else
        break;
    }

  _gnutls_debug_log ("Found generator g of %u bits\n",
                     wrap_nettle_mpi_get_nbits (generator));
  _gnutls_debug_log ("Prime n is %u bits\n",
                     wrap_nettle_mpi_get_nbits (prime));

  ret = 0;
  goto exit;

fail:
  mpz_clear (*prime);
  mpz_clear (*generator);

exit:
  mpz_clear (q);
  mpz_clear (w);
  mpz_clear (r);
  gnutls_free (buffer);

  return ret;
}

static int
wrap_nettle_generate_group (gnutls_group_st * group, unsigned int bits)
{
  int ret;
  bigint_t p = wrap_nettle_mpi_new (bits);
  bigint_t g;
  unsigned int q_bits;

  if (p == NULL)
    {
      gnutls_assert ();
      return GNUTLS_E_MEMORY_ERROR;
    }

  g = wrap_nettle_mpi_new (bits);
  if (g == NULL)
    {
      gnutls_assert ();
      _gnutls_mpi_release (&p);
      return GNUTLS_E_MEMORY_ERROR;
    }

  ret = gen_group (p, g, bits, &q_bits);
  if (ret < 0)
    {
      _gnutls_mpi_release (&g);
      _gnutls_mpi_release (&p);
      gnutls_assert ();
      return ret;
    }

  group->p = p;
  group->g = g;
  group->q_bits = q_bits;

  return 0;
}


int crypto_bigint_prio = INT_MAX;

gnutls_crypto_bigint_st _gnutls_mpi_ops = {
  .bigint_new = wrap_nettle_mpi_new,
  .bigint_cmp = wrap_nettle_mpi_cmp,
  .bigint_cmp_ui = wrap_nettle_mpi_cmp_ui,
  .bigint_mod = wrap_nettle_mpi_mod,
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
  .bigint_generate_group = wrap_nettle_generate_group
};
