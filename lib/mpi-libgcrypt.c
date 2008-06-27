/*
 * Copyright (C) 2001, 2002, 2003, 2004, 2005, 2008 Free Software Foundation
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
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301,
 * USA
 *
 */

/* Here lie everything that has to do with large numbers, libgcrypt and
 * other stuff that didn't fit anywhere else.
 */

#include <gnutls_int.h>
#include <libtasn1.h>
#include <gnutls_errors.h>
#include <gnutls_num.h>
#include <gnutls_mpi.h>
#include <gcrypt.h>

/* Functions that refer to the libgcrypt library.
 */

static inline int _format_conv( gnutls_bigint_format_t format)
{
    if (format == GNUTLS_MPI_FORMAT_USG) return GCRYMPI_FMT_USG;
    else if (format == GNUTLS_MPI_FORMAT_STD) return GCRYMPI_FMT_STD;
    else return GCRYMPI_FMT_PGP;
}

/* returns zero on success
 */
bigint_t
wrap_gcry_mpi_scan (const void * buffer, size_t nbytes, gnutls_bigint_format_t format)
{
  gcry_mpi_t ret_mpi = NULL;
  int ret;

  ret = gcry_mpi_scan (&ret_mpi, _format_conv(format), buffer, nbytes, NULL);
  if (ret != 0)
    return NULL;

  return ret_mpi;
}

int
wrap_gcry_mpi_print (const bigint_t a, void *buffer, size_t * nbytes, gnutls_bigint_format_t format)
{
  int ret;

  format = _format_conv(format);
    
  if (nbytes == NULL || a == NULL)
    return GNUTLS_E_INVALID_REQUEST;

  ret = gcry_mpi_print( format, buffer, *nbytes, nbytes, a);
  if (!ret)
    return 0;

  return GNUTLS_E_MPI_PRINT_FAILED;
}

#undef _gnutls_mpi_alloc_like
#define _gnutls_mpi_alloc_like(x) gcry_mpi_new(gcry_mpi_get_nbits(x))

bigint_t wrap_gcry_mpi_mod( const bigint_t a, const bigint_t b)
{
  bigint_t r = _gnutls_mpi_alloc_like (b);
  
  if (r == NULL)
    return NULL;
  
  gcry_mpi_mod( r, a, b);

  return r;
}

bigint_t wrap_gcry_mpi_powm( bigint_t w, const bigint_t b, const bigint_t e, const bigint_t m)
{
  if (w == NULL)
    w = _gnutls_mpi_alloc_like (m);
  
  if (w == NULL)
    return NULL;
  
  gcry_mpi_powm( w, b, e, m);

  return w;
}

bigint_t wrap_gcry_mpi_addm( bigint_t w, const bigint_t a, const bigint_t b, const bigint_t m)
{
  if (w == NULL)
    w = _gnutls_mpi_alloc_like (m);
  
  if (w == NULL)
    return NULL;
  
  gcry_mpi_addm( w, a, b, m);

  return w;
}

bigint_t wrap_gcry_mpi_subm( bigint_t w, const bigint_t a, const bigint_t b, const bigint_t m)
{
  if (w == NULL)
    w = _gnutls_mpi_alloc_like (m);
  
  if (w == NULL)
    return NULL;
  
  gcry_mpi_subm( w, a, b, m);

  return w;
}

bigint_t wrap_gcry_mpi_mulm( bigint_t w, const bigint_t a, const bigint_t b, const bigint_t m)
{
  if (w == NULL)
    w = _gnutls_mpi_alloc_like (m);
  
  if (w == NULL)
    return NULL;
  
  gcry_mpi_mulm( w, a, b, m);

  return w;
}

bigint_t wrap_gcry_mpi_add( bigint_t w, const bigint_t a, const bigint_t b)
{
  if (w == NULL)
    w = _gnutls_mpi_alloc_like (b);
  
  if (w == NULL)
    return NULL;
  
  gcry_mpi_add( w, a, b);

  return w;
}

bigint_t wrap_gcry_mpi_sub( bigint_t w, const bigint_t a, const bigint_t b)
{
  if (w == NULL)
    w = _gnutls_mpi_alloc_like (b);
  
  if (w == NULL)
    return NULL;
  
  gcry_mpi_sub( w, a, b);

  return w;
}

bigint_t wrap_gcry_mpi_mul( bigint_t w, const bigint_t a, const bigint_t b)
{
  if (w == NULL)
    w = _gnutls_mpi_alloc_like (b);
  
  if (w == NULL)
    return NULL;
  
  gcry_mpi_mul( w, a, b);

  return w;
}

/* q = a / b */
bigint_t wrap_gcry_mpi_div( bigint_t q, const bigint_t a, const bigint_t b)
{
  if (q == NULL)
    q = _gnutls_mpi_alloc_like (a);
  
  if (q == NULL)
    return NULL;
  
  gcry_mpi_div( q, NULL, a, b, 0);

  return q;
}

bigint_t wrap_gcry_mpi_add_ui( bigint_t w, const bigint_t a, unsigned long b)
{
  if (w == NULL)
    w = _gnutls_mpi_alloc_like (a);
  
  if (w == NULL)
    return NULL;
  
  gcry_mpi_add_ui( w, a, b);

  return w;
}

bigint_t wrap_gcry_mpi_sub_ui( bigint_t w, const bigint_t a, unsigned long b)
{
  if (w == NULL)
    w = _gnutls_mpi_alloc_like (a);
  
  if (w == NULL)
    return NULL;
  
  gcry_mpi_sub_ui( w, a, b);

  return w;
}

bigint_t wrap_gcry_mpi_mul_ui( bigint_t w, const bigint_t a, unsigned long b)
{
  if (w == NULL)
    w = _gnutls_mpi_alloc_like (a);
  
  if (w == NULL)
    return NULL;
  
  gcry_mpi_mul_ui( w, a, b);

  return w;
}

int wrap_gcry_prime_check( bigint_t pp)
{
  return gcry_prime_check( pp, 0);
}

int wrap_gcry_generate_group( gnutls_group_st *group, unsigned int bits)
{
  bigint_t g = NULL, prime = NULL;
  gcry_error_t err;
  int result, times = 0, qbits;
  gcry_mpi_t *factors = NULL;

  /* Calculate the size of a prime factor of (prime-1)/2.
   * This is an emulation of the values in "Selecting Cryptographic Key Sizes" paper.
   */
  if (bits < 256)
    qbits = bits / 2;
  else
    {
      qbits = (bits/40) + 105;
    }

  if (qbits & 1)		/* better have an even number */
    qbits++;

  /* find a prime number of size bits.
   */
  do
    {

      if (times)
	{
	  _gnutls_mpi_release (&prime);
	  gcry_prime_release_factors (factors);
	}

      err = gcry_prime_generate ((gcry_mpi_t*)&prime, bits, qbits,
				 &factors, NULL, NULL, GCRY_STRONG_RANDOM,
				 GCRY_PRIME_FLAG_SPECIAL_FACTOR);

      if (err != 0)
	{
	  gnutls_assert ();
	  result = GNUTLS_E_INTERNAL_ERROR;
	  goto cleanup;
	}

      err = gcry_prime_check (prime, 0);

      times++;
    }
  while (err != 0 && times < 10);

  if (err != 0)
    {
      gnutls_assert ();
      result = GNUTLS_E_INTERNAL_ERROR;
      goto cleanup;
    }

  /* generate the group generator.
   */
  err = gcry_prime_group_generator ((gcry_mpi_t*)&g, prime, factors, NULL);
  if (err != 0)
    {
      gnutls_assert ();
      result = GNUTLS_E_INTERNAL_ERROR;
      goto cleanup;
    }

  gcry_prime_release_factors (factors);
  factors = NULL;

  group->g = g;
  group->p = prime;

  return 0;

cleanup:
  gcry_prime_release_factors (factors);
  _gnutls_mpi_release (&g);
  _gnutls_mpi_release (&prime);

  return result;

}

int crypto_bigint_prio = INT_MAX;

gnutls_crypto_bigint_st _gnutls_mpi_ops = {
  .bigint_new = gcry_mpi_new,
  .bigint_cmp = gcry_mpi_cmp,
  .bigint_cmp_ui = gcry_mpi_cmp_ui,  
  .bigint_mod = wrap_gcry_mpi_mod,
  .bigint_set = gcry_mpi_set,
  .bigint_set_ui = gcry_mpi_set_ui,
  .bigint_get_nbits = gcry_mpi_get_nbits,
  .bigint_powm = wrap_gcry_mpi_powm,
  .bigint_addm = wrap_gcry_mpi_addm,
  .bigint_subm = wrap_gcry_mpi_subm,
  .bigint_add = wrap_gcry_mpi_add,
  .bigint_sub = wrap_gcry_mpi_sub,
  .bigint_add_ui = wrap_gcry_mpi_add_ui,
  .bigint_sub_ui = wrap_gcry_mpi_sub_ui,
  .bigint_mul = wrap_gcry_mpi_mul,
  .bigint_mulm = wrap_gcry_mpi_mulm,
  .bigint_mul_ui = wrap_gcry_mpi_mul_ui,
  .bigint_div = wrap_gcry_mpi_div,
  .bigint_prime_check = wrap_gcry_prime_check,
  .bigint_release = gcry_mpi_release,
  .bigint_print = wrap_gcry_mpi_print,
  .bigint_scan = wrap_gcry_mpi_scan,
  .bigint_generate_group = wrap_gcry_generate_group
};
