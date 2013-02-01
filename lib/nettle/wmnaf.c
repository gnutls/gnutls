/*
 * Copyright (C) 2011-2012 Free Software Foundation, Inc.
 *
 * Author: Ilya Tumaykin
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

#include <config.h>

#include <stdlib.h>
#include <stdio.h>
#include <gmp.h>

#include "ecc.h"

/* needed constants */
#define BASEW   (1 << WMNAF_WINSIZE)    /* 2^w */
#define BASEWW  (1 << (WMNAF_WINSIZE + 1))      /* 2^(w+1) */
#define WBITS   (BASEWW - 1)

#define ABS(x) ((x) >= 0 ? (x) : -(x))

/* GMP lacks this typedef in versions prior to 5 */
#if __GNU_MP__ < 5
typedef unsigned long int mp_bitcnt_t;
#endif

/*
 * A local replacement for mpz_tstbit.
 * It is needed because original mpz_tstbit process negative numbers
 * in a two-complement manner and we don't want it.
 * This function mimics mpz_tstbit behavior for positive numbers in both cases.
 */
static int
mpz_unitstbit (mpz_t u, mp_bitcnt_t bit_index)
  __GMP_NOTHROW
{
  mp_srcptr u_ptr = u->_mp_d;
  mp_size_t size = u->_mp_size;
  mp_size_t abs_size = ABS (size);
  mp_size_t limb_index = bit_index / GMP_NUMB_BITS;
  mp_srcptr p = u_ptr + limb_index;
  mp_limb_t limb;

  if (limb_index >= abs_size)
    return (size < 0);

  limb = *p;

  return (limb >> (bit_index % GMP_NUMB_BITS)) & 1;
}

/*
 * Return an array with wMNAF representation together with its length.
 * The result is the array with elements from the set {0, +-1, +-3, +-5, ..., +-(2^w - 1)}
 * such that at most one of any (w + 1) consecutive digits is non-zero
 * with exception for the the most significant (w + 1) bits.
 * With the last property it is modified version of wNAF.
 * Overview of this algorithm can be found, for exmaple, in
 * Bodo Moller, Improved Techniques for Fast Exponentiation.
 * Information Security and Cryptology – ICISC 2002, Springer-Verlag LNCS 2587, pp. 298–312
 */
/*
   @param x        The number to get wMNAF for
   @param len      [out] Destination for the length of wMNAF
   @return         array with wMNAF representation
   @return         NULL in case of errors
 */
signed char *
ecc_wMNAF (mpz_t x, size_t * wmnaf_len)
{
  int b, c;
  char sign = 1;
  size_t i, len;

  signed char *ret = NULL;

  if (!(sign = mpz_sgn (x)))
    {
      /* x == 0 */
      ret = malloc (1);
      if (ret == NULL)
        goto done;

      ret[0] = 0;
      *wmnaf_len = 1;
      goto done;
    }

  /* total number of bits */
  len = mpz_sizeinbase (x, 2);

  /* wMNAF is at most (len + 1) bits long */
  ret = malloc (len + 1);
  if (ret == NULL)
    goto done;

  /* get (w + 1) Least Significant Bits */
  c = (mpz_getlimbn (x, 0)) & WBITS;

  /* how many bits we've already processed */
  i = 0;

  while ((c != 0) || (i + WMNAF_WINSIZE + 1 < len))
    {
      if (c & 1)
        {
          /* LSB == 1 */
          if (c >= BASEW)
            {
              b = c - BASEWW;
            }
          else
            {
              b = c;
            }

          c -= b;
        }
      else
        {
          b = 0;
        }

      ret[i++] = sign * b;

      /* fill c with next LSB */
      c >>= 1;
      c += BASEW * mpz_unitstbit (x, i + WMNAF_WINSIZE);
    }

  *wmnaf_len = i--;

  /* do modified wNAF
   * check if wNAF starts with 1 and
   * (w + 1)th bit is negative */
  if ((ret[i] == 1) && (ret[i - (WMNAF_WINSIZE + 1)] < 0))
    {
      ret[i - (WMNAF_WINSIZE + 1)] += BASEW;
      ret[i - 1] = 1;
      *wmnaf_len = i;
    }
done:
  return ret;
}
