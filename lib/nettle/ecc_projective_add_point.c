/*
 * Copyright (C) 2011 Free Software Foundation, Inc.
 *
 * This file is part of GNUTLS.
 *
 * The GNUTLS library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public License
 * as published by the Free Software Foundation; either version 3 of
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

/* Based on public domain code of LibTomCrypt by Tom St Denis.
 * Adapted to gmp and nettle by Nikos Mavrogiannopoulos.
 */

#include "ecc.h"

/*
  @file ecc_projective_add_point.c
  ECC Crypto, Tom St Denis
*/

/*
   Add two ECC points
   @param P        The point to add
   @param Q        The point to add
   @param R        [out] The destination of the double
   @param a        Curve's a value
   @param modulus  The modulus of the field the ECC curve is in
   @return 0 on success
*/
int
ecc_projective_add_point (ecc_point * P, ecc_point * Q, ecc_point * R,
                              mpz_t a, mpz_t modulus)
{
  mpz_t t1, t2, x, y, z;
  int err;

  if (P == NULL || Q == NULL || R == NULL || modulus == NULL)
    return -1;

  if ((err = mp_init_multi (&t1, &t2, &x, &y, &z, NULL)) != 0)
    {
      return err;
    }

  /* Check if P == Q and do doubling in that case 
   * If Q == -P then P+Q=point at infinity
   */
  if ((mpz_cmp (P->x, Q->x) == 0) &&
      (mpz_cmp (P->z, Q->z) == 0))
    {
      /* x and z coordinates match. Check if P->y = Q->y, or P->y = -Q->y
       */
      if (mpz_cmp (P->y, Q->y) == 0)
        {
          mp_clear_multi (&t1, &t2, &x, &y, &z, NULL);
          return ecc_projective_dbl_point (P, R, a, modulus);
        }
      
      mpz_sub (t1, modulus, Q->y);
      if (mpz_cmp (P->y, t1) == 0)
        {
          mp_clear_multi (&t1, &t2, &x, &y, &z, NULL);
          mpz_set_ui(R->x, 1);
          mpz_set_ui(R->y, 1);
          mpz_set_ui(R->z, 0);
          return 0;
        }
    }


  mpz_set (x, P->x);
  mpz_set (y, P->y);
  mpz_set (z, P->z);

  /* if Z is one then these are no-operations */
  if (mpz_cmp_ui (Q->z, 1) != 0)
    {
      /* T1 = Z' * Z' */
      mpz_mul (t1, Q->z, Q->z);
      mpz_mod (t1, t1, modulus);
      /* X = X * T1 */
      mpz_mul (x, x, t1);
      mpz_mod (x, x, modulus);
      /* T1 = Z' * T1 */
      mpz_mul (t1, t1, Q->z);
      mpz_mod (t1, t1, modulus);
      /* Y = Y * T1 */
      mpz_mul (y, y, t1);
      mpz_mod (y, y, modulus);
    }

  /* T1 = Z*Z */
  mpz_mul (t1, z, z);
  mpz_mod (t1, t1, modulus);
  /* T2 = X' * T1 */
  mpz_mul (t2, t1, Q->x);
  mpz_mod (t2, t2, modulus);
  /* T1 = Z * T1 */
  mpz_mul (t1, t1, z);
  mpz_mod (t1, t1, modulus);
  /* T1 = Y' * T1 */
  mpz_mul (t1, t1, Q->y);
  mpz_mod (t1, t1, modulus);

  /* Y = Y - T1 */
  mpz_sub (y, y, t1);
  if (mpz_cmp_ui (y, 0) < 0)
    {
      mpz_add (y, y, modulus);
    }
  /* T1 = 2T1 */
  mpz_add (t1, t1, t1);
  if (mpz_cmp (t1, modulus) >= 0)
    {
      mpz_sub (t1, t1, modulus);
    }
  /* T1 = Y + T1 */
  mpz_add (t1, t1, y);
  if (mpz_cmp (t1, modulus) >= 0)
    {
      mpz_sub (t1, t1, modulus);
    }
  /* X = X - T2 */
  mpz_sub (x, x, t2);
  if (mpz_cmp_ui (x, 0) < 0)
    {
      mpz_add (x, x, modulus);
    }
  /* T2 = 2T2 */
  mpz_add (t2, t2, t2);
  if (mpz_cmp (t2, modulus) >= 0)
    {
      mpz_sub (t2, t2, modulus);
    }
  /* T2 = X + T2 */
  mpz_add (t2, t2, x);
  if (mpz_cmp (t2, modulus) >= 0)
    {
      mpz_sub (t2, t2, modulus);
    }

  /* if Z' != 1 */
  if (mpz_cmp_ui (Q->z, 1) != 0)
    {
      /* Z = Z * Z' */
      mpz_mul (z, z, Q->z);
      mpz_mod (z, z, modulus);
    }

  /* Z = Z * X */
  mpz_mul (z, z, x);
  mpz_mod (z, z, modulus);

  /* T1 = T1 * X  */
  mpz_mul (t1, t1, x);
  mpz_mod (t1, t1, modulus);
  /* X = X * X */
  mpz_mul (x, x, x);
  mpz_mod (x, x, modulus);
  /* T2 = T2 * x */
  mpz_mul (t2, t2, x);
  mpz_mod (t2, t2, modulus);
  /* T1 = T1 * X  */
  mpz_mul (t1, t1, x);
  mpz_mod (t1, t1, modulus);

  /* X = Y*Y */
  mpz_mul (x, y, y);
  mpz_mod (x, x, modulus);
  /* X = X - T2 */
  mpz_sub (x, x, t2);
  if (mpz_cmp_ui (x, 0) < 0)
    {
      mpz_add (x, x, modulus);
    }

  /* T2 = T2 - X */
  mpz_sub (t2, t2, x);
  if (mpz_cmp_ui (t2, 0) < 0)
    {
      mpz_add (t2, t2, modulus);
    }
  /* T2 = T2 - X */
  mpz_sub (t2, t2, x);
  if (mpz_cmp_ui (t2, 0) < 0)
    {
      mpz_add (t2, t2, modulus);
    }
  /* T2 = T2 * Y */
  mpz_mul (t2, t2, y);
  mpz_mod (t2, t2, modulus);
  /* Y = T2 - T1 */
  mpz_sub (y, t2, t1);
  if (mpz_cmp_ui (y, 0) < 0)
    {
      mpz_add (y, y, modulus);
    }
  /* Y = Y/2 */
  if (mpz_odd_p (y))
    {
      mpz_add (y, y, modulus);
    }
  mpz_divexact_ui (y, y, 2);

  mpz_set (R->x, x);
  mpz_set (R->y, y);
  mpz_set (R->z, z);

  err = 0;

  mp_clear_multi (&t1, &t2, &x, &y, &z, NULL);
  return err;
}

/* $Source: /cvs/libtom/libtomcrypt/src/pk/ecc/ecc_projective_add_point.c,v $ */
/* $Revision: 1.16 $ */
/* $Date: 2007/05/12 14:32:35 $ */
