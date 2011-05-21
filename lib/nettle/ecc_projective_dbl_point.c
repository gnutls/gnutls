/*
 * Copyright (C) 2011 Free Software Foundation, Inc.
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

/* Implements ECC point doubling over Z/pZ for curve y^2 = x^3 + ax + b
 */
#include "ecc.h"

#ifndef ECC_SECP_CURVES_ONLY

/**
   Double an ECC point
   @param P   The point to double
   @param R   [out] The destination of the double
   @param a       The "a" value from curve
   @param modulus  The modulus of the field the ECC curve is in
   @return 0 on success
*/
int
ltc_ecc_projective_dbl_point (ecc_point * P, ecc_point * R, mpz_t a,
                              mpz_t modulus)
{
  mpz_t t1, m, s;
  int err;

  assert (P != NULL);
  assert (R != NULL);
  assert (modulus != NULL);

  /*
    algorithm used:
     if (Y == 0)
       return POINT_AT_INFINITY
     S = 4*X*Y^2
     M = 3*X^2 + a*Z^4
     X' = M^2 - 2*S
     Y' = M*(S - X') - 8*Y^4
     Z' = 2*Y*Z
     return (X', Y', Z')
   */

  if (mpz_cmp_ui(P->y, 0) == 0)
    {
      /* point at infinity 
       * under jacobian coordinates
       */
      mpz_set(R->x, 1);
      mpz_set(R->y, 1);
      mpz_set(R->z, 0);
      
      return 0;
    }

  if ((err = mp_init_multi (&t1, &m, &s, NULL)) != 0)
    {
      return err;
    }

  if (P != R)
    {
      mpz_set (R->x, P->x);
      mpz_set (R->y, P->y);
      mpz_set (R->z, P->z);
    }


  /* m = Z * Z */
  mpz_mul (m, R->z, R->z);
  mpz_mod (m, m, modulus);

  /* Calculate Z and get rid of it */
  /* Z = Y * Z */
  mpz_mul (R->z, R->y, R->z);
  mpz_mod (R->z, R->z, modulus);
  /* Z = 2Z */
  mpz_add (R->z, R->z, R->z);
  if (mpz_cmp (R->z, modulus) >= 0)
    {
      mpz_sub (R->z, R->z, modulus);
    }

  /* continue with M and S calculations */

  /* m = m * m = z^4 */
  mpz_mul (m, m, m);
  mpz_mod (m, m, modulus);

  /* m = a * m = a*z^4 */
  mpz_mul (m, a, m);
  mpz_mod (m, m, modulus);

  /* Y = 2y */
  mpz_add (R->y, R->y, R->y);
  if (mpz_cmp (R->y, modulus) >= 0)
    {
      mpz_sub (R->y, R->y, modulus);
    }

  /* Y = Y * Y = 4y^2 */
  mpz_mul (R->y, R->y, R->y);
  mpz_mod (R->y, R->y, modulus);

  /* s = X*Y = 4xy^2 */
  mpz_mul (s, R->x, R->y);
  mpz_mod (s, s, modulus);

  /* X = x^2 */
  mpz_mul (R->x, R->x, R->x);
  mpz_mod (R->x, R->x, modulus);

  /* t1 = 2X = 2x^2 */
  mpz_add (t1, R->x, R->x);
  if (mpz_cmp (t1, modulus) >= 0)
    {
      mpz_sub (t1, t1, modulus);
    }

  /* t1 = t1+X = 3X =  3x^2 */
  mpz_add (t1, t1, R->x);
  if (mpz_cmp (t1, modulus) >= 0)
    {
      mpz_sub (t1, t1, modulus);
    }

  /* m = t1+m = 3x^2 + a*z^4 */
  mpz_add (m, m, t1);
  if (mpz_cmp (m, modulus) >= 0)
    {
      mpz_sub (m, m, modulus);
    }

  /*
     X' = M^2 - 2*S
     Y' = M*(S - X') - 8*Y^4
   */

  /* Y = Y*Y = 16y^4 */
  mpz_mul (R->y, R->y, R->y);
  mpz_mod (R->y, R->y, modulus);

  /* Y = 8y^4 */
  if (mp_isodd (R->y))
    {
      mpz_add (R->y, R->y, modulus);
    }
  mpz_divexact_ui (R->y, R->y, 2);

  /* X = m^2 */
  mpz_mul (R->x, m, m);
  mpz_mod (R->x, R->x, modulus);

  /* X = X - s = m^2 - s */
  mpz_sub (R->x, R->x, s);
  if (mpz_cmp_ui (R->x, 0) < 0)
    {
      mpz_add (R->x, R->x, modulus);
    }

  /* X = X - s = m^2 - 2s */
  mpz_sub (R->x, R->x, s);
  if (mpz_cmp_ui (R->x, 0) < 0)
    {
      mpz_add (R->x, R->x, modulus);
    }

  /* t1 = s - X */
  mpz_sub (t1, s, R->x);
  if (mpz_cmp_ui (t1, 0) < 0)
    {
      mpz_add (t1, t1, modulus);
    }

  /* t1 = M * t1 = M * (s-X) */
  mpz_mul (t1, m, t1);
  mpz_mod (t1, t1, modulus);

  /* Y = t1 - Y = (M * (s-X)) - 8y^4 */
  mpz_sub (R->y, t1, R->y);
  if (mpz_cmp_ui (R->y, 0) < 0)
    {
      mpz_add (R->y, R->y, modulus);
    }

  err = 0;

  mp_clear_multi (&t1, &m, &s, NULL);
  return err;
}

#endif
