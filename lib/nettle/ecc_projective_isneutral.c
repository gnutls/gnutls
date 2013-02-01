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

#include "ecc.h"

/*
   Check if the given point is the neutral point
   @param P        The point to check
   @param modulus  The modulus of the field the ECC curve is in
   @return         0 if given point is a neutral point
   @return         1 if given point is not a neutral point
   @return         negative value in case of error
*/
int
ecc_projective_isneutral (ecc_point * P, mpz_t modulus)
{
  mpz_t t1, t2;
  int err;

  if (P == NULL || modulus == NULL)
    return GNUTLS_E_RECEIVED_ILLEGAL_PARAMETER;

  /*
   * neutral point is a point with projective
   * coordinates (x,y,0) such that y^2 == x^3
   * excluding point (0,0,0)
   */
  if (mpz_sgn (P->z))
    /* Z != 0 */
    return 1;

  if ((err = mp_init_multi (&t1, &t2, NULL)) != 0)
    {
      return err;
    }

  /* t1 == x^3 */
  mpz_mul (t1, P->x, P->x);
  mpz_mod (t1, t1, modulus);
  mpz_mul (t1, t1, P->x);
  mpz_mod (t1, t1, modulus);
  /* t2 == y^2 */
  mpz_mul (t2, P->y, P->y);
  mpz_mod (t2, t2, modulus);

  if ((!mpz_cmp (t1, t2)) && (mpz_sgn (t1)))
    {
      /* Z == 0 and X^3 == Y^2 != 0
       * it is neutral */
      err = 0;
      goto done;
    }

  /* Z == 0 and X^3 != Y^2 or
   * Z == X == Y == 0
   * this should never happen */
  err = GNUTLS_E_RECEIVED_ILLEGAL_PARAMETER;
  goto done;
done:
  mp_clear_multi (&t1, &t2, NULL);
  return err;
}
