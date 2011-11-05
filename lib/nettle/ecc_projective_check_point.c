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

#include "ecc.h"
#include <gnutls_errors.h>

#ifdef ECC_SECP_CURVES_ONLY

/*
  @file ecc_projective_check_point.c
*/

/*
   Checks whether a point lies on the curve y^2 = x^3 - 3x + b
   @param P   The point to check
   @param modulus  The modulus of the field the ECC curve is in
   @param b       The "B" value of the curve
   @return 0 on success
*/
int ecc_projective_check_point (ecc_point * P, mpz_t b, mpz_t modulus)
{
    mpz_t t1, t2, t3;
    int err;

    if (P == NULL || b == NULL || modulus == NULL)
	return -1;

    if ((err = mp_init_multi (&t1, &t2, &t3, NULL)) != 0)
      {
	  return err;
      }

    if (mpz_cmp_ui (P->z, 1) != 0)
      {
	  gnutls_assert ();
	  return -1;
      }

    /* t1 = Z * Z */
    mpz_mul (t1, P->y, P->y);
    mpz_mod (t1, t1, modulus);	/* t1 = y^2 */

    mpz_mul (t2, P->x, P->x);
    mpz_mod (t2, t2, modulus);

    mpz_mul (t2, P->x, t2);
    mpz_mod (t2, t2, modulus);	/* t2 = x^3 */

    mpz_add (t3, P->x, P->x);
    if (mpz_cmp (t3, modulus) >= 0)
      {
	  mpz_sub (t3, t3, modulus);
      }

    mpz_add (t3, t3, P->x);	/* t3 = 3x */
    if (mpz_cmp (t3, modulus) >= 0)
      {
	  mpz_sub (t3, t3, modulus);
      }

    mpz_sub (t1, t1, t2);	/* t1 = y^2 - x^3 */
    if (mpz_cmp_ui (t1, 0) < 0)
      {
	  mpz_add (t1, t1, modulus);
      }

    mpz_add (t1, t1, t3);	/* t1 = y^2 - x^3 + 3x */
    if (mpz_cmp (t1, modulus) >= 0)
      {
	  mpz_sub (t1, t1, modulus);
      }

    mpz_sub (t1, t1, b);	/* t1 = y^2 - x^3 + 3x - b */
    if (mpz_cmp_ui (t1, 0) < 0)
      {
	  mpz_add (t1, t1, modulus);
      }

    if (mpz_cmp_ui (t1, 0) != 0)
      {
	  return -1;
      }
    else
      {
	  return 0;
      }
}

#endif
