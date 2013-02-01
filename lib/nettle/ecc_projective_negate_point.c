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
   Negate an ECC point
   @param P        The point to negate
   @param R        [out] The destination of the negate
   @param modulus  The modulus of the field the ECC curve is in
   @return         GNUTLS_E_SUCCESS on success
*/
int
ecc_projective_negate_point (ecc_point * P, ecc_point * R, mpz_t modulus)
{

  if (P == NULL || R == NULL)
    return GNUTLS_E_RECEIVED_ILLEGAL_PARAMETER;

  if (ecc_projective_isneutral (P, modulus))
    {
      /* we set R.y to (modulus - P.y) to avoid negative coordinates */
      mpz_set (R->x, P->x);
      mpz_sub (R->y, modulus, P->y);
      mpz_mod (R->y, R->y, modulus);
      mpz_set (R->z, P->z);
    }
  else
    {
      /* -neutral = neutral */
      mpz_set_ui (R->x, 1);
      mpz_set_ui (R->y, 1);
      mpz_set_ui (R->z, 0);
    }

  return GNUTLS_E_SUCCESS;
}
