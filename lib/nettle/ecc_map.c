/*
 * Copyright (C) 2011-2012 Free Software Foundation, Inc.
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

/* Based on public domain code of LibTomCrypt by Tom St Denis.
 * Adapted to gmp and nettle by Nikos Mavrogiannopoulos.
 */

#include "ecc.h"

/*
  @file ecc_map.c
  ECC Crypto, Tom St Denis
*/

/*
  Map a projective jacobian point back to affine space
  @param P        [in/out] The point to map
  @param modulus  The modulus of the field the ECC curve is in
  @param mp       The "b" value from montgomery_setup()
  @return 0 on success
*/
int
ecc_map (ecc_point * P, mpz_t modulus)
{
  mpz_t t1, t2;
  int err;

  if (P == NULL)
    return -1;

  if ((err = mp_init_multi (&t1, &t2, NULL)) != 0)
    {
      return -1;
    }

  mpz_mod (P->z, P->z, modulus);

  /* get 1/z */
  mpz_invert (t1, P->z, modulus);

  /* get 1/z^2 and 1/z^3 */
  mpz_mul (t2, t1, t1);
  mpz_mod (t2, t2, modulus);
  mpz_mul (t1, t1, t2);
  mpz_mod (t1, t1, modulus);

  /* multiply against x/y */
  mpz_mul (P->x, P->x, t2);
  mpz_mod (P->x, P->x, modulus);
  mpz_mul (P->y, P->y, t1);
  mpz_mod (P->y, P->y, modulus);
  mpz_set_ui (P->z, 1);

  err = 0;

  mp_clear_multi (&t1, &t2, NULL);
  return err;
}

/* $Source: /cvs/libtom/libtomcrypt/src/pk/ecc/ecc_map.c,v $ */
/* $Revision: 1.7 $ */
/* $Date: 2007/05/12 14:32:35 $ */
