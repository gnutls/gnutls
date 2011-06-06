/*
 * Copyright (C) 2011 Free Software Foundation, Inc.
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

/* Based on public domain code of LibTomCrypt by Tom St Denis.
 * Adapted to gmp and nettle by Nikos Mavrogiannopoulos.
 */

#include "ecc.h"

/**
  @file ecc_mulmod_timing.c
  ECC Crypto, Tom St Denis
*/

/**
   Perform a point multiplication  (timing resistant)
   @param k    The scalar to multiply by
   @param G    The base point
   @param R    [out] Destination for kG
   @param a        The a value of the curve
   @param modulus  The modulus of the field the ECC curve is in
   @param map      Boolean whether to map back to affine or not (1==map, 0 == leave in projective)
   @return 0 on success
*/
int
ecc_mulmod (mpz_t k, ecc_point * G, ecc_point * R, mpz_t a, mpz_t modulus,
                int map)
{
  ecc_point *tG, *M[3];
  int i, j, err;
  unsigned long buf;
  int bitcnt, mode, digidx;

  assert (k != NULL);
  assert (G != NULL);
  assert (R != NULL);
  assert (modulus != NULL);

  /* alloc ram for window temps */
  for (i = 0; i < 3; i++)
    {
      M[i] = ecc_new_point ();
      if (M[i] == NULL)
        {
          for (j = 0; j < i; j++)
            {
              ecc_del_point (M[j]);
            }
          return -1;
        }
    }

  /* make a copy of G incase R==G */
  tG = ecc_new_point ();
  if (tG == NULL)
    {
      err = -1;
      goto done;
    }

  /* tG = G  and convert to montgomery */
  mpz_set (tG->x, G->x);
  mpz_set (tG->y, G->y);
  mpz_set (tG->z, G->z);

  /* calc the M tab */
  /* M[0] == G */
  mpz_set (M[0]->x, tG->x);
  mpz_set (M[0]->y, tG->y);
  mpz_set (M[0]->z, tG->z);
  /* M[1] == 2G */
  if ((err = ecc_projective_dbl_point (tG, M[1], a, modulus)) != 0)
    {
      goto done;
    }

  /* setup sliding window */
  mode = 0;
  bitcnt = 1;
  buf = 0;
  digidx = mpz_size (k) - 1;

  /* perform ops */
  for (;;)
    {
      /* grab next digit as required */
      if (--bitcnt == 0)
        {
          if (digidx == -1)
            {
              break;
            }
          buf = mpz_getlimbn (k, digidx);
          bitcnt = (int) MP_DIGIT_BIT;
          --digidx;
        }

      /* grab the next msb from the ltiplicand */
      i = (buf >> (MP_DIGIT_BIT - 1)) & 1;
      buf <<= 1;

      if (mode == 0 && i == 0)
        {
          /* dummy operations */
          if ((err =
               ecc_projective_add_point (M[0], M[1], M[2], a,
                                             modulus)) != 0)
            {
              goto done;
            }
          if ((err =
               ecc_projective_dbl_point (M[1], M[2], a, modulus)) != 0)
            {
              goto done;
            }
          continue;
        }

      if (mode == 0 && i == 1)
        {
          mode = 1;
          /* dummy operations */
          if ((err =
               ecc_projective_add_point (M[0], M[1], M[2], a,
                                             modulus)) != 0)
            {
              goto done;
            }
          if ((err =
               ecc_projective_dbl_point (M[1], M[2], a, modulus)) != 0)
            {
              goto done;
            }
          continue;
        }

      if ((err =
           ecc_projective_add_point (M[0], M[1], M[i ^ 1], a,
                                         modulus)) != 0)
        {
          goto done;
        }
      if ((err = ecc_projective_dbl_point (M[i], M[i], a, modulus)) != 0)
        {
          goto done;
        }
    }

  /* copy result out */
  mpz_set (R->x, M[0]->x);
  mpz_set (R->y, M[0]->y);
  mpz_set (R->z, M[0]->z);

  /* map R back from projective space */
  if (map)
    {
      err = ecc_map (R, modulus);
    }
  else
    {
      err = 0;
    }
done:
  ecc_del_point (tG);
  for (i = 0; i < 3; i++)
    {
      ecc_del_point (M[i]);
    }
  return err;
}

/* $Source: /cvs/libtom/libtomcrypt/src/pk/ecc/ecc_mulmod_timing.c,v $ */
/* $Revision: 1.13 $ */
/* $Date: 2007/05/12 14:32:35 $ */
