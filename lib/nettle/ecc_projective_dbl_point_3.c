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
  @file ecc_projective_dbl_point.c
  ECC Crypto, Tom St Denis
*/  

#ifdef ECC_SECP_CURVES_ONLY

/*
   Double an ECC point
   @param P   The point to double
   @param R   [out] The destination of the double
   @param modulus  The modulus of the field the ECC curve is in
   @param mp       The "b" value from montgomery_setup()
   @return 0 on success
*/
int
ecc_projective_dbl_point (ecc_point * P, ecc_point * R, mpz_t a /* a is -3 */,
                              mpz_t modulus)
{
   mpz_t t1, t2;
   int   err;

   if (P == NULL || R == NULL || modulus == NULL)
     return -1;

   if ((err = mp_init_multi(&t1, &t2, NULL)) != 0) {
      return err;
   }

   if (P != R) {
      mpz_set(R->x, P->x);
      mpz_set(R->y, P->y);
      mpz_set(R->z, P->z);
   }

   /* t1 = Z * Z */
   mpz_mul(t1, R->z, R->z);
   mpz_mod(t1, t1, modulus);
   /* Z = Y * Z */
   mpz_mul(R->z, R->y, R->z);
   mpz_mod(R->z, R->z, modulus);
   /* Z = 2Z */
   mpz_add(R->z, R->z, R->z);
   if (mpz_cmp(R->z, modulus) >= 0) {
      mpz_sub(R->z, R->z, modulus);
   }
   
   /* T2 = X - T1 */
   mpz_sub(t2, R->x, t1);
   if (mpz_cmp_ui(t2, 0) < 0) {
      mpz_add(t2, t2, modulus);
   }
   /* T1 = X + T1 */
   mpz_add(t1, t1, R->x);
   if (mpz_cmp(t1, modulus) >= 0) {
      mpz_sub(t1, t1, modulus);
   }
   /* T2 = T1 * T2 */
   mpz_mul(t2, t1, t2);
   mpz_mod(t2, t2, modulus);
   /* T1 = 2T2 */
   mpz_add(t1, t2, t2);
   if (mpz_cmp(t1, modulus) >= 0) {
      mpz_sub(t1, t1, modulus);
   }
   /* T1 = T1 + T2 */
   mpz_add(t1, t1, t2);
   if (mpz_cmp(t1, modulus) >= 0) {
      mpz_sub(t1, t1, modulus);
   }

   /* Y = 2Y */
   mpz_add(R->y, R->y, R->y);
   if (mpz_cmp(R->y, modulus) >= 0) {
      mpz_sub(R->y, R->y, modulus);
   }
   /* Y = Y * Y */
   mpz_mul(R->y, R->y, R->y);
   mpz_mod(R->y, R->y, modulus);
   /* T2 = Y * Y */
   mpz_mul(t2, R->y, R->y);
   mpz_mod(t2, t2, modulus);
   /* T2 = T2/2 */
   if (mpz_odd_p(t2)) {
      mpz_add(t2, t2, modulus);
   }
   mpz_divexact_ui(t2, t2, 2);
   /* Y = Y * X */
   mpz_mul(R->y, R->y, R->x);
   mpz_mod(R->y, R->y, modulus);

   /* X  = T1 * T1 */
   mpz_mul(R->x, t1, t1);
   mpz_mod(R->x, R->x, modulus);
   /* X = X - Y */
   mpz_sub(R->x, R->x, R->y);
   if (mpz_cmp_ui(R->x, 0) < 0) {
      mpz_add(R->x, R->x, modulus);
   }
   /* X = X - Y */
   mpz_sub(R->x, R->x, R->y);
   if (mpz_cmp_ui(R->x, 0) < 0) {
      mpz_add(R->x, R->x, modulus);
   }

   /* Y = Y - X */     
   mpz_sub(R->y, R->y, R->x);
   if (mpz_cmp_ui(R->y, 0) < 0) {
      mpz_add(R->y, R->y, modulus);
   }
   /* Y = Y * T1 */
   mpz_mul(R->y, R->y, t1);
   mpz_mod(R->y, R->y, modulus);
   /* Y = Y - T2 */
   mpz_sub(R->y, R->y, t2);
   if (mpz_cmp_ui(R->y, 0) < 0) {
      mpz_add( R->y, R->y, modulus);
   }
 
   err = 0;

   mp_clear_multi(&t1, &t2, NULL);
   return err;
}
#endif
/* $Source: /cvs/libtom/libtomcrypt/src/pk/ecc/ecc_projective_dbl_point.c,v $ */
/* $Revision: 1.11 $ */
/* $Date: 2007/05/12 14:32:35 $ */

