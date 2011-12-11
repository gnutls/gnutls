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

/* size of sliding window, don't change this! */
#define WINSIZE 4

/**
   Perform a point multiplication 
   @param k    The scalar to multiply by
   @param G    The base point
   @param R    [out] Destination for kG
   @param modulus  The modulus of the field the ECC curve is in
   @param map      Boolean whether to map back to affine or not (1==map, 0 == leave in projective)
   @return CRYPT_OK on success
*/
int
ecc_mulmod (mpz_t k, ecc_point * G, ecc_point * R, mpz_t a, mpz_t modulus,
                int map)

{
   ecc_point *tG, *M[8];
   int        i, j, err, bitidx;
   int        first, bitbuf, bitcpy, mode;

   if (k == NULL || G == NULL || R == NULL || modulus == NULL)
     return -1;

  /* alloc ram for window temps */
  for (i = 0; i < 8; i++) {
      M[i] = ecc_new_point();
      if (M[i] == NULL) {
         for (j = 0; j < i; j++) {
             ecc_del_point(M[j]);
         }

         return -1;
      }
  }

   /* make a copy of G incase R==G */
   tG = ecc_new_point();
   if (tG == NULL)
     { 
       err = -1;
       goto done; 
     }

   /* tG = G  and convert to montgomery */
   mpz_set (tG->x, G->x);
   mpz_set (tG->y, G->y);
   mpz_set (tG->z, G->z);

   /* calc the M tab, which holds kG for k==8..15 */
   /* M[0] == 8G */
   if ((err = ecc_projective_dbl_point (tG, M[0], a, modulus)) != 0)
     goto done;

   if ((err = ecc_projective_dbl_point (M[0], M[0], a, modulus)) != 0)
     goto done;

   if ((err = ecc_projective_dbl_point (M[0], M[0], a, modulus)) != 0)
     goto done;
 
   /* now find (8+k)G for k=1..7 */
   for (j = 9; j < 16; j++) {
     if (ecc_projective_add_point(M[j-9], tG, M[j-8], a, modulus) != 0)
       goto done;
   }

   /* setup sliding window */
   mode   = 0;
   bitidx = mpz_size (k) * GMP_NUMB_BITS - 1;
   bitcpy = bitbuf = 0;
   first  = 1;

   /* perform ops */
   for (;;) {
     /* grab next digit as required */
     if (bitidx == -1) {
       break;
     }

     /* grab the next msb from the ltiplicand */
     i = mpz_tstbit (k, bitidx--);

     /* skip leading zero bits */
     if (mode == 0 && i == 0) {
        continue;
     }

     /* if the bit is zero and mode == 1 then we double */
     if (mode == 1 && i == 0) {
        if ((err = ecc_projective_dbl_point(R, R, a, modulus)) != 0)
          goto done;
        continue;
     }

     /* else we add it to the window */
     bitbuf |= (i << (WINSIZE - ++bitcpy));
     mode = 2;

     if (bitcpy == WINSIZE) {
       /* if this is the first window we do a simple copy */
       if (first == 1) {
          /* R = kG [k = first window] */
          mpz_set(R->x, M[bitbuf-8]->x);
          mpz_set(R->y, M[bitbuf-8]->y);
          mpz_set(R->z, M[bitbuf-8]->z);
          first = 0;
       } else {
         /* normal window */
         /* ok window is filled so double as required and add  */
         /* double first */
         for (j = 0; j < WINSIZE; j++) {
           if ((err = ecc_projective_dbl_point(R, R, a, modulus)) != 0)
             goto done;
         }

         /* then add, bitbuf will be 8..15 [8..2^WINSIZE] guaranteed */
         if ((err = ecc_projective_add_point(R, M[bitbuf-8], R, a, modulus)) != 0)
           goto done;
       }
       /* empty window and reset */
       bitcpy = bitbuf = 0;
       mode = 1;
    }
  }

   /* if bits remain then double/add */
   if (mode == 2 && bitcpy > 0) {
     /* double then add */
     for (j = 0; j < bitcpy; j++) {
       /* only double if we have had at least one add first */
       if (first == 0) {
          if ((err = ecc_projective_dbl_point(R, R, a, modulus)) != 0)
            goto done;
       }

       bitbuf <<= 1;
       if ((bitbuf & (1 << WINSIZE)) != 0) {
         if (first == 1){
            /* first add, so copy */
            mpz_set(R->x, tG->x);
            mpz_set(R->y, tG->y);
            mpz_set(R->z, tG->z);
            first = 0;
         } else {
            /* then add */
            if ((err = ecc_projective_add_point(R, tG, R, a, modulus)) != 0)
              goto done;
         }
       }
     }
   }

   /* map R back from projective space */
   if (map) {
      err = ecc_map(R, modulus);
   } else {
      err = 0;
   }
done:
   ecc_del_point(tG);
   for (i = 0; i < 8; i++) {
       ecc_del_point(M[i]);
   }
   return err;
}

