/* LibTomCrypt, modular cryptographic library -- Tom St Denis
 *
 * LibTomCrypt is a library that provides various cryptographic
 * algorithms in a highly modular and flexible manner.
 *
 * The library is free for all purposes without any express
 * guarantee it works.
 *
 * Tom St Denis, tomstdenis@gmail.com, http://libtom.org
 */

/* Implements ECC over Z/pZ for curve y^2 = x^3 - 3x + b
 *
 * All curves taken from NIST recommendation paper of July 1999
 * Available at http://csrc.nist.gov/cryptval/dss.htm
 */
#include "ecc.h"

/**
  @file ltc_ecc_mulmod_timing.c
  ECC Crypto, Tom St Denis
*/  

#ifdef LTC_MECC

/**
   Perform a point multiplication  (timing resistant)
   @param k    The scalar to multiply by
   @param G    The base point
   @param R    [out] Destination for kG
   @param modulus  The modulus of the field the ECC curve is in
   @param map      Boolean whether to map back to affine or not (1==map, 0 == leave in projective)
   @return 0 on success
*/
int ltc_ecc_mulmod(mpz_t k, ecc_point *G, ecc_point *R, mpz_t modulus, int map)
{
   ecc_point *tG, *M[3];
   int        i, j, err;
   unsigned long buf;
   int        first, bitbuf, bitcpy, bitcnt, mode, digidx;

   assert(k       != NULL);
   assert(G       != NULL);
   assert(R       != NULL);
   assert(modulus != NULL);

  /* alloc ram for window temps */
  for (i = 0; i < 3; i++) {
      M[i] = ltc_ecc_new_point();
      if (M[i] == NULL) {
         for (j = 0; j < i; j++) {
             ltc_ecc_del_point(M[j]);
         }
         return -1;
      }
  }

   /* make a copy of G incase R==G */
   tG = ltc_ecc_new_point();
   if (tG == NULL)                                                                   { err = -1; goto done; }

   /* tG = G  and convert to montgomery */
   mpz_set(tG->x, G->x);
   mpz_set(tG->y, G->y);
   mpz_set(tG->z, G->z);
   
   /* calc the M tab */
   /* M[0] == G */
   mpz_set(M[0]->x, tG->x);
   mpz_set(M[0]->y, tG->y);
   mpz_set(M[0]->z, tG->z);
   /* M[1] == 2G */
   if ((err = ltc_ecc_projective_dbl_point(tG, M[1], modulus)) != 0)                  { goto done; }

   /* setup sliding window */
   mode   = 0;
   bitcnt = 1;
   buf    = 0;
   digidx = mpz_size(k) - 1;
   bitcpy = bitbuf = 0;
   first  = 1;

   /* perform ops */
   for (;;) {
     /* grab next digit as required */
      if (--bitcnt == 0) {
         if (digidx == -1) {
            break;
         }
         buf    = mpz_getlimbn(k, digidx);
         bitcnt = (int) MP_DIGIT_BIT;
         --digidx;
      }

      /* grab the next msb from the ltiplicand */
      i = (buf >> (MP_DIGIT_BIT - 1)) & 1;
      buf <<= 1;

      if (mode == 0 && i == 0) {
         /* dummy operations */
         if ((err = ltc_ecc_projective_add_point(M[0], M[1], M[2], modulus)) != 0)    { goto done; }
         if ((err = ltc_ecc_projective_dbl_point(M[1], M[2], modulus)) != 0)          { goto done; }
         continue;
      }

      if (mode == 0 && i == 1) {
         mode = 1;
         /* dummy operations */
         if ((err = ltc_ecc_projective_add_point(M[0], M[1], M[2], modulus)) != 0)    { goto done; }
         if ((err = ltc_ecc_projective_dbl_point(M[1], M[2], modulus)) != 0)          { goto done; }
         continue;
      }

      if ((err = ltc_ecc_projective_add_point(M[0], M[1], M[i^1], modulus)) != 0)     { goto done; }
      if ((err = ltc_ecc_projective_dbl_point(M[i], M[i], modulus)) != 0)             { goto done; }
   }

   /* copy result out */
   mpz_set(R->x, M[0]->x);
   mpz_set(R->y, M[0]->y);
   mpz_set(R->z, M[0]->z);

   /* map R back from projective space */
   if (map) {
      err = ltc_ecc_map(R, modulus);
   } else {
      err = 0;
   }
done:
   ltc_ecc_del_point(tG);
   for (i = 0; i < 3; i++) {
       ltc_ecc_del_point(M[i]);
   }
   return err;
}

#endif
/* $Source: /cvs/libtom/libtomcrypt/src/pk/ecc/ltc_ecc_mulmod_timing.c,v $ */
/* $Revision: 1.13 $ */
/* $Date: 2007/05/12 14:32:35 $ */

