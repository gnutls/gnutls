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
  @file ltc_ecc_map.c
  ECC Crypto, Tom St Denis
*/  

#ifdef LTC_MECC

/**
  Map a projective jacbobian point back to affine space
  @param P        [in/out] The point to map
  @param modulus  The modulus of the field the ECC curve is in
  @param mp       The "b" value from montgomery_setup()
  @return 0 on success
*/
int ltc_ecc_map(ecc_point *P, mpz_t modulus)
{
   mpz_t t1, t2;
   int   err;

   assert(P       != NULL);

   if ((err = mp_init_multi(&t1, &t2, NULL)) != 0) {
      return -1;
   }

   mpz_mod(P->z, P->z, modulus);

   /* get 1/z */
   mpz_invert(t1, P->z, modulus);

   /* get 1/z^2 and 1/z^3 */
   mpz_mul(t2, t1, t1);
   mpz_mod(t2, t2, modulus);
   mpz_mul(t1, t1, t2);
   mpz_mod(t1, t1, modulus);

   /* multiply against x/y */
   mpz_mul(P->x, P->x, t2);
   mpz_mod(P->x, P->x, modulus);
   mpz_mul(P->y, P->y, t1);
   mpz_mod(P->y, P->y, modulus);
   mpz_set_ui(P->z, 1);

   err = 0;

   mp_clear_multi(&t1, &t2, NULL);
   return err;
}

#endif

/* $Source: /cvs/libtom/libtomcrypt/src/pk/ecc/ltc_ecc_map.c,v $ */
/* $Revision: 1.7 $ */
/* $Date: 2007/05/12 14:32:35 $ */

