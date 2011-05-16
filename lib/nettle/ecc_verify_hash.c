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
  @file ecc_verify_hash.c
  ECC Crypto, Tom St Denis
*/  

#ifdef LTC_MECC

/* verify 
 *
 * w  = s^-1 mod n
 * u1 = xw 
 * u2 = rw
 * X = u1*G + u2*Q
 * v = X_x1 mod n
 * accept if v == r
 */

/**
   Verify an ECC signature
   @param signature         The signature to verify
   @param hash        The hash (message digest) that was signed
   @param hashlen     The length of the hash (octets)
   @param stat        Result of signature, 1==valid, 0==invalid
   @param key         The corresponding public ECC key
   @return 0 if successful (even if the signature is not valid)
*/
int ecc_verify_hash(struct dsa_signature * signature,
                    const unsigned char *hash, unsigned long hashlen, 
                    int *stat, ecc_key *key)
{
   ecc_point    *mG, *mQ;
   mpz_t         v, w, u1, u2, e;
   int           err;

   assert(signature  != NULL);
   assert(hash       != NULL);
   assert(stat       != NULL);
   assert(key        != NULL);

   /* default to invalid signature */
   *stat = 0;

   /* allocate ints */
   if ((err = mp_init_multi(&v, &w, &u1, &u2, &e, NULL)) != 0) {
      return -1;
   }

   /* allocate points */
   mG = ltc_ecc_new_point();
   mQ = ltc_ecc_new_point();
   if (mQ  == NULL || mG == NULL) {
      err = -1;
      goto error;
   }

   /* check for zero */
   if (mpz_cmp_ui(signature->r,0) == 0 || mpz_cmp_ui(signature->s,0) == 0 || 
       mpz_cmp(signature->r, key->order) >= 0 || mpz_cmp(signature->s, key->order) >= 0) {
      err = -1;
      goto error;
   }

   /* read hash */
   if ((err = mp_read_unsigned_bin(e, (unsigned char *)hash, (int)hashlen)) != 0)                { goto error; }

   /*  w  = s^-1 mod n */
   mpz_invert(w, signature->s, key->order);

   /* u1 = ew */
   mpz_mul(u1, e, w);
   mpz_mod(u1, u1, key->order);

   /* u2 = rw */
   mpz_mul(u2, signature->r, w);
   mpz_mod(u2, u2, key->order);

   /* find mG and mQ */
   mpz_set(mG->x, key->Gx);
   mpz_set(mG->y, key->Gy);
   mpz_set_ui(mG->z, 1);

   mpz_set(mQ->x, key->pubkey.x);
   mpz_set(mQ->y, key->pubkey.y);
   mpz_set(mQ->z, key->pubkey.z);

   /* compute u1*mG + u2*mQ = mG */
   if ((err = ltc_ecc_mulmod(u1, mG, mG, key->prime, 0)) != 0)                                       { goto error; }
   if ((err = ltc_ecc_mulmod(u2, mQ, mQ, key->prime, 0)) != 0)                                       { goto error; }
  
   /* add them */
   if ((err = ltc_ecc_projective_add_point(mQ, mG, mG, key->prime)) != 0)                                      { goto error; }

   /* reduce */
   if ((err = ltc_ecc_map(mG, key->prime)) != 0)                                                { goto error; }

   /* v = X_x1 mod n */
   mpz_mod(v, mG->x, key->order);

   /* does v == r */
   if (mpz_cmp(v, signature->r) == 0) {
      *stat = 1;
   }

   /* clear up and return */
   err = 0;
error:
   ltc_ecc_del_point(mG);
   ltc_ecc_del_point(mQ);
   mp_clear_multi(&v, &w, &u1, &u2, &e, NULL);
   return err;
}

#endif
/* $Source: /cvs/libtom/libtomcrypt/src/pk/ecc/ecc_verify_hash.c,v $ */
/* $Revision: 1.14 $ */
/* $Date: 2007/05/12 14:32:35 $ */

