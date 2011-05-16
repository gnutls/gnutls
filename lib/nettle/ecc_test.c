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
#include "gnettle.h"
#include <gnutls_int.h>
#include <gnutls_algorithms.h>

/**
  @file ecc_test.c
  ECC Crypto, Tom St Denis
*/  

#ifdef LTC_MECC

/**
  Perform on the ECC system
  @return 0 if successful
*/
int ecc_test(void)
{
   mpz_t     modulus, order;
   ecc_point  *G, *GG;
   int i, err;

   if ((err = mp_init_multi(&modulus, &order, NULL)) != 0) {
      return err;
   }

   G   = ltc_ecc_new_point();
   GG  = ltc_ecc_new_point();
   if (G == NULL || GG == NULL) {
      mp_clear_multi(&modulus,&order, NULL);
      ltc_ecc_del_point(G);
      ltc_ecc_del_point(GG);
      return -1;
   }

   for (i = 1; i<=2; i++) {
       const gnutls_ecc_curve_entry_st *st = _gnutls_ecc_curve_get_params (i);

       printf("Testing %s (%d)\n", _gnutls_ecc_curve_get_name(i), i);

       if (mpz_set_str(modulus, (char *)st->prime, 16) != 0) {
fprintf(stderr, "XXX %d\n", __LINE__);
          err = -1;
          goto done;
       }

       if (mpz_set_str(order, (char *)st->order, 16) != 0) {
fprintf(stderr, "XXX %d\n", __LINE__);
          err = -1;
          goto done;
       }

       /* is prime actually prime? */
       if ((err = mpz_probab_prime_p(modulus, PRIME_CHECK_PARAM)) <= 0) {
fprintf(stderr, "XXX %d\n", __LINE__);
          err = -1;
          goto done;
       }

       if ((err = mpz_probab_prime_p(order, PRIME_CHECK_PARAM)) <= 0) {
fprintf(stderr, "XXX %d\n", __LINE__);
          err = -1;
          goto done;
       }

       if (mpz_set_str(G->x, (char *)st->Gx, 16) != 0) {
fprintf(stderr, "XXX %d\n", __LINE__);
          err = -1;
          goto done;
       }

       if (mpz_set_str(G->y, (char *)st->Gy, 16) != 0) {
fprintf(stderr, "XXX %d\n", __LINE__);
          err = -1;
          goto done;
       }
       mpz_set_ui(G->z, 1);

       /* then we should have G == (order + 1)G */
       mpz_add_ui(order, order, 1);
       if ((err = ltc_ecc_mulmod(order, G, GG, modulus, 1)) != 0)                  { goto done; }
       
       if (mpz_cmp(G->y, GG->y) != 0) {
fprintf(stderr, "XXX %d\n", __LINE__);
          err = -1;
          goto done;
       }

       if (mpz_cmp(G->x, GG->x) != 0) {
fprintf(stderr, "XXX %d\n", __LINE__);
          err = -1;
          goto done;
       }

   }
   err = 0;
done:
   ltc_ecc_del_point(GG);
   ltc_ecc_del_point(G);
   mp_clear_multi(&order, &modulus, NULL);
   return err;
}

#endif

/* $Source: /cvs/libtom/libtomcrypt/src/pk/ecc/ecc_test.c,v $ */
/* $Revision: 1.12 $ */
/* $Date: 2007/05/12 14:32:35 $ */

