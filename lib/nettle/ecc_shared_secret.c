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
#include <string.h>

/**
  @file ecc_shared_secret.c
  ECC Crypto, Tom St Denis
*/  

#ifdef LTC_MECC

/**
  Create an ECC shared secret between two keys
  @param private_key      The private ECC key
  @param public_key       The public key
  @param out              [out] Destination of the shared secret (Conforms to EC-DH from ANSI X9.63)
  @param outlen           [in/out] The max size and resulting size of the shared secret
  @return 0 if successful
*/
int ecc_shared_secret(ecc_key *private_key, ecc_key *public_key,
                      unsigned char *out, unsigned long *outlen)
{
   unsigned long  x;
   ecc_point     *result;
   int            err;

   assert(private_key != NULL);
   assert(public_key  != NULL);
   assert(out         != NULL);
   assert(outlen      != NULL);

   /* type valid? */
   if (private_key->type != PK_PRIVATE) {
      return -1;
   }

   /* make new point */
   result = ltc_ecc_new_point();
   if (result == NULL) {
      return -1;
   }

   if ((err = ltc_ecc_mulmod(private_key->k, &public_key->pubkey, result, private_key->prime, 1)) != 0)                { goto done; }

   x = (unsigned long)mp_unsigned_bin_size(private_key->prime);
   if (*outlen < x) {
      *outlen = x;
      err = -1;
      goto done;
   }
   memset(out, 0, x);
   if ((err = mp_to_unsigned_bin(result->x, out + (x - mp_unsigned_bin_size(result->x))))   != 0)           { goto done; }

   err     = 0;
   *outlen = x;
done:
   ltc_ecc_del_point(result);
   return err;
}

#endif
/* $Source: /cvs/libtom/libtomcrypt/src/pk/ecc/ecc_shared_secret.c,v $ */
/* $Revision: 1.10 $ */
/* $Date: 2007/05/12 14:32:35 $ */

