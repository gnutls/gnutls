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

/* Implements ECC over Z/pZ for curve y^2 = x^3 + ax + b
 *
 * All curves taken from NIST recommendation paper of July 1999
 * Available at http://csrc.nist.gov/cryptval/dss.htm
 */
#include "ecc.h"
#include <nettle/dsa.h>

/**
  @file ecc_sign_hash.c
  ECC Crypto, Tom St Denis
*/

/**
  Sign a message digest
  @param in        The message digest to sign
  @param inlen     The length of the digest
  @param sign      The destination for the signature
  @param prng      An active PRNG state
  @param wprng     The index of the PRNG you wish to use
  @param key       A private ECC key
  @return 0 if successful
*/
int
ecc_sign_hash (const unsigned char *in, unsigned long inlen,
               struct dsa_signature *sig,
               void *random_ctx, nettle_random_func random, ecc_key * key)
{
  ecc_key pubkey;
  mpz_t e;
  int err;

  assert (in != NULL);
  assert (sig != NULL);
  assert (key != NULL);

  /* is this a private key? */
  if (key->type != PK_PRIVATE)
    {
      return -1;
    }

  /* get the hash and load it as a bignum into 'e' */
  /* init the bignums */
  if ((err = mp_init_multi (&e, NULL)) != 0)
    {
      return err;
    }

  nettle_mpz_set_str_256_u (e, inlen, in);

  /* make up a key and export the public copy */
  for (;;)
    {
      if ((err =
           ecc_make_key_ex (random_ctx, random, &pubkey, key->prime,
                            key->order, key->A, key->Gx, key->Gy)) != 0)
        {
          goto errnokey;
        }

      /* find r = x1 mod n */
      mpz_mod (sig->r, pubkey.pubkey.x, pubkey.order);

      if (mpz_cmp_ui (sig->r, 0) == 0)
        {
          ecc_free (&pubkey);
        }
      else
        {
          /* find s = (e + xr)/k */
          mpz_invert (pubkey.k, pubkey.k, pubkey.order);

          /* mulmod */
          mpz_mul (sig->s, key->k, sig->r);
          mpz_mod (sig->s, sig->s, pubkey.order);
          mpz_add (sig->s, e, sig->s);
          mpz_mod (sig->s, sig->s, pubkey.order);

          mpz_mul (sig->s, sig->s, pubkey.k);
          mpz_mod (sig->s, sig->s, pubkey.order);
          ecc_free (&pubkey);
          if (mpz_cmp_ui (sig->s, 0) != 0)
            {
              break;
            }
        }
    }

errnokey:
  mp_clear_multi (&e, NULL);
  return err;
}

/* $Source: /cvs/libtom/libtomcrypt/src/pk/ecc/ecc_sign_hash.c,v $ */
/* $Revision: 1.11 $ */
/* $Date: 2007/05/12 14:32:35 $ */
