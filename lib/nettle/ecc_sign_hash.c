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
#include <nettle/dsa.h>

/*
  @file ecc_sign_hash.c
  ECC Crypto, Tom St Denis
*/

/*
  Sign a message digest
  @param in        The message digest to sign
  @param inlen     The length of the digest
  @param sign      The destination for the signature
  @param prng      An active PRNG state
  @param wprng     The index of the PRNG you wish to use
  @param key       A private ECC key
  @param curve_id  The id of the curve we are working with
  @return 0 if successful
*/
int
ecc_sign_hash (const unsigned char *in, unsigned long inlen,
               struct dsa_signature *sig,
               void *random_ctx, nettle_random_func random,
               ecc_key * key, gnutls_ecc_curve_t curve_id)
{
  ecc_key pubkey;
  mpz_t e;
  int err;

  if (in == NULL || sig == NULL || key == NULL)
    return -1;

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
                            key->order, key->A, key->B, key->Gx, key->Gy, curve_id, 1)) != 0)
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
