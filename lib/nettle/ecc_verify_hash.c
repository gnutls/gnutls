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

/*
  @file ecc_verify_hash.c
  ECC Crypto, Tom St Denis
*/

/* verify 
 *
 * w  = s^-1 mod n
 * u1 = xw 
 * u2 = rw
 * X = u1*G + u2*Q
 * v = X_x1 mod n
 * accept if v == r
 */

/*
   Verify an ECC signature
   @param signature         The signature to verify
   @param hash        The hash (message digest) that was signed
   @param hashlen     The length of the hash (octets)
   @param stat        Result of signature, 1==valid, 0==invalid
   @param key         The corresponding public ECC key
   @param curve_id    The id of the curve we are working with
   @return 0 if successful (even if the signature is not valid)
*/
int
ecc_verify_hash (struct dsa_signature *signature,
                 const unsigned char *hash, unsigned long hashlen,
                 int *stat, ecc_key * key, gnutls_ecc_curve_t curve_id)
{
  ecc_point *mG, *mQ;
  mpz_t v, w, u1, u2, e;
  int err;

  if (signature == NULL || hash == NULL || stat == NULL || key == NULL)
    return -1;

  /* default to invalid signature */
  *stat = 0;

  /* allocate ints */
  if ((err = mp_init_multi (&v, &w, &u1, &u2, &e, NULL)) != 0)
    {
      return -1;
    }

  /* allocate points */
  mG = ecc_new_point ();
  mQ = ecc_new_point ();
  if (mQ == NULL || mG == NULL)
    {
      err = -1;
      goto error;
    }

  /* check for (0) */
  if (mpz_cmp_ui (signature->r, 0) == 0 || mpz_cmp_ui (signature->s, 0) == 0
      || mpz_cmp (signature->r, key->order) >= 0
      || mpz_cmp (signature->s, key->order) >= 0)
    {
      err = -1;
      goto error;
    }

  /* read hash */
  nettle_mpz_set_str_256_u (e, hashlen, hash);

  /*  w  = s^-1 mod n */
  mpz_invert (w, signature->s, key->order);

  /* u1 = ew */
  mpz_mul (u1, e, w);
  mpz_mod (u1, u1, key->order);

  /* u2 = rw */
  mpz_mul (u2, signature->r, w);
  mpz_mod (u2, u2, key->order);

  /* find mG and mQ */
  mpz_set (mG->x, key->Gx);
  mpz_set (mG->y, key->Gy);
  mpz_set_ui (mG->z, 1);

  mpz_set (mQ->x, key->pubkey.x);
  mpz_set (mQ->y, key->pubkey.y);
  mpz_set (mQ->z, key->pubkey.z);

  /* compute u1*mG + u2*mQ = mG */
  if ((err = ecc_mulmod_cached (u1, curve_id, mG, key->A, key->prime, 0)) != 0)
    {
      goto error;
    }
  if ((err = ecc_mulmod (u2, mQ, mQ, key->A, key->prime, 0)) != 0)
    {
      goto error;
    }

  /* add them */
  if ((err =
       ecc_projective_add_point (mQ, mG, mG, key->A, key->prime)) != 0)
    {
      goto error;
    }

  /* reduce */
  if ((err = ecc_map (mG, key->prime)) != 0)
    {
      goto error;
    }

  /* v = X_x1 mod n */
  mpz_mod (v, mG->x, key->order);

  /* does v == r */
  if (mpz_cmp (v, signature->r) == 0)
    {
      *stat = 1;
    }

  /* clear up and return */
  err = 0;
error:
  ecc_del_point (mG);
  ecc_del_point (mQ);
  mp_clear_multi (&v, &w, &u1, &u2, &e, NULL);
  return err;
}

/* $Source: /cvs/libtom/libtomcrypt/src/pk/ecc/ecc_verify_hash.c,v $ */
/* $Revision: 1.14 $ */
/* $Date: 2007/05/12 14:32:35 $ */
