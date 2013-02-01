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
  @file ecc_make_key.c
  ECC Crypto, Tom St Denis
*/

/*
  Make a new ECC key 
  @param prng         An active PRNG state
  @param wprng        The index of the PRNG you wish to use
  @param prime        The prime of curve's field
  @param order        The order of the G point
  @param A            The "a" parameter of the curve
  @param Gx           The x coordinate of the base point
  @param Gy           The y coordinate of the base point
  @param curve_id     The id of the curve we are working with
  @timing_res         If non zero the function will try to return in constant time.
  @return 0 if successful, upon error all allocated memory will be freed
*/

int
ecc_make_key_ex (void *random_ctx, nettle_random_func random, ecc_key * key,
                 mpz_t prime, mpz_t order, mpz_t A, mpz_t B, mpz_t Gx, mpz_t Gy,
                 gnutls_ecc_curve_t curve_id, int timing_res)
{
  int err;
  ecc_point *base;
  unsigned char *buf;
  int keysize;

  if (key == NULL || random == NULL)
    return -1;

  keysize = nettle_mpz_sizeinbase_256_u (order);

  /* allocate ram */
  base = NULL;
  buf = malloc (keysize);
  if (buf == NULL)
    return -1;

  /* make up random string */
  random (random_ctx, keysize, buf);

  /* setup the key variables */
  if ((err =
       mp_init_multi (&key->pubkey.x, &key->pubkey.y, &key->pubkey.z, &key->k,
                      &key->prime, &key->order, &key->A, &key->B, &key->Gx, &key->Gy,
                      NULL)) != 0)
    {
      goto ERR_BUF;
    }
  base = ecc_new_point ();
  if (base == NULL)
    {
      err = -1;
      goto errkey;
    }

  /* read in the specs for this key */
  mpz_set (key->prime, prime);
  mpz_set (key->order, order);
  mpz_set (key->Gx, Gx);
  mpz_set (key->Gy, Gy);
  mpz_set (key->A, A);
  mpz_set (key->B, B);

  mpz_set (base->x, key->Gx);
  mpz_set (base->y, key->Gy);
  mpz_set_ui (base->z, 1);

  nettle_mpz_set_str_256_u (key->k, keysize, buf);

  /* the key should be smaller than the order of base point */
  if (mpz_cmp (key->k, key->order) >= 0)
    {
      mpz_mod (key->k, key->k, key->order);
    }
  /* make the public key */
  if (timing_res)
    err = ecc_mulmod_cached_timing (key->k, curve_id, &key->pubkey, key->A, key->prime, 1);
  else
    err = ecc_mulmod_cached (key->k, curve_id, &key->pubkey, key->A, key->prime, 1);

  if (err != 0)
    goto errkey;

  key->type = PK_PRIVATE;

  /* free up ram */
  err = 0;
  goto cleanup;
errkey:
  mp_clear_multi (&key->pubkey.x, &key->pubkey.y, &key->pubkey.z, &key->k,
                  &key->order, &key->prime, &key->Gx, &key->Gy, &key->A, &key->B,
                  NULL);
cleanup:
  ecc_del_point (base);
ERR_BUF:
  free (buf);
  return err;
}

int
ecc_make_key (void *random_ctx, nettle_random_func random, ecc_key * key,
              const ecc_set_type * dp, gnutls_ecc_curve_t curve_id)
{
  mpz_t prime, order, Gx, Gy, A, B;
  int err;

  /* setup the key variables */
  if ((err = mp_init_multi (&prime, &order, &A, &B, &Gx, &Gy, NULL)) != 0)
    {
      goto cleanup;
    }

  /* read in the specs for this key */
  mpz_set_str (prime, (char *) dp->prime, 16);
  mpz_set_str (order, (char *) dp->order, 16);
  mpz_set_str (Gx, (char *) dp->Gx, 16);
  mpz_set_str (Gy, (char *) dp->Gy, 16);
  mpz_set_str (A, (char *) dp->A, 16);
  mpz_set_str (B, (char *) dp->B, 16);

  err = ecc_make_key_ex (random_ctx, random, key, prime, order, A, B, Gx, Gy, curve_id, 0);

  mp_clear_multi (&prime, &order, &A, &B, &Gx, &Gy, NULL);
cleanup:
  return err;
}

/* $Source: /cvs/libtom/libtomcrypt/src/pk/ecc/ecc_make_key.c,v $ */
/* $Revision: 1.13 $ */
/* $Date: 2007/05/12 14:32:35 $ */
