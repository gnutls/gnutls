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
#include <string.h>

/*
  @file ecc_shared_secret.c
  ECC Crypto, Tom St Denis
*/

/*
  Create an ECC shared secret between two keys
  @param private_key      The private ECC key
  @param public_key       The public key
  @param out              [out] Destination of the shared secret (Conforms to EC-DH from ANSI X9.63)
  @param outlen           [in/out] The max size and resulting size of the shared secret
  @return 0 if successful
*/
int
ecc_shared_secret (ecc_key * private_key, ecc_key * public_key,
                   unsigned char *out, unsigned long *outlen)
{
  unsigned long x;
  ecc_point *result;
  int err;

  if (private_key == NULL || public_key == NULL || out == NULL || outlen == NULL)
    return -1;

  /* type valid? */
  if (private_key->type != PK_PRIVATE)
    {
      return -1;
    }

  /* make new point */
  result = ecc_new_point ();
  if (result == NULL)
    {
      return -1;
    }

  if ((err =
       ecc_mulmod (private_key->k, &public_key->pubkey, result,
                       private_key->A, private_key->prime, 1)) != 0)
    {
      goto done;
    }

  x = nettle_mpz_sizeinbase_256_u (private_key->prime);
  if (*outlen < x)
    {
      *outlen = x;
      err = -1;
      goto done;
    }
  nettle_mpz_get_str_256(x, out, result->x);

  err = 0;
  *outlen = x;
done:
  ecc_del_point (result);
  return err;
}

/* $Source: /cvs/libtom/libtomcrypt/src/pk/ecc/ecc_shared_secret.c,v $ */
/* $Revision: 1.10 $ */
/* $Date: 2007/05/12 14:32:35 $ */
