/* nettle-internal.c
 *
 * Things that are used only by the testsuite and benchmark, and
 * subject to change.
 */

/* nettle, low-level cryptographics library
 *
 * Copyright (C) 2002 Niels Möller
 *  
 * The nettle library is free software; you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License as published by
 * the Free Software Foundation; either version 2.1 of the License, or (at your
 * option) any later version.
 * 
 * The nettle library is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY
 * or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU Lesser General Public
 * License for more details.
 * 
 * You should have received a copy of the GNU Lesser General Public License
 * along with the nettle library; see the file COPYING.LIB.  If not, write to
 * the Free Software Foundation, Inc., 59 Temple Place - Suite 330, Boston,
 * MA 02111-1307, USA.
 */

#if HAVE_CONFIG_H
# include "config.h"
#endif

#include <assert.h>
#include <stdlib.h>

#include "nettle-internal.h"
#include "des.h"

/* DES uses a different signature for the key set function.
 * And we have to adjust parity. */
static void
des_set_key_hack(void *c, unsigned length, const uint8_t *key)
{
  struct des_ctx *ctx = c;
  uint8_t pkey[DES_KEY_SIZE];
  
  assert(length == DES_KEY_SIZE);
  des_fix_parity(DES_KEY_SIZE, pkey, key);
  if (!des_set_key(ctx, pkey))
    abort();
}

static void
des3_set_key_hack(void *c, unsigned length, const uint8_t *key)
{
  struct des3_ctx *ctx = c;
  uint8_t pkey[DES3_KEY_SIZE];
  
  assert(length == DES3_KEY_SIZE);
  des_fix_parity(DES3_KEY_SIZE, pkey, key);
  if (!des3_set_key(ctx, pkey))
    abort();
}

const struct nettle_cipher
nettle_des = {
  "des", sizeof(struct des_ctx),
  DES_BLOCK_SIZE, DES_KEY_SIZE,
  des_set_key_hack, des_set_key_hack,
  (nettle_crypt_func) des_encrypt,
  (nettle_crypt_func) des_decrypt
};

const struct nettle_cipher
nettle_des3 = {
 "des3", sizeof(struct des3_ctx),
 DES3_BLOCK_SIZE, DES3_KEY_SIZE,
 des3_set_key_hack, des3_set_key_hack,
 (nettle_crypt_func) des3_encrypt,
 (nettle_crypt_func) des3_decrypt
};
