/*
 * Copyright (C) 2008 Free Software Foundation
 *
 * Author: Nikos Mavrogiannopoulos
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
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301,
 * USA
 *
 */

/* This file handles all the internal functions that cope with random data.
 */

#include <gnutls_int.h>
#include <gnutls_errors.h>
#include <random.h>

static gnutls_crypto_rnd_st * cc = NULL;
static void * rnd_ctx;

int
_gnutls_rnd_init ()
{
  int result;

  /* check if a digest has been registered 
   */
  cc = _gnutls_get_crypto_rnd();

  if (cc != NULL) {
    if (cc->init(& rnd_ctx) < 0) {
      gnutls_assert();
      return GNUTLS_E_RANDOM_FAILED;
    }
  } else {
    char c;
    gc_pseudo_random (&c, 1);
  }
  
  return 0;
}

void
_gnutls_rnd_deinit ()
{
  if (cc != NULL) {
    cc->deinit( rnd_ctx);
  }
  
  return;
}

int
_gnutls_rnd (int level, void *data, int len)
{
int ret = GC_OK;

  if (len > 0) {
  
    if (cc != NULL) {
      return cc->rnd( rnd_ctx, level, data, len);
    }
    
    if (level == RND_NONCE)
      ret = gc_nonce (data, len);
    else
      ret = gc_pseudo_random( data, len);
  }

  if (ret == GC_OK) return 0;
  else return GNUTLS_E_RANDOM_FAILED;
}

