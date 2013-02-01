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
  @file ecc_points.c
  ECC Crypto, Tom St Denis
*/

/*
   Allocate a new ECC point
   @return A newly allocated point or NULL on error 
*/
ecc_point *
ecc_new_point (void)
{
  ecc_point *p;
  p = calloc (1, sizeof (*p));
  if (p == NULL)
    {
      return NULL;
    }
  if (mp_init_multi (&p->x, &p->y, &p->z, NULL) != 0)
    {
      free (p);
      return NULL;
    }
  return p;
}

/* Free an ECC point from memory
  @param p   The point to free
*/
void
ecc_del_point (ecc_point * p)
{
  /* prevents free'ing null arguments */
  if (p != NULL)
    {
      mp_clear_multi (&p->x, &p->y, &p->z, NULL);       /* note: p->z may be NULL but that's ok with this function anyways */
      free (p);
    }
}

/* $Source: /cvs/libtom/libtomcrypt/src/pk/ecc/ecc_points.c,v $ */
/* $Revision: 1.7 $ */
/* $Date: 2007/05/12 14:32:35 $ */
