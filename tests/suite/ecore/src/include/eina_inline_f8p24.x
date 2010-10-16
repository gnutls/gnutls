/* EINA - EFL data type library
 * Copyright (C) 2007-2008 Jorge Luis Zapata Muga
 * Copyright (C) 2009 Cedric BAIL
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library;
 * if not, see <http://www.gnu.org/licenses/>.
 */

#ifndef EINA_INLINE_F8P24_X_
#define EINA_INLINE_F8P24_X_

static inline Eina_F8p24
eina_f8p24_add(Eina_F8p24 a, Eina_F8p24 b)
{
   return a + b;
}

static inline Eina_F8p24
eina_f8p24_sub(Eina_F8p24 a, Eina_F8p24 b)
{
   return a - b;
}

static inline Eina_F8p24
eina_f8p24_mul(Eina_F8p24 a, Eina_F8p24 b)
{
   return (Eina_F8p24)(((int64_t) a * (int64_t) b) >> 24);
}

static inline Eina_F8p24
eina_f8p24_scale(Eina_F8p24 a, int b)
{
   return a * b;
}

static inline Eina_F8p24
eina_f8p24_div(Eina_F8p24 a, Eina_F8p24 b)
{
   return (Eina_F8p24) ((((int64_t) a) << 24) / (int64_t) b);
}

static inline Eina_F8p24
eina_f8p24_sqrt(Eina_F8p24 a)
{
   unsigned int root, remHi, remLo, testDiv, count;

   root = 0; /* Clear root */
   remHi = 0; /* Clear high part of partial remainder */
   remLo = a; /* Get argument into low part of partial remainder */
   count = (23 + (24 >> 1)); /* Load loop counter */
   do {
      remHi = (remHi << 2) | (remLo >> 30);
      remLo <<= 2; /* get 2 bits of arg */
      root <<= 1; /* Get ready for the next bit in the root */
      testDiv = (root << 1) + 1; /* Test radical */
      if (remHi >= testDiv)
	{
	   remHi -= testDiv;
	   root++;
	}
   } while (count-- != 0);
   return (root);
}

static inline unsigned int
eina_f8p24_fracc_get(Eina_F8p24 v)
{
   return (v & 0xffffff);
}

#endif
