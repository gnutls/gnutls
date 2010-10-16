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

#ifndef EINA_INLINE_F16P16_X_
#define EINA_INLINE_F16P16_X_

static inline Eina_F16p16
eina_f16p16_add(Eina_F16p16 a, Eina_F16p16 b)
{
   return a + b;
}

static inline Eina_F16p16
eina_f16p16_sub(Eina_F16p16 a, Eina_F16p16 b)
{
   return a - b;
}

static inline Eina_F16p16
eina_f16p16_mul(Eina_F16p16 a, Eina_F16p16 b)
{
   return (Eina_F16p16)(((int64_t)a * (int64_t)b) >> 16);
}

static inline Eina_F16p16
eina_f16p16_scale(Eina_F16p16 a, int b)
{
   return a * b;
}

static inline Eina_F16p16
eina_f16p16_div(Eina_F16p16 a, Eina_F16p16 b)
{
   return (Eina_F16p16) ((((int64_t) a) << 16) / (int64_t) b);
}

static inline Eina_F16p16
eina_f16p16_sqrt(Eina_F16p16 a)
{
   unsigned int root, remHi, remLo, testDiv, count;

   root = 0; /* Clear root */
   remHi = 0; /* Clear high part of partial remainder */
   remLo = a; /* Get argument into low part of partial remainder */
   count = (15 + (16 >> 1)); /* Load loop counter */
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

   return root;
}

static inline unsigned int
eina_f16p16_fracc_get(Eina_F16p16 v)
{
   return (v & 0xffff);
}

#endif
