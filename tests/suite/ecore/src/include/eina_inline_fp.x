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
 * if not, see <https://www.gnu.org/licenses/>.
 */

#ifndef EINA_INLINE_FP_X_
# define EINA_INLINE_FP_X_

static inline Eina_F32p32
eina_f32p32_int_from(int32_t v)
{
   return (Eina_F32p32)(v) << 32;
}

static inline int32_t
eina_f32p32_int_to(Eina_F32p32 v)
{
   return (int32_t)(v >> 32);
}

static inline Eina_F32p32
eina_f32p32_double_from(double v)
{
   Eina_F32p32 r;
   r = (Eina_F32p32)(v * 4294967296.0 + (v < 0 ? -0.5 : 0.5));
   return r;
}

static inline double
eina_f32p32_double_to(Eina_F32p32 v)
{
   double r;
   r = v / 4294967296.0;
   return r;
}



static inline Eina_F16p16
eina_f16p16_int_from(int32_t v)
{
   return v << 16;
}

static inline int32_t
eina_f16p16_int_to(Eina_F16p16 v)
{
   return v >> 16;
}

static inline Eina_F16p16
eina_f16p16_float_from(float v)
{
   Eina_F16p16 r;

   r = (Eina_F16p16)(v * 65536.0f + (v < 0 ? -0.5f : 0.5f));
   return r;
}

static inline float
eina_f16p16_float_to(Eina_F16p16 v)
{
   float r;

   r = v / 65536.0f;
   return r;
}



static inline Eina_F8p24
eina_f8p24_int_from(int32_t v)
{
   return v << 24;
}

static inline int32_t
eina_f8p24_int_to(Eina_F8p24 v)
{
   return v >> 24;
}

static inline Eina_F8p24
eina_f8p24_float_from(float v)
{
   Eina_F8p24 r;

   r = (Eina_F8p24)(v * 16777216.0f + (v < 0 ? -0.5f : 0.5f));
   return r;
}

static inline float
eina_f8p24_float_to(Eina_F8p24 v)
{
   float r;

   r = v / 16777216.0f;
   return r;
}



static inline Eina_F32p32
eina_f16p16_to_f32p32(Eina_F16p16 a)
{
   return ((Eina_F32p32) a) << 16;
}

static inline Eina_F32p32
eina_f8p24_to_f32p32(Eina_F8p24 a)
{
   return ((Eina_F32p32) a) << 8;
}

static inline Eina_F16p16
eina_f32p32_to_f16p16(Eina_F32p32 a)
{
   return (Eina_F16p16) (a >> 16);
}

static inline Eina_F16p16
eina_f8p24_to_f16p16(Eina_F8p24 a)
{
   return (Eina_F16p16) (a >> 8);
}

static inline Eina_F8p24
eina_f32p32_to_f8p24(Eina_F32p32 a)
{
   return (Eina_F8p24) (a >> 8);
}

static inline Eina_F8p24
eina_f16p16_to_f8p24(Eina_F16p16 a)
{
   return (Eina_F8p24) (a << 8);
}

#endif
