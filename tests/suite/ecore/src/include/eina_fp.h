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

#ifndef EINA_FP_H_
#define EINA_FP_H_

#include "eina_types.h"

#ifdef _MSC_VER
typedef unsigned __int64 uint64_t;
typedef signed __int64 int64_t;
typedef signed int int32_t;
#else
#include <stdint.h>
#endif

#define EINA_F32P32_PI 0x00000003243f6a89

typedef int64_t Eina_F32p32;
typedef int32_t Eina_F16p16;
typedef int32_t Eina_F8p24;

static inline Eina_F32p32 eina_f32p32_int_from(int32_t v);
static inline int32_t eina_f32p32_int_to(Eina_F32p32 v);
static inline Eina_F32p32 eina_f32p32_double_from(double v);
static inline double eina_f32p32_double_to(Eina_F32p32 v);

static inline Eina_F32p32 eina_f32p32_add(Eina_F32p32 a, Eina_F32p32 b);
static inline Eina_F32p32 eina_f32p32_sub(Eina_F32p32 a, Eina_F32p32 b);
static inline Eina_F32p32 eina_f32p32_mul(Eina_F32p32 a, Eina_F32p32 b);
static inline Eina_F32p32 eina_f32p32_scale(Eina_F32p32 a, int b);
static inline Eina_F32p32 eina_f32p32_div(Eina_F32p32 a, Eina_F32p32 b);
static inline Eina_F32p32 eina_f32p32_sqrt(Eina_F32p32 a);
static inline unsigned int eina_f32p32_fracc_get(Eina_F32p32 v);

// dont use llabs - issues if not on 64bit
#define eina_fp32p32_llabs(a) ((a < 0) ? -(a) : (a))

EAPI Eina_F32p32 eina_f32p32_cos(Eina_F32p32 a);
EAPI Eina_F32p32 eina_f32p32_sin(Eina_F32p32 a);

static inline Eina_F16p16 eina_f16p16_int_from(int32_t v);
static inline int32_t eina_f16p16_int_to(Eina_F16p16 v);
static inline Eina_F16p16 eina_f16p16_float_from(float v);
static inline float eina_f16p16_float_to(Eina_F16p16 v);

static inline Eina_F16p16 eina_f16p16_add(Eina_F16p16 a, Eina_F16p16 b);
static inline Eina_F16p16 eina_f16p16_sub(Eina_F16p16 a, Eina_F16p16 b);
static inline Eina_F16p16 eina_f16p16_mul(Eina_F16p16 a, Eina_F16p16 b);
static inline Eina_F16p16 eina_f16p16_scale(Eina_F16p16 a, int b);
static inline Eina_F16p16 eina_f16p16_div(Eina_F16p16 a, Eina_F16p16 b);
static inline Eina_F16p16 eina_f16p16_sqrt(Eina_F16p16 a);
static inline unsigned int eina_f16p16_fracc_get(Eina_F16p16 v);

static inline Eina_F8p24 eina_f8p24_int_from(int32_t v);
static inline int32_t eina_f8p24_int_to(Eina_F8p24 v);
static inline Eina_F8p24 eina_f8p24_float_from(float v);
static inline float eina_f8p24_float_to(Eina_F8p24 v);

static inline Eina_F8p24 eina_f8p24_add(Eina_F8p24 a, Eina_F8p24 b);
static inline Eina_F8p24 eina_f8p24_sub(Eina_F8p24 a, Eina_F8p24 b);
static inline Eina_F8p24 eina_f8p24_mul(Eina_F8p24 a, Eina_F8p24 b);
static inline Eina_F8p24 eina_f8p24_scale(Eina_F8p24 a, int b);
static inline Eina_F8p24 eina_f8p24_div(Eina_F8p24 a, Eina_F8p24 b);
static inline Eina_F8p24 eina_f8p24_sqrt(Eina_F8p24 a);
static inline unsigned int eina_f8p24_fracc_get(Eina_F8p24 v);

static inline Eina_F32p32 eina_f16p16_to_f32p32(Eina_F16p16 a);
static inline Eina_F32p32 eina_f8p24_to_f32p32(Eina_F8p24 a);
static inline Eina_F16p16 eina_f32p32_to_f16p16(Eina_F32p32 a);
static inline Eina_F16p16 eina_f8p24_to_f16p16(Eina_F8p24 a);
static inline Eina_F8p24 eina_f32p32_to_f8p24(Eina_F32p32 a);
static inline Eina_F8p24 eina_f16p16_to_f8p24(Eina_F16p16 a);

#include "eina_inline_f32p32.x"
#include "eina_inline_f16p16.x"
#include "eina_inline_f8p24.x"
#include "eina_inline_fp.x"

#endif
