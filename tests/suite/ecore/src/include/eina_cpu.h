/* EINA - EFL data type library
 * Copyright (C) 2007-2008 Jorge Luis Zapata Muga
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

#ifndef EINA_CPU_H_
#define EINA_CPU_H_

#include "eina_types.h"

typedef enum _Eina_Cpu_Features
{
   EINA_CPU_MMX = 0x00000001,
   EINA_CPU_SSE = 0x00000002,
   EINA_CPU_SSE2 = 0x00000004,
   EINA_CPU_SSE3 = 0x00000008,
   /* TODO 3DNow! */
   EINA_CPU_ALTIVEC = 0x00000010,
   EINA_CPU_VIS = 0x00000020,
   EINA_CPU_NEON = 0x00000040,
} Eina_Cpu_Features;

EAPI Eina_Cpu_Features eina_cpu_features_get(void);
EAPI int               eina_cpu_count(void);

#endif /* EINA_CPU_H_ */
