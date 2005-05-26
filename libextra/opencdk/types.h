/* types.h - Some type definitions
 *        Copyright (C) 2002 Timo Schulz
 *
 * This file is part of OpenCDK.
 *
 * OpenCDK is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * OpenCDK is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with OpenCDK; if not, write to the Free Software Foundation,
 * Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301, USA
 */

#ifndef CDK_TYPES_H
#define CDK_TYPES_H

#include <gcrypt.h> /*FIXME!*/

#ifndef HAVE_BYTE_TYPEDEF
# undef byte
  typedef unsigned char byte;
# define HAVE_BYTE_TYPEDEF
#endif

#ifndef HAVE_U16_TYPEDEF
# undef u16
  typedef unsigned short u16;
# define HAVE_U16_TYPEDEF
#endif

#ifndef HAVE_U32_TYPEDEF
# undef u32
  typedef unsigned int u32;
# define HAVE_U32_TYPEDEF
#endif

#ifndef DIM
# define DIM(v) (sizeof (v)/sizeof ((v)[0]))
# define DIMof(type, member)   DIM(((type *)0)->member)
#endif


struct cdk_verify_result_s;
typedef struct cdk_verify_result_s *_cdk_verify_result_t;

#endif /* CDK_TYPES_H */
