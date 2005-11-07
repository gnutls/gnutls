/*
 * Copyright (C) 2000, 2001, 2002, 2003, 2004, 2005 Free Software Foundation
 *
 * Author: Nikos Mavroyanopoulos
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

#ifndef DEFINES_H
# define DEFINES_H

#if HAVE_CONFIG_H
# include <config.h>
#endif

#include <stddef.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <ctype.h>

#ifdef NO_SSIZE_T
# define HAVE_SSIZE_T
typedef int ssize_t;
#endif

#ifdef HAVE_STRINGS_H
# include <strings.h>
#endif

#ifdef HAVE_SYS_TYPES_H
# include <sys/types.h>
#endif

#ifdef HAVE_SYS_STAT_H
# include <sys/stat.h>
#endif

#ifdef HAVE_UNISTD_H
# include <unistd.h>
#endif

#if TIME_WITH_SYS_TIME
# include <sys/time.h>
# include <time.h>
#else
# if HAVE_SYS_TIME_H
#  include <sys/time.h>
# else
#  include <time.h>
# endif
#endif

#ifdef HAVE_SYS_SOCKET_H
# include <sys/socket.h>
#endif

#include "memmem.h"

#ifndef HAVE_UINT
typedef unsigned int uint;
typedef signed int sint;
#endif

#define SIZEOF_UNSIGNED_LONG_INT SIZEOF_UNSIGNED_LONG

/* some systems had problems with long long int, thus,
 * it is not used.
 */
typedef struct
{
  unsigned char i[8];
} uint64;

#if SIZEOF_UNSIGNED_LONG == 4
typedef unsigned long int uint32;
typedef signed long int sint32;
#elif SIZEOF_UNSIGNED_INT == 4
typedef unsigned int uint32;
typedef signed int sint32;
#else
# error "Cannot find a 32 bit integer in your system, sorry."
#endif

#if SIZEOF_UNSIGNED_INT == 2
typedef unsigned int uint16;
typedef signed int sint16;
#elif SIZEOF_UNSIGNED_SHORT == 2
typedef unsigned short int uint16;
typedef signed short int sint16;
#else
# error "Cannot find a 16 bit integer in your system, sorry."
#endif

#if SIZEOF_UNSIGNED_CHAR == 1
typedef unsigned char uint8;
typedef signed char int8;
#else
# error "Cannot find an 8 bit char in your system, sorry."
#endif

#endif /* defines_h */
