/*
 *      Copyright (C) 2000 Nikos Mavroyanopoulos
 *
 * This file is part of GNUTLS.
 *
 * GNUTLS is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * GNUTLS is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA
 */

#ifndef DEFINES_H
# define DEFINES_H

#include <config.h>

#ifdef STDC_HEADERS
# include <string.h>
# include <stdlib.h>
# include <stdio.h>
#endif

#ifdef HAVE_STDARG_H
# include <stdarg.h>
#endif

#ifdef HAVE_STRINGS_H
# include <strings.h>
#endif

#include <time.h>
#include <ctype.h>

/* for open */
#ifdef HAVE_SYS_TYPES_H
# include <sys/types.h>
#endif

#ifdef HAVE_LIBGDBM
# include <gdbm.h>
#endif

#ifdef HAVE_SYS_STAT_H
# include <sys/stat.h>
#endif

#ifdef HAVE_UNISTD_H
# include <unistd.h>
#endif

#ifdef HAVE_SYS_SOCKET_H
# include <sys/socket.h>
#endif

#if SIZEOF_UNSIGNED_LONG_INT == 8
# define HAVE_UINT64
/* only used native uint64 in 64 bit machines */
 typedef unsigned long int uint64;
#else
 typedef struct { unsigned char i[8]; } uint64;
#endif


#if SIZEOF_UNSIGNED_LONG_INT == 4
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
#elif SIZEOF_UNSIGNED_SHORT_INT == 2
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

#ifndef HAVE_MEMMOVE
# ifdef HAVE_BCOPY
#  define memmove(d, s, n) bcopy ((s), (d), (n))
# else
#  error "Neither memmove nor bcopy exists on your system."
# endif
#endif

#endif /* defines_h */
