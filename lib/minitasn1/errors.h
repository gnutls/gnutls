/*
 *      Copyright (C) 2002 Fabio Fiorina
 *
 * This file is part of LIBASN1.
 *
 * LIBASN1 is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * LIBASN1 is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA
 */

#ifndef ERRORS_H
#define ERRORS_H


#include "int.h"
#include "errors_int.h"

#ifdef LIBTASN1_DEBUG
# ifdef __FILE__
#  ifdef __LINE__
#   define _libtasn1_assert() fprintf(stderr, "LIBTASN1_ASSERT: %s:%d\n", __FILE__,__LINE__);
#  else
#   define _libtasn1_assert() 
#  endif
# else /* __FILE__ defined */
#  define _libtasn1_assert() 
# endif
#else /* no debug */
# define _libtasn1_assert() 
#endif

const char* libtasn1_strerror(int error);
void libtasn1_perror(int error);

#ifdef LIBTASN1_DEBUG
 void _libtasn1_log( const char *fmt, ...);
#else

/* These macros only work with C99 compliant compilers
 */
# ifdef C99_MACROS
#  define _libtasn1_log(...)
# else
#  define _libtasn1_log _libtasn1_null_log
void _libtasn1_null_log( void*, ...);
# endif /* C99_MACROS */

#endif /* DEBUG */

#endif /* ERRORS_H */
