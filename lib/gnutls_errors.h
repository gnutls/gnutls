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

#include "gnutls_int.h"
#include "gnutls_errors_int.h"

#ifdef DEBUG
# ifdef __FILE__
#  ifdef __LINE__
#   define gnutls_assert() fprintf(stderr, "GNUTLS_ASSERT: %s:%d\n", __FILE__,__LINE__);
#  else
#   define gnutls_assert() 
#  endif
# else /* __FILE__ defined */
#  define gnutls_assert() 
# endif
#else /* no debug */
# define gnutls_assert() 
#endif

const char* gnutls_strerror(int error);
void gnutls_perror(int error);
int gnutls_error_is_fatal( int error);

#ifdef DEBUG
 void _gnutls_log( const char *fmt, ...);
#else
# define _gnutls_log(...)
#endif

