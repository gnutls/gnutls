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

#include <defines.h>
#include "gnutls_errors_int.h"

#ifdef __FILE__
# ifdef __LINE__
#  define gnutls_assert() _gnutls_debug_log( "ASSERT: %s:%d\n", __FILE__,__LINE__);
# else
#  define gnutls_assert()
# endif
#else				/* __FILE__ not defined */
# define gnutls_assert()
#endif

int _gnutls_asn2err(int asn_err);
const char *gnutls_strerror(int error);
void gnutls_perror(int error);
int gnutls_error_is_fatal(int error);

void _gnutls_log(int, const char *fmt, ...);

extern int _gnutls_log_level;

#ifdef C99_MACROS
#define LEVEL(l, ...) if (_gnutls_log_level >= l || _gnutls_log_level > 9) \
	_gnutls_log( l, __VA_ARGS__)

#define LEVEL_EQ(l, ...) if (_gnutls_log_level == l || _gnutls_log_level > 9) \
	_gnutls_log( l, __VA_ARGS__)

# define _gnutls_debug_log(...) LEVEL(2, __VA_ARGS__)
# define _gnutls_handshake_log(...) LEVEL(3, __VA_ARGS__)
# define _gnutls_io_log(...) LEVEL_EQ(5, __VA_ARGS__)
# define _gnutls_buffers_log(...) LEVEL_EQ(6, __VA_ARGS__)
# define _gnutls_hard_log(...) LEVEL(9, __VA_ARGS__)
# define _gnutls_record_log(...) LEVEL(4, __VA_ARGS__)
# define _gnutls_read_log(...) LEVEL_EQ(7, __VA_ARGS__)
# define _gnutls_write_log(...) LEVEL_EQ(7, __VA_ARGS__)
# define _gnutls_x509_log(...) LEVEL(1, __VA_ARGS__)
#else
# define _gnutls_debug_log _gnutls_null_log
# define _gnutls_handshake_log _gnutls_null_log
# define _gnutls_io_log _gnutls_null_log
# define _gnutls_buffers_log _gnutls_null_log
# define _gnutls_hard_log _gnutls_null_log
# define _gnutls_record_log _gnutls_null_log
# define _gnutls_read_log _gnutls_null_log
# define _gnutls_write_log _gnutls_null_log
# define _gnutls_x509_log _gnutls_null_log

void _gnutls_null_log(void *, ...);

#endif				/* C99_MACROS */
