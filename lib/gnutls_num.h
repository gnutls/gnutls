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

#include <gnutls_int.h>

#define GMIN(x,y) (x<y)?x:y
#define GMAX(x,y) (x>y)?x:y

#define rotl32(x,n)   (((x) << ((uint16)(n))) | ((x) >> (32 - (uint16)(n))))
#define rotr32(x,n)   (((x) >> ((uint16)(n))) | ((x) << (32 - (uint16)(n))))
#define rotl16(x,n)   (((x) << ((uint16)(n))) | ((x) >> (16 - (uint16)(n))))
#define rotr16(x,n)   (((x) >> ((uint16)(n))) | ((x) << (16 - (uint16)(n))))

#define byteswap16(x)  ((rotl16(x, 8) & 0x00ff) | (rotr16(x, 8) & 0xff00))
#define byteswap32(x)  ((rotl32(x, 8) & 0x00ff00ffUL) | (rotr32(x, 8) & 0xff00ff00UL))

uint32 _gnutls_uint24touint32( uint24 num);
uint24 _gnutls_uint32touint24( uint32 num);
uint32 _gnutls_read_uint32( const opaque* data);
uint16 _gnutls_read_uint16( const opaque* data);
uint32 _gnutls_conv_uint32( uint32 data);
uint16 _gnutls_conv_uint16( uint16 data);
uint64 _gnutls_conv_uint64( const uint64 *data);
uint32 _gnutls_read_uint24( const opaque* data);
void _gnutls_write_uint24( uint32 num, opaque* data);
void _gnutls_write_uint32( uint32 num, opaque* data);
void _gnutls_write_uint16( uint16 num, opaque* data);
uint32 _gnutls_uint64touint32( const uint64*);

#ifndef HAVE_UINT64
int _gnutls_uint64zero( uint64 *);
int _gnutls_uint64pp( uint64 *);
# define UINT64DATA(x) x.i

#else
# define UINT64DATA(x) &x
# define rotl64(x,n)   (((x) << ((uint16)(n))) | ((x) >> (64 - (uint16)(n))))
# define rotr64(x,n)   (((x) >> ((uint16)(n))) | ((x) << (64 - (uint16)(n))))
# define byteswap64(x)  ((rotl64(x, 8) & 0x00ff00ff00ff00ffUL) | (rotr64(x, 8) & 0xff00ff00ff00ff00UL))

# define _gnutls_uint64pp(x) ((++(*x)==0) ? -1 : 0)
# define _gnutls_uint64zero(x) (*x) = 0

#endif
