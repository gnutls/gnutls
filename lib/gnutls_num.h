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

uint32 uint24touint32( uint24 num);
uint24 uint32touint24( uint32 num);
uint32 READuint32( const opaque* data);
uint16 READuint16( const opaque* data);
uint32 CONVuint32( uint32 data);
uint16 CONVuint16( uint16 data);
uint8* CONVuint64( const uint64 *data); /* note: this returns malloced data */
uint32 READuint24( const opaque* data);
void WRITEuint24( uint32 num, opaque* data);
void WRITEuint32( uint32 num, opaque* data);
void WRITEuint16( uint16 num, opaque* data);
uint32 uint64touint32( const uint64*);

#ifndef HAVE_UINT64
int uint64zero( uint64 *);
int uint64pp( uint64 *);
#else

# define rotl64(x,n)   (((x) << ((uint16)(n))) | ((x) >> (64 - (uint16)(n))))
# define rotr64(x,n)   (((x) >> ((uint16)(n))) | ((x) << (64 - (uint16)(n))))
# define byteswap64(x)  ((rotl64(x, 8) & 0x00ff00ff00ff00ffUL) | (rotr64(x, 8) & 0xff00ff00ff00ff00UL))
# define uint64pp(x) (*x)++ 
# define uint64zero(x) (*x) = 0

#endif
