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
#include <gnutls_int.h>

#define rotl64(x,n)   (((x) << ((uint16)(n))) | ((x) >> (64 - (uint16)(n))))
#define rotr64(x,n)   (((x) >> ((uint16)(n))) | ((x) << (64 - (uint16)(n))))
#define rotl32(x,n)   (((x) << ((uint16)(n))) | ((x) >> (32 - (uint16)(n))))
#define rotr32(x,n)   (((x) >> ((uint16)(n))) | ((x) << (32 - (uint16)(n))))
#define rotl16(x,n)   (((x) << ((uint16)(n))) | ((x) >> (16 - (uint16)(n))))
#define rotr16(x,n)   (((x) >> ((uint16)(n))) | ((x) << (16 - (uint16)(n))))

#define byteswap16(x)  ((rotl16(x, 8) & 0x00ff) | (rotr16(x, 8) & 0xff00))
#define byteswap32(x)  ((rotl32(x, 8) & 0x00ff00ff) | (rotr32(x, 8) & 0xff00ff00))
#define byteswap64(x)  ((rotl64(x, 8) & 0x00ff00ff00ff00ffLL) | (rotr64(x, 8) & 0xff00ff00ff00ff00LL))

inline
uint32 uint24touint32( uint24 num) {
uint32 ret=0;

	((uint8*)&ret)[1] = num.pint[0];
	((uint8*)&ret)[2] = num.pint[1];
	((uint8*)&ret)[3] = num.pint[2];
	return ret;
}

inline
uint24 uint32touint24( uint32 num) {
uint24 ret;

	ret.pint[0] = ((uint8*)&num)[1];
	ret.pint[1] = ((uint8*)&num)[2];
	ret.pint[2] = ((uint8*)&num)[3];
	return ret;

}

/* data should be at least 3 bytes */
inline
uint32 READuint24( const opaque* data) {
uint32 res;
uint24 num;
	
	num.pint[0] = data[0];
	num.pint[1] = data[1];
	num.pint[2] = data[2];

	res = uint24touint32( num);
#ifndef WORDS_BIGENDIAN
	res = byteswap32( res);
#endif
return res;
}

inline
uint32 READuint32( const opaque* data) {
uint32 res;

	memcpy( &res, data, sizeof(uint32));
#ifndef WORDS_BIGENDIAN
	res = byteswap32( res);
#endif
return res;
}

inline
uint16 READuint16( const opaque* data) {
uint16 res;
	memcpy( &res, data, sizeof(uint16));
#ifndef WORDS_BIGENDIAN
	res = byteswap16( res);
#endif
return res;
}

inline
uint32 CONVuint32( uint32 data) {
#ifndef WORDS_BIGENDIAN
	return byteswap32( data);
#else
	return data;
#endif
}

inline
uint16 CONVuint16( uint16 data) {
#ifndef WORDS_BIGENDIAN
	return byteswap16( data);
#else
	return data;
#endif
}

inline
uint64 READuint64( const opaque* data) {
uint64 res;

	memcpy( &res, data, sizeof(uint64));
#ifndef WORDS_BIGENDIAN
	res = byteswap64( res);
#endif
return res;
}

inline
uint64 CONVuint64( uint64 data) {
#ifndef WORDS_BIGENDIAN
 return byteswap64( data);
#else
 return data;
#endif
}
