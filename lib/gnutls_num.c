/*
 *      Copyright (C) 2000,2001 Nikos Mavroyanopoulos
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
#include <gnutls_num.h>
#include <gnutls_errors.h>

#define rotl32(x,n)   (((x) << ((uint16)(n))) | ((x) >> (32 - (uint16)(n))))
#define rotr32(x,n)   (((x) >> ((uint16)(n))) | ((x) << (32 - (uint16)(n))))
#define rotl16(x,n)   (((x) << ((uint16)(n))) | ((x) >> (16 - (uint16)(n))))
#define rotr16(x,n)   (((x) >> ((uint16)(n))) | ((x) << (16 - (uint16)(n))))

#define byteswap16(x)  ((rotl16(x, 8) & 0x00ff) | (rotr16(x, 8) & 0xff00))
#define byteswap32(x)  ((rotl32(x, 8) & 0x00ff00ffUL) | (rotr32(x, 8) & 0xff00ff00UL))

#ifndef HAVE_UINT64

/* This function will set the uint64 x to zero 
 */
int uint64zero( uint64 *x) {

	memset( x->i, 0, 8);
	return 0;
}

/* This function will add one to uint64 x.
 * Returns 0 on success, or -1 if the uint64 max limit
 * has been reached.
 */
int uint64pp( uint64 *x) {
register int i, y;

	for (i=7;i>=0;i--) {
		y = 0;
		if ( x->i[i] == 0xff) {
			x->i[i] = 0;
			y = 1;
		} else x->i[i]++;

		if (y==0) break;
	}
	if (y != 0) return -1; /* over 64 bits! WOW */

	return 0;
}

#endif /* HAVE_UINT64 */

uint32 uint24touint32( uint24 num) {
uint32 ret=0;

	((uint8*)&ret)[1] = num.pint[0];
	((uint8*)&ret)[2] = num.pint[1];
	((uint8*)&ret)[3] = num.pint[2];
	return ret;
}

uint24 uint32touint24( uint32 num) {
uint24 ret;

	ret.pint[0] = ((uint8*)&num)[1];
	ret.pint[1] = ((uint8*)&num)[2];
	ret.pint[2] = ((uint8*)&num)[3];
	return ret;

}

/* data should be at least 3 bytes */
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

void WRITEuint24( uint32 num, opaque* data) {
uint24 tmp;
	
#ifndef WORDS_BIGENDIAN
	num = byteswap32( num);
#endif
	tmp = uint32touint24( num);

	data[0] = tmp.pint[0];
	data[1] = tmp.pint[1];
	data[2] = tmp.pint[2];
	return;
}

uint32 READuint32( const opaque* data) {
uint32 res;

	memcpy( &res, data, sizeof(uint32));
#ifndef WORDS_BIGENDIAN
	res = byteswap32( res);
#endif
return res;
}

void WRITEuint32( uint32 num, opaque* data) {

#ifndef WORDS_BIGENDIAN
	num = byteswap32( num);
#endif
	memcpy( data, &num, sizeof(uint32));
	return;
}

uint16 READuint16( const opaque* data) {
uint16 res;
	memcpy( &res, data, sizeof(uint16));
#ifndef WORDS_BIGENDIAN
	res = byteswap16( res);
#endif
return res;
}

void WRITEuint16( uint16 num, opaque* data) {

#ifndef WORDS_BIGENDIAN
	num = byteswap16( num);
#endif
	memcpy( data, &num, sizeof(uint16));
	return;
}

uint32 CONVuint32( uint32 data) {
#ifndef WORDS_BIGENDIAN
	return byteswap32( data);
#else
	return data;
#endif
}

uint16 CONVuint16( uint16 data) {
#ifndef WORDS_BIGENDIAN
	return byteswap16( data);
#else
	return data;
#endif
}

uint64 CONVuint64( const uint64* data) {
#ifdef HAVE_UINT64
# ifndef WORDS_BIGENDIAN
	return byteswap64(*data);
# else
	return *data;
# endif /* WORDS_BIGENDIAN */
#else
	uint64 ret;

	memcpy( ret.i, data->i, 8);
	return ret;
#endif /* HAVE_UINT64 */
}

uint32 uint64touint32( const uint64* num) {
uint32 ret;

#ifdef HAVE_UINT64
	ret = (uint32) *num;

#else /* no native uint64 */

	memcpy( &ret, &num->i[4], 4);
# ifndef WORDS_BIGENDIAN
	ret = byteswap32(ret);
# endif
#endif /* HAVE_UINT64 */

 

 return ret;
}



