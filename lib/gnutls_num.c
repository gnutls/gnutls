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
