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
#include "gnutls_int.h"
#include "gnutls_algorithms.h"

/* the prototypes for these are in gnutls.h */

void gnutls_set_cipher_priority( int num, ...) {
	
	va_list ap;
	int i;
	BulkCipherAlgorithm* _ap;
	int rnum = num+1;
	
	va_start( ap, num);

	_ap = ap;

	for (i=0;i<num;i++) {
		_gnutls_cipher_set_priority( _ap[i], rnum);
		rnum--;
	}
	va_end(ap);
}

void gnutls_set_kx_priority( int num, ...) {
	
	va_list ap;
	int i;
	KXAlgorithm *_ap;
	int rnum = num+1;
	
	va_start( ap, num);

	_ap = ap;
	
	for (i=0;i<num;i++) {
		_gnutls_kx_set_priority( _ap[i], rnum);
		rnum--;
	}
	va_end(ap);
}

void gnutls_set_mac_priority( int num, ...) {
	
	va_list ap;
	int i;
	MACAlgorithm *_ap;
	int rnum = num+1;
	
	va_start( ap, num);
	_ap = ap;
	
	for (i=0;i<num;i++) {
		_gnutls_mac_set_priority( _ap[i], rnum);
		rnum--;
	}
	va_end(ap);
}