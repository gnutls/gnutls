/*
 *      Copyright (C) 2000,2001,2002 Nikos Mavroyanopoulos
 *
 * This file is part of GNUTLS.
 *           someday was part of gsti
 *
 *  The GNUTLS library is free software; you can redistribute it and/or
 *  modify it under the terms of the GNU Lesser General Public   
 *  License as published by the Free Software Foundation; either 
 *  version 2.1 of the License, or (at your option) any later version.
 *
 *  This library is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of 
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 *  Lesser General Public License for more details.
 *
 *  You should have received a copy of the GNU Lesser General Public
 *  License along with this library; if not, write to the Free Software
 *  Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA 02111-1307  USA
 *
 */

#include <gnutls_int.h>
#include <gnutls_errors.h>


/* 
	--Example-- 
	you: X = g ^ x mod p;
	peer:Y = g ^ y mod p;

	your_key = Y ^ x mod p;
	his_key  = X ^ y mod p;

//      generate our secret and the public value (X) for it
	X = gnutls_calc_dh_secret(&x, g, p);
//      now we can calculate the shared secret
	key = gnutls_calc_dh_key(Y, x, g, p);
	_gnutls_mpi_release(x);
	_gnutls_mpi_release(g);
*/

#define MAX_BITS 12000

/* returns the public value (X), and the secret (ret_x).
 */
GNUTLS_MPI gnutls_calc_dh_secret(GNUTLS_MPI * ret_x, GNUTLS_MPI g, GNUTLS_MPI prime)
{
	GNUTLS_MPI e, x;
	int x_size = _gnutls_mpi_get_nbits(prime) - 1;
	/* The size of the secret key is less than
	 * prime/2
	 */

	if (x_size > MAX_BITS || x_size <= 0) {
		gnutls_assert();
		return NULL;
	}

	x = _gnutls_mpi_new(x_size);
	if (x == NULL) {
		gnutls_assert();
		if (ret_x)
			*ret_x = NULL;

		return NULL;
	}

	/* (x_size/8)*8 is there to overcome a bug in libgcrypt
	 * which does not really check the bits given but the bytes.
	 */
	_gnutls_mpi_randomize(x, (x_size/8)*8, GCRY_STRONG_RANDOM);

	e = _gnutls_mpi_alloc_like(prime);
	if (e == NULL) {
		gnutls_assert();
		if (ret_x)
			*ret_x = NULL;

		_gnutls_mpi_release( &x);
		return NULL;
	}

	_gnutls_mpi_powm(e, g, x, prime);

	if (ret_x)
		*ret_x = x;
	else
		_gnutls_mpi_release(&x);
	return e;
}


GNUTLS_MPI gnutls_calc_dh_key(GNUTLS_MPI f, GNUTLS_MPI x, GNUTLS_MPI prime)
{
	GNUTLS_MPI k;
	int bits;
	
	bits = _gnutls_mpi_get_nbits(prime);
	if (bits <= 0 || bits > MAX_BITS) {
		gnutls_assert();
		return NULL;
	}

	k = _gnutls_mpi_alloc_like(prime);
	if (k == NULL)
		return NULL;
	_gnutls_mpi_powm(k, f, x, prime);
	return k;
}

