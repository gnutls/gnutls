/*
 *      Copyright (C) 2001 Nikos Mavroyanopoulos
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
#include <gnutls_errors.h>
#define gcry_mpi_alloc_like(x) gcry_mpi_new(gcry_mpi_get_nbits(x)) 
/* Here functions for SRP (like g^x mod n) are defined 
 */

/* Taken from gsti -- this is n 
 * g is defined to be 2
 */

#define SRP_G 2

static const uint8 diffie_hellman_group1_prime[130] = { 0x04, 0x00,
	0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xC9, 0x0F, 0xDA, 0xA2,
	0x21, 0x68, 0xC2, 0x34, 0xC4, 0xC6, 0x62, 0x8B, 0x80, 0xDC, 0x1C, 0xD1,
	0x29, 0x02, 0x4E, 0x08, 0x8A, 0x67, 0xCC, 0x74, 0x02, 0x0B, 0xBE, 0xA6,
	0x3B, 0x13, 0x9B, 0x22, 0x51, 0x4A, 0x08, 0x79, 0x8E, 0x34, 0x04, 0xDD,
	0xEF, 0x95, 0x19, 0xB3, 0xCD, 0x3A, 0x43, 0x1B, 0x30, 0x2B, 0x0A, 0x6D,
	0xF2, 0x5F, 0x14, 0x37, 0x4F, 0xE1, 0x35, 0x6D, 0x6D, 0x51, 0xC2, 0x45,
	0xE4, 0x85, 0xB5, 0x76, 0x62, 0x5E, 0x7E, 0xC6, 0xF4, 0x4C, 0x42, 0xE9,
	0xA6, 0x37, 0xED, 0x6B, 0x0B, 0xFF, 0x5C, 0xB6, 0xF4, 0x06, 0xB7, 0xED,
	0xEE, 0x38, 0x6B, 0xFB, 0x5A, 0x89, 0x9F, 0xA5, 0xAE, 0x9F, 0x24, 0x11,
	0x7C, 0x4B, 0x1F, 0xE6, 0x49, 0x28, 0x66, 0x51, 0xEC, 0xE6, 0x53, 0x81,
	0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF
};

int _gnutls_srp_gx(opaque *text, int textsize, opaque** result) {

	MPI g, prime, x, e;
	size_t n = sizeof diffie_hellman_group1_prime;
	int result_size;
	
	if (gcry_mpi_scan(&prime, GCRYMPI_FMT_USG,
			  diffie_hellman_group1_prime, &n)) {
		gnutls_assert();
		return -1;
	}
	if (gcry_mpi_scan(&x, GCRYMPI_FMT_USG,
			  text, &textsize)) {
		gnutls_assert();
		mpi_release(prime);
		return -1;
	}

	g = mpi_set_ui(NULL, SRP_G);

	/* e = g^x mod prime */
	e = gcry_mpi_alloc_like(prime);

	mpi_powm(e, g, x, prime);

	mpi_release(prime);
	mpi_release(x);

	gcry_mpi_print(GCRYMPI_FMT_USG, NULL, &result_size, e);
	if (result!=NULL) {
		*result = gnutls_malloc(result_size);
		gcry_mpi_print(GCRYMPI_FMT_USG, *result, &result_size, e);	
	}
	mpi_release(e);
	return result_size;

}
