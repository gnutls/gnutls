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

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include "prime-gaa.h"
#include <gcrypt.h>
#include <gnutls/gnutls.h>
#include "../lib/defines.h"

MPI _gcry_generate_elg_prime( int mode, unsigned pbits, unsigned qbits,
	                MPI g, MPI **ret_factors );

int main(int argc, char **argv)
{
	gaainfo info;
	int size, i, qbits;
	MPI prime;
	gnutls_datum _prime, _generator;
	uint8 * tmp1, *tmp2;
	MPI g;

	if (gaa(argc, argv, &info) != -1) {
		fprintf(stderr, "Error in the arguments.\n");
		return -1;
	}
	
	gnutls_global_init();

	fprintf(stderr, "Generating DH parameters...");
	gcry_control (GCRYCTL_SET_VERBOSITY, (int)0);
	
	/* this is an emulation of Michael Wiener's table
	 * bad emulation.
	 */
	qbits = 120 + ( ((info.bits/256)-1)*20 );
	if( qbits & 1 ) /* better have a even one */
	qbits++;

	g = mpi_new(16);
	prime = _gcry_generate_elg_prime( 0, info.bits, qbits, g, NULL);

	/* print generator */
	size = 0;
	gcry_mpi_print(GCRYMPI_FMT_USG, NULL, &size, g);

	tmp1 = malloc(size);
   	gcry_mpi_print(GCRYMPI_FMT_USG, tmp1, &size, g);

	_generator.data = tmp1;
	_generator.size = size;

	if (info.cparams) {
		printf( "/* generator - %d bits */\n", gcry_mpi_get_nbits(g)); 
		printf( "\nconst uint8 g[%d] = { ", size);
	
		for (i=0;i<size;i++) {
			if (i%7==0) printf("\n\t");
			printf( "0x%.2x", tmp1[i]);
			if (i!=size-1) printf( ", ");
		}

		printf("\n};\n\n");
	} else {
		printf( "\nGenerator: ");
	
		for (i=0;i<size;i++) {
			if (i!=0 && i%12==0) printf("\n\t");
			else if (i!=0 && i!=size) printf( ":");

			printf( "%.2x", tmp1[i]);
		}

		printf("\n\n");
	}

	/* print prime */
	size = 0;
	gcry_mpi_print(GCRYMPI_FMT_USG, NULL, &size, prime);

	tmp2 = malloc(size);
   	gcry_mpi_print(GCRYMPI_FMT_USG, tmp2, &size, prime);

	_prime.data = tmp2;
	_prime.size = size;

	if (info.cparams) {
		printf( "/* prime - %d bits */\n",  gcry_mpi_get_nbits(prime)); 
		printf( "\nconst uint8 prime[%d] = { ", size);
	
		for (i=0;i<size;i++) {
			if (i%7==0) printf("\n\t");
			printf( "0x%.2x", tmp2[i]);
			if (i!=size-1) printf( ", ");
		}

		printf("\n};\n");
	} else {
		printf( "Prime: ");

		for (i=0;i<size;i++) {
			if (i!=0 && i%12==0) printf("\n\t");
			else if (i!=0 && i!=size) printf( ":");
			printf( "%.2x", tmp2[i]);
		}

		printf("\n\n");

	}

	if (!info.cparams) { /* generate a PKCS#3 structure */
	
		unsigned char out[2048];
		int ret, len = sizeof(out);
	
		ret = gnutls_pkcs3_export_dh_params( &_prime, &_generator, GNUTLS_X509_FMT_PEM,
			out, &len);
	
		if (ret == 0) {
			printf("\n%s", out);
		} else {
			fprintf(stderr, "Error: %s\n", gnutls_strerror(ret));
		}

	}

	gnutls_global_deinit();
	
	return 0;
}
