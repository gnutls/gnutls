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
	uint8 * tmp;
	MPI g;

	if (gaa(argc, argv, &info) != -1) {
		fprintf(stderr, "Error in the arguments.\n");
		return -1;
	}
	
	gnutls_global_init();

	fprintf(stderr, "Generating prime...");
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

	tmp = malloc(size);
   	gcry_mpi_print(GCRYMPI_FMT_USG, tmp, &size, g);

	printf( "/* generator - %d bits */\n", gcry_mpi_get_nbits(g)); 
	printf( "\nconst uint8 g[%d] = { ", size);
	
	for (i=0;i<size;i++) {
		if (i%7==0) printf("\n\t");
		printf( "0x%.2x", tmp[i]);
		if (i!=size-1) printf( ", ");
	}

	printf("\n};\n\n");
	free(tmp);

	/* print prime */
	size = 0;
	gcry_mpi_print(GCRYMPI_FMT_USG, NULL, &size, prime);

	tmp = malloc(size);
   	gcry_mpi_print(GCRYMPI_FMT_USG, tmp, &size, prime);

	printf( "/* prime - %d bits */\n",  gcry_mpi_get_nbits(prime)); 
	printf( "\nconst uint8 prime[%d] = { ", size);
	
	for (i=0;i<size;i++) {
		if (i%7==0) printf("\n\t");
		printf( "0x%.2x", tmp[i]);
		if (i!=size-1) printf( ", ");
	}

	printf("\n};\n");
	free(tmp);

	gnutls_global_deinit();
	
	return 0;
}
