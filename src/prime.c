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
#include "../lib/defines.h"
#include "../lib/gnutls_int.h"
#include "../lib/gnutls_srp.h"
#include "../lib/crypt.h"
#include "../lib/cert_b64.h"
#include "prime-gaa.h"

MPI generate_public_prime( unsigned  nbits );

int main(int argc, char **argv)
{
	gaainfo info;
	int size, i;
	MPI prime;
	uint8 * tmp;
	
	if (gaa(argc, argv, &info) != -1) {
		fprintf(stderr, "Error in the arguments.\n");
		return -1;
	}

	prime = generate_public_prime( info.bits);

	size = 0;
	gcry_mpi_print(GCRYMPI_FMT_USG, NULL, &size, prime);
	
	tmp = malloc(size);
   	gcry_mpi_print(GCRYMPI_FMT_USG, tmp, &size, prime);

	printf( "/* prime - %d bits */\n", info.bits); 
	printf( "\nconst uint8 prime[%d] = { ", size);
	
	for (i=0;i<size;i++) {
		if (i%7==0) printf("\n\t");
		printf( "0x%.2x", tmp[i]);
		if (i!=size-1) printf( ", ");
	}

	printf("\n};\n");
	free(tmp);
	
	return 0;
}
