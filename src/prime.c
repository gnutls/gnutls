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
#include <gnutls/gnutls.h>
#include "../lib/defines.h"

int main(int argc, char **argv)
{
	gaainfo info;
	unsigned int i;
	gnutls_dh_params dh_params;
	gnutls_datum p, g;

	if (gaa(argc, argv, &info) != -1) {
		fprintf(stderr, "Error in the arguments.\n");
		return -1;
	}
	
	gnutls_global_init();
	
	gnutls_dh_params_init( &dh_params);

	fprintf(stderr, "Generating DH parameters...");
	
	gnutls_dh_params_generate2( dh_params, info.bits);
	gnutls_dh_params_export_raw( dh_params, &p, &g, NULL);

	if (info.cparams) {

		printf( "/* generator */\n"); 
		printf( "\nconst uint8 g[%d] = { ", g.size);
	
		for (i=0;i<g.size;i++) {
			if (i%7==0) printf("\n\t");
			printf( "0x%.2x", g.data[i]);
			if (i!=g.size-1) printf( ", ");
		}

		printf("\n};\n\n");
	} else {
		printf( "\nGenerator: ");
	
		for (i=0;i<g.size;i++) {
			if (i!=0 && i%12==0) printf("\n\t");
			else if (i!=0 && i!=g.size) printf( ":");

			printf( "%.2x", g.data[i]);
		}

		printf("\n\n");
	}

	/* print prime */

	if (info.cparams) {
		printf( "/* prime - %d bits */\n", p.size*8);
		printf( "\nconst uint8 prime[%d] = { ", p.size);
	
		for (i=0;i<p.size;i++) {
			if (i%7==0) printf("\n\t");
			printf( "0x%.2x", p.data[i]);
			if (i!=p.size-1) printf( ", ");
		}

		printf("\n};\n");
	} else {
		printf( "Prime: ");

		for (i=0;i<p.size;i++) {
			if (i!=0 && i%12==0) printf("\n\t");
			else if (i!=0 && i!=p.size) printf( ":");
			printf( "%.2x", p.data[i]);
		}

		printf("\n\n");

	}

	if (!info.cparams) { /* generate a PKCS#3 structure */
	
		unsigned char out[5*1024];
		int ret, len = sizeof(out);
	
		ret = gnutls_dh_params_export_pkcs3( dh_params, GNUTLS_X509_FMT_PEM,
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
