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
#include "../lib/gnutls.h"
#include "gaa.h"

int verify_passwd(char *file, char* username, char* passwd) {
	FILE* fd;
	char line[513];
	int i;
	
	fd = fopen( file, "r");
	if (fd==NULL) {
		fprintf(stderr, "Cannot open file '%s'\n", file);
		return -1;
	}

	while( fgets( line, sizeof(line), fd) != NULL) {
		/* move to first ':' */
		i=0;
		while( (line[i]!=':') && (line[i]!='\0') && (i < sizeof(line)) ) {
			i++;
		}
		if (strncmp( username, line, i) == 0) {
				if (gnutls_crypt_vrfy( username, passwd, &line[++i]) == 0) {
					fprintf(stderr, "Password verified\n");
				} else {
					fprintf(stderr, "Password does NOT match\n");
				}
				return 0;
		}
	}

	fclose(fd);
	return -1;
	
}

int main(int argc, char** argv) {
gaainfo info;
char* passwd;
char* cr=NULL;

	if ( gaa(argc, argv, &info) != -1) {
        	fprintf(stderr, "Error in the arguments.\n");
	        return -1;
    }
       
    passwd = getpass("Enter password: ");
        
    if (info.passwd != NULL) {
     	verify_passwd( info.passwd, info.username, passwd);
     	free(cr);
     	return 0;
    }

    cr = gnutls_crypt( info.username, passwd, BLOWFISH_CRYPT);
    printf("%s:%s\n", info.username, cr);
    free(cr);
	return 0;


}