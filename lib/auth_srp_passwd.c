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

/* Functions for operating in an SRP passwd file are included here */

#include "defines.h"
#include "gnutls_int.h"
#include "cert_b64.h"
#include "gnutls_errors.h"
#include "auth_srp_passwd.h"
#include "auth_srp.h"
#include "gnutls_auth_int.h"
#include "gnutls_srp.h"
#include "gnutls_random.h"
#include "debug.h"

/* this function parses tpasswd.conf file. Format is:
 * string(username):base64(v):base64(salt):int(index)
 */
static int pwd_put_values( GNUTLS_SRP_PWD_ENTRY *entry, char *str, int str_size) {
char * p, *p2;
int len;
opaque *verifier;
int verifier_size;
int indx;

	p = rindex( str, ':'); /* we have index */
	if (p==NULL) {
		gnutls_assert();
		return GNUTLS_E_PARSING_ERROR;
	}
	
	*p='\0';
	p++;

	len = strlen(p);
	indx = atoi(p);
	if (indx==0) {
		gnutls_assert();
		return GNUTLS_E_PARSING_ERROR;
	}
	
	/* now go for salt */
	p = rindex( str, ':'); /* we have salt */
	if (p==NULL) {
		gnutls_assert();
		return GNUTLS_E_PARSING_ERROR;
	}
	
	*p='\0';
	p++;
	
	len = strlen(p);
	
	entry->salt_size = _gnutls_sbase64_decode( p, len, &entry->salt);

	if (entry->salt_size <= 0) {
		gnutls_assert();
		return GNUTLS_E_PARSING_ERROR;
	}

	/* now go for verifier */
	p = rindex( str, ':'); /* we have verifier */
	if (p==NULL) {
		gnutls_free(entry->salt);
		return GNUTLS_E_PARSING_ERROR;
	}
	
	*p='\0';
	p++;

	if ( (p2 = index(p, '$')) == NULL) {
		entry->algorithm = SRPSHA1_CRYPT;
	} else {
		p++;
		entry->algorithm = atoi(p);
		p2 = index(p, '$'); /* find the last $ */
		if (p2==NULL) {
			gnutls_assert();
			gnutls_free(entry->salt);
			return GNUTLS_E_PARSING_ERROR;
		}
		p = p2+1;
	}

	len = strlen(p);
	verifier_size = _gnutls_sbase64_decode( p, len, &verifier);
	if (verifier_size <= 0) {
		gnutls_assert();
		gnutls_free(entry->salt);
		return GNUTLS_E_PARSING_ERROR;
	}

	if (gcry_mpi_scan(&entry->v, GCRYMPI_FMT_USG, verifier, &verifier_size)) {
		gnutls_assert();
		gnutls_free(entry->salt);
		return GNUTLS_E_MPI_SCAN_FAILED;
	}


	/* now go for username */
	*p='\0';

	entry->username = strdup(str);

	return indx;
}


/* this function parses tpasswd.conf file. Format is:
 * int(index):base64(n):int(g)
 */
static int pwd_put_values2( GNUTLS_SRP_PWD_ENTRY *entry, char *str, int str_size) {
char * p;
int len;
opaque * tmp;
int tmp_size;

	p = rindex( str, ':'); /* we have g */
	if (p==NULL) {
		gnutls_assert();
		return GNUTLS_E_PARSING_ERROR;
	}
	
	*p='\0';
	p++;
	
	/* read the generator */
	len = strlen(p);
	if (p[len-1]=='\n' || p[len-1]==' ') len--;
	tmp_size = _gnutls_sbase64_decode( p, len, &tmp);

	if (tmp_size < 0) {
		gnutls_assert();
		return GNUTLS_E_PARSING_ERROR;
	}
	if (gcry_mpi_scan(&entry->g, GCRYMPI_FMT_USG, tmp, &tmp_size)) {
		gnutls_assert();
		gnutls_free(tmp);
		return GNUTLS_E_MPI_SCAN_FAILED;
	}

	gnutls_free(tmp);


	/* now go for n - modulo */
	p = rindex( str, ':'); /* we have n */
	if (p==NULL) {
		mpi_release(entry->g);
		gnutls_assert();
		return GNUTLS_E_PARSING_ERROR;
	}
	
	*p='\0';
	p++;
	
	len = strlen(p);
	tmp_size = _gnutls_sbase64_decode( p, len, &tmp);

	if (tmp_size < 0) {
		gnutls_assert();
		mpi_release(entry->g);
		return GNUTLS_E_PARSING_ERROR;
	}
	if (gcry_mpi_scan(&entry->n, GCRYMPI_FMT_USG, tmp, &tmp_size)) {
		gnutls_assert();
		gnutls_free(tmp);
		mpi_release(entry->g);
		return GNUTLS_E_MPI_SCAN_FAILED;
	}

	gnutls_free(tmp);

	return 0;
}


/* this function opens the tpasswd.conf file
 */
static int pwd_read_conf( const SRP_SERVER_CREDENTIALS* cred, GNUTLS_SRP_PWD_ENTRY* entry, int index) {
	FILE * fd;
	char line[5*1024];
	int i;
	char indexstr[10];

	sprintf( indexstr, "%d", index);

	fd = fopen( cred->password_conf_file, "r");
	if (fd==NULL) {
		gnutls_assert();
		gnutls_free(entry);
		return GNUTLS_E_PWD_ERROR;
	}

	while( fgets( line, sizeof(line), fd) != NULL) {
    /* move to first ':' */
	    i=0;
	    while( (line[i]!=':') && (line[i]!='\0') && (i < sizeof(line)) ) {
	            i++;
	    }
	    if (strncmp( indexstr, line, strlen(indexstr)) == 0) {
			if ((index = pwd_put_values2( entry, line, strlen(line))) >= 0)
				return 0;
			else {
				return GNUTLS_E_PWD_ERROR;
			}
	    }
    }
    return GNUTLS_E_PWD_ERROR;
	
}


GNUTLS_SRP_PWD_ENTRY *_gnutls_srp_pwd_read_entry( GNUTLS_KEY key, char* username, int *err) {
	const SRP_SERVER_CREDENTIALS* cred;
	FILE * fd;
	char line[5*1024];
	int i, len;
	GNUTLS_SRP_PWD_ENTRY * entry = gnutls_malloc(sizeof(GNUTLS_SRP_PWD_ENTRY));
	int index;

	*err = 0; /* normal exit */
	
	cred = _gnutls_get_cred( key, GNUTLS_SRP, NULL);
	if (cred==NULL) {
		*err = 1;
		gnutls_assert();
		gnutls_free(entry);
		return NULL;
	}

	fd = fopen( cred->password_file, "r");
	if (fd==NULL) {
		*err = 1; /* failed due to critical error */
		gnutls_assert();
		gnutls_free(entry);
		return NULL;
	}

	while( fgets( line, sizeof(line), fd) != NULL) {
	    /* move to first ':' */
	    i=0;
	    while( (line[i]!=':') && (line[i]!='\0') && (i < sizeof(line)) ) {
	            i++;
	    }
	    len = strlen(username);
	    if (strncmp( username, line, (i>len)?i:len) == 0) {
			if ((index = pwd_put_values( entry, line, strlen(line))) >= 0)
				if (pwd_read_conf( cred, entry, index)==0) {
					return entry;
				} else {
					gnutls_free(entry);
					return NULL;
				}
			else {
				gnutls_free(entry);
				return NULL;
			}
	    }
    }
    return NULL;
	
}
#define RNDUSER "rnd"
#define RND_SALT_SIZE 17
GNUTLS_SRP_PWD_ENTRY* _gnutls_randomize_pwd_entry() {
	GNUTLS_SRP_PWD_ENTRY * pwd_entry = gnutls_malloc(sizeof(GNUTLS_SRP_PWD_ENTRY));
	size_t n = sizeof diffie_hellman_group1_prime;
	opaque * rand;
	
	pwd_entry->username = gnutls_malloc(strlen(RNDUSER)+1);
	strcpy( pwd_entry->username, RNDUSER);
	
	pwd_entry->g = gcry_mpi_set_ui(NULL, SRP_G);
	pwd_entry->v = gcry_mpi_new(160);
        gcry_mpi_randomize( pwd_entry->v, 160, GCRY_WEAK_RANDOM);

	if (gcry_mpi_scan(&pwd_entry->n, GCRYMPI_FMT_USG,
                          diffie_hellman_group1_prime, &n)) {
                gnutls_assert();
   	        return NULL;
	}

	pwd_entry->salt_size = RND_SALT_SIZE;
	rand = _gnutls_get_random(RND_SALT_SIZE, GNUTLS_WEAK_RANDOM);
	pwd_entry->salt = gnutls_malloc(RND_SALT_SIZE);
	memcpy( pwd_entry->salt, rand, RND_SALT_SIZE);
	_gnutls_free_rand( rand);
	
	pwd_entry->algorithm = 0;

	return pwd_entry;
}

void _gnutls_srp_clear_pwd_entry( GNUTLS_SRP_PWD_ENTRY * entry) {
	mpi_release(entry->v);
	mpi_release(entry->g);
	mpi_release(entry->n);
	
	gnutls_free(entry->salt);
	gnutls_free(entry->username);
	
	gnutls_free(entry);
	
	return;
}
