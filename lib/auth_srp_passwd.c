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

static int pwd_put_values( GNUTLS_SRP_PWD_ENTRY *entry, char *str, int str_size) {
char * p;
int len;
opaque *verifier;
int verifier_size;

	p = strrchr( str, '$'); /* we have n */
	if (p==NULL) return -1;
	
	*p='\0';
	p++;
	
	len = strlen(p);
	if (gcry_mpi_scan(&entry->n, GCRYMPI_FMT_HEX, p, &len)) {
		gnutls_assert();
		return -1;
	}

	/* now go for g */
	p = strrchr( str, '$'); /* we have g */
	if (p==NULL) {
		mpi_release(entry->n);
		return -1;
	}
	
	*p='\0';
	p++;
	
	len = strlen(p);
	if (gcry_mpi_scan(&entry->g, GCRYMPI_FMT_HEX, p, &len)) {
		gnutls_assert();
		mpi_release(entry->n);
		return -1;
	}

	/* now go for verifier */
	p = strrchr( str, '$'); /* we have verifier */
	if (p==NULL) {
		mpi_release(entry->n);
		mpi_release(entry->g);
		return -1;
	}
	
	*p='\0';
	p++;
	
	len = strlen(p);
	verifier_size = _gnutls_base64_decode( p, len, &verifier);
	if (verifier_size < 0) {
		gnutls_assert();
		mpi_release(entry->n);
		mpi_release(entry->g);
		return -1;
	}

	if (gcry_mpi_scan(&entry->v, GCRYMPI_FMT_USG, verifier, &verifier_size)) {
		gnutls_assert();
		mpi_release(entry->n);
		mpi_release(entry->g);
		return -1;
	}


	/* now go for salt */
	p = strrchr( str, '$'); /* we have salt */
	if (p==NULL) {
		mpi_release(entry->n);
		mpi_release(entry->g);
		mpi_release(entry->v);
		return -1;
	}
	
	*p='\0';
	p++;

	len = strlen(p);
	entry->salt_size = _gnutls_base64_decode( p, len, &entry->salt);
	if (entry->salt_size < 0) {
		gnutls_assert();
		mpi_release(entry->n);
		mpi_release(entry->v);
		mpi_release(entry->g);
	}

	/* now go for algorithm */
	p = strrchr( str, '$'); /* we have algorithm */
	if (p==NULL) {
		mpi_release(entry->n);
		mpi_release(entry->g);
		mpi_release(entry->v);
		gnutls_free(entry->salt);
		return -1;
	}
	
	*p='\0';
	p++;

	entry->algorithm = atoi(p);

	/* now go for username */
	p = strchr( str, ':'); /* we have algorithm */
	if (p==NULL) {
		mpi_release(entry->n);
		mpi_release(entry->g);
		mpi_release(entry->v);
		gnutls_free(entry->salt);
		return -1;
	}
	*p='\0';

	entry->username = strdup(p);

	return 0;
}

GNUTLS_SRP_PWD_ENTRY *_gnutls_srp_pwd_read_entry( GNUTLS_KEY key, char* username) {
	SRP_SERVER_CREDENTIALS* cred;
	FILE * fd;
	char line[5*1024];
	int i;
	GNUTLS_SRP_PWD_ENTRY * entry = gnutls_malloc(sizeof(GNUTLS_SRP_PWD_ENTRY));
	
	cred = _gnutls_get_kx_cred( key, GNUTLS_KX_SRP);

	fd = fopen( cred->password_file, "r");
	if (fd==NULL) {
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
	    if (strncmp( username, line, i) == 0) {
			if (pwd_put_values( entry, line, sizeof(line)-i)==0)
				return entry;
			else {
				gnutls_free(entry);
				return NULL;
			}
	    }
    }
	return NULL;
	
}

#define RND_SALT_SIZE 16
GNUTLS_SRP_PWD_ENTRY* _gnutls_randomize_pwd_entry() {
	GNUTLS_SRP_PWD_ENTRY * pwd_entry = gnutls_malloc(sizeof(GNUTLS_SRP_PWD_ENTRY));
	size_t n = sizeof diffie_hellman_group1_prime;
	opaque * rand;
	
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
