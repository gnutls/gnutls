/*
 *      Copyright (C) 2001 Nikos Mavroyanopoulos
 *
 * This file is part of GNUTLS.
 *
 * GNUTLS-EXTRA is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * GNUTLS-EXTRA is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA
 */

/* Functions for operating in an SRP passwd file are included here */

#include "gnutls_int.h"

#ifdef ENABLE_SRP

#include "x509_b64.h"
#include "gnutls_errors.h"
#include "auth_srp_passwd.h"
#include "auth_srp.h"
#include "gnutls_auth_int.h"
#include "gnutls_srp.h"
#include "gnutls_random.h"
#include "gnutls_dh.h"
#include "debug.h"
#include <gnutls_str.h>

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

	if (_gnutls_mpi_scan(&entry->v, verifier, &verifier_size) || entry->v == NULL) {
		gnutls_assert();
		gnutls_free( entry->salt);
		return GNUTLS_E_MPI_SCAN_FAILED;
	}

	gnutls_free( verifier);

	/* now go for username */
	*p='\0';

	entry->username = gnutls_strdup(str);
	if (entry->username==NULL) {
		gnutls_free( entry->salt);
		gnutls_assert();
		return GNUTLS_E_MEMORY_ERROR;
	}

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
	if (_gnutls_mpi_scan(&entry->g, tmp, &tmp_size) || entry->g==NULL) {
		gnutls_assert();
		gnutls_free(tmp);
		return GNUTLS_E_MPI_SCAN_FAILED;
	}

	gnutls_free(tmp);


	/* now go for n - modulo */
	p = rindex( str, ':'); /* we have n */
	if (p==NULL) {
		_gnutls_mpi_release(&entry->g);
		gnutls_assert();
		return GNUTLS_E_PARSING_ERROR;
	}
	
	*p='\0';
	p++;
	
	len = strlen(p);
	tmp_size = _gnutls_sbase64_decode( p, len, &tmp);

	if (tmp_size < 0) {
		gnutls_assert();
		_gnutls_mpi_release(&entry->g);
		return GNUTLS_E_PARSING_ERROR;
	}
	if (_gnutls_mpi_scan(&entry->n, tmp, &tmp_size) || entry->n==NULL) {
		gnutls_assert();
		gnutls_free(tmp);
		_gnutls_mpi_release(&entry->g);
		return GNUTLS_E_MPI_SCAN_FAILED;
	}

	gnutls_free(tmp);

	return 0;
}


/* this function opens the tpasswd.conf file
 */
static int pwd_read_conf( const char* pconf_file, GNUTLS_SRP_PWD_ENTRY* entry, int index) {
	FILE * fd;
	char line[2*1024];
	int i;
	char indexstr[10];

	sprintf( indexstr, "%d", index); /* Flawfinder: ignore */

	fd = fopen( pconf_file, "r");
	if (fd==NULL) {
		gnutls_assert();
		return GNUTLS_E_FILE_ERROR;
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


GNUTLS_SRP_PWD_ENTRY *_gnutls_srp_pwd_read_entry( GNUTLS_STATE state, char* username, int *err) {
	const GNUTLS_SRP_SERVER_CREDENTIALS cred;
	FILE * fd;
	char line[2*1024];
	int i, len;
	GNUTLS_SRP_PWD_ENTRY * entry = gnutls_malloc(sizeof(GNUTLS_SRP_PWD_ENTRY));
	int index;
	int pwd_index = 0;
	
	if (entry==NULL) {
		gnutls_assert();
		*err = 1;
		return NULL;
	}

	*err = 0; /* normal exit */
	
	cred = _gnutls_get_cred( state->gnutls_key, GNUTLS_CRD_SRP, NULL);
	if (cred==NULL) {
		*err = 1;
		gnutls_assert();
		gnutls_free(entry);
		return NULL;
	}

	if (cred->password_files<=0) {
		gnutls_assert();
		return NULL;
	}
	
	/* use the callback to select a password file */
	if (state->gnutls_internals.server_srp_callback!=NULL) {
		pwd_index = state->gnutls_internals.server_srp_callback(
			state, cred->password_file, cred->password_conf_file,
				cred->password_files);

		if (pwd_index < 0) {
			gnutls_assert();
			return NULL;
		}
	}

	fd = fopen( cred->password_file[pwd_index], "r");
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
				if (pwd_read_conf( cred->password_conf_file[pwd_index], entry, index)==0) {
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
	GNUTLS_SRP_PWD_ENTRY * pwd_entry = gnutls_calloc(1, sizeof(GNUTLS_SRP_PWD_ENTRY));
	
	if (pwd_entry == NULL) {
		gnutls_assert(); 
		return NULL;
	}
	
	pwd_entry->g = _gnutls_get_rnd_srp_params( &pwd_entry->n, 1024);
	if (pwd_entry->g==NULL || pwd_entry->n==NULL) {
		gnutls_assert();
		_gnutls_srp_clear_pwd_entry( pwd_entry);
		return NULL;
	}
	
	pwd_entry->username = gnutls_malloc(strlen(RNDUSER)+1);
	if (pwd_entry->username == NULL) {
		gnutls_assert();
		_gnutls_srp_clear_pwd_entry( pwd_entry);
		return NULL;
	}
	_gnutls_str_cpy( pwd_entry->username, MAX_SRP_USERNAME, RNDUSER); /* Flawfinder: ignore */
	
	pwd_entry->v = _gnutls_mpi_new(160);
	if (pwd_entry->v==NULL) {
		gnutls_assert();
		_gnutls_srp_clear_pwd_entry( pwd_entry);
		return NULL;
	}

        _gnutls_mpi_randomize( pwd_entry->v, 160, GCRY_WEAK_RANDOM);

	pwd_entry->salt_size = RND_SALT_SIZE;
	
	pwd_entry->salt = gnutls_malloc(RND_SALT_SIZE);
	if (pwd_entry->salt==NULL) {
		gnutls_assert();
		_gnutls_srp_clear_pwd_entry( pwd_entry);
		return NULL;
	}
	
	if (_gnutls_get_random(pwd_entry->salt, RND_SALT_SIZE, GNUTLS_WEAK_RANDOM) < 0) {
		gnutls_assert();
		_gnutls_srp_clear_pwd_entry( pwd_entry);
		return NULL;
	}
	
	pwd_entry->algorithm = 0;

	return pwd_entry;

}

void _gnutls_srp_clear_pwd_entry( GNUTLS_SRP_PWD_ENTRY * entry) {
	_gnutls_mpi_release(&entry->v);
	_gnutls_mpi_release(&entry->g);
	_gnutls_mpi_release(&entry->n);
	
	gnutls_free(entry->salt);
	gnutls_free(entry->username);
	
	gnutls_free(entry);
	
	return;
}

/* Generates a prime and a generator, and returns the srpbase64 encoded value.
 */
int _gnutls_srp_generate_prime(opaque ** ret_g, opaque ** ret_n, int bits)
{

	GNUTLS_MPI prime, g;
	int siz;
	char *tmp;

	if ( _gnutls_dh_generate_prime(&g, &prime, bits) < 0) {
		gnutls_assert();
		return GNUTLS_E_MEMORY_ERROR;
	}

	siz = 0;
	_gnutls_mpi_print( NULL, &siz, g);
	if (ret_g != NULL) {
		tmp = gnutls_malloc(siz);
		if (tmp==NULL) return GNUTLS_E_MEMORY_ERROR;
		
		_gnutls_mpi_print( tmp, &siz, g);

		if (_gnutls_sbase64_encode(tmp, siz, ret_g) < 0) {
			gnutls_free(tmp);
			return GNUTLS_E_UNKNOWN_ERROR;
		}
		gnutls_free(tmp);
	}

	siz = 0;
	_gnutls_mpi_print( NULL, &siz, prime);
	if (ret_n != NULL) {
		tmp = gnutls_malloc(siz);
		if (tmp==NULL) return GNUTLS_E_MEMORY_ERROR;

		_gnutls_mpi_print( tmp, &siz, prime);
		if (_gnutls_sbase64_encode(tmp, siz, ret_n) < 0) {
			gnutls_free(tmp);
			return GNUTLS_E_UNKNOWN_ERROR;
		}

		gnutls_free(tmp);
	}

	_gnutls_mpi_release(&g);
	_gnutls_mpi_release(&prime);

	return 0;

}

#endif /* ENABLE SRP */
