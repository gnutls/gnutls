/*
 * Copyright (C) 2001 Nikos Mavroyanopoulos
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
#include <gnutls_datum.h>

/* this function parses tpasswd.conf file. Format is:
 * string(username):base64(v):base64(salt):int(index)
 */
static int pwd_put_values( SRP_PWD_ENTRY *entry, char *str) {
char * p;
int len, ret;
opaque *verifier;
size_t verifier_size;
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

	entry->salt.size = _gnutls_sbase64_decode( p, len, &entry->salt.data);

	if (entry->salt.size <= 0) {
		gnutls_assert();
		return GNUTLS_E_PARSING_ERROR;
	}

	/* now go for verifier */
	p = rindex( str, ':'); /* we have verifier */
	if (p==NULL) {
		_gnutls_free_datum(&entry->salt);
		return GNUTLS_E_PARSING_ERROR;
	}
	
	*p='\0';
	p++;

	len = strlen(p);
	ret = _gnutls_sbase64_decode( p, len, &verifier);
	if (ret <= 0) {
		gnutls_assert();
		_gnutls_free_datum(&entry->salt);
		return GNUTLS_E_PARSING_ERROR;
	}

	verifier_size = ret;
	entry->v.data = verifier;
	entry->v.size = verifier_size;

	/* now go for username */
	*p='\0';

	entry->username = gnutls_strdup(str);
	if (entry->username==NULL) {
		_gnutls_free_datum( &entry->salt);
		_gnutls_free_datum( &entry->v);
		gnutls_assert();
		return GNUTLS_E_MEMORY_ERROR;
	}

	return indx;
}


/* this function parses tpasswd.conf file. Format is:
 * int(index):base64(n):int(g)
 */
static int pwd_put_values2( SRP_PWD_ENTRY *entry, char *str) 
{
char * p;
int len;
opaque * tmp;
int ret;

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
	ret = _gnutls_sbase64_decode( p, len, &tmp);

	if (ret < 0) {
		gnutls_assert();
		return GNUTLS_E_PARSING_ERROR;
	}

	entry->g.data = tmp;
	entry->g.size = ret;

	/* now go for n - modulo */
	p = rindex( str, ':'); /* we have n */
	if (p==NULL) {
		_gnutls_free_datum( &entry->g);
		gnutls_assert();
		return GNUTLS_E_PARSING_ERROR;
	}
	
	*p='\0';
	p++;
	
	len = strlen(p);
	ret = _gnutls_sbase64_decode( p, len, &tmp);

	if (ret < 0) {
		gnutls_assert();
		_gnutls_free_datum( &entry->g);
		return GNUTLS_E_PARSING_ERROR;
	}
	
	entry->n.data = tmp;
	entry->n.size = ret;

	return 0;
}


/* this function opens the tpasswd.conf file
 */
static int pwd_read_conf( const char* pconf_file, SRP_PWD_ENTRY* entry, int index) {
	FILE * fd;
	char line[2*1024];
	uint i;
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
			if ((index = pwd_put_values2( entry, line)) >= 0)
				return 0;
			else {
				return GNUTLS_E_PWD_ERROR;
			}
	    }
    }
    return GNUTLS_E_PWD_ERROR;
	
}


SRP_PWD_ENTRY *_gnutls_srp_pwd_read_entry( gnutls_session state, char* username, int *err) {
	const gnutls_srp_server_credentials cred;
	FILE * fd;
	char line[2*1024];
	uint i, len;
	SRP_PWD_ENTRY * entry;
	int index, pwd_index = 0, ret;

	entry = gnutls_calloc(1, sizeof(SRP_PWD_ENTRY));
	if (entry==NULL) {
		gnutls_assert();
		*err = 1;
		return NULL;
	}

	*err = 0; /* normal exit */
	
	cred = _gnutls_get_cred( state->key, GNUTLS_CRD_SRP, NULL);
	if (cred==NULL) {
		*err = 1;
		gnutls_assert();
		_gnutls_srp_entry_free(entry);
		return NULL;
	}

	/* if the callback which sends the parameters is
	 * set.
	 */
	if (cred->pwd_callback != NULL) {
		ret = cred->pwd_callback( state, username, &entry->salt,
			&entry->v, &entry->g, &entry->n);
		
		if (ret < 0) {
			gnutls_assert();
			_gnutls_srp_entry_free(entry);
			return NULL;
		}
		
		return entry;
	}

	if (cred->password_files<=0) {
		gnutls_assert();
		return NULL;
	}
	
	/* use the callback to select a password file */
	if (state->internals.server_srp_callback!=NULL) {
		pwd_index = state->internals.server_srp_callback(
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
		_gnutls_srp_entry_free(entry);
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
			if ((index = pwd_put_values( entry, line)) >= 0)
				if (pwd_read_conf( cred->password_conf_file[pwd_index], entry, index)==0) {
					return entry;
				} else {
					_gnutls_srp_entry_free(entry);
					return NULL;
				}
			else {
				_gnutls_srp_entry_free(entry);
				return NULL;
			}
	    }
    }
    return NULL;
	
}
#define RNDUSER "rnd"
#define RND_SALT_SIZE 17
SRP_PWD_ENTRY* _gnutls_randomize_pwd_entry() {
	int ret;
	SRP_PWD_ENTRY * pwd_entry = gnutls_calloc(1, sizeof(SRP_PWD_ENTRY));
	
	if (pwd_entry == NULL) {
		gnutls_assert(); 
		return NULL;
	}
	
	ret = _gnutls_get_rnd_srp_params( &pwd_entry->g, &pwd_entry->n, 1024);
	if (ret < 0) {
		gnutls_assert();
		_gnutls_srp_entry_free( pwd_entry);
		return NULL;
	}
	
	pwd_entry->username = gnutls_malloc(strlen(RNDUSER)+1);
	if (pwd_entry->username == NULL) {
		gnutls_assert();
		_gnutls_srp_entry_free( pwd_entry);
		return NULL;
	}
	_gnutls_str_cpy( pwd_entry->username, MAX_SRP_USERNAME, RNDUSER); /* Flawfinder: ignore */
	
	pwd_entry->v.data = gnutls_malloc(20);
	pwd_entry->v.size = 20;
	if (pwd_entry->v.data==NULL) {
		gnutls_assert();
		_gnutls_srp_entry_free( pwd_entry);
		return NULL;
	}

	_gnutls_get_random( pwd_entry->v.data, 20, GNUTLS_WEAK_RANDOM);

	pwd_entry->salt.size = RND_SALT_SIZE;
	
	pwd_entry->salt.data = gnutls_malloc(RND_SALT_SIZE);
	if (pwd_entry->salt.data==NULL) {
		gnutls_assert();
		_gnutls_srp_entry_free( pwd_entry);
		return NULL;
	}
	
	if (_gnutls_get_random(pwd_entry->salt.data, RND_SALT_SIZE, GNUTLS_WEAK_RANDOM) < 0) {
		gnutls_assert();
		_gnutls_srp_entry_free( pwd_entry);
		return NULL;
	}
	
	return pwd_entry;

}

void _gnutls_srp_entry_free( SRP_PWD_ENTRY * entry) {
	_gnutls_free_datum(&entry->v);
	_gnutls_free_datum(&entry->g);
	_gnutls_free_datum(&entry->n);
	_gnutls_free_datum(&entry->salt);

	gnutls_free(entry->username);
	gnutls_free(entry);
	
	return;
}


#endif /* ENABLE SRP */
