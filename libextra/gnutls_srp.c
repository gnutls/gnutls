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

#include <gnutls_int.h>
#include <gnutls_errors.h>
#include <auth_srp.h>
#include <gnutls_state.h>

#ifdef ENABLE_SRP

#include <gnutls_srp.h>
#include <auth_srp_passwd.h>
#include <gnutls_mpi.h>
#include "debug.h"


/* Here functions for SRP (like g^x mod n) are defined 
 */


int _gnutls_srp_gx(opaque * text, size_t textsize, opaque ** result, GNUTLS_MPI g,
		   GNUTLS_MPI prime)
{
	GNUTLS_MPI x, e;
	size_t result_size;

	if (_gnutls_mpi_scan(&x, text, &textsize)) {
		gnutls_assert();
		return GNUTLS_E_MPI_SCAN_FAILED;
	}

	e = _gnutls_mpi_alloc_like(prime);
	if (e==NULL) {
		gnutls_assert();
		_gnutls_mpi_release(&x);
		return GNUTLS_E_MEMORY_ERROR;
	}

	/* e = g^x mod prime (n) */
	_gnutls_mpi_powm(e, g, x, prime);
	_gnutls_mpi_release(&x);

	_gnutls_mpi_print( NULL, &result_size, e);
	if (result != NULL) {
		*result = gnutls_malloc(result_size);
		if ((*result)==NULL) return GNUTLS_E_MEMORY_ERROR;

		_gnutls_mpi_print( *result, &result_size, e);
	}

	_gnutls_mpi_release(&e);

	return result_size;

}


/****************
 * Choose a random value b and calculate B = (v + g^b) % N.
 * Return: B and if ret_b is not NULL b.
 */
GNUTLS_MPI _gnutls_calc_srp_B(GNUTLS_MPI * ret_b, GNUTLS_MPI g, GNUTLS_MPI n, GNUTLS_MPI v)
{
	GNUTLS_MPI tmpB;
	GNUTLS_MPI b, B;
	int bits;

	/* calculate:  B = (v + g^b) % N */
	bits = _gnutls_mpi_get_nbits(n);
	b = _gnutls_mpi_new(bits);	/* FIXME: allocate in secure memory */
	if (b==NULL) {
		gnutls_assert();
		return NULL;
	}
	
	_gnutls_mpi_randomize(b, bits, GCRY_STRONG_RANDOM);

	tmpB = _gnutls_mpi_new(bits);	/* FIXME: allocate in secure memory */
	if (tmpB==NULL) {
		gnutls_assert();
		_gnutls_mpi_release( &b);
		return NULL;
	}

	B = _gnutls_mpi_new(bits);	/* FIXME: allocate in secure memory */
	if (tmpB==NULL) {
		gnutls_assert();
		_gnutls_mpi_release( &b);
		_gnutls_mpi_release( &tmpB);
		return NULL;
	}

	_gnutls_mpi_powm(tmpB, g, b, n);
	_gnutls_mpi_addm(B, v, tmpB, n);

	_gnutls_mpi_release(&tmpB);

	if (ret_b)
		*ret_b = b;
	else
		_gnutls_mpi_release(&b);

	return B;
}

GNUTLS_MPI _gnutls_calc_srp_u(GNUTLS_MPI B)
{
	size_t b_size;
	opaque *b_holder, hd[MAX_HASH_SIZE];
	GNUTLS_HASH_HANDLE td;
	uint32 u;
	GNUTLS_MPI ret;

	_gnutls_mpi_print( NULL, &b_size, B);
	b_holder = gnutls_malloc(b_size);
	if (b_holder==NULL) return NULL;

	_gnutls_mpi_print( b_holder, &b_size, B);


	td = _gnutls_hash_init(GNUTLS_MAC_SHA);
	if (td==NULL) {
		gnutls_free(b_holder);
		gnutls_assert();
		return NULL;
	}
	_gnutls_hash(td, b_holder, b_size);
	_gnutls_hash_deinit(td, hd);
	
	memcpy(&u, hd, sizeof(u));

	gnutls_free(b_holder);

	ret = _gnutls_mpi_set_ui(NULL, u);
	if (ret==NULL) {
		gnutls_assert();
		return NULL;
	}

	return ret;
}

/* S = (A * v^u) ^ b % N 
 * this is our shared key
 */
GNUTLS_MPI _gnutls_calc_srp_S1(GNUTLS_MPI A, GNUTLS_MPI b, GNUTLS_MPI u, GNUTLS_MPI v, GNUTLS_MPI n)
{
	GNUTLS_MPI tmp1, tmp2;
	GNUTLS_MPI S;

	S = _gnutls_mpi_alloc_like(n);
	if (S==NULL)
		return NULL;

	tmp1 = _gnutls_mpi_alloc_like(n);
	tmp2 = _gnutls_mpi_alloc_like(n);

	if (tmp1 == NULL || tmp2 == NULL) {
		_gnutls_mpi_release(&tmp1);
		_gnutls_mpi_release(&tmp2);
		return NULL;
	}

	_gnutls_mpi_powm(tmp1, v, u, n);
	_gnutls_mpi_mulm(tmp2, A, tmp1, n);
	_gnutls_mpi_release(&tmp1);

	_gnutls_mpi_powm(S, tmp2, b, n);
	_gnutls_mpi_release(&tmp2);

	return S;
}

/* A = g^a % N 
 * returns A and a (which is random)
 */
GNUTLS_MPI _gnutls_calc_srp_A(GNUTLS_MPI * a, GNUTLS_MPI g, GNUTLS_MPI n)
{
	GNUTLS_MPI tmpa;
	GNUTLS_MPI A;
	int bits;

	bits = _gnutls_mpi_get_nbits(n);
	tmpa = _gnutls_mpi_new(bits);	/* FIXME: allocate in secure memory */
	if (tmpa==NULL) {
		gnutls_assert();
		return NULL;
	}
	
	_gnutls_mpi_randomize(tmpa, bits, GCRY_STRONG_RANDOM);

	A = _gnutls_mpi_new(bits);	/* FIXME: allocate in secure memory */
	if (A==NULL) {
		gnutls_assert();
		_gnutls_mpi_release( &tmpa);
		return NULL;
	}
	_gnutls_mpi_powm(A, g, tmpa, n);

	if (a != NULL)
		*a = tmpa;
	else
		_gnutls_mpi_release(&tmpa);

	return A;
}

/* generate x = SHA(s | SHA(U | ":" | p))
 * The output is exactly 20 bytes
 */
int _gnutls_calc_srp_sha(char *username, char *password, opaque * salt,
			   int salt_size, int *size, void* digest)
{
	GNUTLS_HASH_HANDLE td;
	opaque res[MAX_HASH_SIZE];

	*size = 20;

	td = _gnutls_hash_init(GNUTLS_MAC_SHA);
	if (td==NULL) {
		return GNUTLS_E_MEMORY_ERROR;
	}
	_gnutls_hash(td, username, strlen(username));
	_gnutls_hash(td, ":", 1);
	_gnutls_hash(td, password, strlen(password));
	
	_gnutls_hash_deinit(td, res);

	td = _gnutls_hash_init(GNUTLS_MAC_SHA);
	if (td==NULL) {
		return GNUTLS_E_MEMORY_ERROR;
	}

	_gnutls_hash(td, salt, salt_size);
	_gnutls_hash(td, res, 20);	/* 20 bytes is the output of sha1 */

	_gnutls_hash_deinit(td, digest);

	return 0;
}

int _gnutls_calc_srp_x(char *username, char *password, opaque * salt,
			 size_t salt_size, size_t *size, void* digest)
{

	return _gnutls_calc_srp_sha(username, password, salt,
					    salt_size, size, digest);
}


/* S = (B - g^x) ^ (a + u * x) % N
 * this is our shared key
 */
GNUTLS_MPI _gnutls_calc_srp_S2(GNUTLS_MPI B, GNUTLS_MPI g, GNUTLS_MPI x, GNUTLS_MPI a, GNUTLS_MPI u, GNUTLS_MPI n)
{
	GNUTLS_MPI S, tmp1, tmp2, tmp4;

	S = _gnutls_mpi_alloc_like(n);
	if (S==NULL)
		return NULL;
		
	tmp1 = _gnutls_mpi_alloc_like(n);
	tmp2 = _gnutls_mpi_alloc_like(n);
	if (tmp1 == NULL || tmp2 == NULL) {
		_gnutls_mpi_release(&tmp1);
		_gnutls_mpi_release(&tmp2);
		return NULL;
	}

	_gnutls_mpi_powm(tmp1, g, x, n);

	_gnutls_mpi_subm(tmp2, B, tmp1, n);

	tmp4 = _gnutls_mpi_alloc_like(n);
	if (tmp4==NULL)
		return NULL;

	_gnutls_mpi_mul(tmp1, u, x);
	_gnutls_mpi_add(tmp4, a, tmp1);
	_gnutls_mpi_release(&tmp1);

	_gnutls_mpi_powm(S, tmp2, tmp4, n);
	_gnutls_mpi_release(&tmp2);
	_gnutls_mpi_release(&tmp4);

	return S;
}

/**
  * gnutls_srp_free_server_cred - Used to free an allocated GNUTLS_SRP_CLIENT_CREDENTIALS structure
  * @sc: is an &GNUTLS_SRP_CLIENT_CREDENTIALS structure.
  *
  * This structure is complex enough to manipulate directly thus
  * this helper function is provided in order to free (deallocate)
  * the structure.
  **/
void gnutls_srp_free_client_cred( GNUTLS_SRP_CLIENT_CREDENTIALS sc) {
	gnutls_free( sc->username);
	gnutls_free( sc->password);
	gnutls_free( sc);
}

/**
  * gnutls_srp_allocate_server_cred - Used to allocate an GNUTLS_SRP_SERVER_CREDENTIALS structure
  * @sc: is a pointer to an &GNUTLS_SRP_SERVER_CREDENTIALS structure.
  *
  * This structure is complex enough to manipulate directly thus
  * this helper function is provided in order to allocate
  * the structure.
  **/
int gnutls_srp_allocate_client_cred( GNUTLS_SRP_CLIENT_CREDENTIALS *sc) {
	*sc = gnutls_calloc( 1, sizeof(SRP_CLIENT_CREDENTIALS_INT));
  
	if (*sc==NULL) return GNUTLS_E_MEMORY_ERROR;

	return 0;
}

/**
  * gnutls_srp_set_client_cred - Used to set the username/password, in a GNUTLS_SRP_CLIENT_CREDENTIALS structure
  * @res: is an &GNUTLS_SRP_CLIENT_CREDENTIALS structure.
  * @username: is the user's userid
  * @password: is the user's password
  *
  **/
int gnutls_srp_set_client_cred( GNUTLS_SRP_CLIENT_CREDENTIALS res, char *username, char * password) {

	if (username==NULL || password == NULL) {
		gnutls_assert();
		return GNUTLS_E_INVALID_PARAMETERS;
	}
	
	res->username = gnutls_strdup( username);
	if (res->username == NULL) return GNUTLS_E_MEMORY_ERROR;

	res->password = gnutls_strdup( password);
	if (res->password==NULL) {
		gnutls_free(res->username);
		return GNUTLS_E_MEMORY_ERROR;
	}

	return 0;
}

/**
  * gnutls_srp_free_server_cred - Used to free an allocated GNUTLS_SRP_SERVER_CREDENTIALS structure
  * @sc: is an &GNUTLS_SRP_SERVER_CREDENTIALS structure.
  *
  * This structure is complex enough to manipulate directly thus
  * this helper function is provided in order to free (deallocate)
  * the structure.
  **/
void gnutls_srp_free_server_cred( GNUTLS_SRP_SERVER_CREDENTIALS sc) {
int i;
	for (i=0;i<sc->password_files;i++) {
		gnutls_free( sc->password_file[i]);
		gnutls_free( sc->password_conf_file[i]);
	}
	gnutls_free(sc->password_file);
	gnutls_free(sc->password_conf_file);
	
	gnutls_free(sc);
}

/**
  * gnutls_srp_allocate_server_cred - Used to allocate an GNUTLS_SRP_SERVER_CREDENTIALS structure
  * @sc: is a pointer to an &GNUTLS_SRP_SERVER_CREDENTIALS structure.
  *
  * This structure is complex enough to manipulate directly thus
  * this helper function is provided in order to allocate
  * the structure.
  **/
int gnutls_srp_allocate_server_cred( GNUTLS_SRP_SERVER_CREDENTIALS *sc) {
	*sc = gnutls_calloc( 1, sizeof(SRP_SERVER_CREDENTIALS_INT));
	
	if (*sc==NULL) return GNUTLS_E_MEMORY_ERROR;
	
	return 0;
}

inline
static int file_exists( const char* file) {
FILE* fd;

	fd = fopen( file, "r");
	if (fd==NULL) return -1;

	fclose(fd);
	return 0;
}

/**
  * gnutls_srp_set_server_cred_file - Used to set the password files, in a GNUTLS_SRP_SERVER_CREDENTIALS structure
  * @res: is an &GNUTLS_SRP_SERVER_CREDENTIALS structure.
  * @password_file: is the SRP password file (tpasswd)
  * @password_conf_file: is the SRP password conf file (tpasswd.conf)
  *
  **/
int gnutls_srp_set_server_cred_file( GNUTLS_SRP_SERVER_CREDENTIALS res, char *password_file, char * password_conf_file) {
int i;
	
	if (password_file==NULL || password_conf_file==NULL) {
		gnutls_assert();
		return GNUTLS_E_INVALID_PARAMETERS;
	}

	/* Check if the files can be opened */
	if (file_exists( password_file)!=0) {
		gnutls_assert();
		return GNUTLS_E_FILE_ERROR;
	}

	if (file_exists( password_conf_file)!=0) {
		gnutls_assert();
		return GNUTLS_E_FILE_ERROR;
	}
	
	res->password_file = gnutls_realloc( res->password_file,
		sizeof(char*)*(res->password_files+1));
	if (res->password_file==NULL) {
		gnutls_assert();
		return GNUTLS_E_MEMORY_ERROR;
	}

	res->password_conf_file = gnutls_realloc( res->password_conf_file,
		sizeof(char*)*(res->password_files+1));
	if (res->password_conf_file==NULL) {
		gnutls_assert();
		return GNUTLS_E_MEMORY_ERROR;
	}
	
	i = res->password_files++;
	
	res->password_file[i] = gnutls_strdup( password_file);
	if (res->password_file[i]==NULL) {
		gnutls_assert();
		return GNUTLS_E_MEMORY_ERROR;
	}
	
	res->password_conf_file[i] = gnutls_strdup( password_conf_file);
	if (res->password_conf_file[i]==NULL) {
		gnutls_assert();
		gnutls_free(res->password_file[i]);
		return GNUTLS_E_MEMORY_ERROR;
	}

	return 0;
}

/**
  * gnutls_srp_server_set_select_function - Used to set a callback to assist in selecting the proper password file
  * @session: is a &gnutls_session structure.
  * @func: is the callback function
  *
  * The callback's function form is:
  * int (*callback)(gnutls_session, const char** pfiles, const char** pconffiles, int npfiles);
  *
  * 'pfiles' contains 'npfiles' char* structures which hold
  * the password file name. 'pconffiles' contain the corresponding
  * conf files.
  *
  * This function specifies what we, in case of a server, are going
  * to do when we have to use a password file. If this callback
  * function is not provided then gnutls will automaticaly select the
  * first password file
  *
  * In case the callback returned a negative number then gnutls will
  * not attempt to choose the appropriate certificate and the caller function
  * will fail.
  *
  * The callback function will only be called once per handshake.
  * The callback function should return the index of the certificate
  * choosen by the server. -1 indicates an error.
  *
  **/
void gnutls_srp_server_set_select_function(gnutls_session session,
					     srp_server_select_func
					     * func)
{
	session->internals.server_srp_callback = func;
}

/**
  * gnutls_srp_server_get_username - This function returns the username of the peer
  * @session: is a gnutls session
  *
  * This function will return the username of the peer. This should only be
  * called in case of SRP authentication and in case of a server.
  * Returns NULL in case of an error.
  *
  **/
const char *gnutls_srp_server_get_username(gnutls_session session)
{
	SRP_SERVER_AUTH_INFO info;

	CHECK_AUTH(GNUTLS_CRD_SRP, NULL);

	info = _gnutls_get_auth_info(session);
	if (info == NULL)
		return NULL;
	return info->username;
}

#endif /* ENABLE_SRP */
