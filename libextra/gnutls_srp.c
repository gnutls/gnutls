/*
 * Copyright (C) 2001,2003 Nikos Mavroyanopoulos
 * Copyright (C) 2004 Free Software Foundation
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
#include <gnutls_num.h>
#include "debug.h"


/* Here functions for SRP (like g^x mod n) are defined 
 */

int _gnutls_srp_gx(opaque * text, size_t textsize, opaque ** result, GNUTLS_MPI g,
		   GNUTLS_MPI prime, gnutls_alloc_function galloc_func)
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
		*result = galloc_func(result_size);
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
	GNUTLS_MPI tmpB, tmpV;
	GNUTLS_MPI b, B;
	int bits;

	/* calculate:  B = (3v + g^b) % N 
	 */
	bits = _gnutls_mpi_get_nbits(n);
	b = _gnutls_mpi_snew(bits);
	if (b==NULL) {
		gnutls_assert();
		return NULL;
	}

	tmpV = _gnutls_mpi_alloc_like(n);

	if (tmpV == NULL) {
		_gnutls_mpi_release(&b);
		return NULL;
	}
	
	_gnutls_mpi_randomize(b, bits, GCRY_STRONG_RANDOM);

	tmpB = _gnutls_mpi_snew(bits);
	if (tmpB==NULL) {
		gnutls_assert();
		_gnutls_mpi_release( &b);
		_gnutls_mpi_release(&tmpV);
		return NULL;
	}

	B = _gnutls_mpi_snew(bits);
	if (tmpB==NULL) {
		gnutls_assert();
		_gnutls_mpi_release( &b);
		_gnutls_mpi_release( &tmpB);
		_gnutls_mpi_release(&tmpV);
		return NULL;
	}

	_gnutls_mpi_mul_ui(tmpV, v, 3);

	_gnutls_mpi_powm(tmpB, g, b, n);
	_gnutls_mpi_addm(B, tmpV, tmpB, n);

	_gnutls_mpi_release(&tmpB);
	_gnutls_mpi_release(&tmpV);

	if (ret_b)
		*ret_b = b;
	else
		_gnutls_mpi_release(&b);

	return B;
}

GNUTLS_MPI _gnutls_calc_srp_u(GNUTLS_MPI A, GNUTLS_MPI B)
{
	size_t b_size, a_size;
	opaque *holder, hd[MAX_HASH_SIZE];
	size_t holder_size, hash_size;
	GNUTLS_HASH_HANDLE td;
	int ret;
	GNUTLS_MPI res;

	_gnutls_mpi_print( NULL, &a_size, A);
	_gnutls_mpi_print( NULL, &b_size, B);

	holder_size = a_size + b_size;

	holder = gnutls_alloca(holder_size);
	if (holder==NULL) return NULL;
	
	_gnutls_mpi_print( holder, &a_size, A);
	_gnutls_mpi_print( &holder[a_size], &b_size, B);

	td = _gnutls_hash_init(GNUTLS_MAC_SHA);
	if (td==NULL) {
		gnutls_afree(holder);
		gnutls_assert();
		return NULL;
	}
	_gnutls_hash(td, holder, holder_size);
	_gnutls_hash_deinit(td, hd);

	/* convert the bytes of hd to integer
	 */
	hash_size = 20; /* SHA */
	ret = _gnutls_mpi_scan( &res, hd, &hash_size);
	gnutls_afree(holder);

	if (ret < 0) {
		gnutls_assert();
		return NULL;
	}

	return res;
}

/* S = (A * v^u) ^ b % N 
 * this is our shared key
 */
GNUTLS_MPI _gnutls_calc_srp_S1(GNUTLS_MPI A, GNUTLS_MPI b, GNUTLS_MPI u, GNUTLS_MPI v, GNUTLS_MPI n)
{
	GNUTLS_MPI tmp1=NULL, tmp2 = NULL;
	GNUTLS_MPI S = NULL;

	S = _gnutls_mpi_alloc_like(n);
	if (S==NULL)
		return NULL;

	tmp1 = _gnutls_mpi_alloc_like(n);
	tmp2 = _gnutls_mpi_alloc_like(n);

	if (tmp1 == NULL || tmp2 == NULL)
		goto freeall;

	_gnutls_mpi_powm(tmp1, v, u, n);
	_gnutls_mpi_mulm(tmp2, A, tmp1, n);
	_gnutls_mpi_powm(S, tmp2, b, n);

	_gnutls_mpi_release(&tmp1);
	_gnutls_mpi_release(&tmp2);

	return S;

	freeall:
		_gnutls_mpi_release(&tmp1);
		_gnutls_mpi_release(&tmp2);
		return NULL;
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
	tmpa = _gnutls_mpi_snew(bits);
	if (tmpa==NULL) {
		gnutls_assert();
		return NULL;
	}
	
	_gnutls_mpi_randomize(tmpa, bits, GCRY_STRONG_RANDOM);

	A = _gnutls_mpi_snew(bits);
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
int _gnutls_calc_srp_sha(const char *username, const char *password, opaque * salt,
			   int salt_size, size_t *size, void* digest)
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


/* S = (B - 3*g^x) ^ (a + u * x) % N
 * this is our shared key
 */
GNUTLS_MPI _gnutls_calc_srp_S2(GNUTLS_MPI B, GNUTLS_MPI g, GNUTLS_MPI x, GNUTLS_MPI a, GNUTLS_MPI u, GNUTLS_MPI n)
{
	GNUTLS_MPI S=NULL, tmp1=NULL, tmp2=NULL;
	GNUTLS_MPI tmp4=NULL, tmp3=NULL;

	S = _gnutls_mpi_alloc_like(n);
	if (S==NULL)
		return NULL;
		
	tmp1 = _gnutls_mpi_alloc_like(n);
	tmp2 = _gnutls_mpi_alloc_like(n);
	tmp3 = _gnutls_mpi_alloc_like(n);
	if (tmp1 == NULL || tmp2 == NULL || tmp3 == NULL) {
		goto freeall;
	}

	_gnutls_mpi_powm(tmp1, g, x, n); /* g^x */
	_gnutls_mpi_mul_ui(tmp3, tmp1, 3); /* 3*g^x */
	_gnutls_mpi_subm(tmp2, B, tmp3, n);

	tmp4 = _gnutls_mpi_alloc_like(n);
	if (tmp4==NULL)
		goto freeall;

	_gnutls_mpi_mul(tmp1, u, x);
	_gnutls_mpi_add(tmp4, a, tmp1);
	_gnutls_mpi_powm(S, tmp2, tmp4, n);

	_gnutls_mpi_release(&tmp1);
	_gnutls_mpi_release(&tmp2);
	_gnutls_mpi_release(&tmp3);
	_gnutls_mpi_release(&tmp4);
	
	return S;

	freeall:
		_gnutls_mpi_release(&tmp1);
		_gnutls_mpi_release(&tmp2);
		_gnutls_mpi_release(&tmp3);
		_gnutls_mpi_release(&tmp4);
		_gnutls_mpi_release(&S);
		return NULL;
}

/**
  * gnutls_srp_free_server_credentials - Used to free an allocated gnutls_srp_client_credentials structure
  * @sc: is an &gnutls_srp_client_credentials structure.
  *
  * This structure is complex enough to manipulate directly thus
  * this helper function is provided in order to free (deallocate) it.
  *
  **/
void gnutls_srp_free_client_credentials( gnutls_srp_client_credentials sc) {
	gnutls_free( sc->username);
	gnutls_free( sc->password);
	gnutls_free( sc);
}

/**
  * gnutls_srp_allocate_server_credentials - Used to allocate an gnutls_srp_server_credentials structure
  * @sc: is a pointer to an &gnutls_srp_server_credentials structure.
  *
  * This structure is complex enough to manipulate directly thus
  * this helper function is provided in order to allocate it.
  *
  * Returns 0 on success.
  **/
int gnutls_srp_allocate_client_credentials( gnutls_srp_client_credentials *sc) {
	*sc = gnutls_calloc( 1, sizeof(SRP_CLIENT_CREDENTIALS_INT));
  
	if (*sc==NULL) return GNUTLS_E_MEMORY_ERROR;

	return 0;
}

/**
  * gnutls_srp_set_client_credentials - Used to set the username/password, in a gnutls_srp_client_credentials structure
  * @res: is an &gnutls_srp_client_credentials structure.
  * @username: is the user's userid
  * @password: is the user's password
  *
  * This function sets the username and password, in a gnutls_srp_client_credentials structure.
  * Those will be used in SRP authentication. @username and @password should be ASCII
  * strings or UTF-8 strings prepared using the "SASLprep" profile of "stringprep".
  *
  * Returns 0 on success.
  **/
int gnutls_srp_set_client_credentials( gnutls_srp_client_credentials res, char *username, char * password) 
{

	if (username==NULL || password == NULL) {
		gnutls_assert();
		return GNUTLS_E_INVALID_REQUEST;
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
  * gnutls_srp_free_server_credentials - Used to free an allocated gnutls_srp_server_credentials structure
  * @sc: is an &gnutls_srp_server_credentials structure.
  *
  * This structure is complex enough to manipulate directly thus
  * this helper function is provided in order to free (deallocate) it.
  *
  **/
void gnutls_srp_free_server_credentials( gnutls_srp_server_credentials sc) {
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
  * gnutls_srp_allocate_server_credentials - Used to allocate an gnutls_srp_server_credentials structure
  * @sc: is a pointer to an &gnutls_srp_server_credentials structure.
  *
  * This structure is complex enough to manipulate directly thus
  * this helper function is provided in order to allocate it.
  * 
  * Returns 0 on success.
  **/
int gnutls_srp_allocate_server_credentials( gnutls_srp_server_credentials *sc) {
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
  * gnutls_srp_set_server_credentials_file - Used to set the password files, in a gnutls_srp_server_credentials structure
  * @res: is an &gnutls_srp_server_credentials structure.
  * @password_file: is the SRP password file (tpasswd)
  * @password_conf_file: is the SRP password conf file (tpasswd.conf)
  *
  * This function sets the password files, in a gnutls_srp_server_credentials structure.
  * Those password files hold usernames and verifiers and will be used for SRP authentication.
  *
  * Returns 0 on success.
  *
  **/
int gnutls_srp_set_server_credentials_file( gnutls_srp_server_credentials res, 
	const char *password_file, const char * password_conf_file) 
{
int i;
	
	if (password_file==NULL || password_conf_file==NULL) {
		gnutls_assert();
		return GNUTLS_E_INVALID_REQUEST;
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
	
	res->password_file = gnutls_realloc_fast( res->password_file,
		sizeof(char*)*(res->password_files+1));
	if (res->password_file==NULL) {
		gnutls_assert();
		return GNUTLS_E_MEMORY_ERROR;
	}

	res->password_conf_file = gnutls_realloc_fast( res->password_conf_file,
		sizeof(char*)*(res->password_files+1));
	if (res->password_conf_file==NULL) {
		gnutls_assert();
		return GNUTLS_E_MEMORY_ERROR;
	}
	
	i = res->password_files;
	
	res->password_file[i] = gnutls_strdup( password_file);
	if (res->password_file[i]==NULL) {
		gnutls_assert();
		return GNUTLS_E_MEMORY_ERROR;
	}
	
	res->password_conf_file[i] = gnutls_strdup( password_conf_file);
	if (res->password_conf_file[i]==NULL) {
		gnutls_assert();
		gnutls_free(res->password_file[i]);
		res->password_file[i] = NULL;
		return GNUTLS_E_MEMORY_ERROR;
	}

	res->password_files++;

	return 0;
}

#define gnutls_srp_server_select_function srp_server_select_func

/**
  * gnutls_srp_server_set_select_function - Used to set a callback to assist in selecting the proper password file
  * @session: is a &gnutls_session structure.
  * @func: is the callback function
  *
  * This function sets a callback to assist in selecting the proper password file,
  * in case there are more than one. The callback's function form is:
  * int (*callback)(gnutls_session, const char** pfiles, const char** pconffiles, int npfiles);
  *
  * @pfiles contains @npfiles char* structures which hold
  * the password file name. @pconffiles contain the corresponding
  * conf files.
  *
  * This function specifies what we, in case of a server, are going
  * to do when we have to use a password file. If this callback
  * function is not provided then gnutls will automatically select the
  * first password file
  *
  * In case the callback returned a negative number then gnutls will
  * terminate this handshake.
  *
  * The callback function will only be called once per handshake.
  * The callback function should return the index of the password file
  * that will be used by the server. -1 indicates an error.
  *
  **/
void gnutls_srp_server_set_select_function(gnutls_session session,
					     gnutls_srp_server_select_function
					     * func)
{
	session->internals.server_srp_callback = func;
}

/**
  * gnutls_srp_set_server_credentials_function - Used to set a callback to retrieve the user's SRP credentials
  * @cred: is a &gnutls_srp_server_credentials structure.
  * @func: is the callback function
  *
  * This function can be used to set a callback to retrieve the user's SRP credentials.
  * The callback's function form is:
  * int (*callback)(gnutls_session, const char* username,
  *  gnutls_datum* salt, gnutls_datum *verifier, gnutls_datum* g,
  *  gnutls_datum* n);
  *
  * @username contains the actual username. 
  * The @salt, @verifier, @generator and @prime must be filled
  * in using the gnutls_malloc().
  *
  * In case the callback returned a negative number then gnutls will
  * assume that the username does not exist.
  *
  * In order to prevent allowing an attack to guess valid usernames,
  * if username does not exist, the g, and n values should be filled in 
  * using a random user's parameters. In that case the callback should
  * return the special value (1).
  *
  * The callback function will only be called once per handshake.
  * The callback function should return 0 on success.
  * -1 indicates an error.
  *
  **/
void gnutls_srp_set_server_credentials_function(
	gnutls_srp_server_credentials cred, 
	gnutls_srp_server_credentials_function * func)
{
	cred->pwd_callback = func;
}

/**
  * gnutls_srp_set_client_credentials_function - Used to set a callback to retrieve the username and password
  * @cred: is a &gnutls_srp_server_credentials structure.
  * @func: is the callback function
  *
  * This function can be used to set a callback to retrieve the username and
  * password for client SRP authentication.
  * The callback's function form is:
  * int (*callback)(gnutls_session, unsigned int times, char** username,
  *  char** password);
  *
  * The @username and @password must be allocated using gnutls_malloc().
  * @times will be 0 the first time called, and 1 the second.
  * @username and @password should be ASCII strings or UTF-8 strings 
  * prepared using the "SASLprep" profile of "stringprep".
  *
  * The callback function will be called once or twice per handshake.
  * The first time called, is before the ciphersuite is negotiated.
  * At that time if the callback returns a negative error code,
  * the callback will be called again if SRP has been
  * negotiated. This uses a special TLS-SRP idiom in order to avoid
  * asking the user for SRP password and username if the server does
  * not support SRP.
  * 
  * The callback should not return a negative error code the second
  * time called, since the handshake procedure will be aborted.
  *
  * The callback function should return 0 on success.
  * -1 indicates an error.
  *
  **/
void gnutls_srp_set_client_credentials_function(
	gnutls_srp_client_credentials cred, 
	gnutls_srp_client_credentials_function * func)
{
	cred->get_function = func;
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

/**
  * gnutls_srp_verifier - Used to calculate an SRP verifier
  * @username: is the user's name
  * @password: is the user's password
  * @salt: should be some randomly generated bytes
  * @generator: is the generator of the group
  * @prime: is the group's prime
  * @res: where the verifier will be stored.
  *
  * This function will create an SRP verifier, as specified in RFC2945.
  * The @prime and @generator should be one of the static parameters defined
  * in gnutls/extra.h or may be generated using the GCRYPT functions
  * gcry_prime_generate() and gcry_prime_group_generator().
  * The verifier will be allocated with @malloc and will be stored in @res using 
  * binary format.
  *
  **/
int gnutls_srp_verifier( const char* username, const char* password, 
	const gnutls_datum *salt, 
	const gnutls_datum* generator, const gnutls_datum* prime, 
	gnutls_datum * res)
{
GNUTLS_MPI _n, _g;
int ret;
size_t digest_size = 20, size;
opaque digest[20];

	ret = _gnutls_calc_srp_sha( username, password, salt->data,
			   salt->size, &digest_size, digest);
	if (ret < 0) {
		gnutls_assert();
		return ret;
	}

	size = prime->size;
	if (_gnutls_mpi_scan(&_n, prime->data, &size)) {
		gnutls_assert();
		return GNUTLS_E_MPI_SCAN_FAILED;
	}

	size = generator->size;
	if (_gnutls_mpi_scan(&_g, generator->data, &size)) {
		gnutls_assert();
		return GNUTLS_E_MPI_SCAN_FAILED;
	}

	ret = _gnutls_srp_gx( digest, 20, &res->data, _g, _n, malloc);
	if (ret < 0) {
		gnutls_assert();
		return ret;
	}
	res->size = ret;
	
	return 0;
}

#endif /* ENABLE_SRP */
