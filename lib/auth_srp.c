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

#include "gnutls_int.h"
#include "gnutls_errors.h"
#include "auth_srp_passwd.h"
#include "gnutls_auth.h"
#include "gnutls_auth_int.h"
#include "gnutls_srp.h"
#include "debug.h"
#include "gnutls_num.h"
#include "auth_srp.h"

int gen_srp_server_kx2(GNUTLS_STATE, opaque **);
int gen_srp_client_kx0(GNUTLS_STATE, opaque **);

int proc_srp_server_kx2(GNUTLS_STATE, opaque *, int);
int proc_srp_client_kx0(GNUTLS_STATE, opaque *, int);

MOD_AUTH_STRUCT srp_auth_struct = {
	"SRP",
	NULL,
	NULL,
	NULL,
	gen_srp_server_kx2,
	gen_srp_client_kx0,
	NULL,
	NULL,
	NULL,

	NULL,
	NULL, /* certificate */
	NULL,
	proc_srp_server_kx2,
	proc_srp_client_kx0,
	NULL,
	NULL,
	NULL
};


#define _b state->gnutls_key->b
#define B state->gnutls_key->B
#define _a state->gnutls_key->a
#define A state->gnutls_key->A
#define N state->gnutls_key->client_p
#define G state->gnutls_key->client_g
#define V state->gnutls_key->x
#define S state->gnutls_key->KEY

/* Send the first key exchange message ( g, n, s) and append the verifier algorithm number */
int gen_srp_server_hello(GNUTLS_STATE state, opaque ** data)
{
	size_t n_g, n_n, n_s;
	size_t ret;
	uint8 *data_n, *data_s;
	uint8 *data_g, *username;
	uint8 pwd_algo;
	GNUTLS_SRP_PWD_ENTRY *pwd_entry;
	int err;

	if ( state->gnutls_key->auth_info == NULL)
              	state->gnutls_key->auth_info = gnutls_calloc(1, sizeof(SRP_SERVER_AUTH_INFO_INT));
	                         	
	if (state->gnutls_key->auth_info == NULL) {
		gnutls_assert();
		return GNUTLS_E_MEMORY_ERROR;
	}
	state->gnutls_key->auth_info_size = sizeof(SRP_SERVER_AUTH_INFO_INT);
	
	username = ((SRP_SERVER_AUTH_INFO)state->gnutls_key->auth_info)->username;
	strcpy( username, state->security_parameters.extensions.srp_username);

#warning GET_PWD_ENTRY_USERNAME
	pwd_entry = _gnutls_srp_pwd_read_entry( state->gnutls_key, username, &err);

	if (pwd_entry == NULL) {
		if (err==0)
			/* in order to avoid informing the peer that
			 * username does not exist.
			 */
			pwd_entry = _gnutls_randomize_pwd_entry();
		else 
		        return GNUTLS_E_PWD_ERROR;
	}

	pwd_algo = (uint8) pwd_entry->algorithm;

	if (gcry_mpi_print(GCRYMPI_FMT_USG, NULL, &n_g, pwd_entry->g)!=0) {
		gnutls_assert();
		return GNUTLS_E_MPI_PRINT_FAILED;
	}
	if (gcry_mpi_print(GCRYMPI_FMT_USG, NULL, &n_n, pwd_entry->n)!=0) {
		gnutls_assert();
		return GNUTLS_E_MPI_PRINT_FAILED;
	}
	
	/* copy from pwd_entry to local variables (actually in state) */
	G = gcry_mpi_alloc_like(pwd_entry->g);
	N = gcry_mpi_alloc_like(pwd_entry->n);
	V = gcry_mpi_alloc_like(pwd_entry->v);

	if (G==NULL || N == NULL || V == NULL) {
		gnutls_assert();
		return GNUTLS_E_MEMORY_ERROR;
	}

	gcry_mpi_set(G, pwd_entry->g);
	gcry_mpi_set(N, pwd_entry->n);
	gcry_mpi_set(V, pwd_entry->v);

	(*data) = gnutls_malloc(n_n + n_g + pwd_entry->salt_size + 6 + 1);
	if ((*data)==NULL) {
		gnutls_assert();
		return GNUTLS_E_MEMORY_ERROR;
	}

	data_g = (*data); 

	/* firstly copy the algorithm used to generate the verifier 
	 */
	memcpy( data_g, &pwd_algo, 1);

	/* copy G (generator) to data */

	data_g++;
	
	if(gcry_mpi_print(GCRYMPI_FMT_USG, &data_g[2], &n_g, G)!=0) {
		gnutls_assert();
		return GNUTLS_E_MPI_PRINT_FAILED;
	}
	
	WRITEuint16( n_g, data_g);

	/* copy N (mod n) */
	data_n = &data_g[2 + n_g];

	if (gcry_mpi_print(GCRYMPI_FMT_USG, &data_n[2], &n_n, N)!=0) {
		gnutls_assert();
		return GNUTLS_E_MPI_PRINT_FAILED;
	}
	
	WRITEuint16( n_n, data_n);

	/* copy the salt */
	data_s = &data_n[2 + n_n];
	n_s = pwd_entry->salt_size;
	memcpy(&data_s[2], pwd_entry->salt, n_s);

	WRITEuint16( n_s, data_s);

	ret = n_g + n_n + pwd_entry->salt_size + 6 + 1;
	_gnutls_srp_clear_pwd_entry( pwd_entry);

	return ret;
}

/* send the second key exchange message  */
int gen_srp_server_kx2(GNUTLS_STATE state, opaque ** data)
{
	int ret;
	size_t n_b;
	uint8 *data_b;
	
	/* calculate:  B = (v + g^b) % N */
	B = _gnutls_calc_srp_B( &_b, G, N, V);
	if (B==NULL) {
		gnutls_assert();
		return GNUTLS_E_MEMORY_ERROR;
	}

	if (gcry_mpi_print(GCRYMPI_FMT_USG, NULL, &n_b, B)!=0)
		return GNUTLS_E_MPI_PRINT_FAILED;

	(*data) = gnutls_malloc(n_b + 2);
	if ( (*data) == NULL) {
		gnutls_assert();
		return GNUTLS_E_MEMORY_ERROR;
	}

	/* copy B */
	data_b = (*data);
	if (gcry_mpi_print(GCRYMPI_FMT_USG, &data_b[2], &n_b, B)!=0)
		return GNUTLS_E_MPI_PRINT_FAILED;

	WRITEuint16( n_b, data_b);

	/* calculate u */
	state->gnutls_key->u = _gnutls_calc_srp_u(B);
	if (state->gnutls_key->u==NULL) {
		gnutls_assert();
		gnutls_free( *data);
		return GNUTLS_E_MEMORY_ERROR;
	}

	/* S = (A * v^u) ^ b % N */
	S = _gnutls_calc_srp_S1( A, _b, state->gnutls_key->u, V, N);
	if ( S==NULL) {
		gnutls_assert();
		gnutls_free( *data);
		return GNUTLS_E_MEMORY_ERROR;
	}

	_gnutls_mpi_release(&A);
	_gnutls_mpi_release(&_b);
	_gnutls_mpi_release(&V);
	_gnutls_mpi_release(&state->gnutls_key->u);
	_gnutls_mpi_release(&B);

	ret = _gnutls_generate_key( state->gnutls_key);
	_gnutls_mpi_release( &S);

	if (ret < 0)
		return ret;

	return n_b + 2;
}


/* return A = g^a % N */
int gen_srp_client_kx0(GNUTLS_STATE state, opaque ** data)
{
	size_t n_a;
	uint8 *data_a;
	char *username;
	char *password;
	const SRP_CLIENT_CREDENTIALS cred =
	    _gnutls_get_cred(state->gnutls_key, GNUTLS_SRP, NULL);

	if (cred == NULL) {
		gnutls_assert();
		return GNUTLS_E_INSUFICIENT_CRED;
	}
	
#warning GET_USERNAME_PASSWORD
	username = cred->username;
	password = cred->password;

	if (username == NULL || password == NULL)
		return GNUTLS_E_INSUFICIENT_CRED;

	/* calc A = g^a % N */
	if (G == NULL || N == NULL) {
		gnutls_assert();
		return GNUTLS_E_INSUFICIENT_CRED;
	}
	
	A = _gnutls_calc_srp_A( &_a, G, N);
	if (A==NULL) {
		gnutls_assert();
		return GNUTLS_E_MEMORY_ERROR;
	}

	if (gcry_mpi_print(GCRYMPI_FMT_USG, NULL, &n_a, A)!=0)
		return GNUTLS_E_MPI_PRINT_FAILED;

	(*data) = gnutls_malloc(n_a + 2);
	if ( (*data) == NULL) {
		gnutls_assert();
		return GNUTLS_E_MEMORY_ERROR;
	}

	/* copy A */
	data_a = (*data);
	if (gcry_mpi_print(GCRYMPI_FMT_USG, &data_a[2], &n_a, A)!=0) {
		gnutls_free( *data);
		return GNUTLS_E_MPI_PRINT_FAILED;
	}
	
	WRITEuint16( n_a, data_a);

	return n_a + 2;
}

/* receive the first key exchange message ( g, n, s) */
int proc_srp_server_hello(GNUTLS_STATE state, const opaque * data, int data_size)
{
	uint16 n_s, n_g, n_n;
	size_t _n_s, _n_g, _n_n;
	const uint8 *data_n;
	const uint8 *data_g;
	const uint8 *data_s;
	uint8 pwd_algo;
	int i, ret;
	opaque hd[SRP_MAX_HASH_SIZE];
	char *username;
	char *password;
	const SRP_CLIENT_CREDENTIALS cred =
	    _gnutls_get_cred(state->gnutls_key, GNUTLS_SRP, NULL);

	if (cred == NULL) {
		gnutls_assert();
		return GNUTLS_E_INSUFICIENT_CRED;
	}
	
#warning GET_USERNAME_PASSWORD
	username = cred->username;
	password = cred->password;

	if (username == NULL || password == NULL)
		return GNUTLS_E_INSUFICIENT_CRED;

/* read the algorithm used to generate V */
	
	i = 0;
	memcpy( &pwd_algo, data, 1);

	i++;
	n_g = READuint16( &data[i]);
	i += 2;

	data_g = &data[i];
	i += n_g;
	if (i > data_size) {
		gnutls_assert();
		return GNUTLS_E_UNEXPECTED_PACKET_LENGTH;
	}

	n_n = READuint16( &data[i]);
	i += 2;

	data_n = &data[i];
	i += n_n;
	if (i > data_size) {
		gnutls_assert();
		return GNUTLS_E_UNEXPECTED_PACKET_LENGTH;
	}
	
	n_s = READuint16( &data[i]);
	i += 2;

	data_s = &data[i];
	i += n_s;
	if (i > data_size) {
		gnutls_assert();
		return GNUTLS_E_UNEXPECTED_PACKET_LENGTH;
	}
	_n_s = n_s;
	_n_g = n_g;
	_n_n = n_n;

	if (gcry_mpi_scan(&N, GCRYMPI_FMT_USG, data_n, &_n_n) != 0 || N == NULL) {
		gnutls_assert();
		return GNUTLS_E_MPI_SCAN_FAILED;
	}

	if (gcry_mpi_scan(&G, GCRYMPI_FMT_USG, data_g, &_n_g) != 0 || G == NULL) {
		gnutls_assert();
		return GNUTLS_E_MPI_SCAN_FAILED;
	}

	/* generate x = SHA(s | SHA(U | ":" | p))
	 * (or the equivalent using bcrypt)
	 */
	if ( ( ret =_gnutls_calc_srp_x( username, password, (opaque*)data_s, n_s, pwd_algo, &_n_g, hd)) < 0) {
		gnutls_assert();
		return ret;
	}

	if (gcry_mpi_scan(&state->gnutls_key->x, GCRYMPI_FMT_USG, hd, &_n_g) != 0 || state->gnutls_key->x==NULL) {
		gnutls_assert();
		return GNUTLS_E_MPI_SCAN_FAILED;
	}

	return 0;
}

/* just read A and put it to state */
int proc_srp_client_kx0(GNUTLS_STATE state, opaque * data, int data_size)
{
	size_t _n_A;

	_n_A = READuint16( &data[0]);

	if (gcry_mpi_scan(&A, GCRYMPI_FMT_USG, &data[2], &_n_A) || A == NULL) {
		gnutls_assert();
		return GNUTLS_E_MPI_SCAN_FAILED;
	}

	return 0;
}


int proc_srp_server_kx2(GNUTLS_STATE state, opaque * data, int data_size)
{
	size_t _n_B;
	int ret;
	
	_n_B = READuint16( &data[0]);

	if (gcry_mpi_scan(&B, GCRYMPI_FMT_USG, &data[2], &_n_B) || B==NULL) {
		gnutls_assert();
		return GNUTLS_E_MPI_SCAN_FAILED;
	}

	/* calculate u */
	state->gnutls_key->u = _gnutls_calc_srp_u( B);
	if ( state->gnutls_key->u == NULL) {
		gnutls_assert();
		return GNUTLS_E_MEMORY_ERROR;
	}

	/* S = (B - g^x) ^ (a + u * x) % N */
	S = _gnutls_calc_srp_S2( B, G, state->gnutls_key->x, _a, state->gnutls_key->u, N);
	if (S==NULL) {
		gnutls_assert();
		return GNUTLS_E_MEMORY_ERROR;
	}
	

	_gnutls_mpi_release(&A);
	_gnutls_mpi_release(&_b);
	_gnutls_mpi_release(&V);
	_gnutls_mpi_release(&state->gnutls_key->u);
	_gnutls_mpi_release(&B);

	ret = _gnutls_generate_key( state->gnutls_key);
	_gnutls_mpi_release(&S);

	if (ret < 0)
		return ret;

	return 0;
}

