/*
 * Copyright (C) 2001,2002 Nikos Mavroyanopoulos
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

#include "gnutls_int.h"

#ifdef ENABLE_SRP

#include "gnutls_errors.h"
#include "auth_srp_passwd.h"
#include "gnutls_auth.h"
#include "gnutls_auth_int.h"
#include "gnutls_srp.h"
#include "debug.h"
#include "gnutls_num.h"
#include "auth_srp.h"
#include <gnutls_str.h>
#include <gnutls_datum.h>

int _gnutls_gen_srp_server_kx2(gnutls_session, opaque **);
int _gnutls_gen_srp_client_kx0(gnutls_session, opaque **);

int _gnutls_proc_srp_server_kx2(gnutls_session, opaque *, size_t);
int _gnutls_proc_srp_client_kx0(gnutls_session, opaque *, size_t);

const MOD_AUTH_STRUCT srp_auth_struct = {
	"SRP",
	NULL,
	NULL,
	NULL,
	_gnutls_gen_srp_server_kx2,
	_gnutls_gen_srp_client_kx0,
	NULL,
	NULL,
	NULL,

	NULL,
	NULL, /* certificate */
	NULL,
	_gnutls_proc_srp_server_kx2,
	_gnutls_proc_srp_client_kx0,
	NULL,
	NULL,
	NULL
};


#define _b state->key->b
#define B state->key->B
#define _a state->key->a
#define A state->key->A
#define N state->key->client_p
#define G state->key->client_g
#define V state->key->x
#define S state->key->KEY

/* Send the first key exchange message ( g, n, s) and append the verifier algorithm number 
 * Data is allocated by the caller, and should have data_size size.
 */
int _gnutls_gen_srp_server_hello(gnutls_session state, opaque * data, size_t _data_size)
{
	int ret;
	uint8 *data_n, *data_s;
	uint8 *data_g, *username;
	SRP_PWD_ENTRY *pwd_entry;
	int err;
	SRP_SERVER_AUTH_INFO info;
	ssize_t data_size = _data_size;
	
	if ( (ret=_gnutls_auth_info_set( state, GNUTLS_CRD_SRP, sizeof( SRP_SERVER_AUTH_INFO_INT), 1)) < 0) {
		gnutls_assert();
		return ret;
	}

	info = _gnutls_get_auth_info( state);
	username = info->username;
	
	_gnutls_str_cpy( username, MAX_SRP_USERNAME, state->security_parameters.extensions.srp_username);

	pwd_entry = _gnutls_srp_pwd_read_entry( state, username, &err);

	if (pwd_entry == NULL) {
		if (err==0) {
			gnutls_assert();
			/* in order to avoid informing the peer that
			 * username does not exist.
			 */
			pwd_entry = _gnutls_randomize_pwd_entry();
		} else {
		        return GNUTLS_E_PWD_ERROR;
		}
	}

	/* copy from pwd_entry to local variables (actually in state) */
	if (_gnutls_mpi_scan( &G, pwd_entry->g.data, &pwd_entry->g.size) < 0) {
		gnutls_assert();
		return GNUTLS_E_MPI_SCAN_FAILED;
	}

	if (_gnutls_mpi_scan( &N, pwd_entry->n.data, &pwd_entry->n.size) < 0) {
		gnutls_assert();
		return GNUTLS_E_MPI_SCAN_FAILED;
	}

	if (_gnutls_mpi_scan( &V, pwd_entry->v.data, &pwd_entry->v.size) < 0) {
		gnutls_assert();
		return GNUTLS_E_MPI_SCAN_FAILED;
	}

	if ((size_t)data_size < pwd_entry->n.size + 
		pwd_entry->g.size + pwd_entry->salt.size + 5) {
		gnutls_assert();
		return GNUTLS_E_INVALID_REQUEST;
	}

	/* copy the salt 
	 */
	data_s = data;

	_gnutls_write_datum8( data_s, pwd_entry->salt);

	/* copy N (mod n) */
	data_n = &data_s[1 + pwd_entry->salt.size];
	_gnutls_write_datum16( data_n, pwd_entry->n);


	data_g = &data_n[2 + pwd_entry->n.size];
	/* copy G (generator) to data */
	_gnutls_write_datum16( data_g, pwd_entry->g);


	ret = pwd_entry->g.size + pwd_entry->n.size + 
		pwd_entry->salt.size + 5;
	_gnutls_srp_entry_free( pwd_entry);

	return ret;
}

/* send the second key exchange message  */
int _gnutls_gen_srp_server_kx2(gnutls_session state, opaque ** data)
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

	if (_gnutls_mpi_print( NULL, &n_b, B)!=0) {
		gnutls_assert();
		return GNUTLS_E_MPI_PRINT_FAILED;
	}

	(*data) = gnutls_malloc(n_b + 2);
	if ( (*data) == NULL) {
		gnutls_assert();
		return GNUTLS_E_MEMORY_ERROR;
	}

	/* copy B */
	data_b = (*data);
	if (_gnutls_mpi_print( &data_b[2], &n_b, B)!=0)
		return GNUTLS_E_MPI_PRINT_FAILED;

	_gnutls_write_uint16( n_b, data_b);

	/* calculate u */
	state->key->u = _gnutls_calc_srp_u(B);
	if (state->key->u==NULL) {
		gnutls_assert();
		gnutls_free( *data);
		return GNUTLS_E_MEMORY_ERROR;
	}

	/* S = (A * v^u) ^ b % N */
	S = _gnutls_calc_srp_S1( A, _b, state->key->u, V, N);
	if ( S==NULL) {
		gnutls_assert();
		gnutls_free( *data);
		return GNUTLS_E_MEMORY_ERROR;
	}

	_gnutls_mpi_release(&A);
	_gnutls_mpi_release(&_b);
	_gnutls_mpi_release(&V);
	_gnutls_mpi_release(&state->key->u);
	_gnutls_mpi_release(&B);

	ret = _gnutls_generate_key( state->key);
	_gnutls_mpi_release( &S);

	if (ret < 0) {
		gnutls_assert();
		return ret;
	}

	return n_b + 2;
}


/* return A = g^a % N */
int _gnutls_gen_srp_client_kx0(gnutls_session state, opaque ** data)
{
	size_t n_a;
	uint8 *data_a;
	char *username;
	char *password;
	const gnutls_srp_client_credentials cred =
	    _gnutls_get_cred(state->key, GNUTLS_CRD_SRP, NULL);

	if (cred == NULL) {
		gnutls_assert();
		return GNUTLS_E_INSUFICIENT_CRED;
	}
	
	username = cred->username;
	password = cred->password;

	if (username == NULL || password == NULL) {
		gnutls_assert();
		return GNUTLS_E_INSUFICIENT_CRED;
	}

	/* calc A = g^a % N 
	 */
	if (G == NULL || N == NULL) {
		gnutls_assert();
		return GNUTLS_E_INSUFICIENT_CRED;
	}
	
	A = _gnutls_calc_srp_A( &_a, G, N);
	if (A==NULL) {
		gnutls_assert();
		return GNUTLS_E_MEMORY_ERROR;
	}

	if (_gnutls_mpi_print( NULL, &n_a, A)!=0) {
		gnutls_assert();
		return GNUTLS_E_MPI_PRINT_FAILED;
	}

	(*data) = gnutls_malloc(n_a + 2);
	if ( (*data) == NULL) {
		gnutls_assert();
		return GNUTLS_E_MEMORY_ERROR;
	}

	/* copy A */
	data_a = (*data);
	if (_gnutls_mpi_print( &data_a[2], &n_a, A)!=0) {
		gnutls_free( *data);
		return GNUTLS_E_MPI_PRINT_FAILED;
	}
	
	_gnutls_write_uint16( n_a, data_a);

	return n_a + 2;
}

/* receive the first key exchange message ( g, n, s) */
int _gnutls_proc_srp_server_hello(gnutls_session state, const opaque * data, size_t _data_size)
{
	uint8 n_s;
	uint16 n_g, n_n;
	size_t _n_s, _n_g, _n_n;
	const uint8 *data_n;
	const uint8 *data_g;
	const uint8 *data_s;
	int i, ret;
	opaque hd[SRP_MAX_HASH_SIZE];
	char *username, *password;
	ssize_t data_size = _data_size;

	const gnutls_srp_client_credentials cred =
	    _gnutls_get_cred(state->key, GNUTLS_CRD_SRP, NULL);

	if (cred == NULL) {
		gnutls_assert();
		return GNUTLS_E_INSUFICIENT_CRED;
	}
	
	username = cred->username;
	password = cred->password;

	if (username == NULL || password == NULL) {
		gnutls_assert();
		return GNUTLS_E_INSUFICIENT_CRED;
	}

	i = 0;

	DECR_LEN( data_size, 1);
	n_s = data[i];
	i += 1;

	DECR_LEN( data_size, n_s);
	data_s = &data[i];
	i += n_s;

	DECR_LEN( data_size, 2);
	n_n = _gnutls_read_uint16( &data[i]);
	i += 2;

	DECR_LEN( data_size, n_n);
	data_n = &data[i];
	i += n_n;
	
	DECR_LEN( data_size, 2);
	n_g = _gnutls_read_uint16( &data[i]);
	i += 2;

	DECR_LEN( data_size, n_g);
	data_g = &data[i];
	i += n_g;

	_n_s = n_s;
	_n_g = n_g;
	_n_n = n_n;

	if (_gnutls_mpi_scan(&N, data_n, &_n_n) != 0 || N == NULL) {
		gnutls_assert();
		return GNUTLS_E_MPI_SCAN_FAILED;
	}

	if (_gnutls_mpi_scan(&G, data_g, &_n_g) != 0 || G == NULL) {
		gnutls_assert();
		return GNUTLS_E_MPI_SCAN_FAILED;
	}

	/* generate x = SHA(s | SHA(U | ":" | p))
	 * (or the equivalent using bcrypt)
	 */
	if ( ( ret =_gnutls_calc_srp_x( username, password, (opaque*)data_s, n_s, &_n_g, hd)) < 0) {
		gnutls_assert();
		return ret;
	}

	if (_gnutls_mpi_scan(&state->key->x, hd, &_n_g) != 0 || state->key->x==NULL) {
		gnutls_assert();
		return GNUTLS_E_MPI_SCAN_FAILED;
	}

	return 0;
}

/* just read A and put it to state */
int _gnutls_proc_srp_client_kx0(gnutls_session state, opaque * data, size_t _data_size)
{
	size_t _n_A;
	ssize_t data_size = _data_size;

	DECR_LEN( data_size, 2);
	_n_A = _gnutls_read_uint16( &data[0]);

	DECR_LEN( data_size, _n_A);
	if (_gnutls_mpi_scan(&A, &data[2], &_n_A) || A == NULL) {
		gnutls_assert();
		return GNUTLS_E_MPI_SCAN_FAILED;
	}

	return 0;
}


int _gnutls_proc_srp_server_kx2(gnutls_session state, opaque * data, size_t _data_size)
{
	size_t _n_B;
	ssize_t data_size = _data_size;
	int ret;
	
	DECR_LEN( data_size, 2);
	_n_B = _gnutls_read_uint16( &data[0]);

	DECR_LEN( data_size, _n_B);
	if (_gnutls_mpi_scan(&B, &data[2], &_n_B) || B==NULL) {
		gnutls_assert();
		return GNUTLS_E_MPI_SCAN_FAILED;
	}

	/* calculate u */
	state->key->u = _gnutls_calc_srp_u( B);
	if ( state->key->u == NULL) {
		gnutls_assert();
		return GNUTLS_E_MEMORY_ERROR;
	}

	/* S = (B - g^x) ^ (a + u * x) % N */
	S = _gnutls_calc_srp_S2( B, G, state->key->x, _a, state->key->u, N);
	if (S==NULL) {
		gnutls_assert();
		return GNUTLS_E_MEMORY_ERROR;
	}
	

	_gnutls_mpi_release(&A);
	_gnutls_mpi_release(&_b);
	_gnutls_mpi_release(&V);
	_gnutls_mpi_release(&state->key->u);
	_gnutls_mpi_release(&B);

	ret = _gnutls_generate_key( state->key);
	_gnutls_mpi_release(&S);

	if (ret < 0)
		return ret;

	return _data_size - data_size; /* return the remaining data 
					* needed in auth_srp_rsa.
					*/
}

#endif /* ENABLE_SRP */
