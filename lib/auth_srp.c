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

#include <defines.h>
#include "gnutls_int.h"
#include "gnutls_errors.h"
#include "auth_srp_passwd.h"
#include "auth_srp.h"
#include "gnutls_auth_int.h"

int gen_srp_server_kx( GNUTLS_KEY, opaque**);
int gen_srp_server_kx2( GNUTLS_KEY, opaque**);
int gen_srp_client_kx0( GNUTLS_KEY, opaque**);

int proc_srp_server_kx( GNUTLS_KEY, opaque*, int);
int proc_srp_server_kx2( GNUTLS_KEY, opaque*, int);
int proc_srp_client_kx0( GNUTLS_KEY, opaque*, int);

MOD_AUTH_STRUCT srp_auth_struct = {
	"SRP",
	gen_srp_server_kx,
	gen_srp_server_kx2,
	gen_srp_client_kx0,
	NULL,
	NULL,
	NULL,
	proc_srp_server_kx,
	proc_srp_server_kx2,
	proc_srp_client_kx0,
	NULL,
	NULL,
	NULL
};


#define _b key->b
#define B key->B
#define _a key->a
#define A key->A
#define N key->client_p
#define G key->client_g
#define V key->x
#define S key->KEY

/* Send the first key exchange message ( g, n, s) */
int gen_srp_server_kx( GNUTLS_KEY key, opaque** data) {
	size_t n_g, n_n;
	uint16 _n_n, _n_g, _n_s;
	size_t ret;	
	uint8 *data_n, *data_s;
	uint8 *data_g;
	GNUTLS_SRP_PWD_ENTRY * pwd_entry;

	pwd_entry = _gnutls_srp_pwd_read_entry( key, key->username);

	if (pwd_entry==NULL) {
		return GNUTLS_E_PWD_ERROR;
	}

	gcry_mpi_print(GCRYMPI_FMT_USG, NULL, &n_g, pwd_entry->g);
	gcry_mpi_print(GCRYMPI_FMT_USG, NULL, &n_n, pwd_entry->n);

	G = gcry_mpi_alloc_like(pwd_entry->g);
	N = gcry_mpi_alloc_like(pwd_entry->n);
	V = gcry_mpi_alloc_like(pwd_entry->v);

	mpi_set( G, pwd_entry->g);
	mpi_set( N, pwd_entry->n);
	mpi_set( V, pwd_entry->v);
	
	(*data) = gnutls_malloc(n_n + n_g + pwd_entry->salt_size + 6);

	/* copy G (generator) */
	data_g = (*data);
	gcry_mpi_print(GCRYMPI_FMT_USG, &data_g[2], &n_g, G);
	_n_g = n_g;
#ifndef WORDS_BIGENDIAN
	_n_g = byteswap16(_n_g);
	memcpy(data_g, &_n_g, 2);
#else
	memcpy(data_g, &_n_g, 2);
#endif

	/* copy N (mod n) */
	data_n = &data_g[2 + n_g];
	gcry_mpi_print(GCRYMPI_FMT_USG, &data_n[2], &n_n, N);
	_n_n = n_n;
#ifndef WORDS_BIGENDIAN
	_n_n = byteswap16(_n_n);
	memcpy(data_n, &_n_n, 2);
#else
	memcpy(data_n, &_n_n, 2);
#endif

	/* copy the salt */
	data_s = &data_n[2+n_n];
	_n_s = pwd_entry->salt_size;
	memcpy( &data_s[2], pwd_entry->salt, _n_s);
	
#ifndef WORDS_BIGENDIAN
	_n_s = byteswap16(_n_s);
	memcpy(data_s, &_n_s, 2);
#else
	memcpy(data_s, &_n_s, 2);
#endif


	ret = n_g+ n_n + pwd_entry->salt_size + 6;
	gnutls_free(pwd_entry);
	
	return ret;
}

/* send the second key exchange message ( B = (v + g^b) % N) */
int gen_srp_server_kx2( GNUTLS_KEY key, opaque** data) {
	size_t n_b, bits;
	uint16 _n_b;
	MPI tmpB;
	uint8 *data_b;
	GNUTLS_MAC_HANDLE td;
	opaque* hd;
	MPI tmp1, tmp2;
	uint32 u;
	
        bits = gcry_mpi_get_nbits( key->client_p);
        _b = mpi_new(bits);	/* FIXME: allocate in secure memory */
        gcry_mpi_randomize( _b, bits, GCRY_STRONG_RANDOM);

        tmpB = mpi_new(bits);	/* FIXME: allocate in secure memory */
        B = mpi_new(bits);	/* FIXME: allocate in secure memory */
        mpi_powm( tmpB, G, _b, N);
        mpi_addm( B, V, tmpB, N);
        
        mpi_release(tmpB);
		
	gcry_mpi_print(GCRYMPI_FMT_USG, NULL, &n_b, B);

	(*data) = gnutls_malloc(n_b + 2);

	/* copy B */
	data_b = (*data);
	gcry_mpi_print(GCRYMPI_FMT_USG, &data_b[2], &n_b, B);

	_n_b = n_b;
#ifndef WORDS_BIGENDIAN
	_n_b = byteswap16(_n_b);
	memcpy(data_b, &_n_b, 2);
#else
	memcpy(data_b, &_n_b, 2);
#endif

	/* hash B to get u */
	td = gnutls_hash_init( GNUTLS_MAC_SHA);
	gnutls_hash( td, &data_b[2], n_b);
	hd = gnutls_hash_deinit(td);
	memcpy( &u, hd, sizeof(u));
	gnutls_free(hd);
	
	key->u = mpi_set_ui( NULL, u);

	/* CALC HERE */
	/* S = (A * v^u) ^ b % N */
	
	S = gcry_mpi_alloc_like(N);
	tmp1 = gcry_mpi_alloc_like(N);
	tmp2 = gcry_mpi_alloc_like(N);

	mpi_pow(tmp1, V, key->u);
	mpi_mul(tmp2, A, tmp1);
	mpi_release(tmp1);

	mpi_powm( S, tmp2, _b, N);
	mpi_release(tmp2);
	
	mpi_release(A);
	mpi_release(_b);
	mpi_release(V);
	mpi_release(key->u);
	mpi_release(B);
	return n_b + 2;
}


/* return A = g^a % N */
int gen_srp_client_kx0( GNUTLS_KEY key, opaque** data) {
	size_t n_a, bits;
	uint16 _n_a;
	uint8 *data_a;
	char *username;
	char *password;
	SRP_CLIENT_CREDENTIALS* cred = _gnutls_get_kx_cred( key, GNUTLS_KX_SRP);

	if (cred==NULL) return  GNUTLS_E_INSUFICIENT_CRED;
	
	username = cred->username;
	password = cred->password;

	if (username==NULL || password == NULL) 
		 return  GNUTLS_E_INSUFICIENT_CRED;
        
        bits = gcry_mpi_get_nbits( N);
        _a = mpi_new(bits);	/* FIXME: allocate in secure memory */
        gcry_mpi_randomize(_a, bits, GCRY_STRONG_RANDOM);

        A = mpi_new(bits);	/* FIXME: allocate in secure memory */
        mpi_powm( A, G, _a, N);
        
	gcry_mpi_print(GCRYMPI_FMT_USG, NULL, &n_a, A);

	(*data) = gnutls_malloc(n_a + 2);

	/* copy A */
	data_a = (*data);
	gcry_mpi_print(GCRYMPI_FMT_USG, &data_a[2], &n_a, A);
	_n_a = n_a;
#ifndef WORDS_BIGENDIAN
	_n_a = byteswap16(_n_a);
	memcpy(data_a, &_n_a, 2);
#else
	memcpy(data_a, &_n_a, 2);
#endif

	return n_a + 2;
}

/* receive the first key exchange message ( g, n, s) */
int proc_srp_server_kx( GNUTLS_KEY key, opaque* data, int data_size) {
	uint16 n_s, n_g, n_n;
	size_t _n_s, _n_g, _n_n;
	uint8 *data_n;
	uint8 *data_g;
	uint8 *data_s;
	int i;
	GNUTLS_MAC_HANDLE td;
	opaque* hd;
	char *username;
	char *password;
	SRP_CLIENT_CREDENTIALS* cred = _gnutls_get_kx_cred( key, GNUTLS_KX_SRP);

	if (cred==NULL) return GNUTLS_E_INSUFICIENT_CRED;
	
	username = cred->username;
	password = cred->password;

	if (username==NULL || password == NULL) 
		 return GNUTLS_E_INSUFICIENT_CRED;

	i = 0;
	memcpy(&n_g, &data[i], 2);
	i += 2;
#ifndef WORDS_BIGENDIAN
	n_g = byteswap16(n_g);
#endif

	data_g = &data[i];
	i += n_g;
	if (i > data_size) {
		gnutls_assert();
		return GNUTLS_E_UNEXPECTED_PACKET_LENGTH;
	}
	memcpy(&n_n, &data[i], 2);
#ifndef WORDS_BIGENDIAN
	n_n = byteswap16(n_n);
#endif
	i += 2;
	data_n = &data[i];
	i += n_n;
	if (i > data_size) {
		gnutls_assert();
		return GNUTLS_E_UNEXPECTED_PACKET_LENGTH;
	}
	memcpy(&n_s, &data[i], 2);
	i += 2;
#ifndef WORDS_BIGENDIAN
	n_s = byteswap16(n_s);
#endif

	data_s = &data[i];
	i += n_s;
	if (i > data_size) {
		gnutls_assert();
		return GNUTLS_E_UNEXPECTED_PACKET_LENGTH;
	}
	_n_s = n_s;
	_n_g = n_g;
	_n_n = n_n;

	if (gcry_mpi_scan(&N,
			      GCRYMPI_FMT_USG, data_n, &_n_n) != 0) {
		gnutls_assert();
		return GNUTLS_E_MPI_SCAN_FAILED;
	}

	if (gcry_mpi_scan(&G,
			      GCRYMPI_FMT_USG, data_g, &_n_g) != 0) {
		gnutls_assert();
		return GNUTLS_E_MPI_SCAN_FAILED;
	}

	/* generate x = SHA(s | SHA(U | ":" | p))
	 */
	td = gnutls_hash_init( GNUTLS_MAC_SHA);
	gnutls_hash( td, username, strlen(username));
	gnutls_hash( td, ":", 1);
	gnutls_hash( td, password, strlen(password));
	hd = gnutls_hash_deinit(td);

	td = gnutls_hash_init( GNUTLS_MAC_SHA);
	gnutls_hash( td, data_s, n_s);
	gnutls_hash( td, hd, 20);
	gnutls_free(hd);
	
	hd = gnutls_hash_deinit(td);
	
	_n_g = 20;
	if (gcry_mpi_scan(&key->x,
			      GCRYMPI_FMT_USG, hd, &_n_g) != 0) {
		gnutls_assert();
		return GNUTLS_E_MPI_SCAN_FAILED;
	}

	gnutls_free(hd);
	

	return 0;
}

int proc_srp_client_kx0( GNUTLS_KEY key, opaque* data, int data_size) {
	uint16 n_A;
	size_t _n_A;

	memcpy(&n_A, &data[0], 2);
#ifndef WORDS_BIGENDIAN
	n_A = byteswap16(n_A);
#endif
	_n_A = n_A;
	if (gcry_mpi_scan(&A,
		      GCRYMPI_FMT_USG, &data[2], &_n_A)) {
		gnutls_assert();
		return GNUTLS_E_MPI_SCAN_FAILED;
	}

	return 0;
}


int proc_srp_server_kx2( GNUTLS_KEY key, opaque* data, int data_size) {
	uint16 n_B;
	size_t _n_B;
	MPI tmp1, tmp2, tmp3, tmp4;

	memcpy(&n_B, &data[0], 2);
#ifndef WORDS_BIGENDIAN
	n_B = byteswap16(n_B);
#endif
	_n_B = n_B;
	if (gcry_mpi_scan(&B,
		      GCRYMPI_FMT_USG, &data[2], &_n_B)) {
		gnutls_assert();
		return GNUTLS_E_MPI_SCAN_FAILED;
	}

	/* CALC HERE */
	/* S = (B - g^x) ^ (a + u * x) % N */

	S = gcry_mpi_alloc_like(N);
	tmp1 = gcry_mpi_alloc_like(N);
	tmp2 = gcry_mpi_alloc_like(N);

	mpi_pow(tmp1, G, V);
	mpi_sub(tmp2, B, tmp1);
	mpi_release(tmp1);


	tmp3 = gcry_mpi_alloc_like(N);
	tmp4 = gcry_mpi_alloc_like(N);
	
	mpi_add( tmp3, key->u, V);
	mpi_add( tmp4, _a, tmp3);
	mpi_release(tmp3);
	
	mpi_powm( S, tmp2, tmp4, N);
	mpi_release(tmp2);
	mpi_release(tmp4);
	
	mpi_release(A);
	mpi_release(_b);
	mpi_release(V);
	mpi_release(key->u);
	mpi_release(B);
	return 0;
}

