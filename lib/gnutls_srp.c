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
#include <gnutls_int.h>
#include <gnutls_errors.h>
#include <crypt_bcrypt.h>
#include <gnutls_srp.h>
#include <cert_b64.h>
#include "debug.h"

/* These should be added in gcrypt.h */
#define gcry_mpi_add mpi_add
#define gcry_mpi_subm mpi_subm
#define gcry_mpi_addm mpi_addm
#define gcry_mpi_mul mpi_mul
#define gcry_mpi_mulm mpi_mulm

/* Here functions for SRP (like g^x mod n) are defined 
 */

/* Taken from gsti -- this is n 
 */

const uint8 diffie_hellman_group1_prime[130] = { 0x04, 0x00,
	0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xC9, 0x0F, 0xDA, 0xA2,
	0x21, 0x68, 0xC2, 0x34, 0xC4, 0xC6, 0x62, 0x8B, 0x80, 0xDC, 0x1C, 0xD1,
	0x29, 0x02, 0x4E, 0x08, 0x8A, 0x67, 0xCC, 0x74, 0x02, 0x0B, 0xBE, 0xA6,
	0x3B, 0x13, 0x9B, 0x22, 0x51, 0x4A, 0x08, 0x79, 0x8E, 0x34, 0x04, 0xDD,
	0xEF, 0x95, 0x19, 0xB3, 0xCD, 0x3A, 0x43, 0x1B, 0x30, 0x2B, 0x0A, 0x6D,
	0xF2, 0x5F, 0x14, 0x37, 0x4F, 0xE1, 0x35, 0x6D, 0x6D, 0x51, 0xC2, 0x45,
	0xE4, 0x85, 0xB5, 0x76, 0x62, 0x5E, 0x7E, 0xC6, 0xF4, 0x4C, 0x42, 0xE9,
	0xA6, 0x37, 0xED, 0x6B, 0x0B, 0xFF, 0x5C, 0xB6, 0xF4, 0x06, 0xB7, 0xED,
	0xEE, 0x38, 0x6B, 0xFB, 0x5A, 0x89, 0x9F, 0xA5, 0xAE, 0x9F, 0x24, 0x11,
	0x7C, 0x4B, 0x1F, 0xE6, 0x49, 0x28, 0x66, 0x51, 0xEC, 0xE6, 0x53, 0x81,
	0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF
};

int _gnutls_srp_gn( opaque** ret_g, opaque** ret_n) {

	MPI g, prime;
	size_t n = sizeof diffie_hellman_group1_prime;
	int siz;
	char* tmp;

	if (gcry_mpi_scan(&prime, GCRYMPI_FMT_USG,
			  diffie_hellman_group1_prime, &n)) {
		gnutls_assert();
		return GNUTLS_E_MPI_SCAN_FAILED;
	}

	g = gcry_mpi_set_ui(NULL, SRP_G);


	siz = 0;
	gcry_mpi_print(GCRYMPI_FMT_USG, NULL, &siz, g);
	if (ret_g!=NULL) {
		tmp = gnutls_malloc(siz);
		gcry_mpi_print(GCRYMPI_FMT_USG, tmp, &siz, g);

		if (_gnutls_sbase64_encode( tmp, siz, ret_g) < 0)  {
			gnutls_free(tmp);
			return GNUTLS_E_UNKNOWN_ERROR;
		}
		gnutls_free(tmp);
	}

	siz = 0;
	gcry_mpi_print(GCRYMPI_FMT_USG, NULL, &siz, prime);
	if (ret_n!=NULL) {
		tmp = gnutls_malloc(siz);
		gcry_mpi_print(GCRYMPI_FMT_USG, tmp, &siz, prime);
		if (_gnutls_sbase64_encode( tmp, siz, ret_n) < 0) {
			gnutls_free(tmp);
			return GNUTLS_E_UNKNOWN_ERROR;
		}

		gnutls_free(tmp);
	}
	
	gcry_mpi_release(g);
	gcry_mpi_release(prime);

	return 0;

}


int _gnutls_srp_gx(opaque *text, int textsize, opaque** result, MPI g, MPI prime) {

	MPI x, e;
	int result_size;

	if (gcry_mpi_scan(&x, GCRYMPI_FMT_USG,
			  text, &textsize)) {
		gnutls_assert();
		return GNUTLS_E_MPI_SCAN_FAILED;
	}

	e = gcry_mpi_alloc_like(prime);

	/* e = g^x mod prime (n) */
	gcry_mpi_powm(e, g, x, prime);
	gcry_mpi_release(x);

	
	gcry_mpi_print(GCRYMPI_FMT_USG, NULL, &result_size, e);
	if (result!=NULL) {
		*result = gnutls_malloc(result_size);
		gcry_mpi_print(GCRYMPI_FMT_USG, *result, &result_size, e);	
	}

	gcry_mpi_release(e);

	return result_size;

}


/****************
 * Choose a random value b and calculate B = (v + g^b) % N.
 * Return: B and if ret_b is not NULL b.
 */
MPI _gnutls_calc_srp_B(MPI * ret_b, MPI g, MPI n, MPI v)
{
	MPI tmpB;
	MPI b, B;
	int bits;
	
	/* calculate:  B = (v + g^b) % N */
	bits = gcry_mpi_get_nbits(n);
	b = gcry_mpi_new(bits);	/* FIXME: allocate in secure memory */
	gcry_mpi_randomize(b, bits, GCRY_STRONG_RANDOM);

	tmpB = gcry_mpi_new(bits);	/* FIXME: allocate in secure memory */
	B = gcry_mpi_new(bits);	/* FIXME: allocate in secure memory */
	gcry_mpi_powm(tmpB, g, b, n);
	gcry_mpi_addm(B, v, tmpB, n);

	gcry_mpi_release(tmpB);

	if (ret_b)
		*ret_b = b;
	else
		gcry_mpi_release(b);

	return B;
}

MPI _gnutls_calc_srp_u( MPI B) {
int b_size;
opaque* b_holder, *hd;
GNUTLS_MAC_HANDLE td;
uint32 u;
MPI ret;

	gcry_mpi_print(GCRYMPI_FMT_USG, NULL, &b_size, B);
	b_holder = gnutls_malloc(b_size);
	
	gcry_mpi_print(GCRYMPI_FMT_USG, b_holder, &b_size, B);
	
	
	td = gnutls_hash_init(GNUTLS_MAC_SHA);
	gnutls_hash(td, b_holder, b_size);
	hd = gnutls_hash_deinit(td);
	memcpy(&u, hd, sizeof(u));
	gnutls_free(hd);
	gnutls_free(b_holder);

	ret = gcry_mpi_set_ui(NULL, u);

	return ret;	
}

/* S = (A * v^u) ^ b % N 
 * this is our shared key
 */
MPI _gnutls_calc_srp_S1(MPI A, MPI b, MPI u, MPI v, MPI n)
{
MPI tmp1, tmp2;
MPI S;

S = gcry_mpi_alloc_like(n);
tmp1 = gcry_mpi_alloc_like(n);
tmp2 = gcry_mpi_alloc_like(n);

gcry_mpi_powm(tmp1, v, u, n);
gcry_mpi_mulm(tmp2, A, tmp1, n);
gcry_mpi_release(tmp1);

gcry_mpi_powm(S, tmp2, b, n);
gcry_mpi_release(tmp2);

return S;
}

/* A = g^a % N 
 * returns A and a (which is random)
 */
MPI _gnutls_calc_srp_A(MPI *a, MPI g, MPI n)
{
MPI tmpa;
MPI A;
int bits;

	bits = gcry_mpi_get_nbits(n);
	tmpa = gcry_mpi_new(bits);	/* FIXME: allocate in secure memory */
	gcry_mpi_randomize(tmpa, bits, GCRY_STRONG_RANDOM);

	A = gcry_mpi_new(bits);	/* FIXME: allocate in secure memory */
	gcry_mpi_powm(A, g, tmpa, n);

	if (a!=NULL)
		*a = tmpa;
	else
		gcry_mpi_release(tmpa);
	
	return A;
}

/* generate x = SHA(s | SHA(U | ":" | p))
 * The output is exactly 20 bytes
 */
void* _gnutls_calc_srp_sha( char* username, char* password, opaque* salt, int salt_size, int* size) {
GNUTLS_MAC_HANDLE td;
opaque* res;

	*size = 20;
	
	td = gnutls_hash_init(GNUTLS_MAC_SHA);
	gnutls_hash(td, username, strlen(username));
	gnutls_hash(td, ":", 1);
	gnutls_hash(td, password, strlen(password));
	res = gnutls_hash_deinit(td);

	td = gnutls_hash_init(GNUTLS_MAC_SHA);
	gnutls_hash(td, salt, salt_size);
	gnutls_hash(td, res, 20); /* 20 bytes is the output of sha1 */
	gnutls_free(res);

	return gnutls_hash_deinit(td);
}

void* _gnutls_calc_srp_x( char* username, char* password, opaque* salt, int salt_size, uint8 crypt_algo, int* size) {
	
	switch(crypt_algo) {
		case SRPSHA1_CRYPT:
			return _gnutls_calc_srp_sha( username, password, salt, salt_size, size);
		case BLOWFISH_CRYPT:
			return _gnutls_calc_srp_bcrypt( password, salt, salt_size, size);
	}
	return NULL;	
}


/* S = (B - g^x) ^ (a + u * x) % N
 * this is our shared key
 */
MPI _gnutls_calc_srp_S2(MPI B, MPI g, MPI x, MPI a, MPI u, MPI n)
{
MPI S, tmp1, tmp2, tmp4;

	S = gcry_mpi_alloc_like(n);
	tmp1 = gcry_mpi_alloc_like(n);
	tmp2 = gcry_mpi_alloc_like(n);

	gcry_mpi_powm(tmp1, g, x, n);

	gcry_mpi_subm(tmp2, B, tmp1, n);

	tmp4 = gcry_mpi_alloc_like(n);

	gcry_mpi_mul(tmp1, u, x);
	gcry_mpi_add(tmp4, a, tmp1);
	gcry_mpi_release(tmp1);

	gcry_mpi_powm(S, tmp2, tmp4, n);
	gcry_mpi_release(tmp2);
	gcry_mpi_release(tmp4);

	return S;
}
