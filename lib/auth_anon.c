/*
 *      Copyright (C) 2000,2001 Nikos Mavroyanopoulos
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
#include "gnutls_auth_int.h"
#include "gnutls_errors.h"
#include "gnutls_dh.h"
#include "auth_anon.h"
#include "gnutls_num.h"

#define DEFAULT_BITS 1024

int gen_anon_server_kx( GNUTLS_KEY, opaque**);
int gen_anon_client_kx( GNUTLS_KEY, opaque**);
int proc_anon_server_kx( GNUTLS_KEY, opaque*, int);
int proc_anon_client_kx( GNUTLS_KEY, opaque*, int);

MOD_AUTH_STRUCT anon_auth_struct = {
	"ANON",
	NULL,
	gen_anon_server_kx,
	NULL,
	NULL,
	gen_anon_client_kx,
	NULL,
	NULL,
	proc_anon_server_kx,
	NULL,
	NULL,
	proc_anon_client_kx,
	NULL,
	NULL
};

int gen_anon_server_kx( GNUTLS_KEY key, opaque** data) {
	GNUTLS_MPI x, X, g, p;
	int bits;
	size_t n_X, n_g, n_p;
	uint8 *data_p;
	uint8 *data_g;
	uint8 *data_X;
	const ANON_SERVER_CREDENTIALS * cred;

	cred = _gnutls_get_cred( key, GNUTLS_ANON, NULL);
	if (cred==NULL) {
		bits = DEFAULT_BITS; /* default */
	} else {
		bits = cred->dh_bits;
	}

	g = gnutls_get_dh_params(&p, bits);

	key->auth_info = gnutls_malloc(sizeof(ANON_AUTH_INFO));
	if (key->auth_info==NULL) return GNUTLS_E_MEMORY_ERROR;
	((ANON_AUTH_INFO*)key->auth_info)->dh_bits = gcry_mpi_get_nbits(p);
	key->auth_info_size = sizeof(ANON_AUTH_INFO);

	X = gnutls_calc_dh_secret(&x, g, p);
	key->dh_secret = x;
	gcry_mpi_print(GCRYMPI_FMT_USG, NULL, &n_g, g);
	gcry_mpi_print(GCRYMPI_FMT_USG, NULL, &n_p, p);
	gcry_mpi_print(GCRYMPI_FMT_USG, NULL, &n_X, X);
	(*data) = gnutls_malloc(n_g + n_p + n_X + 6);
	data_p = &(*data)[0];
	gcry_mpi_print(GCRYMPI_FMT_USG, &data_p[2], &n_p, p);
	gnutls_mpi_release(p);

	WRITEuint16( n_p, data_p);

	data_g = &data_p[2 + n_p];
	gcry_mpi_print(GCRYMPI_FMT_USG, &data_g[2], &n_g, g);
	gnutls_mpi_release(g);
	
	WRITEuint16( n_g, data_g);

	data_X = &data_g[2 + n_g];
	gcry_mpi_print(GCRYMPI_FMT_USG, &data_X[2], &n_X, X);
	gnutls_mpi_release(X);

	WRITEuint16( n_X, data_X);

	return n_p+n_g+n_X+6;
}

int gen_anon_client_kx( GNUTLS_KEY key, opaque** data) {
GNUTLS_MPI x, X;
size_t n_X;

	X =  gnutls_calc_dh_secret(&x, key->client_g,
		   key->client_p);
		   
	gcry_mpi_print(GCRYMPI_FMT_USG, NULL, &n_X, X);
	(*data) = gnutls_malloc(n_X + 2);
	
	gcry_mpi_print(GCRYMPI_FMT_USG, &(*data)[2], &n_X, X);
	(*data)[0] = 1;	/* extern - explicit since we do not have
				   certificate */
	gnutls_mpi_release(X);
	
	WRITEuint16( n_X, &(*data)[0]);
	
	/* calculate the key after calculating the message */
	key->KEY = gnutls_calc_dh_key(key->client_Y, x, key->client_p);

	/* THESE SHOULD BE DISCARDED */
	gnutls_mpi_release(key->client_Y);
	gnutls_mpi_release(key->client_p);
	gnutls_mpi_release(key->client_g);
	key->client_Y = NULL;
	key->client_p = NULL;
	key->client_g = NULL;

	return n_X+2;
}

int proc_anon_server_kx( GNUTLS_KEY key, opaque* data, int data_size) {
	uint16 n_Y, n_g, n_p;
	size_t _n_Y, _n_g, _n_p;
	uint8 *data_p;
	uint8 *data_g;
	uint8 *data_Y;
	int i;


	i = 0;
	n_p = READuint16( &data[i]);
	i += 2;

	data_p = &data[i];
	i += n_p;
	if (i > data_size) {
		gnutls_assert();
		return GNUTLS_E_UNEXPECTED_PACKET_LENGTH;
	}
	n_g = READuint16( &data[i]);
	i += 2;

	data_g = &data[i];
	i += n_g;
	if (i > data_size) {
		gnutls_assert();
		return GNUTLS_E_UNEXPECTED_PACKET_LENGTH;
	}
	
	n_Y = READuint16( &data[i]);
	i += 2;

	data_Y = &data[i];
	i += n_Y;
	if (i > data_size) {
		gnutls_assert();
		return GNUTLS_E_UNEXPECTED_PACKET_LENGTH;
	}
	_n_Y = n_Y;
	_n_g = n_g;
	_n_p = n_p;

	if (gcry_mpi_scan(&key->client_Y,
			      GCRYMPI_FMT_USG, data_Y, &_n_Y) != 0) {
		gnutls_assert();
		return GNUTLS_E_MPI_SCAN_FAILED;
	}

	if (gcry_mpi_scan(&key->client_g,
			      GCRYMPI_FMT_USG, data_g, &_n_g) != 0) {
		gnutls_assert();
		return GNUTLS_E_MPI_SCAN_FAILED;
	}
	if (gcry_mpi_scan(&key->client_p,
				      GCRYMPI_FMT_USG, data_p, &_n_p) != 0) {
		gnutls_assert();
		return GNUTLS_E_MPI_SCAN_FAILED;
	}

	/* set auth_info */
	key->auth_info = gnutls_malloc(sizeof(ANON_AUTH_INFO));
	if (key->auth_info==NULL) return GNUTLS_E_MEMORY_ERROR;
	((ANON_AUTH_INFO*)key->auth_info)->dh_bits = gcry_mpi_get_nbits(key->client_p);
	key->auth_info_size = sizeof(ANON_AUTH_INFO);

	/* We should check signature in non-anonymous KX 
	 * this is anonymous however
	 */

	return 0;
}

int proc_anon_client_kx( GNUTLS_KEY key, opaque* data, int data_size) {
	uint16 n_Y;
	size_t _n_Y;
	MPI g, p;
	int bits;
	const ANON_SERVER_CREDENTIALS * cred;

	cred = _gnutls_get_cred( key, GNUTLS_ANON, NULL);
	if (cred==NULL) {
		bits = DEFAULT_BITS; /* default */
	} else {
		bits = cred->dh_bits;
	}

#if 0 /* removed. I do not know why - maybe I didn't get the protocol,
       * but openssl does not use that byte
       */
	if (data[0] != 1) {
		gnutls_assert();
		return GNUTLS_E_UNIMPLEMENTED_FEATURE;
	}
#endif

	n_Y = READuint16( &data[0]);

	_n_Y = n_Y;
	if (gcry_mpi_scan(&key->client_Y,
		      GCRYMPI_FMT_USG, &data[2], &_n_Y)) {
		gnutls_assert();
		return GNUTLS_E_MPI_SCAN_FAILED;
	}

	g = gnutls_get_dh_params(&p, bits);
	key->KEY = gnutls_calc_dh_key( key->client_Y, key->dh_secret, p);

	gnutls_mpi_release(key->client_Y);
	gnutls_mpi_release(key->dh_secret);
	gnutls_mpi_release(p);
	gnutls_mpi_release(g);
	key->client_Y = NULL;
	key->dh_secret = NULL;

	return 0;
}

