/*
 *      Copyright (C) 2000 Nikos Mavroyanopoulos
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
#include "gnutls_dh.h"
#include "gnutls_num.h"

int gen_anon_server_kx( GNUTLS_KEY, opaque**);
int gen_anon_client_kx( GNUTLS_KEY, opaque**);
int proc_anon_server_kx( GNUTLS_KEY, opaque*, int);
int proc_anon_client_kx( GNUTLS_KEY, opaque*, int);

MOD_AUTH_STRUCT anon_auth_struct = {
	"ANON",
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
	size_t n_X, n_g, n_p;
	uint16 _n_X, _n_g, _n_p;
	uint8 *data_p;
	uint8 *data_g;
	uint8 *data_X;

	X = gnutls_calc_dh_secret(&x);
	key->dh_secret = x;
	g = gnutls_get_dh_params(&p);
	gcry_mpi_print(GCRYMPI_FMT_USG, NULL, &n_g, g);
	gcry_mpi_print(GCRYMPI_FMT_USG, NULL, &n_p, p);
	gcry_mpi_print(GCRYMPI_FMT_USG, NULL, &n_X, X);
	(*data) = gnutls_malloc(n_g + n_p + n_X + 6);
	data_p = &(*data)[0];
	gcry_mpi_print(GCRYMPI_FMT_USG, &data_p[2], &n_p, p);
	gnutls_mpi_release(p);

	_n_p = CONVuint16( (uint16)n_p);
	memmove(data_p, &_n_p, 2);

	data_g = &data_p[2 + n_p];
	gcry_mpi_print(GCRYMPI_FMT_USG, &data_g[2], &n_g, g);
	gnutls_mpi_release(g);
	
	_n_g = CONVuint16( (uint16)n_g);
	memmove(data_g, &_n_g, 2);

	data_X = &data_g[2 + n_g];
	gcry_mpi_print(GCRYMPI_FMT_USG, &data_X[2], &n_X, X);
	gnutls_mpi_release(X);

	_n_X = CONVuint16( (uint16)n_X);
	memmove(data_X, &_n_X, 2);

	return n_p+n_g+n_X+6;
}

int gen_anon_client_kx( GNUTLS_KEY key, opaque** data) {
GNUTLS_MPI x, X;
size_t n_X;
uint16 _n_X;

	X =  _gnutls_calc_dh_secret(&x, key->client_g,
		   key->client_p);
		   
	gcry_mpi_print(GCRYMPI_FMT_USG, NULL, &n_X, X);
	(*data) = gnutls_malloc(n_X + 2);
	
	gcry_mpi_print(GCRYMPI_FMT_USG, &(*data)[2], &n_X, X);
	(*data)[0] = 1;	/* extern - explicit since we do not have
				   certificate */
	gnutls_mpi_release(X);
	
	_n_X = CONVuint16( (uint16)n_X);
	memmove(&(*data)[0], &_n_X, 2);
	
	/* calculate the key after calculating the message */
	key->KEY = _gnutls_calc_dh_key(key->client_Y, x, key->client_p);

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

	/* We should check signature in non-anonymous KX 
	 * this is anonymous however
	 */

	return 0;
}

int proc_anon_client_kx( GNUTLS_KEY key, opaque* data, int data_size) {
	uint16 n_Y;
	size_t _n_Y;

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

	key->KEY = gnutls_calc_dh_key( key->client_Y, key->dh_secret);

	gnutls_mpi_release(key->client_Y);
	gnutls_mpi_release(key->dh_secret);
	key->client_Y = NULL;
	key->dh_secret = NULL;

	return 0;
}

