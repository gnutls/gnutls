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

int gen_anon_server_kx( GNUTLS_KEY, opaque**);
int gen_anon_client_kx( GNUTLS_KEY, opaque**);
int proc_anon_server_kx( GNUTLS_KEY, opaque*, int);
int proc_anon_client_kx( GNUTLS_KEY, opaque*, int);

int gen_anon_client_cert_vrfy( GNUTLS_KEY, opaque**);
int proc_anon_client_cert_vrfy( GNUTLS_KEY, opaque*, int);

int gen_anon_server_cert_vrfy( GNUTLS_KEY, opaque**);
int proc_anon_server_cert_vrfy( GNUTLS_KEY, opaque*, int);

MOD_AUTH_STRUCT anon_auth_struct = {
	"ANON",
	gen_anon_server_kx,
	gen_anon_client_kx,
	gen_anon_client_cert_vrfy,
	gen_anon_server_cert_vrfy,
	proc_anon_server_kx,
	proc_anon_client_kx,
	proc_anon_client_cert_vrfy,
	proc_anon_server_cert_vrfy
};

int gen_anon_server_kx( GNUTLS_KEY key, opaque** data) {
	GNUTLS_MPI x, X, g, p;
	size_t n_X, n_g, n_p;
	uint16 _n_X, _n_g, _n_p;
	uint8 *data_p;
	uint8 *data_g;
	uint8 *data_X;
	int ret = 0;

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
	_n_p = n_p;
#ifndef WORDS_BIGENDIAN
	_n_p = byteswap16(_n_p);
	memmove(data_p, &_n_p, 2);
#else
	memmove(data_p, &_n_p, 2);
#endif
	data_g = &data_p[2 + n_p];
	gcry_mpi_print(GCRYMPI_FMT_USG, &data_g[2], &n_g, g);
	gnutls_mpi_release(g);
	_n_g = n_g;
#ifndef WORDS_BIGENDIAN
	_n_g = byteswap16(_n_g);
	memmove(data_g, &_n_g, 2);
#else
	memmove(data_g, &_n_g, 2);
#endif
	data_X = &data_g[2 + n_g];
	gcry_mpi_print(GCRYMPI_FMT_USG, &data_X[2], &n_X, X);
	gnutls_mpi_release(X);
	_n_X = n_X;
#ifndef WORDS_BIGENDIAN
	_n_X = byteswap16(_n_X);
	memmove(data_X, &_n_X, 2);
#else
	memmove(data_X, &_n_X, 2);
#endif
	ret = n_p+n_g+n_X+6;

	return ret;
}

int gen_anon_client_kx( GNUTLS_KEY key, opaque** data) {
GNUTLS_MPI x, X;
size_t n_X;
uint16 _n_X;
int data_size;

	X =  _gnutls_calc_dh_secret(&x, key->client_g,
		   key->client_p);
		   
	gcry_mpi_print(GCRYMPI_FMT_USG, NULL, &n_X, X);
	(*data) = gnutls_malloc(n_X + 2);
	
	gcry_mpi_print(GCRYMPI_FMT_USG, &(*data)[2], &n_X, X);
	(*data)[0] = 1;	/* extern - explicit since we do not have
				   certificate */
	gnutls_mpi_release(X);
	_n_X = n_X;
#ifndef WORDS_BIGENDIAN
	_n_X = byteswap16(_n_X);
	memmove(&(*data)[0], &_n_X, 2);
#else
	memmove(&(*data)[0], &_n_X, 2);
#endif
	data_size = _n_X+2;
	
	/* calculate the key after calculating the message */
	key->KEY = _gnutls_calc_dh_key(key->client_Y, x, key->client_p);

	/* THESE SHOULD BE DISCARDED */
	gnutls_mpi_release(key->client_Y);
	gnutls_mpi_release(key->client_p);
	gnutls_mpi_release(key->client_g);
	key->client_Y = NULL;
	key->client_p = NULL;
	key->client_g = NULL;

	return data_size;
}

int proc_anon_server_kx( GNUTLS_KEY key, opaque* data, int data_size) {
	uint16 n_Y, n_g, n_p;
	size_t _n_Y, _n_g, _n_p;
	uint8 *data_p;
	uint8 *data_g;
	uint8 *data_Y;
	int i;


	i = 0;
	memmove(&n_p, &data[i], 2);
	i += 2;
#ifndef WORDS_BIGENDIAN
	n_p = byteswap16(n_p);
#endif

	data_p = &data[i];
	i += n_p;
	if (i > data_size) {
		gnutls_assert();
		return GNUTLS_E_UNEXPECTED_PACKET_LENGTH;
	}
	memmove(&n_g, &data[i], 2);
#ifndef WORDS_BIGENDIAN
	n_g = byteswap16(n_g);
#endif
	i += 2;
	data_g = &data[i];
	i += n_g;
	if (i > data_size) {
		gnutls_assert();
		return GNUTLS_E_UNEXPECTED_PACKET_LENGTH;
	}
	memmove(&n_Y, &data[i], 2);
	i += 2;
#ifndef WORDS_BIGENDIAN
	n_Y = byteswap16(n_Y);
#endif

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

	memmove(&n_Y, &data[0], 2);
#ifndef WORDS_BIGENDIAN
	n_Y = byteswap16(n_Y);
#endif
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

int gen_anon_client_cert_vrfy( GNUTLS_KEY key, opaque** data) {
	(*data) =  NULL;
	return 0;
}
int gen_anon_server_cert_vrfy( GNUTLS_KEY key, opaque** data) {
	(*data) =  NULL;
	return 0;
}
int proc_anon_client_cert_vrfy( GNUTLS_KEY key, opaque* data, int data_size) {
	/* no certificate check in anonymous KX */
	return 0;
}
int proc_anon_server_cert_vrfy( GNUTLS_KEY key, opaque* data, int data_size) {
	/* no certificate check in this algorithm */
	return 0;
}
