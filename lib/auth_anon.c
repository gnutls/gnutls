/*
 *      Copyright (C) 2000,2001,2002 Nikos Mavroyanopoulos
 *
 * This file is part of GNUTLS.
 *
 *  The GNUTLS library is free software; you can redistribute it and/or
 *  modify it under the terms of the GNU Lesser General Public   
 *  License as published by the Free Software Foundation; either 
 *  version 2.1 of the License, or (at your option) any later version.
 *
 *  This library is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of 
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 *  Lesser General Public License for more details.
 *
 *  You should have received a copy of the GNU Lesser General Public
 *  License along with this library; if not, write to the Free Software
 *  Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA 02111-1307  USA
 * 
 */

/* This file contains the Anonymous Diffie Hellman key exchange part of
 * the anonymous authentication. The functions here are used in the
 * handshake.
 */

#include "gnutls_int.h"

#ifdef ENABLE_ANON

#include "gnutls_auth_int.h"
#include "gnutls_errors.h"
#include "gnutls_dh.h"
#include "auth_anon.h"
#include "gnutls_num.h"
#include "gnutls_mpi.h"
#include <gnutls_state.h>

int gen_anon_server_kx( GNUTLS_STATE, opaque**);
int gen_anon_client_kx( GNUTLS_STATE, opaque**);
int proc_anon_server_kx( GNUTLS_STATE, opaque*, int);
int proc_anon_client_kx( GNUTLS_STATE, opaque*, int);

const MOD_AUTH_STRUCT anon_auth_struct = {
	"ANON",
	NULL,
	NULL,
	gen_anon_server_kx,
	NULL,
	NULL,
	gen_anon_client_kx,
	NULL,
	NULL,

	NULL,
	NULL, /* certificate */
	proc_anon_server_kx,
	NULL,
	NULL,
	proc_anon_client_kx,
	NULL,
	NULL
};

int gen_anon_server_kx( GNUTLS_STATE state, opaque** data) {
	GNUTLS_MPI x, X, g, p;
	int bits, ret;
	size_t n_X, n_g, n_p;
	uint8 *data_p;
	uint8 *data_g;
	uint8 *data_X;
	ANON_SERVER_AUTH_INFO info;
	const GNUTLS_ANON_SERVER_CREDENTIALS cred;
	
	cred = _gnutls_get_cred(state->gnutls_key, GNUTLS_CRD_ANON, NULL);
	if (cred == NULL) {
		gnutls_assert();
		return GNUTLS_E_INSUFICIENT_CRED;
	}

	bits = _gnutls_dh_get_prime_bits( state);

	g = gnutls_get_dh_params( cred->dh_params, &p, bits);
	if (g==NULL || p==NULL) {
		gnutls_assert();
		return GNUTLS_E_MEMORY_ERROR;
	}

	if ( (ret=_gnutls_auth_info_set( state, GNUTLS_CRD_ANON, sizeof( ANON_SERVER_AUTH_INFO_INT), 1)) < 0) {
		gnutls_assert();
		return ret;
	}

	info = _gnutls_get_auth_info( state);	
	if ((ret=_gnutls_dh_set_prime_bits( state, _gnutls_mpi_get_nbits(p))) < 0) {
		gnutls_assert();
		return ret;
	}
	
	X = gnutls_calc_dh_secret(&x, g, p);
	if (X==NULL || x==NULL) {
		gnutls_assert();
		_gnutls_mpi_release( &g);
		_gnutls_mpi_release( &p);
		_gnutls_mpi_release( &x);
		_gnutls_mpi_release( &X);
		return GNUTLS_E_MEMORY_ERROR;
	}
	ret=_gnutls_dh_set_secret_bits( state, _gnutls_mpi_get_nbits(x));
	if (ret<0) {
		gnutls_assert();
		return ret;
	}
	
	state->gnutls_key->dh_secret = x;
	_gnutls_mpi_print( NULL, &n_g, g);
	_gnutls_mpi_print( NULL, &n_p, p);
	_gnutls_mpi_print( NULL, &n_X, X);
	(*data) = gnutls_malloc(n_g + n_p + n_X + 6);
	if (*data==NULL) {
		_gnutls_mpi_release( &X);
		_gnutls_mpi_release( &g);
		_gnutls_mpi_release( &p);
		return GNUTLS_E_MEMORY_ERROR;
	}
	data_p = &(*data)[0];
	_gnutls_mpi_print( &data_p[2], &n_p, p);
	_gnutls_mpi_release(&p);

	_gnutls_write_uint16( n_p, data_p);

	data_g = &data_p[2 + n_p];
	_gnutls_mpi_print( &data_g[2], &n_g, g);
	_gnutls_mpi_release(&g);
	
	_gnutls_write_uint16( n_g, data_g);

	data_X = &data_g[2 + n_g];
	_gnutls_mpi_print( &data_X[2], &n_X, X);
	_gnutls_mpi_release(&X);

	_gnutls_write_uint16( n_X, data_X);

	return n_p+n_g+n_X+6;
}

int gen_anon_client_kx( GNUTLS_STATE state, opaque** data) {
GNUTLS_MPI x, X;
size_t n_X;
int ret;

	X =  gnutls_calc_dh_secret(&x, state->gnutls_key->client_g,
		   state->gnutls_key->client_p);

	if (X==NULL) {
		gnutls_assert();
		return GNUTLS_E_MEMORY_ERROR;
	}
	
	ret=_gnutls_dh_set_secret_bits( state, _gnutls_mpi_get_nbits(x));
	if (ret<0) {
		gnutls_assert();
		return ret;
	}
			   
	_gnutls_mpi_print( NULL, &n_X, X);
	(*data) = gnutls_malloc(n_X + 2);
	if (*data==NULL)
		return GNUTLS_E_MEMORY_ERROR;
	
	_gnutls_mpi_print( &(*data)[2], &n_X, X);
	(*data)[0] = 1;	/* extern - explicit since we do not have
				   certificate */
	_gnutls_mpi_release(&X);
	
	_gnutls_write_uint16( n_X, &(*data)[0]);

	/* calculate the key after calculating the message */
	state->gnutls_key->KEY = gnutls_calc_dh_key(state->gnutls_key->client_Y, x, state->gnutls_key->client_p);
	if (state->gnutls_key->KEY==NULL)
		return GNUTLS_E_MEMORY_ERROR;

	/* THESE SHOULD BE DISCARDED */
	_gnutls_mpi_release(&state->gnutls_key->client_Y);
	_gnutls_mpi_release(&state->gnutls_key->client_p);
	_gnutls_mpi_release(&state->gnutls_key->client_g);

	ret = _gnutls_generate_key( state->gnutls_key);
	_gnutls_mpi_release(&state->gnutls_key->KEY);

	if (ret < 0) {
		return ret;
	}
	return n_X+2;
}

int proc_anon_server_kx( GNUTLS_STATE state, opaque* data, int data_size) {
	uint16 n_Y, n_g, n_p;
	size_t _n_Y, _n_g, _n_p;
	uint8 *data_p;
	uint8 *data_g;
	uint8 *data_Y;
	int i, ret;

	i = 0;
	DECR_LEN( data_size, 2);
	n_p = _gnutls_read_uint16( &data[i]);
	i += 2;

	DECR_LEN( data_size, n_p);
	data_p = &data[i];
	i += n_p;
	if (i > data_size) {
		gnutls_assert();
		return GNUTLS_E_UNEXPECTED_PACKET_LENGTH;
	}
	DECR_LEN( data_size, 2);
	n_g = _gnutls_read_uint16( &data[i]);
	i += 2;

	DECR_LEN( data_size, n_g);
	data_g = &data[i];
	i += n_g;
	
	DECR_LEN( data_size, 2);
	n_Y = _gnutls_read_uint16( &data[i]);
	i += 2;

	DECR_LEN( data_size, n_Y);
	data_Y = &data[i];
	i += n_Y;

	_n_Y = n_Y;
	_n_g = n_g;
	_n_p = n_p;

	if (_gnutls_mpi_scan(&state->gnutls_key->client_Y, data_Y, &_n_Y) != 0 || state->gnutls_key->client_Y==NULL) {
		gnutls_assert();
		return GNUTLS_E_MPI_SCAN_FAILED;
	}

	if (_gnutls_mpi_scan(&state->gnutls_key->client_g, data_g, &_n_g) != 0 || state->gnutls_key->client_g==NULL) {
		gnutls_assert();
		return GNUTLS_E_MPI_SCAN_FAILED;
	}
	if (_gnutls_mpi_scan(&state->gnutls_key->client_p, data_p, &_n_p) != 0 || state->gnutls_key->client_p==NULL) {
		gnutls_assert();
		return GNUTLS_E_MPI_SCAN_FAILED;
	}


	/* set auth_info */
	if ( (ret=_gnutls_auth_info_set( state, GNUTLS_CRD_ANON, sizeof( ANON_CLIENT_AUTH_INFO_INT), 1)) < 0) {
		gnutls_assert();
		return ret;
	}

	if ( _gnutls_mpi_get_nbits( state->gnutls_key->client_p) < _gnutls_dh_get_prime_bits( state)) {
		/* the prime used by the peer is not acceptable
		 */
		gnutls_assert();
		return GNUTLS_E_DH_PRIME_UNACCEPTABLE;
	}
	
	ret=_gnutls_dh_set_prime_bits( state, _gnutls_mpi_get_nbits(
		state->gnutls_key->client_p));
	if (ret<0) {
		gnutls_assert();
		return ret;
	}

	ret=_gnutls_dh_set_peer_public_bits( state, _gnutls_mpi_get_nbits(
		state->gnutls_key->client_Y));
	if (ret<0) {
		gnutls_assert();
		return ret;
	}


	return 0;
}

int proc_anon_client_kx( GNUTLS_STATE state, opaque* data, int data_size) {
	uint16 n_Y;
	size_t _n_Y;
	GNUTLS_MPI g, p;
	int bits, ret;
	const GNUTLS_ANON_SERVER_CREDENTIALS cred;
	
	cred = _gnutls_get_cred(state->gnutls_key, GNUTLS_CRD_ANON, NULL);
	if (cred == NULL) {
		gnutls_assert();
		return GNUTLS_E_INSUFICIENT_CRED;
	}

	bits = _gnutls_dh_get_prime_bits( state);

	DECR_LEN( data_size, 2);
	n_Y = _gnutls_read_uint16( &data[0]);

	_n_Y = n_Y;
	DECR_LEN( data_size, n_Y);
	if (_gnutls_mpi_scan(&state->gnutls_key->client_Y, &data[2], &_n_Y) !=0 || state->gnutls_key->client_Y==NULL) {
		gnutls_assert();
		return GNUTLS_E_MPI_SCAN_FAILED;
	}

	g = gnutls_get_dh_params( cred->dh_params, &p, bits);
	if (g==NULL) {
		gnutls_assert();
		return GNUTLS_E_MEMORY_ERROR;
	}

	ret=_gnutls_dh_set_peer_public_bits( state, _gnutls_mpi_get_nbits(state->gnutls_key->client_Y));
	if (ret<0) {
		gnutls_assert();
		return ret;
	}

	state->gnutls_key->KEY = gnutls_calc_dh_key( state->gnutls_key->client_Y, state->gnutls_key->dh_secret, p);
	if (state->gnutls_key->KEY==NULL)
		return GNUTLS_E_MEMORY_ERROR;
	
	_gnutls_mpi_release(&state->gnutls_key->client_Y);
	_gnutls_mpi_release(&state->gnutls_key->dh_secret);
	_gnutls_mpi_release(&p);
	_gnutls_mpi_release(&g);

	ret = _gnutls_generate_key( state->gnutls_key);
	_gnutls_mpi_release(&state->gnutls_key->KEY);

	if (ret < 0) {
		return ret;
	}

	return 0;
}

#endif /* ENABLE_ANON */
