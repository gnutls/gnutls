/*
 * Copyright (C) 2002 Nikos Mavroyanopoulos
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

/* This file contains common stuff in Ephemeral Diffie Hellman (DHE) and
 * Anonymous DH key exchange(DHA). These are used in the handshake procedure 
 * of the certificate and anoymous authentication.
 */

#include "gnutls_int.h"
#include "gnutls_auth_int.h"
#include "gnutls_errors.h"
#include "gnutls_dh.h"
#include "gnutls_num.h"
#include "gnutls_sig.h"
#include <gnutls_datum.h>
#include <gnutls_x509.h>
#include <gnutls_extra.h>
#include <gnutls_state.h>
#include <auth_dh_common.h>

int _gnutls_proc_dh_common_client_kx(gnutls_session session, opaque * data,
				  size_t _data_size, GNUTLS_MPI g, GNUTLS_MPI p)
{
	uint16 n_Y;
	size_t _n_Y;
	int ret;
	ssize_t data_size = _data_size;


	DECR_LEN( data_size, 2);
	n_Y = _gnutls_read_uint16(&data[0]);
	_n_Y = n_Y;

	DECR_LEN( data_size, n_Y);
	if (_gnutls_mpi_scan(&session->key->client_Y, &data[2], &_n_Y)) {
		gnutls_assert();
		return GNUTLS_E_MPI_SCAN_FAILED;
	}

	ret=_gnutls_dh_set_peer_public_bits( session, _gnutls_mpi_get_nbits(
		session->key->client_Y));
	if (ret<0) {
		gnutls_assert();
		return ret;
	}


	session->key->KEY =
	    gnutls_calc_dh_key(session->key->client_Y,
			       session->key->dh_secret, p);

	if (session->key->KEY == NULL) {
		gnutls_assert();
		return GNUTLS_E_MEMORY_ERROR;
	}

	_gnutls_mpi_release(&session->key->client_Y);
	_gnutls_mpi_release(&session->key->dh_secret);

	ret = _gnutls_generate_key(session->key);
	_gnutls_mpi_release(&session->key->KEY);

	if (ret < 0) {
		return ret;
	}

	return 0;
}

int _gnutls_gen_dh_common_client_kx(gnutls_session session, opaque ** data)
{
	GNUTLS_MPI x, X;
	size_t n_X;
	int ret;

	X = gnutls_calc_dh_secret(&x, session->key->client_g,
				  session->key->client_p);
	if (X == NULL || x == NULL) {
		gnutls_assert();
		_gnutls_mpi_release(&x);
		_gnutls_mpi_release(&X);
		return GNUTLS_E_MEMORY_ERROR;
	}

	ret=_gnutls_dh_set_secret_bits( session, _gnutls_mpi_get_nbits(x));
	if (ret<0) {
		gnutls_assert();
		return ret;
	}

	_gnutls_mpi_print( NULL, &n_X, X);
	(*data) = gnutls_malloc(n_X + 2);
	if (*data == NULL) {
		_gnutls_mpi_release(&x);
		_gnutls_mpi_release(&X);
		return GNUTLS_E_MEMORY_ERROR;
	}

	_gnutls_mpi_print( &(*data)[2], &n_X, X);
	_gnutls_mpi_release(&X);

	_gnutls_write_uint16(n_X, &(*data)[0]);

	/* calculate the key after calculating the message */
	session->key->KEY =
	    gnutls_calc_dh_key(session->key->client_Y, x,
			       session->key->client_p);

	_gnutls_mpi_release(&x);
	if (session->key->KEY == NULL) {
		gnutls_assert();
		return GNUTLS_E_MEMORY_ERROR;
	}

	ret=_gnutls_dh_set_peer_public_bits( session, _gnutls_mpi_get_nbits(
		session->key->client_Y));
	if (ret<0) {
		gnutls_assert();
		return ret;
	}


	/* THESE SHOULD BE DISCARDED */
	_gnutls_mpi_release(&session->key->client_Y);
	_gnutls_mpi_release(&session->key->client_p);
	_gnutls_mpi_release(&session->key->client_g);

	ret = _gnutls_generate_key(session->key);
	_gnutls_mpi_release(&session->key->KEY);

	if (ret < 0) {
		return ret;
	}

	return n_X + 2;
}

int _gnutls_proc_dh_common_server_kx( gnutls_session session, opaque* data, size_t _data_size) 
{
	uint16 n_Y, n_g, n_p;
	size_t _n_Y, _n_g, _n_p;
	uint8 *data_p;
	uint8 *data_g;
	uint8 *data_Y;
	int i, ret, bits;
	ssize_t data_size = _data_size;

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

	if (_gnutls_mpi_scan(&session->key->client_Y, data_Y, &_n_Y) != 0 || session->key->client_Y==NULL) {
		gnutls_assert();
		return GNUTLS_E_MPI_SCAN_FAILED;
	}

	if (_gnutls_mpi_scan(&session->key->client_g, data_g, &_n_g) != 0 || session->key->client_g==NULL) {
		gnutls_assert();
		return GNUTLS_E_MPI_SCAN_FAILED;
	}
	if (_gnutls_mpi_scan(&session->key->client_p, data_p, &_n_p) != 0 || session->key->client_p==NULL) {
		gnutls_assert();
		return GNUTLS_E_MPI_SCAN_FAILED;
	}

	bits = _gnutls_dh_get_prime_bits( session);
	if (bits < 0) {
		gnutls_assert();
		return bits;
	}

	if ( _gnutls_mpi_get_nbits( session->key->client_p) < (size_t)bits) {
		/* the prime used by the peer is not acceptable
		 */
		gnutls_assert();
		return GNUTLS_E_DH_PRIME_UNACCEPTABLE;
	}
	
	ret=_gnutls_dh_set_prime_bits( session, _gnutls_mpi_get_nbits(
		session->key->client_p));
	if (ret<0) {
		gnutls_assert();
		return ret;
	}

	ret=_gnutls_dh_set_peer_public_bits( session, _gnutls_mpi_get_nbits(
		session->key->client_Y));
	if (ret<0) {
		gnutls_assert();
		return ret;
	}

	return n_Y + n_p + n_g + 6;
}

int _gnutls_dh_common_print_server_kx( gnutls_session session,
	GNUTLS_MPI g, GNUTLS_MPI p, opaque** data)
{
	GNUTLS_MPI x, X;
	size_t n_X, n_g, n_p;
	int ret;
	uint8 *data_p;
	uint8 *data_g;
	uint8 *data_X;

	X = gnutls_calc_dh_secret(&x, g, p);
	if (X == NULL || x == NULL) {
		gnutls_assert();
		return GNUTLS_E_MEMORY_ERROR;
	}

	session->key->dh_secret = x;
	ret= _gnutls_dh_set_secret_bits( session, _gnutls_mpi_get_nbits(x));
	if (ret < 0) {
		gnutls_assert();
		_gnutls_mpi_release(&X);
		return ret;
	}

	_gnutls_mpi_print( NULL, &n_g, g);
	_gnutls_mpi_print( NULL, &n_p, p);
	_gnutls_mpi_print( NULL, &n_X, X);
	(*data) = gnutls_malloc(n_g + n_p + n_X + 6);
	if (*data == NULL) {
		_gnutls_mpi_release(&X);
		return GNUTLS_E_MEMORY_ERROR;
	}

	data_p = &(*data)[0];
	_gnutls_mpi_print( &data_p[2], &n_p, p);

	_gnutls_write_uint16(n_p, data_p);

	data_g = &data_p[2 + n_p];
	_gnutls_mpi_print( &data_g[2], &n_g, g);

	_gnutls_write_uint16(n_g, data_g);

	data_X = &data_g[2 + n_g];
	_gnutls_mpi_print( &data_X[2], &n_X, X);
	_gnutls_mpi_release(&X);

	_gnutls_write_uint16(n_X, data_X);

	ret = n_p + n_g + n_X + 6;

	return ret;
}
