/*
 * Copyright (C) 2000 Nikos Mavroyanopoulos
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

#include "defines.h"
#include "gnutls_int.h"
#include "gnutls_handshake.h"
#include "gnutls_kx.h"
#include "gnutls_dh.h"
#include "gnutls_errors.h"
#include "gnutls_algorithms.h"
#include "debug.h"

#define MASTER_SECRET "master secret"

/* This is called when we want to receive the key exchange message of the
 * server. It does nothing if this type of message is not required
 * by the selected ciphersuite. 
 */
int _gnutls_send_server_kx_message(int cd, GNUTLS_STATE state)
{
	KXAlgorithm algorithm;
	GNUTLS_MPI x, X, g, p;
	int n_X, n_g, n_p;
	uint16 _n_X, _n_g, _n_p;
	uint8 *data = NULL;
	uint8 *data_p;
	uint8 *data_g;
	uint8 *data_X;
	int ret = 0;

#ifdef HARD_DEBUG
	fprintf(stderr, "Sending server KX message\n");
#endif

	algorithm =
	    _gnutls_cipher_suite_get_kx_algo(state->
					     gnutls_internals.current_cipher_suite);

	/* Do key exchange only if the algorithm permits it */
	if (_gnutls_kx_server_key_exchange(algorithm) != 0) {
		switch (_gnutls_cipher_suite_get_kx_algo
			(state->gnutls_internals.current_cipher_suite)) {
		case GNUTLS_KX_ANON_DH:
		case GNUTLS_KX_DHE_DSS:
		case GNUTLS_KX_DHE_RSA:
			X = gnutls_calc_dh_secret(&x);
			state->gnutls_internals.dh_secret = x;
			g = gnutls_get_dh_params(&p);
			gcry_mpi_print(GCRYMPI_FMT_STD, NULL, &n_g, g);
			gcry_mpi_print(GCRYMPI_FMT_STD, NULL, &n_p, p);
			gcry_mpi_print(GCRYMPI_FMT_STD, NULL, &n_X, X);
			data = gnutls_malloc(n_g + n_p + n_X + 6);
			data_p = &data[0];
			gcry_mpi_print(GCRYMPI_FMT_STD, &data_p[2],
				       &n_p, p);
			gnutls_mpi_release(p);
			_n_p = n_p;
#ifndef WORDS_BIGENDIAN
			_n_p = byteswap16(_n_p);
			memmove(data_p, &_n_p, 2);
#else
			memmove(data_p, &_n_p, 2);
#endif
			data_g = &data_p[2 + n_p];
			gcry_mpi_print(GCRYMPI_FMT_STD, &data_g[2],
				       &n_g, g);
			gnutls_mpi_release(g);
			_n_g = n_g;
#ifndef WORDS_BIGENDIAN
			_n_g = byteswap16(_n_g);
			memmove(data_g, &_n_g, 2);
#else
			memmove(data_g, &_n_g, 2);
#endif
			data_X = &data_g[2 + n_g];
			gcry_mpi_print(GCRYMPI_FMT_STD, &data_X[2],
				       &n_X, X);
			gnutls_mpi_release(X);
			_n_X = n_X;
#ifndef WORDS_BIGENDIAN
			_n_X = byteswap16(_n_X);
			memmove(data_X, &_n_X, 2);
#else
			memmove(data_X, &_n_X, 2);
#endif
			ret =
			    _gnutls_send_handshake(cd, state, data,
						   n_p + n_g + n_X + 6,
						   GNUTLS_SERVER_KEY_EXCHANGE);
			gnutls_free(data);
			break;
		default:
			gnutls_assert();
			ret = GNUTLS_E_UNKNOWN_KX_ALGORITHM;
		}
	}

	return ret;
}

/* This is the function for the client to send the key
 * exchange message 
 */
int _gnutls_send_client_kx_message(int cd, GNUTLS_STATE state)
{
	KXAlgorithm algorithm;
	GNUTLS_MPI x, X;
	int n_X;
	uint16 _n_X;
	uint8 *data;
	int ret = 0;
	uint8 *premaster = NULL;
	int premaster_size = 0;
	svoid *master;
	char *random = gnutls_malloc(64);
#ifdef HARD_DEBUG
	fprintf(stderr, "Sending client KX message\n");
#endif
	memmove(random, state->security_parameters.client_random, 32);
	memmove(&random[32], state->security_parameters.server_random, 32);
	algorithm =
	    _gnutls_cipher_suite_get_kx_algo
	    (state->gnutls_internals.current_cipher_suite);

	switch (_gnutls_cipher_suite_get_kx_algo
		(state->gnutls_internals.current_cipher_suite)) {
	case GNUTLS_KX_ANON_DH:
	case GNUTLS_KX_DHE_DSS:
	case GNUTLS_KX_DHE_RSA:
		X =
		    _gnutls_calc_dh_secret(&x,
					   state->
					   gnutls_internals.client_g,
					   state->
					   gnutls_internals.client_p);
		gcry_mpi_print(GCRYMPI_FMT_STD, NULL, &n_X, X);
		data = gnutls_malloc(n_X + 3);
		gcry_mpi_print(GCRYMPI_FMT_STD, &data[3], &n_X, X);
		data[0] = 1;	/* extern */
		gnutls_mpi_release(X);
		_n_X = n_X;
#ifndef WORDS_BIGENDIAN
		_n_X = byteswap16(_n_X);
		memmove(&data[1], &_n_X, 2);
#else
		memmove(&data[1], &_n_X, 2);
#endif
		ret =
		    _gnutls_send_handshake(cd, state, data,
					   n_X + 3,
					   GNUTLS_CLIENT_KEY_EXCHANGE);
		gnutls_free(data);
		/* calculate the key after sending the message */
		state->gnutls_internals.KEY =
		    _gnutls_calc_dh_key(state->gnutls_internals.client_Y,
					x,
					state->gnutls_internals.client_p);
		gcry_mpi_print(GCRYMPI_FMT_STD, NULL, &premaster_size,
			       state->gnutls_internals.KEY);
		premaster = secure_malloc(premaster_size);
		gcry_mpi_print(GCRYMPI_FMT_STD, premaster,
			       &premaster_size,
			       state->gnutls_internals.KEY);
		/* THIS SHOULD BE DISCARDED */
		gnutls_mpi_release(state->gnutls_internals.KEY);
		gnutls_mpi_release(state->gnutls_internals.client_Y);
		gnutls_mpi_release(state->gnutls_internals.client_p);
		gnutls_mpi_release(state->gnutls_internals.client_g);
		state->gnutls_internals.KEY = NULL;
		state->gnutls_internals.client_Y = NULL;
		state->gnutls_internals.client_p = NULL;
		state->gnutls_internals.client_g = NULL;
		break;
	default:
		gnutls_assert();
		ret = GNUTLS_E_UNKNOWN_KX_ALGORITHM;
	}

	master =
	    gnutls_PRF(premaster, premaster_size,
		       MASTER_SECRET, strlen(MASTER_SECRET), random, 64,
		       48);
	secure_free(premaster);
#ifdef HARD_DEBUG
	fprintf(stderr, "master secret: %s\n", bin2hex(master, 48));
#endif
	memmove(state->security_parameters.master_secret, master, 48);
	secure_free(master);
	gnutls_free(random);
	return ret;
}


int _gnutls_recv_server_kx_message(int cd, GNUTLS_STATE state)
{
	KXAlgorithm algorithm;
	uint16 n_Y, n_g, n_p;
	int _n_Y, _n_g, _n_p;
	uint8 *data;
	int datasize;
	uint8 *data_p;
	uint8 *data_g;
	uint8 *data_Y;
	int ret = 0, i;
#ifdef HARD_DEBUG
	fprintf(stderr, "Receiving Server KX message\n");
#endif
	algorithm =
	    _gnutls_cipher_suite_get_kx_algo
	    (state->gnutls_internals.current_cipher_suite);
	/* Do key exchange only if the algorithm permits it */
	if (_gnutls_kx_server_key_exchange(algorithm) != 0) {

		switch (_gnutls_cipher_suite_get_kx_algo
			(state->gnutls_internals.current_cipher_suite)) {
		case GNUTLS_KX_ANON_DH:
		case GNUTLS_KX_DHE_DSS:
		case GNUTLS_KX_DHE_RSA:
			ret =
			    _gnutls_recv_handshake(cd, state, &data,
						   &datasize,
						   GNUTLS_SERVER_KEY_EXCHANGE);
			if (ret < 0)
				return ret;
			i = 0;
			memmove(&n_p, &data[i], 2);
			i += 2;
#ifndef WORDS_BIGENDIAN
			n_p = byteswap16(n_p);
#endif
			data_p = &data[i];
			i += n_p;
			if (i > datasize) {
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
			if (i > datasize) {
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
			if (i > datasize) {
				gnutls_assert();
				return GNUTLS_E_UNEXPECTED_PACKET_LENGTH;
			}
			_n_Y = n_Y;
			_n_g = n_g;
			_n_p = n_p;
			gcry_mpi_scan(&state->gnutls_internals.client_Y,
				      GCRYMPI_FMT_STD, data_Y, &_n_Y);
			gcry_mpi_scan(&state->gnutls_internals.client_g,
				      GCRYMPI_FMT_STD, data_g, &_n_g);
			gcry_mpi_scan(&state->gnutls_internals.client_p,
				      GCRYMPI_FMT_STD, data_p, &_n_p);
			gnutls_free(data);
			break;
		default:
			gnutls_assert();
			ret = GNUTLS_E_UNKNOWN_KX_ALGORITHM;
		}
	}

	return ret;
}

int _gnutls_recv_client_kx_message(int cd, GNUTLS_STATE state)
{
	KXAlgorithm algorithm;
	uint16 n_Y;
	int _n_Y;
	uint8 *data;
	int datasize;
	int ret = 0;
	uint8 *premaster = NULL;
	int premaster_size = 0;
	svoid *master;
	uint8 *random = gnutls_malloc(64);
#ifdef HARD_DEBUG
	fprintf(stderr, "Receiving client KX message\n");
#endif
	memmove(random, state->security_parameters.client_random, 32);
	memmove(&random[32], state->security_parameters.server_random, 32);
	algorithm =
	    _gnutls_cipher_suite_get_kx_algo
	    (state->gnutls_internals.current_cipher_suite);
	/* Do key exchange only if the algorithm permits it */
	if (_gnutls_kx_server_key_exchange(algorithm) != 0) {

		switch (_gnutls_cipher_suite_get_kx_algo
			(state->gnutls_internals.current_cipher_suite)) {
		case GNUTLS_KX_ANON_DH:
		case GNUTLS_KX_DHE_DSS:
		case GNUTLS_KX_DHE_RSA:
			ret =
			    _gnutls_recv_handshake(cd, state, &data,
						   &datasize,
						   GNUTLS_CLIENT_KEY_EXCHANGE);
			if (ret < 0)
				return ret;
			if (data[0] != 1) {
				gnutls_assert();
				return GNUTLS_E_UNIMPLEMENTED_FEATURE;
			}
			memmove(&n_Y, &data[1], 2);
#ifndef WORDS_BIGENDIAN
			n_Y = byteswap16(n_Y);
#endif
			_n_Y = n_Y;
			gcry_mpi_scan(&state->gnutls_internals.client_Y,
				      GCRYMPI_FMT_STD, &data[3], &_n_Y);
			state->gnutls_internals.KEY =
			    gnutls_calc_dh_key(state->
					       gnutls_internals.client_Y,
					       state->
					       gnutls_internals.dh_secret);
			gcry_mpi_print(GCRYMPI_FMT_STD, NULL,
				       &premaster_size,
				       state->gnutls_internals.KEY);
			premaster = secure_malloc(premaster_size);
			gcry_mpi_print(GCRYMPI_FMT_STD, premaster,
				       &premaster_size,
				       state->gnutls_internals.KEY);
			/* THESE SHOULD BE DISCARDED */
			gnutls_mpi_release(state->gnutls_internals.KEY);
			gnutls_mpi_release(state->
					   gnutls_internals.client_Y);
			gnutls_mpi_release(state->
					   gnutls_internals.dh_secret);
			state->gnutls_internals.KEY = NULL;
			state->gnutls_internals.client_Y = NULL;
			state->gnutls_internals.dh_secret = NULL;
			gnutls_free(data);
			break;
		default:
			gnutls_assert();
			ret = GNUTLS_E_UNKNOWN_KX_ALGORITHM;
		}
	}

	master =
	    gnutls_PRF(premaster, premaster_size,
		       MASTER_SECRET, strlen(MASTER_SECRET),
		       random, 64, 48); secure_free(premaster);
#ifdef HARD_DEBUG
	fprintf(stderr, "master secret: %s\n", bin2hex(master, 48));
#endif
	memmove(state->security_parameters.master_secret, master, 48);
	secure_free(master);
	gnutls_free(random);
	return ret;
}
