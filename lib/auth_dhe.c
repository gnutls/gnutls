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
 * */


#include "gnutls_int.h"
#include "gnutls_auth_int.h"
#include "gnutls_errors.h"
#include "gnutls_dh.h"
#include "gnutls_num.h"
#include "gnutls_sig.h"
#include <gnutls_datum.h>
#include <auth_cert.h>
#include <gnutls_x509.h>
#include <gnutls_extra.h>
#include <gnutls_state.h>

static int gen_dhe_server_kx(GNUTLS_STATE, opaque **);
static int gen_dhe_client_kx(GNUTLS_STATE, opaque **);
static int proc_dhe_server_kx(GNUTLS_STATE, opaque *, int);
static int proc_dhe_client_kx(GNUTLS_STATE, opaque *, int);

const MOD_AUTH_STRUCT dhe_rsa_auth_struct = {
	"DHE_RSA",
	_gnutls_gen_cert_server_certificate,
	_gnutls_gen_cert_client_certificate,
	gen_dhe_server_kx,
	NULL,
	NULL,
	gen_dhe_client_kx,
	_gnutls_gen_cert_client_cert_vrfy,	/* gen client cert vrfy */
	_gnutls_gen_cert_server_cert_req,	/* server cert request */

	_gnutls_proc_cert_server_certificate,
	_gnutls_proc_cert_client_certificate,
	proc_dhe_server_kx,
	NULL,
	NULL,
	proc_dhe_client_kx,
	_gnutls_proc_cert_client_cert_vrfy,	/* proc client cert vrfy */
	_gnutls_proc_cert_cert_req	/* proc server cert request */
};

const MOD_AUTH_STRUCT dhe_dss_auth_struct = {
	"DHE_DSS",
	_gnutls_gen_cert_server_certificate,
	_gnutls_gen_cert_client_certificate,
	gen_dhe_server_kx,
	NULL,
	NULL,
	gen_dhe_client_kx,
	_gnutls_gen_cert_client_cert_vrfy,	/* gen client cert vrfy */
	_gnutls_gen_cert_server_cert_req,	/* server cert request */

	_gnutls_proc_cert_server_certificate,
	_gnutls_proc_cert_client_certificate,
	proc_dhe_server_kx,
	NULL,
	NULL,
	proc_dhe_client_kx,
	_gnutls_proc_cert_client_cert_vrfy,	/* proc client cert vrfy */
	_gnutls_proc_cert_cert_req	/* proc server cert request */
};

static int gen_dhe_server_kx(GNUTLS_STATE state, opaque ** data)
{
	GNUTLS_MPI x, X, g, p;
	size_t n_X, n_g, n_p;
	uint8 *data_p;
	uint8 *data_g;
	uint8 *data_X;
	int ret = 0, data_size;
	int bits;
	gnutls_cert *apr_cert_list;
	gnutls_private_key *apr_pkey;
	int apr_cert_list_length;
	gnutls_datum signature, ddata;
	CERTIFICATE_AUTH_INFO info;
	const GNUTLS_CERTIFICATE_CREDENTIALS cred;

	cred = _gnutls_get_cred(state->gnutls_key, GNUTLS_CRD_CERTIFICATE, NULL);
	if (cred == NULL) {
	        gnutls_assert();
	        return GNUTLS_E_INSUFICIENT_CRED;
	}

	bits = _gnutls_dh_get_prime_bits( state);

	/* find the appropriate certificate */
	if ((ret =
	     _gnutls_find_apr_cert(state, &apr_cert_list,
				   &apr_cert_list_length,
				   &apr_pkey)) < 0) {
		gnutls_assert();
		return ret;
	}

	g = gnutls_get_dh_params( cred->dh_params, &p, bits);
	if (g == NULL) {
		gnutls_assert();
		return GNUTLS_E_MEMORY_ERROR;
	}

	if ( (ret=_gnutls_auth_info_set( state, GNUTLS_CRD_CERTIFICATE, sizeof( CERTIFICATE_AUTH_INFO_INT), 0)) < 0) {
		gnutls_assert();
		return ret;
	}

	info = _gnutls_get_auth_info( state);
	ret=_gnutls_dh_set_prime_bits( state, _gnutls_mpi_get_nbits(p));
	if (ret<0) {
		gnutls_assert();
		return ret;
	}

	X = gnutls_calc_dh_secret(&x, g, p);
	if (X == NULL) {
		_gnutls_mpi_release(&g);
		_gnutls_mpi_release(&p);
		gnutls_assert();
		return GNUTLS_E_MEMORY_ERROR;
	}
	state->gnutls_key->dh_secret = x;
	ret=_gnutls_dh_set_secret_bits( state, _gnutls_mpi_get_nbits(x));
	if (ret<0) {
		gnutls_assert();
		return ret;
	}


	_gnutls_mpi_print( NULL, &n_g, g);
	_gnutls_mpi_print( NULL, &n_p, p);
	_gnutls_mpi_print( NULL, &n_X, X);
	(*data) = gnutls_malloc(n_g + n_p + n_X + 6);
	if (*data == NULL) {
		_gnutls_mpi_release(&X);
		_gnutls_mpi_release(&g);
		_gnutls_mpi_release(&p);
		return GNUTLS_E_MEMORY_ERROR;
	}

	data_p = &(*data)[0];
	_gnutls_mpi_print( &data_p[2], &n_p, p);
	_gnutls_mpi_release(&p);

	_gnutls_write_uint16(n_p, data_p);

	data_g = &data_p[2 + n_p];
	_gnutls_mpi_print( &data_g[2], &n_g, g);
	_gnutls_mpi_release(&g);

	_gnutls_write_uint16(n_g, data_g);

	data_X = &data_g[2 + n_g];
	_gnutls_mpi_print( &data_X[2], &n_X, X);
	_gnutls_mpi_release(&X);

	_gnutls_write_uint16(n_X, data_X);

	data_size = n_p + n_g + n_X + 6;


	/* Generate the signature. */

	ddata.data = *data;
	ddata.size = data_size;

	if (apr_pkey != NULL) {
		if ((ret =
		     _gnutls_generate_sig_params(state, &apr_cert_list[0],
						 apr_pkey, &ddata,
						 &signature)) < 0) {
			gnutls_assert();
			gnutls_free(*data);
			return ret;
		}
	} else {
		gnutls_assert();
		return data_size;	/* do not put a signature - ILLEGAL! */
	}

	*data = gnutls_realloc(*data, data_size + signature.size + 2);
	if (*data == NULL) {
		gnutls_free_datum(&signature);
		gnutls_assert();
		return GNUTLS_E_MEMORY_ERROR;
	}

	_gnutls_write_datum16(&(*data)[data_size], signature);
	data_size += signature.size + 2;

	gnutls_free_datum(&signature);

	return data_size;
}

static int gen_dhe_client_kx(GNUTLS_STATE state, opaque ** data)
{
	GNUTLS_MPI x, X;
	size_t n_X;
	int ret;

	X = gnutls_calc_dh_secret(&x, state->gnutls_key->client_g,
				  state->gnutls_key->client_p);
	if (X == NULL || x == NULL) {
		gnutls_assert();
		_gnutls_mpi_release(&x);
		_gnutls_mpi_release(&X);
		return GNUTLS_E_MEMORY_ERROR;
	}

	ret=_gnutls_dh_set_secret_bits( state, _gnutls_mpi_get_nbits(x));
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
	state->gnutls_key->KEY =
	    gnutls_calc_dh_key(state->gnutls_key->client_Y, x,
			       state->gnutls_key->client_p);

	_gnutls_mpi_release(&x);
	if (state->gnutls_key->KEY == NULL) {
		gnutls_assert();
		return GNUTLS_E_MEMORY_ERROR;
	}

	ret=_gnutls_dh_set_peer_public_bits( state, _gnutls_mpi_get_nbits(
		state->gnutls_key->client_Y));
	if (ret<0) {
		gnutls_assert();
		return ret;
	}


	/* THESE SHOULD BE DISCARDED */
	_gnutls_mpi_release(&state->gnutls_key->client_Y);
	_gnutls_mpi_release(&state->gnutls_key->client_p);
	_gnutls_mpi_release(&state->gnutls_key->client_g);

	ret = _gnutls_generate_key(state->gnutls_key);
	_gnutls_mpi_release(&state->gnutls_key->KEY);

	if (ret < 0) {
		return ret;
	}

	return n_X + 2;
}

OPENPGP_CERT2GNUTLS_CERT _E_gnutls_openpgp_cert2gnutls_cert = NULL;

static int proc_dhe_server_kx(GNUTLS_STATE state, opaque * data,
				  int data_size)
{
	uint16 n_Y, n_g, n_p;
	size_t _n_Y, _n_g, _n_p;
	uint8 *data_p;
	uint8 *data_g;
	uint8 *data_Y;
	int i, sigsize;
	gnutls_datum vparams, signature;
	int ret;
	CERTIFICATE_AUTH_INFO info = _gnutls_get_auth_info( state);
	gnutls_cert peer_cert;

	if (info == NULL || info->ncerts==0) {
		gnutls_assert();
		/* we need this in order to get peer's certificate */
		return GNUTLS_E_UNKNOWN_ERROR;
	}

	i = 0;
	
	DECR_LEN( data_size, 2);
	n_p = _gnutls_read_uint16(&data[i]);
	i += 2;

	DECR_LEN( data_size, n_p);
	data_p = &data[i];
	i += n_p;
	if (i > data_size) {
		gnutls_assert();
		return GNUTLS_E_UNEXPECTED_PACKET_LENGTH;
	}

	DECR_LEN( data_size, 2);
	n_g = _gnutls_read_uint16(&data[i]);
	i += 2;

	DECR_LEN( data_size, n_g);
	data_g = &data[i];
	i += n_g;
	if (i > data_size) {
		gnutls_assert();
		return GNUTLS_E_UNEXPECTED_PACKET_LENGTH;
	}

	DECR_LEN( data_size, 2);
	n_Y = _gnutls_read_uint16(&data[i]);
	i += 2;

	DECR_LEN( data_size, n_Y);
	data_Y = &data[i];
	i += n_Y;

	_n_Y = n_Y;
	_n_g = n_g;
	_n_p = n_p;

	if (_gnutls_mpi_scan(&state->gnutls_key->client_Y, data_Y, &_n_Y) != 0) {
		gnutls_assert();
		return GNUTLS_E_MPI_SCAN_FAILED;
	}

	if (_gnutls_mpi_scan(&state->gnutls_key->client_g, data_g, &_n_g) != 0) {
		gnutls_assert();
		return GNUTLS_E_MPI_SCAN_FAILED;
	}
	if (_gnutls_mpi_scan(&state->gnutls_key->client_p, data_p, &_n_p) != 0) {
		gnutls_assert();
		return GNUTLS_E_MPI_SCAN_FAILED;
	}

	ret=_gnutls_dh_set_peer_public_bits( state, _gnutls_mpi_get_nbits(
		state->gnutls_key->client_Y));
	if (ret<0) {
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

	/* VERIFY SIGNATURE */

	vparams.size = n_Y + n_p + n_g + 6;
	vparams.data = data;

	DECR_LEN( data_size, 2);
	sigsize = _gnutls_read_uint16(&data[vparams.size]);

	DECR_LEN( data_size, sigsize);
	signature.data = &data[vparams.size + 2];
	signature.size = sigsize;

	switch( state->security_parameters.cert_type) {
		case GNUTLS_CRT_X509:
			if ((ret =
			     _gnutls_x509_cert2gnutls_cert( &peer_cert,
					     info->raw_certificate_list[0], 1)) < 0) {
				gnutls_assert();
				return ret;
			}
			break;

		case GNUTLS_CRT_OPENPGP:
			if (_E_gnutls_openpgp_cert2gnutls_cert==NULL) {
				gnutls_assert();
				return GNUTLS_E_INVALID_REQUEST;
			}
			if ((ret =
			     _E_gnutls_openpgp_cert2gnutls_cert( &peer_cert,
					     info->raw_certificate_list[0])) < 0) {
				gnutls_assert();
				return ret;
			}
			break;

		default:
			gnutls_assert();
			return GNUTLS_E_UNKNOWN_ERROR;
	}

	ret =
	    _gnutls_verify_sig_params(state,
				      &peer_cert,
				      &vparams, &signature);
	
	_gnutls_free_cert( peer_cert);
	if (ret < 0) {
		gnutls_assert();
		return ret;
	}

	return ret;
}

static int proc_dhe_client_kx(GNUTLS_STATE state, opaque * data,
				  int data_size)
{
	uint16 n_Y;
	size_t _n_Y;
	GNUTLS_MPI g, p;
	int bits, ret;
	const GNUTLS_CERTIFICATE_CREDENTIALS cred;

	cred = _gnutls_get_cred(state->gnutls_key, GNUTLS_CRD_CERTIFICATE, NULL);
	if (cred == NULL) {
	        gnutls_assert();
	        return GNUTLS_E_INSUFICIENT_CRED;
	}

	bits = _gnutls_dh_get_prime_bits( state);

	DECR_LEN( data_size, 2);
	n_Y = _gnutls_read_uint16(&data[0]);
	_n_Y = n_Y;

	DECR_LEN( data_size, n_Y);
	if (_gnutls_mpi_scan(&state->gnutls_key->client_Y, &data[2], &_n_Y)) {
		gnutls_assert();
		return GNUTLS_E_MPI_SCAN_FAILED;
	}

	ret=_gnutls_dh_set_peer_public_bits( state, _gnutls_mpi_get_nbits(
		state->gnutls_key->client_Y));
	if (ret<0) {
		gnutls_assert();
		return ret;
	}

	g = gnutls_get_dh_params( cred->dh_params, &p, bits);
	if (g == NULL || p == NULL) {
		gnutls_assert();
		_gnutls_mpi_release(&g);
		_gnutls_mpi_release(&p);
		return GNUTLS_E_MEMORY_ERROR;
	}

	state->gnutls_key->KEY =
	    gnutls_calc_dh_key(state->gnutls_key->client_Y,
			       state->gnutls_key->dh_secret, p);
	_gnutls_mpi_release(&g);
	_gnutls_mpi_release(&p);

	if (state->gnutls_key->KEY == NULL) {
		return GNUTLS_E_MEMORY_ERROR;
	}

	_gnutls_mpi_release(&state->gnutls_key->client_Y);
	_gnutls_mpi_release(&state->gnutls_key->dh_secret);

	ret = _gnutls_generate_key(state->gnutls_key);
	_gnutls_mpi_release(&state->gnutls_key->KEY);

	if (ret < 0) {
		return ret;
	}

	return 0;
}
