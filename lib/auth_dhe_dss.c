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

/* DHE_DSS is not really working. It is used as a template 
 * (it may work BUT it does not check certificates)
 */

#if 0

#include "gnutls_int.h"
#include "gnutls_auth_int.h"
#include "gnutls_errors.h"
#include "gnutls_dh.h"
#include "auth_dhe_dss.h"
#include "gnutls_num.h"

int gen_dhe_dss_server_kx( GNUTLS_KEY , opaque**);
int gen_dhe_dss_client_kx( GNUTLS_KEY , opaque**);
int proc_dhe_dss_server_kx( GNUTLS_KEY , opaque*, int);
int proc_dhe_dss_client_kx( GNUTLS_KEY , opaque*, int);

int gen_dhe_dss_client_cert_vrfy( GNUTLS_KEY, opaque**);
int proc_dhe_dss_client_cert_vrfy( GNUTLS_KEY, opaque*, int);

int gen_dhe_dss_server_cert_vrfy( GNUTLS_KEY, opaque**);
int proc_dhe_dss_server_cert_vrfy( GNUTLS_KEY, opaque*, int);

MOD_AUTH_STRUCT dhe_dss_auth_struct = {
	"DHE_DSS",
	gen_dhe_dss_server_kx,
	NULL,
	NULL,
	gen_dhe_dss_client_kx,
	gen_dhe_dss_client_cert_vrfy,
	gen_dhe_dss_server_cert_vrfy,
	proc_dhe_dss_server_kx,
	NULL,
	NULL,
	proc_dhe_dss_client_kx,
	proc_dhe_dss_client_cert_vrfy,
	proc_dhe_dss_server_cert_vrfy
};

int gen_dhe_dss_server_kx( GNUTLS_KEY key, opaque** data) {
	GNUTLS_MPI x, X, g, p;
	size_t n_X, n_g, n_p;
	uint8 *data_p;
	uint8 *data_g;
	uint8 *data_X;
	int ret = 0;
	DHE_DSS_SERVER_CREDENTIALS * cred;

	cred = _gnutls_get_kx_cred( key, GNUTLS_KX_DHE_DSS, NULL);
	if (cred==NULL) {
		bits = DEFAULT_BITS; /* default */
	} else {
		bits = cred->bits;
	}

	g = gnutls_get_dh_params(&p, bits);

	key->auth_info = gnutls_malloc(sizeof(DHE_DSS_AUTH_INFO));
	if (key->auth_info==NULL) return GNUTLS_E_MEMORY_ERROR;
	((DHE_DSS_AUTH_INFO*)key->auth_info)->bits = gcry_mpi_get_nbits(p);
	key->auth_info_size = sizeof(DHE_DSS_AUTH_INFO);

	X = gnutls_calc_dh_secret(&x, g, p);

	key->dh_secret = x;

	_gnutls_mpi_print( NULL, &n_g, g);
	_gnutls_mpi_print( NULL, &n_p, p);
	_gnutls_mpi_print( NULL, &n_X, X);
	(*data) = gnutls_malloc(n_g + n_p + n_X + 6);
	data_p = &(*data)[0];
	_gnutls_mpi_print( &data_p[2], &n_p, p);
	_gnutls_mpi_release(p);

	WRITEuint16( n_p, data_p);

	data_g = &data_p[2 + n_p];
	_gnutls_mpi_print( &data_g[2], &n_g, g);
	_gnutls_mpi_release(g);

	WRITEuint16( n_g, data_g);

	data_X = &data_g[2 + n_g];
	_gnutls_mpi_print( &data_X[2], &n_X, X);
	_gnutls_mpi_release(X);

	WRITEuint16( n_X, data_X);

	ret = n_p+n_g+n_X+6;

	return ret;
}

int gen_dhe_dss_client_kx( GNUTLS_KEY key, opaque** data) {
GNUTLS_MPI x, X;
size_t n_X;

	X =  _gnutls_calc_dh_secret(&x, key->client_g,
		   key->client_p);
		   
	_gnutls_mpi_print( NULL, &n_X, X);
	(*data) = gnutls_malloc(n_X + 2);
	
	_gnutls_mpi_print( &(*data)[2], &n_X, X);
	(*data)[0] = 1;	/* extern - explicit since we do not have
				   certificate */
	_gnutls_mpi_release(X);
	
	WRITEuint16( n_X, &(*data)[0]);    
	
	/* calculate the key after calculating the message */
	key->KEY = _gnutls_calc_dh_key(key->client_Y, x, key->client_p);

	/* THESE SHOULD BE DISCARDED */
	_gnutls_mpi_release(key->client_Y);
	_gnutls_mpi_release(key->client_p);
	_gnutls_mpi_release(key->client_g);
	key->client_Y = NULL;
	key->client_p = NULL;
	key->client_g = NULL;

	return n_X+2;
}

int proc_dhe_dss_server_kx( GNUTLS_KEY key, opaque* data, int data_size) {
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

	if (gcry_mpi_scan(&key->client_Y, data_Y, &_n_Y) != 0) {
		gnutls_assert();
		return GNUTLS_E_MPI_SCAN_FAILED;
	}

	if (gcry_mpi_scan(&key->client_g,, data_g, &_n_g) != 0) {
		gnutls_assert();
		return GNUTLS_E_MPI_SCAN_FAILED;
	}
	if (gcry_mpi_scan(&key->client_p, data_p, &_n_p) != 0) {
		gnutls_assert();
		return GNUTLS_E_MPI_SCAN_FAILED;
	}

	/* We should check signature in non-anonymous KX 
	 * this is anonymous however
	 */
	gnutls_free(data);

	return 0;
}

int proc_dhe_dss_client_kx( GNUTLS_KEY key, opaque* data, int data_size) {
	uint16 n_Y;
	size_t _n_Y;
	MPI g, p;
	
	cred = _gnutls_get_kx_cred( key, GNUTLS_KX_DHE_DSS, NULL);
	if (cred==NULL) {
		bits = DEFAULT_BITS; /* default */
	} else {
		bits = cred->bits;
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

	if (gcry_mpi_scan(&key->client_Y, &data[2], &_n_Y)) {
		gnutls_assert();
		return GNUTLS_E_MPI_SCAN_FAILED;
	}

	g = gnutls_get_dh_params(&p, bits);
	key->KEY = gnutls_calc_dh_key( key->client_Y, key->dh_secret, p);
	
	mpi_release(g);
	mpi_release(p);

	_gnutls_mpi_release(key->client_Y);
	_gnutls_mpi_release(key->dh_secret);
	key->client_Y = NULL;
	key->dh_secret = NULL;

	return 0;
}

int gen_dhe_dss_client_cert_vrfy( GNUTLS_KEY key, opaque** data) {
	/* FIXME: not ready yet */
	(*data)=gnutls_calloc(1, 20);
	return 20;
}
int gen_dhe_dss_server_cert_vrfy( GNUTLS_KEY key, opaque** data) {
	/* FIXME: not ready yet */
	(*data)=gnutls_calloc(1, 20);
	return 20;
}
int proc_dhe_dss_client_cert_vrfy( GNUTLS_KEY key, opaque* data, int data_size) {
	/* no certificate check in anonymous KX */
	return 0;
}
int proc_dhe_dss_server_cert_vrfy( GNUTLS_KEY key, opaque* data, int data_size) {
	/* no certificate check in this algorithm */
	return 0;
}

#endif
