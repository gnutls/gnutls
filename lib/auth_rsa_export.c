/*
 *  Copyright (C) 2000,2001,2002,2003 Nikos Mavroyanopoulos
 *
 *  This file is part of GNUTLS.
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

/* This file contains the RSA key exchange part of the certificate
 * authentication.
 */

#include "gnutls_int.h"
#include "gnutls_auth_int.h"
#include "gnutls_errors.h"
#include "gnutls_dh.h"
#include "gnutls_num.h"
#include "libtasn1.h"
#include "gnutls_datum.h"
#include "auth_cert.h"
#include <gnutls_random.h>
#include <gnutls_pk.h>
#include <gnutls_algorithms.h>
#include <gnutls_global.h>
#include "debug.h"
#include <gnutls_sig.h>
#include <gnutls_x509.h>
#include <gnutls_extra.h>
#include <gnutls_rsa_export.h>
#include <gnutls_state.h>

int _gnutls_gen_rsa_client_kx(gnutls_session, opaque **);
int _gnutls_proc_rsa_client_kx(gnutls_session, opaque *, size_t);
static int gen_rsa_export_server_kx(gnutls_session, opaque **);
static int proc_rsa_export_server_kx(gnutls_session, opaque *, size_t);

const MOD_AUTH_STRUCT rsa_export_auth_struct = {
	"RSA EXPORT",
	_gnutls_gen_cert_server_certificate,
	_gnutls_gen_cert_client_certificate,
	gen_rsa_export_server_kx,
	_gnutls_gen_rsa_client_kx,
	_gnutls_gen_cert_client_cert_vrfy,	/* gen client cert vrfy */
	_gnutls_gen_cert_server_cert_req,	/* server cert request */

	_gnutls_proc_cert_server_certificate,
	_gnutls_proc_cert_client_certificate,
	proc_rsa_export_server_kx,
	_gnutls_proc_rsa_client_kx,	/* proc client kx */
	_gnutls_proc_cert_client_cert_vrfy,	/* proc client cert vrfy */
	_gnutls_proc_cert_cert_req	/* proc server cert request */
};

extern OPENPGP_CERT2GNUTLS_CERT _E_gnutls_openpgp_cert2gnutls_cert;


static int gen_rsa_export_server_kx(gnutls_session session, opaque ** data)
{
	const GNUTLS_MPI *rsa_params;
	size_t n_e, n_m;
	uint8 *data_e, *data_m;
	int ret = 0, data_size;
	gnutls_cert *apr_cert_list;
	gnutls_privkey* apr_pkey;
	int apr_cert_list_length;
	gnutls_datum signature, ddata;
	CERTIFICATE_AUTH_INFO info;
	const gnutls_certificate_credentials cred;

	cred = _gnutls_get_cred(session->key, GNUTLS_CRD_CERTIFICATE, NULL);
	if (cred == NULL) {
	        gnutls_assert();
	        return GNUTLS_E_INSUFFICIENT_CREDENTIALS;
	}

	/* find the appropriate certificate */
	if ((ret =
	     _gnutls_find_apr_cert(session, &apr_cert_list,
				   &apr_cert_list_length,
				   &apr_pkey)) < 0) {
		gnutls_assert();
		return ret;
	}

	/* abort sending this message if we have a certificate
	 * of 512 bits or less.
	 */
	if ( _gnutls_mpi_get_nbits( apr_pkey->params[0]) <= 512) {
		return GNUTLS_E_INT_RET_0;
	}

	rsa_params = _gnutls_get_rsa_params( cred->rsa_params);
	if (rsa_params == NULL) {
		gnutls_assert();
		return GNUTLS_E_NO_TEMPORARY_RSA_PARAMS;
	}

	if ( (ret=_gnutls_auth_info_set( session, GNUTLS_CRD_CERTIFICATE, sizeof( CERTIFICATE_AUTH_INFO_INT), 0)) < 0) {
		gnutls_assert();
		return ret;
	}

	info = _gnutls_get_auth_info( session);
	ret=_gnutls_rsa_export_set_modulus_bits( session, _gnutls_mpi_get_nbits(rsa_params[0]));
	if (ret<0) {
		gnutls_assert();
		return ret;
	}

	_gnutls_mpi_print( NULL, &n_m, rsa_params[0]);
	_gnutls_mpi_print( NULL, &n_e, rsa_params[1]);

	(*data) = gnutls_malloc(n_e + n_m + 4);
	if (*data == NULL) {
		return GNUTLS_E_MEMORY_ERROR;
	}

	data_m = &(*data)[0];
	_gnutls_mpi_print( &data_m[2], &n_m, rsa_params[0]);

	_gnutls_write_uint16(n_m, data_m);

	data_e = &data_m[2 + n_m];
	_gnutls_mpi_print( &data_e[2], &n_e, rsa_params[1]);

	_gnutls_write_uint16(n_e, data_e);

	data_size = n_m + n_e + 4;


	/* Generate the signature. */

	ddata.data = *data;
	ddata.size = data_size;

	if (apr_pkey != NULL) {
		if ((ret =
		     _gnutls_tls_sign_params(session, &apr_cert_list[0],
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

	*data = gnutls_realloc_fast(*data, data_size + signature.size + 2);
	if (*data == NULL) {
		_gnutls_free_datum(&signature);
		gnutls_assert();
		return GNUTLS_E_MEMORY_ERROR;
	}

	_gnutls_write_datum16(&(*data)[data_size], signature);
	data_size += signature.size + 2;

	_gnutls_free_datum(&signature);

	return data_size;
}

/* if the peer's certificate is of 512 bits or less, returns non zero.
 */
int _gnutls_peers_cert_less_512( gnutls_session session) 
{
gnutls_cert peer_cert;
int ret;
CERTIFICATE_AUTH_INFO info = _gnutls_get_auth_info( session);

	if (info == NULL || info->ncerts==0) {
		gnutls_assert();
		/* we need this in order to get peer's certificate */
		return 0;
	}

	switch( session->security_parameters.cert_type) {
		case GNUTLS_CRT_X509:
			if ((ret =
			     _gnutls_x509_cert2gnutls_cert( &peer_cert,
					     &info->raw_certificate_list[0], CERT_NO_COPY)) < 0) {
				gnutls_assert();
				return 0;
			}
			break;

		case GNUTLS_CRT_OPENPGP:
			if (_E_gnutls_openpgp_cert2gnutls_cert==NULL) {
				gnutls_assert();
				return GNUTLS_E_INIT_LIBEXTRA;
			}
			if ((ret =
			     _E_gnutls_openpgp_cert2gnutls_cert( &peer_cert,
					     &info->raw_certificate_list[0])) < 0) {
				gnutls_assert();
				return 0;
			}
			break;

		default:
			gnutls_assert();
			return 0;
	}

	if (peer_cert.subject_pk_algorithm != GNUTLS_PK_RSA) {
		gnutls_assert();
		return 0;
	}

	if ( _gnutls_mpi_get_nbits( peer_cert.params[0]) 
		<= 512) {
		_gnutls_free_cert( &peer_cert);
		return 1;
	}
	
	_gnutls_free_cert( &peer_cert);
	
	return 0;
}

static int proc_rsa_export_server_kx(gnutls_session session, opaque * data,
				size_t _data_size)
{
	uint16 n_m, n_e;
	size_t _n_m, _n_e;
	uint8 *data_m;
	uint8 *data_e;
	int i, sigsize;
	gnutls_datum vparams, signature;
	int ret;
	ssize_t data_size = _data_size;
	CERTIFICATE_AUTH_INFO info;
	gnutls_cert peer_cert;

	info = _gnutls_get_auth_info( session);
	if (info == NULL || info->ncerts==0) {
		gnutls_assert();
		/* we need this in order to get peer's certificate */
		return GNUTLS_E_INTERNAL_ERROR;
	}


	i = 0;
	
	DECR_LEN( data_size, 2);
	n_m = _gnutls_read_uint16(&data[i]);
	i += 2;

	DECR_LEN( data_size, n_m);
	data_m = &data[i];
	i += n_m;
	if (i > data_size) {
		gnutls_assert();
		return GNUTLS_E_UNEXPECTED_PACKET_LENGTH;
	}

	DECR_LEN( data_size, 2);
	n_e = _gnutls_read_uint16(&data[i]);
	i += 2;

	DECR_LEN( data_size, n_e);
	data_e = &data[i];
	i += n_e;
	if (i > data_size) {
		gnutls_assert();
		return GNUTLS_E_UNEXPECTED_PACKET_LENGTH;
	}

	_n_e = n_e;
	_n_m = n_m;

	if (_gnutls_mpi_scan(&session->key->rsa[0], data_m, &_n_m) != 0) {
		gnutls_assert();
		return GNUTLS_E_MPI_SCAN_FAILED;
	}

	if (_gnutls_mpi_scan(&session->key->rsa[1], data_e, &_n_e) != 0) {
		gnutls_assert();
		return GNUTLS_E_MPI_SCAN_FAILED;
	}

	ret=_gnutls_rsa_export_set_modulus_bits( session, _gnutls_mpi_get_nbits(
		session->key->rsa[0]));
	if (ret<0) {
		gnutls_assert();
		return ret;
	}

	/* VERIFY SIGNATURE */

	vparams.size = n_m + n_e + 4;
	vparams.data = data;

	DECR_LEN( data_size, 2);
	sigsize = _gnutls_read_uint16(&data[vparams.size]);

	DECR_LEN( data_size, sigsize);
	signature.data = &data[vparams.size + 2];
	signature.size = sigsize;

	switch( session->security_parameters.cert_type) {
		case GNUTLS_CRT_X509:
			if ((ret =
			     _gnutls_x509_cert2gnutls_cert( &peer_cert,
					     &info->raw_certificate_list[0], CERT_NO_COPY)) < 0) {
				gnutls_assert();
				return ret;
			}
			break;

		case GNUTLS_CRT_OPENPGP:
			if (_E_gnutls_openpgp_cert2gnutls_cert==NULL) {
				gnutls_assert();
				return GNUTLS_E_INIT_LIBEXTRA;
			}
			if ((ret =
			     _E_gnutls_openpgp_cert2gnutls_cert( &peer_cert,
					     &info->raw_certificate_list[0])) < 0) {
				gnutls_assert();
				return ret;
			}
			break;

		default:
			gnutls_assert();
			return GNUTLS_E_INTERNAL_ERROR;
	}

	ret =
	    _gnutls_verify_sig_params(session,
				      &peer_cert,
				      &vparams, &signature);
	
	_gnutls_free_cert( &peer_cert);
	if (ret < 0) {
		gnutls_assert();
		return ret;
	}

	return ret;
}
