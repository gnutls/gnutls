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
#include <x509_verify.h>
#include "debug.h"
#include <gnutls_sig.h>
#include <gnutls_x509.h>
#include <gnutls_extra.h>

int _gnutls_gen_rsa_client_kx(gnutls_session, opaque **);
int _gnutls_proc_rsa_client_kx(gnutls_session, opaque *, int);

const MOD_AUTH_STRUCT rsa_auth_struct = {
	"RSA",
	_gnutls_gen_cert_server_certificate,
	_gnutls_gen_cert_client_certificate,
	NULL,			/* gen server kx */
	NULL,			/* gen server kx2 */
	NULL,			/* gen client kx0 */
	_gnutls_gen_rsa_client_kx,
	_gnutls_gen_cert_client_cert_vrfy,	/* gen client cert vrfy */
	_gnutls_gen_cert_server_cert_req,	/* server cert request */

	_gnutls_proc_cert_server_certificate,
	_gnutls_proc_cert_client_certificate,
	NULL,			/* proc server kx */
	NULL,			/* proc server kx2 */
	NULL,			/* proc client kx0 */
	_gnutls_proc_rsa_client_kx,	/* proc client kx */
	_gnutls_proc_cert_client_cert_vrfy,	/* proc client cert vrfy */
	_gnutls_proc_cert_cert_req	/* proc server cert request */
};

/* in auth_dhe.c */
extern OPENPGP_CERT2GNUTLS_CERT _E_gnutls_openpgp_cert2gnutls_cert;

/* This function reads the RSA parameters from peer's certificate;
 */
int _gnutls_get_public_rsa_params(gnutls_session session, GNUTLS_MPI params[MAX_PARAMS_SIZE], int* params_len)
{
int ret;
CERTIFICATE_AUTH_INFO info;
gnutls_cert peer_cert;
int i;

	/* normal non export case */

	info = _gnutls_get_auth_info( session);

	if (info==NULL || info->ncerts==0) {
		gnutls_assert();
		return GNUTLS_E_UNKNOWN_ERROR;
	}
	
	switch( session->security_parameters.cert_type) {
		case GNUTLS_CRT_X509:
			if ((ret =
			     _gnutls_x509_cert2gnutls_cert( &peer_cert,
					     info->raw_certificate_list[0], CERT_ONLY_PUBKEY|CERT_NO_COPY)) < 0) {
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
					     info->raw_certificate_list[0])) < 0) {
				gnutls_assert();
				return ret;
			}
			break;

		default:
			gnutls_assert();
			return GNUTLS_E_INTERNAL_ERROR;
	}


	/* EXPORT case: */
	if ( _gnutls_cipher_suite_get_kx_algo(session->security_parameters.current_cipher_suite)
		 == GNUTLS_KX_RSA_EXPORT && 
		 	_gnutls_mpi_get_nbits(peer_cert.params[0]) > 512) {

		_gnutls_free_cert( peer_cert);

		if (session->gnutls_key->rsa[0] == NULL ||
			session->gnutls_key->rsa[1] == NULL) {
			gnutls_assert();
			return GNUTLS_E_INTERNAL_ERROR;
		}

		if (*params_len < 2) {
			gnutls_assert();
			return GNUTLS_E_INTERNAL_ERROR;
		}
		*params_len = 2;
		for (i=0;i<*params_len;i++) {
			params[i] = _gnutls_mpi_copy(session->gnutls_key->rsa[i]);
		}

		return 0;
	}

	/* end of export case */
	
	if (*params_len < peer_cert.params_size) {
		gnutls_assert();
		return GNUTLS_E_INTERNAL_ERROR;
	}
	*params_len = peer_cert.params_size;

	for (i=0;i<*params_len;i++) {
		params[i] = _gnutls_mpi_copy(peer_cert.params[i]);
	}
	_gnutls_free_cert( peer_cert);

	return 0;
}

/* This function reads the RSA parameters from the private key
 */
int _gnutls_get_private_rsa_params(gnutls_session session, GNUTLS_MPI **params, int* params_size)
{
int index;
const gnutls_certificate_credentials cred;

	cred = _gnutls_get_cred(session->gnutls_key, GNUTLS_CRD_CERTIFICATE, NULL);
	if (cred == NULL) {
	        gnutls_assert();
	        return GNUTLS_E_INSUFICIENT_CREDENTIALS;
	}

	if ( (index=session->internals.selected_cert_index) < 0) {
		gnutls_assert();
		return GNUTLS_E_UNKNOWN_ERROR;
	}

	if ( _gnutls_cipher_suite_get_kx_algo(session->security_parameters.current_cipher_suite)
		 == GNUTLS_KX_RSA_EXPORT && 
		 	_gnutls_mpi_get_nbits(cred->cert_list[index][0].params[0]) > 512) {

		/* EXPORT case: */
		if (cred->rsa_params == NULL) {
			gnutls_assert();
			return GNUTLS_E_NO_TEMPORARY_RSA_PARAMS;
		}

		*params_size = RSA_PRIVATE_PARAMS;
		*params = cred->rsa_params->params;

		return 0;
	}

	/* non export cipher suites. */	
	
	*params_size = cred->pkey[index].params_size;
	*params = cred->pkey[index].params;

	return 0;
}



#define RANDOMIZE_KEY(x, galloc, rand) x.size=TLS_MASTER_SIZE; x.data=galloc(x.size); \
		if (x.data==NULL) return GNUTLS_E_MEMORY_ERROR; \
		if (_gnutls_get_random( x.data, x.size, rand) < 0) { \
			gnutls_assert(); \
			return GNUTLS_E_MEMORY_ERROR; \
		}

int _gnutls_proc_rsa_client_kx(gnutls_session session, opaque * data, int data_size)
{
	gnutls_sdatum plaintext;
	gnutls_datum ciphertext;
	int ret, dsize;
	GNUTLS_MPI *params;
	int params_len;

	if (gnutls_protocol_get_version(session) == GNUTLS_SSL3) {
		/* SSL 3.0 */
		ciphertext.data = data;
		ciphertext.size = data_size;
	} else {		/* TLS 1 */
		DECR_LEN( data_size, 2);
		ciphertext.data = &data[2];
		dsize = _gnutls_read_uint16(data);

		if (dsize != data_size) {
			gnutls_assert();
			return GNUTLS_E_UNEXPECTED_PACKET_LENGTH;
		}
		ciphertext.size = dsize;
	}

	ret = _gnutls_get_private_rsa_params(session, &params, &params_len);
	if (ret < 0) {
		gnutls_assert();
		return ret;
	}

	ret = _gnutls_pkcs1_rsa_decrypt(&plaintext, ciphertext, params, 
		params_len, 2);	/* btype==2 */

	if (ret < 0 || plaintext.size != TLS_MASTER_SIZE) {
		/* in case decryption fails then don't inform
		 * the peer. Just use a random key. (in order to avoid
		 * attack against pkcs-1 formating).
		 */
		ret = 0;
		gnutls_assert();

		_gnutls_log("RSA_AUTH: Possible PKCS-1 format attack\n");

		RANDOMIZE_KEY(session->gnutls_key->key,
			      gnutls_secure_malloc, GNUTLS_WEAK_RANDOM);
	} else {
		ret = 0;
		if (session->internals.rsa_pms_check==0)
			if (_gnutls_get_adv_version_major(session) !=
			    plaintext.data[0]
			    || _gnutls_get_adv_version_minor(session) !=
			    plaintext.data[1]) {
				gnutls_assert();
				ret = GNUTLS_E_DECRYPTION_FAILED;
			}

		session->gnutls_key->key.data = plaintext.data;
		session->gnutls_key->key.size = plaintext.size;
	}

	return ret;
}



/* return RSA(random) using the peers public key 
 */
int _gnutls_gen_rsa_client_kx(gnutls_session session, opaque ** data)
{
	CERTIFICATE_AUTH_INFO auth = session->gnutls_key->auth_info;
	gnutls_datum sdata;	/* data to send */
	GNUTLS_MPI params[MAX_PARAMS_SIZE];
	int params_len = MAX_PARAMS_SIZE;
	int ret, i;
	gnutls_protocol_version ver;

	if (auth == NULL) {
		/* this shouldn't have happened. The proc_certificate
		 * function should have detected that.
		 */
		gnutls_assert();
		return GNUTLS_E_INSUFICIENT_CREDENTIALS;
	}
	RANDOMIZE_KEY(session->gnutls_key->key, gnutls_secure_malloc, GNUTLS_STRONG_RANDOM);

	ver = _gnutls_get_adv_version(session);

	session->gnutls_key->key.data[0] = _gnutls_version_get_major(ver);
	session->gnutls_key->key.data[1] = _gnutls_version_get_minor(ver);

	/* move RSA parameters to gnutls_key (session).
	 */
	if ((ret =
	     _gnutls_get_public_rsa_params(session, params, &params_len)) < 0) {
		gnutls_assert();
		return ret;
	}

	if ((ret =
	     _gnutls_pkcs1_rsa_encrypt(&sdata, session->gnutls_key->key,
				       params, params_len, 2)) < 0) {
		gnutls_assert();
		return ret;
	}

	for (i=0;i<params_len;i++)
		_gnutls_mpi_release( &params[i]);

	if (gnutls_protocol_get_version( session) == GNUTLS_SSL3) {
		/* SSL 3.0 */
		*data = sdata.data;
		return sdata.size;
	} else {		/* TLS 1 */
		*data = gnutls_malloc(sdata.size + 2);
		if (*data == NULL) {
			gnutls_free_datum(&sdata);
			return GNUTLS_E_MEMORY_ERROR;
		}
		_gnutls_write_datum16( *data, sdata);
		ret = sdata.size + 2;
		gnutls_free_datum(&sdata);
		return ret;
	}

}
