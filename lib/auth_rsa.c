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

#include "gnutls_int.h"
#include "gnutls_auth_int.h"
#include "gnutls_errors.h"
#include "gnutls_dh.h"
#include "gnutls_num.h"
#include "x509_asn1.h"
#include "x509_der.h"
#include "gnutls_datum.h"
#include "auth_x509.h"
#include <gnutls_random.h>
#include <gnutls_pk.h>
#include <gnutls_algorithms.h>
#include <gnutls_global.h>
#include <x509_verify.h>
#include "debug.h"
#include <gnutls_sig.h>


int gen_rsa_client_kx(GNUTLS_STATE, opaque **);
int proc_rsa_client_kx(GNUTLS_STATE, opaque *, int);


MOD_AUTH_STRUCT rsa_auth_struct =
{
	"RSA",
	_gnutls_gen_x509_server_certificate,
	_gnutls_gen_x509_client_certificate,
	NULL,			/* gen server kx */
	NULL,			/* gen server kx2 */
	NULL,			/* gen client kx0 */
	gen_rsa_client_kx,
	_gnutls_gen_x509_client_cert_vrfy, /* gen client cert vrfy */
	_gnutls_gen_x509_server_cert_req, /* server cert request */

	_gnutls_proc_x509_server_certificate,
	_gnutls_proc_x509_client_certificate,
	NULL,			/* proc server kx */
	NULL,			/* proc server kx2 */
	NULL,			/* proc client kx0 */
	proc_rsa_client_kx,	/* proc client kx */
	_gnutls_proc_x509_client_cert_vrfy, /* proc client cert vrfy */
	_gnutls_proc_x509_cert_req	/* proc server cert request */
};






#define RANDOMIZE_KEY(x, galloc) x.size=TLS_MASTER_SIZE; x.data=galloc(x.size); \
		if (x.data==NULL) return GNUTLS_E_MEMORY_ERROR; \
		if (_gnutls_get_random( x.data, x.size, GNUTLS_WEAK_RANDOM) < 0) { \
			return GNUTLS_E_MEMORY_ERROR; \
		}

int proc_rsa_client_kx(GNUTLS_STATE state, opaque * data, int data_size)
{
	gnutls_sdatum plaintext;
	gnutls_datum ciphertext;
	int ret, dsize;

	if ( gnutls_get_current_version(state) == GNUTLS_SSL3) {
		/* SSL 3.0 */
		ciphertext.data = data;
		ciphertext.size = data_size;
	} else {		/* TLS 1 */
		ciphertext.data = &data[2];
		dsize = READuint16(data);
		
		if (dsize != data_size - 2) {
			gnutls_assert();
			return GNUTLS_E_UNEXPECTED_PACKET_LENGTH;
		}
		ciphertext.size = dsize;
	}

	ret =
	    _gnutls_pkcs1_rsa_decrypt(&plaintext, ciphertext, state->gnutls_key->u,
				      state->gnutls_key->A, 2);		/* btype==2 */

	if (ret < 0) {
		/* in case decryption fails then don't inform
		 * the peer. Just use a random key. (in order to avoid
		 * attack against pkcs-1 formating).
		 */
return ret;
		gnutls_assert();
#ifdef DEBUG
		_gnutls_log( "Possible PKCS-1 format attack\n");
#endif
		RANDOMIZE_KEY(state->gnutls_key->key, secure_malloc);
	} else {
		ret = 0;
		if (plaintext.size != TLS_MASTER_SIZE) {	/* WOW */
			RANDOMIZE_KEY(state->gnutls_key->key, secure_malloc);
		} else {
			if (_gnutls_get_adv_version_major( state) != plaintext.data[0] 
				|| _gnutls_get_adv_version_minor( state) != plaintext.data[1]) {
				gnutls_assert();
				ret = GNUTLS_E_DECRYPTION_FAILED;
			}
			if (ret != 0) {
				_gnutls_mpi_release(&state->gnutls_key->B);
				_gnutls_mpi_release(&state->gnutls_key->u);
				_gnutls_mpi_release(&state->gnutls_key->A);
				gnutls_assert();
				return ret;
			}
			state->gnutls_key->key.data = plaintext.data;
			state->gnutls_key->key.size = plaintext.size;
		}
	}

	_gnutls_mpi_release(&state->gnutls_key->A);
	_gnutls_mpi_release(&state->gnutls_key->B);
	_gnutls_mpi_release(&state->gnutls_key->u);
	return 0;
}



/* return RSA(random) using the peers public key 
 */
int gen_rsa_client_kx(GNUTLS_STATE state, opaque ** data)
{
	X509PKI_AUTH_INFO auth = state->gnutls_key->auth_info;
	gnutls_datum sdata;	/* data to send */
	MPI pkey, n;
	int ret;
	GNUTLS_Version ver;

	if (auth == NULL) {
		/* this shouldn't have happened. The proc_certificate
		 * function should have detected that.
		 */
		gnutls_assert();
		return GNUTLS_E_INSUFICIENT_CRED;
	}
	RANDOMIZE_KEY(state->gnutls_key->key, secure_malloc);

	ver = _gnutls_version_max(state);

	state->gnutls_key->key.data[0] = _gnutls_version_get_major(ver);
	state->gnutls_key->key.data[1] = _gnutls_version_get_minor(ver);

	if ((ret =
	     _gnutls_pkcs1_rsa_encrypt(&sdata, state->gnutls_key->key, state->gnutls_key->x, state->gnutls_key->a, 2)) < 0) {
		gnutls_assert();
		_gnutls_mpi_release(&pkey);
		_gnutls_mpi_release(&n);
		return ret;
	}
	_gnutls_mpi_release(&state->gnutls_key->a);
	_gnutls_mpi_release(&state->gnutls_key->x);

	if ( ver == GNUTLS_SSL3) {
		/* SSL 3.0 */
		*data = sdata.data;
		return sdata.size;
	} else {		/* TLS 1 */
		*data = gnutls_malloc(sdata.size + 2);
		if (*data == NULL) {
			gnutls_free_datum(&sdata);
			return GNUTLS_E_MEMORY_ERROR;
		}
		WRITEuint16(sdata.size, *data);
		memcpy(&(*data)[2], sdata.data, sdata.size);
		ret = sdata.size + 2;
		gnutls_free_datum(&sdata);
		return ret;
	}

}

