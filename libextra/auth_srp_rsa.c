/*
 * Copyright (C) 2001,2002 Nikos Mavroyanopoulos
 *
 * This file is part of GNUTLS.
 *
 * GNUTLS-EXTRA is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * GNUTLS-EXTRA is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA
 */

#include "gnutls_int.h"

#ifdef ENABLE_SRP

#include "gnutls_errors.h"
#include "auth_srp_passwd.h"
#include "gnutls_auth.h"
#include "gnutls_auth_int.h"
#include "gnutls_srp.h"
#include "debug.h"
#include "gnutls_num.h"
#include "auth_srp.h"
#include <gnutls_str.h>
#include <auth_cert.h>
#include <x509_verify.h>
#include <gnutls_datum.h>
#include <gnutls_sig.h>
#include <auth_srp.h>
#include <gnutls_x509.h>
#include <gnutls_extra.h>

static int gen_srp_cert_server_kx2(gnutls_session, opaque **);
static int proc_srp_cert_server_kx2(gnutls_session, opaque *, size_t);

const MOD_AUTH_STRUCT srp_rsa_auth_struct = {
	"SRP",
	_gnutls_gen_cert_server_certificate,
	NULL,
	NULL,
	gen_srp_cert_server_kx2,
	_gnutls_gen_srp_client_kx0,
	NULL,
	NULL,
	NULL,

	_gnutls_proc_cert_server_certificate,
	NULL, /* certificate */
	NULL,
	proc_srp_cert_server_kx2,
	_gnutls_proc_srp_client_kx0,
	NULL,
	NULL,
	NULL
};

const MOD_AUTH_STRUCT srp_dss_auth_struct = {
	"SRP",
	_gnutls_gen_cert_server_certificate,
	NULL,
	NULL,
	gen_srp_cert_server_kx2,
	_gnutls_gen_srp_client_kx0,
	NULL,
	NULL,
	NULL,

	_gnutls_proc_cert_server_certificate,
	NULL, /* certificate */
	NULL,
	proc_srp_cert_server_kx2,
	_gnutls_proc_srp_client_kx0,
	NULL,
	NULL,
	NULL
};

static int gen_srp_cert_server_kx2(gnutls_session session, opaque ** data)
{
ssize_t ret, data_size;
gnutls_datum signature, ddata;
const gnutls_certificate_credentials cred;
gnutls_cert *apr_cert_list;
gnutls_private_key *apr_pkey;
int apr_cert_list_length;

	ret = _gnutls_gen_srp_server_kx2( session, data);

	if (ret < 0) return ret;
	
	data_size = ret;
	ddata.data = *data;
	ddata.size = data_size;

	cred = _gnutls_get_cred(session->key, GNUTLS_CRD_CERTIFICATE, NULL);
	if (cred == NULL) {
	        gnutls_assert();
	        return GNUTLS_E_INSUFICIENT_CREDENTIALS;
	}

	/* find the appropriate certificate */
	if ((ret =
	     _gnutls_find_apr_cert(session, &apr_cert_list,
				   &apr_cert_list_length,
				   &apr_pkey)) < 0) {
		gnutls_assert();
		return ret;
	}

	if ((ret =
	     _gnutls_generate_sig_params(session, &apr_cert_list[0],
			 apr_pkey, &ddata, &signature)) < 0) 
	{
		gnutls_assert();
		gnutls_free(*data);
		return ret;
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

extern OPENPGP_CERT2GNUTLS_CERT _E_gnutls_openpgp_cert2gnutls_cert;

static int proc_srp_cert_server_kx2(gnutls_session session, opaque * data, size_t _data_size)
{
ssize_t ret;
int sigsize;
gnutls_datum vparams, signature;
ssize_t data_size;
CERTIFICATE_AUTH_INFO info;
gnutls_cert peer_cert;
opaque* p;

	ret = _gnutls_proc_srp_server_kx2( session, data, _data_size);
	if (ret < 0) return ret;
	
	data_size = _data_size - ret;

	info = _gnutls_get_auth_info( session);
	if (info == NULL || info->ncerts==0) {
		gnutls_assert();
		/* we need this in order to get peer's certificate */
		return GNUTLS_E_INTERNAL_ERROR;
	}

	/* VERIFY SIGNATURE */

	vparams.size = ret; /* all the data minus the signature */
	vparams.data = data;

	p = &data[vparams.size];

	DECR_LEN( data_size, 2);
	sigsize = _gnutls_read_uint16( p);

	DECR_LEN( data_size, sigsize);
	signature.data = &p[2];
	signature.size = sigsize;

	switch( session->security_parameters.cert_type) {
		case GNUTLS_CRT_X509:
			if ((ret =
			     _gnutls_x509_cert2gnutls_cert( &peer_cert,
					     info->raw_certificate_list[0], CERT_NO_COPY)) < 0) {
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

	ret =
	    _gnutls_verify_sig_params(session,
				      &peer_cert,
				      &vparams, &signature);
	
	_gnutls_free_cert( peer_cert);
	if (ret < 0) {
		gnutls_assert();
		return ret;
	}

	return 0;
}


#endif /* ENABLE_SRP */
