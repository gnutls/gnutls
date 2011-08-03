/*
 * Copyright (C) 2001, 2002, 2003, 2004, 2005, 2007, 2010 Free Software
 * Foundation, Inc.
 *
 * Author: Nikos Mavrogiannopoulos
 *
 * This file is part of GnuTLS.
 *
 * The GnuTLS is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public License
 * as published by the Free Software Foundation; either version 3 of
 * the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>
 *
 */

#include <gnutls_int.h>

#ifdef ENABLE_SRP

#include "gnutls_errors.h"
#include <auth/srp_passwd.h>
#include "gnutls_auth.h"
#include "gnutls_auth.h"
#include "gnutls_srp.h"
#include "debug.h"
#include "gnutls_num.h"
#include <auth/srp.h>
#include <gnutls_str.h>
#include <auth/cert.h>
#include <gnutls_datum.h>
#include <gnutls_sig.h>
#include <auth/srp.h>
#include <gnutls_x509.h>

static int gen_srp_cert_server_kx (gnutls_session_t, gnutls_buffer_st*);
static int proc_srp_cert_server_kx (gnutls_session_t, opaque *, size_t);

const mod_auth_st srp_rsa_auth_struct = {
  "SRP",
  _gnutls_gen_cert_server_certificate,
  NULL,
  gen_srp_cert_server_kx,
  _gnutls_gen_srp_client_kx,
  NULL,
  NULL,

  _gnutls_proc_cert_server_certificate,
  NULL,                         /* certificate */
  proc_srp_cert_server_kx,
  _gnutls_proc_srp_client_kx,
  NULL,
  NULL
};

const mod_auth_st srp_dss_auth_struct = {
  "SRP",
  _gnutls_gen_cert_server_certificate,
  NULL,
  gen_srp_cert_server_kx,
  _gnutls_gen_srp_client_kx,
  NULL,
  NULL,

  _gnutls_proc_cert_server_certificate,
  NULL,                         /* certificate */
  proc_srp_cert_server_kx,
  _gnutls_proc_srp_client_kx,
  NULL,
  NULL
};

static int
gen_srp_cert_server_kx (gnutls_session_t session, gnutls_buffer_st* data)
{
  ssize_t ret;
  gnutls_datum_t signature, ddata;
  gnutls_certificate_credentials_t cred;
  gnutls_pcert_st *apr_cert_list;
  gnutls_privkey_t apr_pkey;
  int apr_cert_list_length;
  gnutls_sign_algorithm_t sign_algo;

  ret = _gnutls_gen_srp_server_kx (session, data);

  if (ret < 0)
    return ret;

  ddata.data = data->data;
  ddata.size = data->length;

  cred = (gnutls_certificate_credentials_t)
    _gnutls_get_cred (session->key, GNUTLS_CRD_CERTIFICATE, NULL);
  if (cred == NULL)
    {
      gnutls_assert ();
      return GNUTLS_E_INSUFFICIENT_CREDENTIALS;
    }

  /* find the appropriate certificate */
  if ((ret =
       _gnutls_get_selected_cert (session, &apr_cert_list,
                                  &apr_cert_list_length, &apr_pkey)) < 0)
    {
      gnutls_assert ();
      return ret;
    }

  if ((ret =
       _gnutls_handshake_sign_data (session, &apr_cert_list[0],
                                    apr_pkey, &ddata, &signature,
                                    &sign_algo)) < 0)
    {
      gnutls_assert ();
      return ret;
    }

  ret = _gnutls_buffer_append_data_prefix( data, 16, signature.data, signature.size);

  _gnutls_free_datum (&signature);

  if (ret < 0)
    return gnutls_assert_val(ret);

  return data->length;

}

static int
proc_srp_cert_server_kx (gnutls_session_t session, opaque * data,
                         size_t _data_size)
{
  ssize_t ret;
  int sigsize;
  gnutls_datum_t vparams, signature;
  ssize_t data_size;
  cert_auth_info_t info;
  gnutls_pcert_st peer_cert;
  opaque *p;

  ret = _gnutls_proc_srp_server_kx (session, data, _data_size);
  if (ret < 0)
    return ret;

  data_size = _data_size - ret;

  info = _gnutls_get_auth_info (session);
  if (info == NULL || info->ncerts == 0)
    {
      gnutls_assert ();
      /* we need this in order to get peer's certificate */
      return GNUTLS_E_INTERNAL_ERROR;
    }

  /* VERIFY SIGNATURE */

  vparams.size = ret;           /* all the data minus the signature */
  vparams.data = data;

  p = &data[vparams.size];

  DECR_LEN (data_size, 2);
  sigsize = _gnutls_read_uint16 (p);

  DECR_LEN (data_size, sigsize);
  signature.data = &p[2];
  signature.size = sigsize;

  ret =
    _gnutls_get_auth_info_pcert (&peer_cert,
                                 session->security_parameters.cert_type,
                                 info);

  if (ret < 0)
    {
      gnutls_assert ();
      return ret;
    }

  ret =
    _gnutls_handshake_verify_data (session, &peer_cert, &vparams, &signature,
                                   GNUTLS_SIGN_UNKNOWN);

  gnutls_pcert_deinit (&peer_cert);
  if (ret < 0)
    {
      gnutls_assert ();
      return ret;
    }

  return 0;
}


#endif /* ENABLE_SRP */
