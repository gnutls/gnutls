/*
 * Copyright (C) 2011 Free Software Foundation, Inc.
 *
 * Author: Nikos Mavrogiannopoulos
 *
 * This file is part of GnuTLS.
 *
 * The GnuTLS is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public License
 * as published by the Free Software Foundation; either version 2.1 of
 * the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301,
 * USA
 *
 */

/* This file contains common stuff in Ephemeral Diffie-Hellman (DHE)
 * and Anonymous DH key exchange(DHA). These are used in the handshake
 * procedure of the certificate and anoymous authentication.
 */

#include "gnutls_int.h"
#include "gnutls_auth.h"
#include "gnutls_errors.h"
#include "gnutls_dh.h"
#include "gnutls_num.h"
#include "gnutls_sig.h"
#include <gnutls_datum.h>
#include <gnutls_x509.h>
#include <gnutls_state.h>
#include <auth/ecdh_common.h>
#include <gnutls_ecc.h>
#include <ext/ecc.h>
#include <gnutls_algorithms.h>
#include <auth/psk.h>
#include <gnutls_pk.h>

static int calc_ecdh_key( gnutls_session_t session)
{
gnutls_pk_params_st pub;
int ret;

  pub.params[0] = session->key->ecdh_params.params[0];
  pub.params[1] = session->key->ecdh_params.params[1];
  pub.params[2] = session->key->ecdh_params.params[2];
  pub.params[3] = session->key->ecdh_params.params[3];
  pub.params[4] = session->key->ecdh_x;
  pub.params[5] = session->key->ecdh_y;
  pub.params[6] = _gnutls_mpi_new(1);
  if (pub.params[6] == NULL)
    return gnutls_assert_val(GNUTLS_E_MEMORY_ERROR);
  
  _gnutls_mpi_set_ui(pub.params[6], 1);
  
  ret = _gnutls_pk_derive(GNUTLS_PK_ECDH, &session->key->key, &session->key->ecdh_params, &pub);
  
  _gnutls_mpi_release(&pub.params[6]);
  
  if (ret < 0)
    return gnutls_assert_val(ret);
    
  return 0;
}


int
_gnutls_proc_ecdh_common_client_kx (gnutls_session_t session,
                                  opaque * data, size_t _data_size,
                                  ecc_curve_t curve)
{
  ssize_t data_size = _data_size;
  int ret, i = 0;
  int point_size;

  DECR_LEN (data_size, 1);
  point_size = data[i];
  i+=1;

  DECR_LEN (data_size, point_size);
  ret = _gnutls_ecc_ansi_x963_import(curve, &data[i], point_size, &session->key->ecdh_x, &session->key->ecdh_y);
  if (ret < 0)
    return gnutls_assert_val(ret);

  /* generate pre-shared key */
  ret = calc_ecdh_key(session);
  if (ret < 0)
    return gnutls_assert_val(ret);

  return 0;
}

int
_gnutls_gen_ecdh_common_client_kx (gnutls_session_t session, gnutls_buffer_st* data)
{
  int ret;
  gnutls_datum_t out;
  int curve = _gnutls_session_ecc_curve_get(session);

  /* generate temporal key */
  ret = _gnutls_pk_generate(GNUTLS_PK_ECDH, curve, &session->key->ecdh_params);
  if (ret < 0)
    return gnutls_assert_val(ret);

  ret = _gnutls_ecc_ansi_x963_export(curve, session->key->ecdh_params.params[4] /* x */,
    session->key->ecdh_params.params[5] /* y */, &out);
  if (ret < 0)
    return gnutls_assert_val(ret);

  ret = _gnutls_buffer_append_data_prefix(data, 8, out.data, out.size);
  
  _gnutls_free_datum(&out);
  
  if (ret < 0)
    return gnutls_assert_val(ret);
    
  /* generate pre-shared key */
  ret = calc_ecdh_key(session);
  if (ret < 0)
    return gnutls_assert_val(ret);

  return data->length;
}

int
_gnutls_proc_ecdh_common_server_kx (gnutls_session_t session,
                                  opaque * data, size_t _data_size)
{
  int i, ret, point_size;
  ecc_curve_t curve;
  ssize_t data_size = _data_size;

  i = 0;
  DECR_LEN (data_size, 1);
  if (data[i++] != 3)
    return gnutls_assert_val(GNUTLS_E_ECC_NO_SUPPORTED_CURVES);
  
  DECR_LEN (data_size, 2);
  curve = _gnutls_num_to_ecc(_gnutls_read_uint16 (&data[i]));
  i += 2;

  ret = _gnutls_session_supports_ecc_curve(session, curve);
  if (ret < 0)
    return gnutls_assert_val(ret);

  DECR_LEN (data_size, 1);
  point_size = data[i];
  i+=1;

  DECR_LEN (data_size, point_size);
  ret = _gnutls_ecc_ansi_x963_import(curve, &data[i], point_size, &session->key->ecdh_x, &session->key->ecdh_y);
  if (ret < 0)
    return gnutls_assert_val(ret);

  return ret;
}

/* If the psk flag is set, then an empty psk_identity_hint will
 * be inserted */
int _gnutls_ecdh_common_print_server_kx (gnutls_session_t session, gnutls_buffer_st* data,
                                         ecc_curve_t curve)
{
  opaque p;
  int ret;
  gnutls_datum_t out;

  /* curve type */
  p = 3;
  
  ret = _gnutls_buffer_append_data(data, &p, 1);
  if (ret < 0)
    return gnutls_assert_val(ret);

  ret = _gnutls_buffer_append_prefix(data, 16, _gnutls_ecc_to_num(curve));
  if (ret < 0)
    return gnutls_assert_val(ret);

  /* generate temporal key */
  ret = _gnutls_pk_generate(GNUTLS_PK_ECDH, curve, &session->key->ecdh_params);
  if (ret < 0)
    return gnutls_assert_val(ret);

  ret = _gnutls_ecc_ansi_x963_export(curve, session->key->ecdh_params.params[4] /* x */,
    session->key->ecdh_params.params[5] /* y */, &out);
  if (ret < 0)
    return gnutls_assert_val(ret);

  ret = _gnutls_buffer_append_data_prefix(data, 8, out.data, out.size);
  
  _gnutls_free_datum(&out);
  
  if (ret < 0)
    return gnutls_assert_val(ret);
    
  return data->length;
}
