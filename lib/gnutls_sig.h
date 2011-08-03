/*
 * Copyright (C) 2000-2011 Free Software Foundation, Inc.
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

#ifndef GNUTLS_SIG_H
#define GNUTLS_SIG_H

#include <gnutls/abstract.h>

int _gnutls_handshake_sign_cert_vrfy (gnutls_session_t session,
                                      gnutls_pcert_st* cert,
                                      gnutls_privkey_t pkey,
                                      gnutls_datum_t * signature);

int _gnutls_handshake_sign_data (gnutls_session_t session,
                                 gnutls_pcert_st* cert,
                                 gnutls_privkey_t pkey,
                                 gnutls_datum_t * params,
                                 gnutls_datum_t * signature,
                                 gnutls_sign_algorithm_t * algo);

int _gnutls_handshake_verify_cert_vrfy (gnutls_session_t session,
                                        gnutls_pcert_st* cert,
                                        gnutls_datum_t * signature,
                                        gnutls_sign_algorithm_t);

int _gnutls_handshake_verify_data (gnutls_session_t session,
                                   gnutls_pcert_st* cert,
                                   const gnutls_datum_t * params,
                                   gnutls_datum_t * signature,
                                   gnutls_sign_algorithm_t algo);

int _gnutls_soft_sign (gnutls_pk_algorithm_t algo,
                       gnutls_pk_params_st* params,
                       const gnutls_datum_t * data,
                       gnutls_datum_t * signature);

int pk_prepare_hash (gnutls_pk_algorithm_t pk, gnutls_digest_algorithm_t hash,
                     gnutls_datum_t * output);
int pk_hash_data (gnutls_pk_algorithm_t pk, gnutls_digest_algorithm_t hash,
                  gnutls_pk_params_st * params, const gnutls_datum_t * data,
                  gnutls_datum_t * digest);

int
_gnutls_privkey_sign_hash (gnutls_privkey_t key,
                           const gnutls_datum_t * hash,
                           gnutls_datum_t * signature);

int
decode_ber_digest_info (const gnutls_datum_t * info,
                        gnutls_mac_algorithm_t * hash,
                        opaque * digest, int *digest_size);

#endif
