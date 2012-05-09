/*
 * Copyright (C) 2010-2012 Free Software Foundation, Inc.
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

#ifndef _ABSTRACT_INT_H
# define _ABSTRACT_INT_H

#include <gnutls/abstract.h>

int _gnutls_privkey_get_public_mpis (gnutls_privkey_t key,
                                     gnutls_pk_params_st*);

int pubkey_to_bits(gnutls_pk_algorithm_t pk, gnutls_pk_params_st* params);
int _gnutls_pubkey_compatible_with_sig(gnutls_pubkey_t pubkey, gnutls_protocol_t ver, 
  gnutls_sign_algorithm_t sign);
int _gnutls_pubkey_is_over_rsa_512(gnutls_pubkey_t pubkey);
int
_gnutls_pubkey_get_mpis (gnutls_pubkey_t key,
                                 gnutls_pk_params_st * params);

int
pubkey_verify_hashed_data (gnutls_pk_algorithm_t pk,
                           gnutls_digest_algorithm_t hash_algo,
                           const gnutls_datum_t * hash,
                           const gnutls_datum_t * signature,
                           gnutls_pk_params_st * issuer_params);

int pubkey_verify_data (gnutls_pk_algorithm_t pk,
                        gnutls_digest_algorithm_t algo,
                       const gnutls_datum_t * data,
                       const gnutls_datum_t * signature,
                       gnutls_pk_params_st * issuer_params);



gnutls_digest_algorithm_t _gnutls_dsa_q_to_hash (gnutls_pk_algorithm_t algo, 
  const gnutls_pk_params_st* params, unsigned int* hash_len);

#endif
