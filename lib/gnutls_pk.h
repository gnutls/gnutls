/*
 * Copyright (C) 2000-2012 Free Software Foundation, Inc.
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
 * You should have received a copy of the GNU Lesser General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>
 *
 */

#ifndef GNUTLS_PK_H
#define GNUTLS_PK_H

extern int crypto_pk_prio;
extern gnutls_crypto_pk_st _gnutls_pk_ops;

#define _gnutls_pk_encrypt( algo, ciphertext, plaintext, params) _gnutls_pk_ops.encrypt( algo, ciphertext, plaintext, params)
#define _gnutls_pk_decrypt( algo, ciphertext, plaintext, params) _gnutls_pk_ops.decrypt( algo, ciphertext, plaintext, params)
#define _gnutls_pk_sign( algo, sig, data, params) _gnutls_pk_ops.sign( algo, sig, data, params)
#define _gnutls_pk_verify( algo, data, sig, params) _gnutls_pk_ops.verify( algo, data, sig, params)
#define _gnutls_pk_verify_params( algo, params) _gnutls_pk_ops.verify_params( algo, params)
#define _gnutls_pk_derive( algo, out, pub, priv) _gnutls_pk_ops.derive( algo, out, pub, priv)
#define _gnutls_pk_generate( algo, bits, priv) _gnutls_pk_ops.generate( algo, bits, priv)
#define _gnutls_pk_hash_algorithm( pk, sig, params, hash) _gnutls_pk_ops.hash_algorithm(pk, sig, params, hash)

inline static int
_gnutls_pk_fixup (gnutls_pk_algorithm_t algo, gnutls_direction_t direction,
                  gnutls_pk_params_st * params)
{
  if (_gnutls_pk_ops.pk_fixup_private_params)
    return _gnutls_pk_ops.pk_fixup_private_params (algo, direction, params);
  return 0;
}

int _gnutls_pk_params_copy (gnutls_pk_params_st * dst, const gnutls_pk_params_st * src);

/* The internal PK interface */
int
_gnutls_encode_ber_rs (gnutls_datum_t * sig_value, bigint_t r, bigint_t s);
int
_gnutls_encode_ber_rs_raw (gnutls_datum_t * sig_value, 
                           const gnutls_datum_t *r, 
                           const gnutls_datum_t *s);

int
_gnutls_decode_ber_rs (const gnutls_datum_t * sig_value, bigint_t * r,
                       bigint_t * s);

int
encode_ber_digest_info (gnutls_digest_algorithm_t hash,
                        const gnutls_datum_t * digest,
                        gnutls_datum_t * output);

int
decode_ber_digest_info (const gnutls_datum_t * info,
                        gnutls_digest_algorithm_t * hash,
                        uint8_t * digest, unsigned int *digest_size);

int _gnutls_pk_get_hash_algorithm (gnutls_pk_algorithm_t pk,
                                   gnutls_pk_params_st*,
                                   gnutls_digest_algorithm_t * dig,
                                   unsigned int *mand);

#endif /* GNUTLS_PK_H */
