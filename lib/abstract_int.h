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

int pubkey_verify_hashed_data (gnutls_pk_algorithm_t pk, 
                       const gnutls_datum_t * hash,
                       const gnutls_datum_t * signature,
                       gnutls_pk_params_st * issuer_params);

int pubkey_verify_data (gnutls_pk_algorithm_t pk,
                        gnutls_digest_algorithm_t algo,
                       const gnutls_datum_t * data,
                       const gnutls_datum_t * signature,
                       gnutls_pk_params_st * issuer_params);



gnutls_digest_algorithm_t _gnutls_dsa_q_to_hash (gnutls_pk_algorithm_t algo, 
  const gnutls_pk_params_st* params, int* hash_len);

#endif
