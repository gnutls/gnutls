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

#endif
