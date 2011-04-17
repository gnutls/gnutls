#ifndef _ABSTRACT_INT_H
# define _ABSTRACT_INT_H

#include <gnutls/abstract.h>

int _gnutls_privkey_get_public_mpis (gnutls_privkey_t key,
                                     bigint_t * params, int *params_size);

int _gnutls_pubkey_compatible_with_sig(gnutls_pubkey_t pubkey, gnutls_protocol_t ver, 
  gnutls_sign_algorithm_t sign);
int _gnutls_pubkey_is_over_rsa_512(gnutls_pubkey_t pubkey);
int
_gnutls_pubkey_get_mpis (gnutls_pubkey_t key,
                                 bigint_t * params, int *params_size);

#endif
