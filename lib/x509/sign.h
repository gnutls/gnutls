#ifndef GNUTLS_SIGN_H
#define GNUTLS_SIGN_H

int pk_prepare_pkcs1_rsa_hash (gnutls_digest_algorithm_t hash,
		       gnutls_datum_t * output);
int pk_hash_data(gnutls_pk_algorithm_t pk, gnutls_digest_algorithm_t hash,
  bigint_t * params, const gnutls_datum_t * data, gnutls_datum_t * digest);

#endif
