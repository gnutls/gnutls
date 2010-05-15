#ifndef GNUTLS_SIGN_H
# define GNUTLS_SIGN_H

int pk_pkcs1_rsa_hash (gnutls_digest_algorithm_t hash, const gnutls_datum_t * text, gnutls_datum_t * output);
int pk_dsa_hash (const gnutls_datum_t * text, gnutls_datum_t * hash);

#endif
