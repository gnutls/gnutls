#ifndef RSA_PSS_H_INCLUDED
#define RSA_PSS_H_INCLUDED

#include <nettle/rsa.h>

int
rsa_pss_sha256_sign_digest_tr(const struct rsa_public_key *pub,
			      const struct rsa_private_key *key,
			      void *random_ctx, nettle_random_func *random,
			      size_t salt_length, const uint8_t *salt,
			      const uint8_t *digest,
			      mpz_t s);

int
rsa_pss_sha256_verify_digest(const struct rsa_public_key *key,
			     size_t salt_length,
			     const uint8_t *digest,
			     const mpz_t signature);

int
rsa_pss_sha384_sign_digest_tr(const struct rsa_public_key *pub,
			      const struct rsa_private_key *key,
			      void *random_ctx, nettle_random_func *random,
			      size_t salt_length, const uint8_t *salt,
			      const uint8_t *digest,
			      mpz_t s);

int
rsa_pss_sha384_verify_digest(const struct rsa_public_key *key,
			     size_t salt_length,
			     const uint8_t *digest,
			     const mpz_t signature);

int
rsa_pss_sha512_sign_digest_tr(const struct rsa_public_key *pub,
			      const struct rsa_private_key *key,
			      void *random_ctx, nettle_random_func *random,
			      size_t salt_length, const uint8_t *salt,
			      const uint8_t *digest,
			      mpz_t s);

int
rsa_pss_sha512_verify_digest(const struct rsa_public_key *key,
			     size_t salt_length,
			     const uint8_t *digest,
			     const mpz_t signature);

int
_rsa_verify_recover(const struct rsa_public_key *key,
		    mpz_t m,
		    const mpz_t s);

#endif
