#include "rsa-pss.h"

int
_rsa_verify_recover(const struct rsa_public_key *key,
		    mpz_t m,
		    const mpz_t s)
{
  if ( (mpz_sgn(s) <= 0)
       || (mpz_cmp(s, key->n) >= 0) )
    return 0;

  mpz_powm(m, s, key->e, key->n);

  return 1;
}
