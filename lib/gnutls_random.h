#include "defines.h"

#ifndef USE_GCRYPT
# define GNUTLS_WEAK_RANDOM 0 
# define GNUTLS_STRONG_RANDOM 1
#else
# define GNUTLS_WEAK_RANDOM GCRY_WEAK_RANDOM
# define GNUTLS_STRONG_RANDOM GCRY_STRONG_RANDOM
#endif

char *_gnutls_get_random(int bytes, int);
void _gnutls_free_rand(void* rand);
