#include "defines.h"

#define GNUTLS_WEAK_RANDOM GCRY_WEAK_RANDOM
#define GNUTLS_STRONG_RANDOM GCRY_STRONG_RANDOM

int _gnutls_get_random(opaque* res, int bytes, int);
