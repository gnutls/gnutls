#include "defines.h"

#define GNUTLS_WEAK_RANDOM 0
#define GNUTLS_STRONG_RANDOM 1
#define GNUTLS_VERY_STRONG_RANDOM 2

int _gnutls_get_random(opaque * res, int bytes, int);
