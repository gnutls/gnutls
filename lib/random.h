#ifndef RANDOM_H
# define RANDOM_H

#include <gnutls/crypto.h>

#define RND_RANDOM GNUTLS_RND_RANDOM
#define RND_NONCE GNUTLS_RND_NONCE
#define RND_KEY GNUTLS_RND_KEY

int _gnutls_rnd (int level, void *data, int len);
void _gnutls_rnd_deinit ();
int _gnutls_rnd_init ();

#endif
