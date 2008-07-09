#ifndef RANDOM_H
# define RANDOM_H

#include <gnutls/crypto.h>

extern int crypto_rnd_prio;
extern gnutls_crypto_rnd_st _gnutls_rnd_ops;

int _gnutls_rnd (int level, void *data, size_t len);
void _gnutls_rnd_deinit (void);
int _gnutls_rnd_init (void);

#endif
