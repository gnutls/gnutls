#ifndef GNUTLS_HASH_INT_H
# define GNUTLS_HASH_INT_H

#include <gnutls_int.h>

#ifdef USE_MHASH
# include <mhash.h>
#else
# include <gcrypt.h>
#endif

/* for message digests */
#ifdef USE_MHASH
# define GNUTLS_HASH_HANDLE MHASH
# define GNUTLS_MAC_HANDLE MHASH
#else
# define GNUTLS_HASH_HANDLE GCRY_MD_HD
# define GNUTLS_MAC_HANDLE GCRY_MD_HD
#endif

#define GNUTLS_HASH_FAILED NULL
#define GNUTLS_MAC_FAILED NULL

GNUTLS_MAC_HANDLE gnutls_hmac_init(MACAlgorithm algorithm, char* key, int keylen);
int gnutls_hmac_get_algo_len(MACAlgorithm algorithm);
int gnutls_hmac(GNUTLS_HASH_HANDLE handle, void* text, int textlen);
void* gnutls_hmac_deinit(GNUTLS_HASH_HANDLE handle);

GNUTLS_HASH_HANDLE gnutls_hash_init(MACAlgorithm algorithm);
int gnutls_hash_get_algo_len(MACAlgorithm algorithm);
int gnutls_hash(GNUTLS_HASH_HANDLE handle, void* text, int textlen);
void* gnutls_hash_deinit(GNUTLS_HASH_HANDLE handle);

#endif /* GNUTLS_HASH_INT_H */
