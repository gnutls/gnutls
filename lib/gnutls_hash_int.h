#ifndef GNUTLS_HASH_INT_H
# define GNUTLS_HASH_INT_H

#include <gnutls_int.h>

#ifdef USE_MHASH
# include <mhash.h>
#else
# include <gcrypt.h>
#endif

/* for message digests */

typedef struct {
#ifdef USE_MHASH
	MHASH handle;
#else
	GCRY_MD_HD handle;
#endif
	MACAlgorithm algorithm;
	void* key;
	int keysize;
} GNUTLS_MAC_HANDLE_INT;
typedef GNUTLS_MAC_HANDLE_INT* GNUTLS_MAC_HANDLE;


#define GNUTLS_HASH_FAILED NULL
#define GNUTLS_MAC_FAILED NULL

#define gnutls_mac_ssl3 gnutls_hmac

GNUTLS_MAC_HANDLE gnutls_hmac_init( MACAlgorithm algorithm, void* key, int keylen);
int gnutls_hmac_get_algo_len(MACAlgorithm algorithm);
int gnutls_hmac(GNUTLS_MAC_HANDLE handle, void* text, int textlen);
void* gnutls_hmac_deinit( GNUTLS_MAC_HANDLE handle);

GNUTLS_MAC_HANDLE gnutls_mac_init_ssl3( MACAlgorithm algorithm, void* key, int keylen);
void* gnutls_mac_deinit_ssl3( GNUTLS_MAC_HANDLE handle);

GNUTLS_MAC_HANDLE gnutls_hash_init(MACAlgorithm algorithm);
int gnutls_hash_get_algo_len(MACAlgorithm algorithm);
int gnutls_hash(GNUTLS_MAC_HANDLE handle, void* text, int textlen);
void* gnutls_hash_deinit(GNUTLS_MAC_HANDLE handle);

void *gnutls_ssl3_generate_random(void *secret, int secret_len, void *random, int random_len, int bytes);

GNUTLS_MAC_HANDLE gnutls_mac_init_ssl3_handshake(MACAlgorithm algorithm, void *key, int keylen);
void *gnutls_mac_deinit_ssl3_handshake(GNUTLS_MAC_HANDLE handle);
#endif /* GNUTLS_HASH_INT_H */
