extern int _gnutls_cryptodev_fd;

#ifndef CRYPTO_CIPHER_MAX_KEY_LEN
#define CRYPTO_CIPHER_MAX_KEY_LEN 64
#endif

#ifndef EALG_MAX_BLOCK_LEN
#define EALG_MAX_BLOCK_LEN 16
#endif

void _gnutls_cryptodev_deinit (void);
int _gnutls_cryptodev_init (void);
int _cryptodev_register_gcm_crypto (int cfd);
