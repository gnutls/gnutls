#ifndef GNUTLS_CIPHER_INT
# define GNUTLS_CIPHER_INT

#ifdef USE_MCRYPT
# include <mcrypt.h>
# define GNUTLS_CIPHER_HANDLE MCRYPT
# define GNUTLS_CIPHER_FAILED MCRYPT_FAILED
#else
# include <gcrypt.h>
# define GNUTLS_CIPHER_HANDLE GCRY_CIPHER_HD
# define GNUTLS_CIPHER_FAILED NULL
#endif

GNUTLS_CIPHER_HANDLE gnutls_cipher_init( BulkCipherAlgorithm cipher, void* key, int keysize, void* iv, int ivsize);
int gnutls_cipher_encrypt(GNUTLS_CIPHER_HANDLE handle, void* text, int textlen);
int gnutls_cipher_decrypt(GNUTLS_CIPHER_HANDLE handle, void* ciphertext, int ciphertextlen);
void gnutls_cipher_deinit(GNUTLS_CIPHER_HANDLE handle);

#endif /* GNUTLS_CIPHER_INT */
