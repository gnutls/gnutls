GNUTLS_CIPHER_HANDLE gnutls_cipher_init( BulkCipherAlgorithm cipher, void* key, int keysize, void* iv, int ivsize);
int gnutls_cipher_encrypt(GNUTLS_CIPHER_HANDLE handle, void* text, int textlen);
int gnutls_cipher_decrypt(GNUTLS_CIPHER_HANDLE handle, void* ciphertext, int ciphertextlen);
void gnutls_cipher_deinit(GNUTLS_CIPHER_HANDLE handle);
