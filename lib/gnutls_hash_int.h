GNUTLS_MAC_HANDLE gnutls_hmac_init(MACAlgorithm algorithm, char* key, int keylen);
int gnutls_hmac_get_algo_len(MACAlgorithm algorithm);
int gnutls_hmac(GNUTLS_HASH_HANDLE handle, void* text, int textlen);
void* gnutls_hmac_deinit(GNUTLS_HASH_HANDLE handle);

GNUTLS_HASH_HANDLE gnutls_hash_init(MACAlgorithm algorithm);
int gnutls_hash_get_algo_len(MACAlgorithm algorithm);
int gnutls_hash(GNUTLS_HASH_HANDLE handle, void* text, int textlen);
void* gnutls_hash_deinit(GNUTLS_HASH_HANDLE handle);

