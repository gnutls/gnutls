int _gnutls_encrypt( GNUTLS_STATE state, char* data, size_t data_size, uint8** ciphertext, ContentType type);
int _gnutls_TLSCompressed2TLSCiphertext(GNUTLS_STATE state,
						      GNUTLSCiphertext**
						      cipher,
						      GNUTLSCompressed *
						      compressed);
int _gnutls_freeTLSCiphertext(GNUTLSCiphertext * ciphertext);
int _gnutls_set_cipher( GNUTLS_STATE state, BulkCipherAlgorithm algo);
int _gnutls_set_mac( GNUTLS_STATE state, MACAlgorithm algo);
int _gnutls_set_compression( GNUTLS_STATE state, CompressionMethod algo);
int _gnutls_connection_state_init(GNUTLS_STATE state);
int _gnutls_TLSCiphertext2TLSCompressed(GNUTLS_STATE state,
						      GNUTLSCompressed**
						      compress,
						      GNUTLSCiphertext *
						      ciphertext);
