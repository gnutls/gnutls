int _gnutls_base64_encode(const uint8 * data, size_t data_size, uint8 ** result);
int _gnutls_fbase64_encode(const char *msg, const uint8 * data, int data_size,
			   uint8 ** result);
int _gnutls_base64_decode(const uint8 * data, size_t data_size, uint8 ** result);
int _gnutls_fbase64_decode( const opaque* header, const uint8 * data, size_t data_size,
			   uint8 ** result);
