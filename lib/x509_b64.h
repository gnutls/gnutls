int _gnutls_base64_encode(uint8 * data, int data_size, uint8 ** result);
int _gnutls_fbase64_encode(const char *msg, const uint8 * data, int data_size,
			   uint8 ** result);
int _gnutls_base64_decode(uint8 * data, int data_size, uint8 ** result);
int _gnutls_fbase64_decode( const uint8 * data, int data_size,
			   uint8 ** result);
