int _gnutls_base64_encode(uint8 * const data, int data_size, uint8 ** result);
int _gnutls_fbase64_encode( char *msg, const uint8 * data, int data_size,
			   uint8 ** result);
int _gnutls_base64_decode( const uint8 * data, int data_size, uint8 ** result);
int _gnutls_fbase64_decode( const uint8 * data, int data_size,
			   uint8 ** result);
