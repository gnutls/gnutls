int _gnutls_base64_encode(uint8 * data, int data_size, uint8 ** result);
int _gnutls_fbase64_encode(char *msg, uint8 * data, int data_size,
			   uint8 ** result);
int _gnutls_base64_decode(uint8 * data, int data_size, uint8 ** result);
int _gnutls_fbase64_decode(char *msg, uint8 * data, int data_size,
			   uint8 ** result);
int _gnutls_sbase64_encode(uint8 * data, int data_size, uint8 ** result);
int _gnutls_sbase64_decode(uint8 * data, int data_size, uint8 ** result);
