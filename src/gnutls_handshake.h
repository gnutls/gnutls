int _gnutls_supported_ciphersuites(GNUTLS_CipherSuite **ciphers);
int _gnutls_supported_compression_methods(CompressionMethod **comp);
int _gnutls_send_handshake(int cd, GNUTLS_STATE state, void* i_data, uint32 i_datasize, HandshakeType type);
int _gnutls_send_hello_request(int cd, GNUTLS_STATE state);
int _gnutls_send_hello(int cd, GNUTLS_STATE state, opaque* SessionID, uint8 SessionIDLen);
int _gnutls_recv_hello(int cd, GNUTLS_STATE state, char* data, int datalen, opaque** SessionID, int SessionIDnum);
int gnutls_handshake(int cd, GNUTLS_STATE state);
int _gnutls_recv_handshake( int cd, GNUTLS_STATE state, void*, uint32);
