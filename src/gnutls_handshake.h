int _gnutls_supported_ciphersuites(GNUTLS_CipherSuite **ciphers);
int _gnutls_supported_compression_methods(CompressionMethod **comp);
int _gnutls_send_handshake(int cd, GNUTLS_STATE state, void* i_data, uint32 i_datasize, HandshakeType type, int hash);
int _gnutls_send_hello_request(int cd, GNUTLS_STATE state);
int _gnutls_send_hello(int cd, GNUTLS_STATE state, opaque* SessionID, uint8 SessionIDLen);
int _gnutls_recv_hello(int cd, GNUTLS_STATE state, char* data, int datalen, opaque** SessionID, int SessionIDnum);
int gnutls_handshake(int cd, GNUTLS_STATE state);
int _gnutls_recv_handshake_int( int cd, GNUTLS_STATE state, void*, uint32, void*, uint32);
int _gnutls_generate_session_id( char** session_id, uint8* len);
