int _gnutls_send_handshake(int cd, GNUTLS_STATE state, void* i_data, uint32 i_datasize, HandshakeType type);
int _gnutls_send_hello_request(int cd, GNUTLS_STATE state);
int _gnutls_send_hello(int cd, GNUTLS_STATE state, opaque* SessionID, uint8 SessionIDLen);
int _gnutls_recv_hello(int cd, GNUTLS_STATE state, char* data, int datalen);
int gnutls_handshake(int cd, GNUTLS_STATE state);
int _gnutls_recv_handshake( int cd, GNUTLS_STATE state, uint8**, int*, HandshakeType);
int _gnutls_generate_session_id( char** session_id, uint8* len);
