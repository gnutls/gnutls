AlertDescription gnutls_get_last_alert( GNUTLS_STATE state);
KXAlgorithm gnutls_get_current_kx( GNUTLS_STATE state);
ssize_t gnutls_send_int(SOCKET cd, GNUTLS_STATE state, ContentType type, HandshakeType htype, const void* data, size_t sizeofdata);
ssize_t gnutls_recv_int(SOCKET cd, GNUTLS_STATE state, ContentType type, HandshakeType, char* data, size_t sizeofdata);
ssize_t _gnutls_send_change_cipher_spec(SOCKET cd, GNUTLS_STATE state, int again);
