ssize_t gnutls_send_int( GNUTLS_STATE state, ContentType type, HandshakeType htype, const void* data, size_t sizeofdata);
ssize_t gnutls_recv_int( GNUTLS_STATE state, ContentType type, HandshakeType, char* data, size_t sizeofdata);
ssize_t _gnutls_send_change_cipher_spec( GNUTLS_STATE state, int again);
void gnutls_transport_set_lowat(GNUTLS_STATE state, int num);
